from pathlib import Path
from contextlib import asynccontextmanager
from typing import List

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from .agents import new_scan_id, run_scan
from .config import get_settings
from .db import create_scan, ensure_data_dirs, init_db, list_rows, loads, one_row, utc_now
from .reports import public_report
from .scanners import finding_to_public_dict
from .schemas import (
    BlackboxScanRequest,
    EventResponse,
    InviteRequest,
    InviteResponse,
    ReportDetail,
    ReportSummary,
    ScanCreated,
    ScanResponse,
)
from .security import create_session, normalize_public_url, require_token


@asynccontextmanager
async def lifespan(app: FastAPI):
    del app
    settings = get_settings()
    ensure_data_dirs(settings)
    init_db(settings)
    yield


app = FastAPI(title="AI2Sec Backend", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "time": utc_now()}


@app.post("/api/auth/invite", response_model=InviteResponse)
def auth_invite(payload: InviteRequest) -> InviteResponse:
    session = create_session(payload.inviteCode, get_settings())
    return InviteResponse(valid=True, token=session["token"], expiresAt=session["expiresAt"])


@app.post("/api/scans/blackbox", response_model=ScanCreated)
def create_blackbox_scan(
    payload: BlackboxScanRequest,
    background: BackgroundTasks,
    token: str = Depends(require_token),
) -> ScanCreated:
    del token
    settings = get_settings()
    try:
        target = normalize_public_url(payload.targetUrl, settings)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    scan_id = new_scan_id()
    config = payload.model_dump()
    config["targetUrl"] = target
    create_scan(scan_id, "blackbox", payload.profile, config, target=target)
    background.add_task(run_scan, scan_id)
    return ScanCreated(scanId=scan_id, status="queued")


@app.post("/api/scans/whitebox", response_model=ScanCreated)
async def create_whitebox_scan(
    background: BackgroundTasks,
    projectName: str = Form(...),
    language: str = Form("auto"),
    auditProfile: str = Form("full"),
    vulnerabilityClasses: List[str] = Form(default=[]),
    archive: UploadFile = File(...),
    token: str = Depends(require_token),
) -> ScanCreated:
    del token
    settings = get_settings()
    scan_id = new_scan_id()
    upload_root = settings.upload_dir / scan_id
    upload_root.mkdir(parents=True, exist_ok=True)

    filename = Path(archive.filename or "").name
    if not _supported_archive_name(filename):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported archive type")

    archive_path = upload_root / filename
    size = 0
    with archive_path.open("wb") as handle:
        while True:
            chunk = await archive.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > settings.max_upload_bytes:
                raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Archive too large")
            handle.write(chunk)

    work_dir = upload_root / "work"
    config = {
        "projectName": projectName,
        "language": language,
        "auditProfile": auditProfile,
        "vulnerabilityClasses": vulnerabilityClasses,
        "archivePath": str(archive_path),
        "workDir": str(work_dir),
    }
    create_scan(scan_id, "whitebox", auditProfile, config, project_name=projectName)
    background.add_task(run_scan, scan_id)
    return ScanCreated(scanId=scan_id, status="queued")


@app.get("/api/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, token: str = Depends(require_token)) -> ScanResponse:
    del token
    scan = one_row("SELECT * FROM scans WHERE id = ?", (scan_id,))
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return _scan_response(scan)


@app.get("/api/scans/{scan_id}/events", response_model=List[EventResponse])
def get_scan_events(scan_id: str, token: str = Depends(require_token)) -> List[EventResponse]:
    del token
    rows = list_rows("SELECT * FROM scan_events WHERE scan_id = ? ORDER BY id", (scan_id,))
    return [
        EventResponse(
            id=row["id"],
            scanId=row["scan_id"],
            agent=row["agent"],
            level=row["level"],
            message=row["message"],
            data=loads(row["data_json"], {}),
            createdAt=row["created_at"],
        )
        for row in rows
    ]


@app.get("/api/reports", response_model=List[ReportSummary])
def list_reports(token: str = Depends(require_token)) -> List[ReportSummary]:
    del token
    rows = list_rows("SELECT * FROM reports ORDER BY created_at DESC")
    return [ReportSummary(**public_report(row)) for row in rows]


@app.get("/api/reports/{report_id}", response_model=ReportDetail)
def get_report(report_id: str, token: str = Depends(require_token)) -> ReportDetail:
    del token
    report = one_row("SELECT * FROM reports WHERE id = ?", (report_id,))
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    findings = [
        finding_to_public_dict(row)
        for row in list_rows("SELECT * FROM findings WHERE scan_id = ? ORDER BY created_at", (report["scan_id"],))
    ]
    return ReportDetail(**public_report(report), findings=findings)


@app.get("/api/reports/{report_id}/export.json")
def export_report_json(report_id: str, token: str = Depends(require_token)) -> JSONResponse:
    del token
    report = _report_or_404(report_id)
    path = Path(report["json_path"])
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report JSON missing")
    return JSONResponse(content=loads(path.read_text(encoding="utf-8"), {}))


@app.get("/api/reports/{report_id}/export.md")
def export_report_markdown(report_id: str, token: str = Depends(require_token)) -> PlainTextResponse:
    del token
    report = _report_or_404(report_id)
    path = Path(report["markdown_path"])
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report Markdown missing")
    return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown")


@app.get("/api/reports/{report_id}/export.pdf")
def export_report_pdf(report_id: str, token: str = Depends(require_token)) -> FileResponse:
    del token
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="PDF export is reserved for a later renderer")


def _scan_response(scan: dict) -> ScanResponse:
    return ScanResponse(
        id=scan["id"],
        type=scan["type"],
        status=scan["status"],
        target=scan["target"],
        projectName=scan["project_name"],
        profile=scan["profile"],
        config=loads(scan["config_json"], {}),
        createdAt=scan["created_at"],
        updatedAt=scan["updated_at"],
        completedAt=scan["completed_at"],
    )


def _report_or_404(report_id: str) -> dict:
    report = one_row("SELECT * FROM reports WHERE id = ?", (report_id,))
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


def _supported_archive_name(filename: str) -> bool:
    lowered = filename.lower()
    return lowered.endswith(".zip") or lowered.endswith(".tar.gz") or lowered.endswith(".tgz")
