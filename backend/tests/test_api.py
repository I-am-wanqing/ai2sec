import io
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from ai2sec_backend.config import get_settings
from ai2sec_backend.main import app


def _client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.setenv("AI2SEC_DATABASE_URL", f"sqlite:///{tmp_path / 'ai2sec.db'}")
    monkeypatch.setenv("AI2SEC_UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("AI2SEC_EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("AI2SEC_REPORT_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("AI2SEC_INVITE_CODE", "demo-invite-code")
    get_settings.cache_clear()
    return TestClient(app)


def _token(client: TestClient) -> str:
    response = client.post("/api/auth/invite", json={"inviteCode": "demo-invite-code"})
    assert response.status_code == 200
    return response.json()["token"]


def test_invite_success_and_failure(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch) as client:
        assert client.post("/api/auth/invite", json={"inviteCode": "wrong"}).status_code == 401
        response = client.post("/api/auth/invite", json={"inviteCode": "demo-invite-code"})
        assert response.status_code == 200
        assert response.json()["valid"] is True


def test_blackbox_rejects_localhost(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch) as client:
        token = _token(client)
        response = client.post(
            "/api/scans/blackbox",
            json={"targetUrl": "http://127.0.0.1", "profile": "quick", "modules": []},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 400


def test_whitebox_scan_generates_report(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch) as client:
        token = _token(client)
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, "w") as archive:
            archive.writestr("requirements.txt", "fastapi==0.115.6\n")
            archive.writestr(
                "app.py",
                "def search(q, db):\n    return db.execute('select * from users where name=' + q)\n",
            )
        archive_bytes.seek(0)

        response = client.post(
            "/api/scans/whitebox",
            data={
                "projectName": "demo",
                "language": "python",
                "auditProfile": "full",
                "vulnerabilityClasses": ["SQL Injection"],
            },
            files={"archive": ("source.zip", archive_bytes, "application/zip")},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        scan_id = response.json()["scanId"]

        scan_response = client.get(f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {token}"})
        assert scan_response.status_code == 200
        assert scan_response.json()["status"] in {"completed", "running", "queued"}

        reports = client.get("/api/reports", headers={"Authorization": f"Bearer {token}"})
        assert reports.status_code == 200
        assert reports.json()
        report_id = reports.json()[0]["id"]

        report = client.get(f"/api/reports/{report_id}", headers={"Authorization": f"Bearer {token}"})
        assert report.status_code == 200
        assert report.json()["findings"]

        markdown = client.get(
            f"/api/reports/{report_id}/export.md", headers={"Authorization": f"Bearer {token}"}
        )
        assert markdown.status_code == 200
        assert "Whitebox Security Report" in markdown.text
