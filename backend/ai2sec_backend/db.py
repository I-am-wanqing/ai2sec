import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

from .config import Settings, get_settings


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True)


def loads(raw: Optional[str], default: Any = None) -> Any:
    if not raw:
        return default
    return json.loads(raw)


def dict_from_row(row: sqlite3.Row) -> Dict[str, Any]:
    return {key: row[key] for key in row.keys()}


@contextmanager
def connect(settings: Optional[Settings] = None) -> Iterator[sqlite3.Connection]:
    settings = settings or get_settings()
    path = settings.sqlite_path
    if path.parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(settings: Optional[Settings] = None) -> None:
    settings = settings or get_settings()
    with connect(settings) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS invites (
              code TEXT PRIMARY KEY,
              active INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
              token TEXT PRIMARY KEY,
              invite_code TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(invite_code) REFERENCES invites(code)
            );

            CREATE TABLE IF NOT EXISTS scans (
              id TEXT PRIMARY KEY,
              type TEXT NOT NULL,
              status TEXT NOT NULL,
              target TEXT,
              project_name TEXT,
              profile TEXT NOT NULL,
              config_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              completed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS scan_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              scan_id TEXT NOT NULL,
              agent TEXT NOT NULL,
              level TEXT NOT NULL,
              message TEXT NOT NULL,
              data_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
              id TEXT PRIMARY KEY,
              scan_id TEXT NOT NULL,
              title TEXT NOT NULL,
              severity TEXT NOT NULL,
              source_agent TEXT NOT NULL,
              component TEXT NOT NULL,
              description TEXT NOT NULL,
              evidence_json TEXT NOT NULL,
              recommendation TEXT NOT NULL,
              verified INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL,
              FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS reports (
              id TEXT PRIMARY KEY,
              scan_id TEXT NOT NULL UNIQUE,
              title TEXT NOT NULL,
              risk_score REAL NOT NULL,
              summary TEXT NOT NULL,
              markdown_path TEXT NOT NULL,
              json_path TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS evidence_files (
              id TEXT PRIMARY KEY,
              scan_id TEXT NOT NULL,
              finding_id TEXT,
              kind TEXT NOT NULL,
              path TEXT NOT NULL,
              sha256 TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute(
            "INSERT OR IGNORE INTO invites(code, active, created_at) VALUES (?, 1, ?)",
            (settings.invite_code, utc_now()),
        )


def insert_event(scan_id: str, agent: str, message: str, level: str = "info", data: Any = None) -> None:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO scan_events(scan_id, agent, level, message, data_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (scan_id, agent, level, message, dumps(data or {}), utc_now()),
        )


def set_scan_status(scan_id: str, status: str) -> None:
    completed_at = utc_now() if status in {"completed", "failed"} else None
    with connect() as conn:
        conn.execute(
            """
            UPDATE scans
            SET status = ?, updated_at = ?, completed_at = COALESCE(?, completed_at)
            WHERE id = ?
            """,
            (status, utc_now(), completed_at, scan_id),
        )


def create_scan(scan_id: str, scan_type: str, profile: str, config: Dict[str, Any], target: Optional[str] = None, project_name: Optional[str] = None) -> None:
    now = utc_now()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO scans(id, type, status, target, project_name, profile, config_json, created_at, updated_at)
            VALUES (?, ?, 'queued', ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, scan_type, target, project_name, profile, dumps(config), now, now),
        )


def list_rows(query: str, args: Iterable[Any] = ()) -> List[Dict[str, Any]]:
    with connect() as conn:
        return [dict_from_row(row) for row in conn.execute(query, tuple(args)).fetchall()]


def one_row(query: str, args: Iterable[Any] = ()) -> Optional[Dict[str, Any]]:
    with connect() as conn:
        row = conn.execute(query, tuple(args)).fetchone()
        return dict_from_row(row) if row else None


def insert_finding(finding: Dict[str, Any]) -> None:
    with connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO findings(
              id, scan_id, title, severity, source_agent, component, description,
              evidence_json, recommendation, verified, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding["id"],
                finding["scan_id"],
                finding["title"],
                finding["severity"],
                finding["source_agent"],
                finding["component"],
                finding["description"],
                dumps(finding.get("evidence", {})),
                finding["recommendation"],
                1 if finding.get("verified") else 0,
                utc_now(),
            ),
        )


def insert_report(report: Dict[str, Any]) -> None:
    with connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO reports(
              id, scan_id, title, risk_score, summary, markdown_path, json_path, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report["id"],
                report["scan_id"],
                report["title"],
                report["risk_score"],
                report["summary"],
                report["markdown_path"],
                report["json_path"],
                utc_now(),
            ),
        )


def ensure_data_dirs(settings: Optional[Settings] = None) -> None:
    settings = settings or get_settings()
    for path in (settings.upload_dir, settings.evidence_dir, settings.report_dir):
        Path(path).mkdir(parents=True, exist_ok=True)
