import ipaddress
import socket
import secrets
import zipfile
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, List
from urllib.parse import urlparse, urlunparse

from fastapi import HTTPException, Request, status

from .config import Settings, get_settings
from .db import connect, utc_now


PRIVATE_HOSTS = {"localhost", "localhost.localdomain", "0.0.0.0"}
METADATA_IPS = {"169.254.169.254"}


def create_session(invite_code: str, settings: Settings) -> dict:
    with connect(settings) as conn:
        invite = conn.execute(
            "SELECT code FROM invites WHERE code = ? AND active = 1", (invite_code,)
        ).fetchone()
        if not invite:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid invite code")

        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=settings.session_hours)
        conn.execute(
            """
            INSERT INTO sessions(token, invite_code, expires_at, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (token, invite_code, expires_at.isoformat(), utc_now()),
        )
        return {"token": token, "expiresAt": expires_at.isoformat()}


def require_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    token = header.split(" ", 1)[1].strip()
    row = None
    with connect() as conn:
        row = conn.execute("SELECT token, expires_at FROM sessions WHERE token = ?", (token,)).fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")

    expires_at = datetime.fromisoformat(row["expires_at"])
    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Expired bearer token")
    return token


def normalize_public_url(raw_url: str, settings: Settings = None) -> str:
    settings = settings or get_settings()
    parsed = urlparse(raw_url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Target URL must use http:// or https://")
    if parsed.username or parsed.password:
        raise ValueError("Target URL must not include credentials")

    host = parsed.hostname or ""
    validate_public_host(host, settings)

    path = parsed.path or "/"
    normalized = parsed._replace(path=path, params="", fragment="")
    return urlunparse(normalized)


def validate_public_host(host: str, settings: Settings = None) -> None:
    settings = settings or get_settings()
    lowered = host.strip().lower().rstrip(".")
    if not lowered or lowered in PRIVATE_HOSTS or lowered.endswith(".localhost"):
        raise ValueError("Private or local targets are disabled by default")

    try:
        ip = ipaddress.ip_address(lowered)
        if _blocked_ip(ip, settings):
            raise ValueError("Private, loopback, link-local or metadata targets are disabled")
        return
    except ValueError as exc:
        if "disabled" in str(exc):
            raise

    if "." not in lowered:
        raise ValueError("Target host must be a fully qualified domain or public IP")

    try:
        resolved = socket.getaddrinfo(lowered, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return

    for item in resolved:
        ip = ipaddress.ip_address(item[4][0])
        if _blocked_ip(ip, settings):
            raise ValueError("Resolved target includes a private or local address")


def _blocked_ip(ip: ipaddress._BaseAddress, settings: Settings) -> bool:
    if settings.allow_private_targets:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or str(ip) in METADATA_IPS
    )


def safe_extract_archive(archive_path: Path, destination: Path, max_members: int = 5000) -> List[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    suffixes = "".join(archive_path.suffixes).lower()
    if suffixes.endswith(".zip"):
        return _extract_zip(archive_path, destination, max_members)
    if suffixes.endswith(".tar.gz") or suffixes.endswith(".tgz") or suffixes.endswith(".tar"):
        return _extract_tar(archive_path, destination, max_members)
    raise ValueError("Unsupported source archive type")


def _validate_member_paths(names: Iterable[str], destination: Path, max_members: int) -> None:
    base = destination.resolve()
    count = 0
    for name in names:
        count += 1
        if count > max_members:
            raise ValueError("Archive contains too many files")
        target = (destination / name).resolve()
        if not str(target).startswith(str(base) + "/") and target != base:
            raise ValueError("Archive contains an unsafe path")


def _extract_zip(archive_path: Path, destination: Path, max_members: int) -> List[Path]:
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        _validate_member_paths(names, destination, max_members)
        archive.extractall(destination)
        return [destination / name for name in names if not name.endswith("/")]


def _extract_tar(archive_path: Path, destination: Path, max_members: int) -> List[Path]:
    with tarfile.open(archive_path) as archive:
        members = archive.getmembers()
        _validate_member_paths((member.name for member in members), destination, max_members)
        for member in members:
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError("Archive contains unsupported link or device entries")
        archive.extractall(destination)
        return [destination / member.name for member in members if member.isfile()]
