import hashlib
import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qs, urljoin, urlparse

from .security import safe_extract_archive

SECRET_PATTERNS = [
    ("Potential AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Potential Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Potential API Token", re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*['\"][^'\"]{12,}['\"]")),
]

SAST_PATTERNS = [
    ("Possible SQL Injection", "high", re.compile(r"(?i)(execute|query|raw)\s*\([^)]*(\+|f['\"]|format\()")),
    ("Possible XSS Sink", "medium", re.compile(r"(?i)(innerHTML|dangerouslySetInnerHTML|document\.write)")),
    ("Possible SSRF Sink", "medium", re.compile(r"(?i)(requests\.get|requests\.post|httpx\.get|fetch)\s*\(")),
    ("Possible Auth Bypass", "high", re.compile(r"(?i)(is_admin\s*=\s*true|bypass|skip_auth|auth\s*==\s*false)")),
    ("Possible Unsafe File Upload", "medium", re.compile(r"(?i)(upload|filename|save\(|write\()")),
    ("Possible Path Traversal", "medium", re.compile(r"(?i)(\.\./|send_file|FileResponse|open\()")),
]

DEPENDENCY_FILES = {
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "pom.xml",
    "go.mod",
    "composer.json",
}


def analyze_blackbox(target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
    response = _fetch_url(target_url)
    findings: List[Dict[str, Any]] = []
    headers = response.get("headers", {})
    body = response.get("body", "")

    required_headers = {
        "content-security-policy": "Missing Content-Security-Policy header",
        "x-frame-options": "Missing X-Frame-Options header",
        "x-content-type-options": "Missing X-Content-Type-Options header",
    }
    lower_headers = {key.lower(): value for key, value in headers.items()}
    for header, title in required_headers.items():
        if header not in lower_headers:
            findings.append(
                {
                    "title": title,
                    "severity": "low",
                    "source_agent": "Discovery Agent",
                    "component": target_url,
                    "description": f"The response does not include {header}, which weakens browser-side protections.",
                    "evidence": {"url": target_url, "missing_header": header},
                    "recommendation": f"Configure the application or reverse proxy to send {header}.",
                }
            )

    if "server" in lower_headers:
        findings.append(
            {
                "title": "Server header exposes technology detail",
                "severity": "low",
                "source_agent": "Recon Agent",
                "component": target_url,
                "description": "The Server header exposes platform details that can help fingerprinting.",
                "evidence": {"server": lower_headers["server"]},
                "recommendation": "Reduce or normalize Server headers at the edge proxy.",
            }
        )

    links = sorted(set(re.findall(r"""href=["']([^"']+)["']""", body, flags=re.I)))[:50]
    api_paths = [urljoin(target_url, item) for item in links if "/api" in item.lower()]
    params = sorted({key for link in links for key in parse_qs(urlparse(link).query).keys()})

    for path in ("/robots.txt", "/sitemap.xml"):
        probe = _fetch_url(urljoin(target_url, path), body_limit=2048)
        if probe.get("status_code") and int(probe["status_code"]) < 500:
            findings.append(
                {
                    "title": f"Public {path} discovered",
                    "severity": "low",
                    "source_agent": "Recon Agent",
                    "component": urljoin(target_url, path),
                    "description": f"{path} is reachable and should be reviewed for sensitive path disclosure.",
                    "evidence": {"status_code": probe.get("status_code")},
                    "recommendation": "Keep only intentionally public paths in crawler metadata files.",
                }
            )

    return {
        "recon": {
            "target_url": target_url,
            "status_code": response.get("status_code"),
            "headers": headers,
        },
        "discovery": {
            "links": [urljoin(target_url, item) for item in links],
            "api_paths": api_paths,
            "parameters": params,
        },
        "findings": findings,
    }


def analyze_whitebox(archive_path: Path, work_dir: Path, config: Dict[str, Any]) -> Dict[str, Any]:
    source_dir = work_dir / "source"
    files = safe_extract_archive(archive_path, source_dir)
    text_files = [_read_text_file(path) for path in files]
    text_files = [item for item in text_files if item is not None]

    findings: List[Dict[str, Any]] = []
    dependencies = []
    for path in files:
        if path.name in DEPENDENCY_FILES:
            dependencies.append(str(path.relative_to(source_dir)))

    if dependencies:
        findings.append(
            {
                "title": "Dependency manifest discovered",
                "severity": "low",
                "source_agent": "Discovery Agent",
                "component": ", ".join(dependencies[:5]),
                "description": "Dependency files were identified for downstream dependency and license scanning.",
                "evidence": {"dependency_files": dependencies},
                "recommendation": "Run pinned dependency vulnerability scanning in the sandbox pipeline.",
            }
        )

    for relative_path, text in text_files:
        for title, pattern in SECRET_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    {
                        "title": title,
                        "severity": "high",
                        "source_agent": "Discovery Agent",
                        "component": relative_path,
                        "description": "A secret-like token was found in source text by deterministic pattern matching.",
                        "evidence": {"file": relative_path, "snippet_sha256": _sha256(match.group(0))},
                        "recommendation": "Remove the secret, rotate the credential, and move runtime secrets to a secret manager.",
                    }
                )

        for title, severity, pattern in SAST_PATTERNS:
            match = pattern.search(text)
            if match:
                line_no = text[: match.start()].count("\n") + 1
                findings.append(
                    {
                        "title": title,
                        "severity": severity,
                        "source_agent": "Discovery Agent",
                        "component": f"{relative_path}:{line_no}",
                        "description": "A rule-based SAST pattern matched code that needs manual validation.",
                        "evidence": {"file": relative_path, "line": line_no, "pattern": title},
                        "recommendation": "Review data flow from user-controlled input to the matched sink and add validation or safe APIs.",
                    }
                )

    return {
        "source": {
            "file_count": len(files),
            "text_file_count": len(text_files),
            "dependency_files": dependencies,
        },
        "findings": findings[:100],
    }


def _fetch_url(url: str, body_limit: int = 128 * 1024) -> Dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "AI2Sec-SafeMVP/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=6) as response:
            body = response.read(body_limit).decode("utf-8", errors="replace")
            return {
                "status_code": response.status,
                "headers": dict(response.headers.items()),
                "body": body,
            }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "status_code": None,
            "headers": {},
            "body": "",
            "error": str(exc),
        }


def _read_text_file(path: Path) -> Any:
    try:
        if path.stat().st_size > 1024 * 1024:
            return None
        raw = path.read_bytes()
        if b"\x00" in raw[:4096]:
            return None
        return str(path), raw.decode("utf-8", errors="replace")
    except OSError:
        return None


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def finding_to_public_dict(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "scanId": row["scan_id"],
        "title": row["title"],
        "severity": row["severity"],
        "source": row["source_agent"],
        "component": row["component"],
        "description": row["description"],
        "evidence": json.loads(row["evidence_json"]),
        "recommendation": row["recommendation"],
        "verified": bool(row["verified"]),
        "createdAt": row["created_at"],
    }
