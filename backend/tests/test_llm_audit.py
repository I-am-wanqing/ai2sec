"""Offline tests for the LLM-driven skill audit (mocked LLM client)."""

import io
import zipfile
from pathlib import Path
from typing import Any

import pytest

from ai2sec_backend.audit import run_whitebox_audit
from ai2sec_backend.audit.llm_audit import run_llm_audit

VULN_APP = {
    "app.py": (
        "import requests\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "app.debug = True\n"
        "\n"
        "@app.route('/fetch')\n"
        "def fetch():\n"
        "    url = request.args.get('url')\n"
        "    return requests.get(url).text\n"
    ),
    "requirements.txt": "flask==2.0.0\nrequests==2.31.0\n",
}


class FakeLLMClient:
    """Mimics LLMClient.chat_json without network access."""

    def __init__(self) -> None:
        self.calls: list = []

    def chat_json(self, system: str, user: str, **kwargs: Any) -> Any:
        self.calls.append(user[:60])
        if "audit execution plan" in user.lower() or "Return JSON" in user and "projectType" in user:
            return {
                "mode": "deep",
                "projectType": "通用Web",
                "dimensionPriorities": {"D1": "high"},
                "focusAreas": ["SSRF in fetch endpoint"],
                "plannedDimensions": ["D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10"],
            }
        if "SOURCE FILES" in user:
            if "app.py" in user:
                return {
                    "findings": [
                        {
                            "title": "SSRF via user-controlled URL",
                            "dimension": "D6",
                            "severity": "high",
                            "file": "app.py",
                            "line": 8,
                            "code_quote": "url = request.args.get('url')",
                            "description": "User-supplied URL passed to requests.get → SSRF.",
                            "recommendation": "Allowlist destinations and block private IPs.",
                            "user_controlled": True,
                            "confidence": 0.9,
                        },
                        {
                            "title": "Hallucinated finding",
                            "dimension": "D1",
                            "severity": "critical",
                            "file": "not/a/real/file.py",
                            "line": 1,
                            "code_quote": "db.execute('SELECT ' + user)",
                            "description": "Fake finding, must be dropped.",
                            "recommendation": "x",
                            "user_controlled": True,
                            "confidence": 0.9,
                        },
                        {
                            "title": "Quote-not-in-file finding",
                            "dimension": "D2",
                            "severity": "high",
                            "file": "app.py",
                            "line": 3,
                            "code_quote": "this exact quote does not exist in the file at all",
                            "description": "Fake quote, must be dropped.",
                            "recommendation": "x",
                            "user_controlled": False,
                            "confidence": 0.5,
                        },
                    ]
                }
            return {"findings": []}
        if "report gate" in user.lower() or "gatePassed" in user:
            return {
                "coverage": {f"D{i}": "covered" for i in range(1, 11)},
                "gatePassed": True,
                "gateReason": "all planned dimensions covered",
                "duplicatedFindingTitles": [],
            }
        raise AssertionError(f"unexpected prompt: {user[:100]}")


def _make_archive(tmp_path: Path, files: dict) -> Path:
    archive_path = tmp_path / "source.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return archive_path


def _settings(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AI2SEC_DATABASE_URL", f"sqlite:///{tmp_path / 'db.sqlite'}")
    monkeypatch.setenv("AI2SEC_UPLOAD_DIR", str(tmp_path / "up"))
    monkeypatch.setenv("AI2SEC_EVIDENCE_DIR", str(tmp_path / "ev"))
    monkeypatch.setenv("AI2SEC_REPORT_DIR", str(tmp_path / "rp"))
    monkeypatch.setenv("AI2SEC_OPENAI_API_KEY", "sk-fake")
    monkeypatch.setenv("AI2SEC_SKILL_DIR", str(Path(__file__).resolve().parents[2] / "code-audit-main"))
    from ai2sec_backend.config import get_settings

    get_settings.cache_clear()
    return get_settings()


def test_run_llm_audit_with_fake_client(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path, monkeypatch)
    monkeypatch.setenv("AI2SEC_OPENAI_API_KEY", "sk-fake")
    from ai2sec_backend.config import get_settings

    get_settings.cache_clear()
    settings = get_settings()

    archive = _make_archive(tmp_path, VULN_APP)
    import zipfile as zf

    with zf.ZipFile(archive) as z:
        z.extractall(tmp_path / "src")
    texts = [
        ("app.py", (tmp_path / "src" / "app.py").read_text()),
        ("requirements.txt", (tmp_path / "src" / "requirements.txt").read_text()),
    ]
    recon = {"language": "python", "file_count": 2, "frameworks": ["Flask"], "entry_points": 1}
    events = []

    result = run_llm_audit(
        recon=recon,
        texts=texts,
        mode="deep",
        planned_dimensions=["D1", "D6"],
        config={},
        emit=lambda agent, msg, level, data: events.append((agent, msg, level, data)),
        settings=settings,
        client=FakeLLMClient(),
    )

    assert result is not None
    assert result["engine"] == "code-audit-skill-llm"
    titles = [f["title"] for f in result["findings"]]
    assert "SSRF via user-controlled URL" in titles
    assert "Hallucinated finding" not in titles  # fake file dropped
    assert "Quote-not-in-file finding" not in titles  # quote mismatch dropped
    ssrf = next(f for f in result["findings"] if f["title"] == "SSRF via user-controlled URL")
    assert ssrf["verified"] is True  # user_controlled + confidence >= 0.6
    assert ssrf["source_agent"] == "LLM Dimension Agent D6"
    assert result["gate"]["passed"] is True
    messages = [msg for _a, msg, _l, _d in events]
    assert any("[LOADED]" in m for m in messages)
    assert any("[PLAN]" in m for m in messages)
    assert any("[SCAN]" in m for m in messages)
    assert any("[GATE]" in m for m in messages)


def test_llm_failure_falls_back_to_rules(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path, monkeypatch)

    class FailingClient:
        def chat_json(self, *args: Any, **kwargs: Any) -> Any:
            from ai2sec_backend.audit.llm_client import LLMError

            raise LLMError("boom")

    texts = [("app.py", VULN_APP["app.py"])]
    recon = {"language": "python", "file_count": 1, "frameworks": [], "entry_points": 1}
    result = run_llm_audit(
        recon=recon,
        texts=texts,
        mode="deep",
        planned_dimensions=["D1", "D6"],
        config={},
        emit=lambda *a: None,
        settings=settings,
        client=FailingClient(),
    )
    assert result is None  # signals caller to use deterministic fallback


def test_no_api_key_uses_deterministic_path(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AI2SEC_DATABASE_URL", f"sqlite:///{tmp_path / 'db.sqlite'}")
    monkeypatch.setenv("AI2SEC_UPLOAD_DIR", str(tmp_path / "up"))
    monkeypatch.setenv("AI2SEC_EVIDENCE_DIR", str(tmp_path / "ev"))
    monkeypatch.setenv("AI2SEC_REPORT_DIR", str(tmp_path / "rp"))
    monkeypatch.setenv("AI2SEC_OPENAI_API_KEY", "")
    monkeypatch.setenv("AI2SEC_SKILL_DIR", str(Path(__file__).resolve().parents[2] / "code-audit-main"))
    from ai2sec_backend.config import get_settings

    get_settings.cache_clear()

    archive = _make_archive(tmp_path, VULN_APP)
    result = run_whitebox_audit(
        archive,
        tmp_path / "work2",
        {"auditProfile": "deep", "language": "python", "vulnerabilityClasses": []},
        emit=lambda *a: None,
    )
    assert result["engine"] == "deterministic-rules"
    assert any(f["evidence"].get("rule") == "SSRF-FETCH-USER-URL" for f in result["findings"])
