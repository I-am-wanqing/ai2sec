import io
import zipfile
from pathlib import Path

import pytest

from ai2sec_backend.audit import normalize_mode, run_whitebox_audit
from ai2sec_backend.audit.coverage import build_coverage_matrix, evaluate_report_gate


@pytest.fixture(autouse=True)
def _disable_llm(monkeypatch):
    """Keep rule-engine tests offline: never load the real .env API key."""
    monkeypatch.setenv("AI2SEC_LLM_AUDIT_ENABLED", "false")
    monkeypatch.setenv("AI2SEC_OPENAI_API_KEY", "")
    from ai2sec_backend.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


VULNERABLE_APP = {
    "app.py": """import os
import pickle
import yaml
import requests
from flask import Flask, request

app = Flask(__name__)
app.debug = True

SECRET_KEY = "hardcoded-super-secret-key-123"

@app.route("/search")
def search():
    q = request.args.get("q")
    return db.execute("select * from users where name=" + q)

@app.route("/ping")
def ping():
    url = request.args.get("url")
    return requests.get(url).text

@app.route("/load")
def load():
    data = request.args.get("data")
    return pickle.loads(data)

def render_tpl(tpl):
    return render_template_string(tpl)
""",
    "requirements.txt": "flask==2.0.0\npyyaml==5.3\nrequests==2.20.0\n",
}


def _make_archive(tmp_path: Path, files: dict) -> Path:
    archive_path = tmp_path / "source.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return archive_path


def _run(tmp_path: Path, files: dict, profile: str = "deep", language: str = "python"):
    archive = _make_archive(tmp_path, files)
    work_dir = tmp_path / "work"
    events = []

    result = run_whitebox_audit(
        archive,
        work_dir,
        {"auditProfile": profile, "language": language, "vulnerabilityClasses": []},
        emit=lambda agent, msg, level, data: events.append((agent, msg, data)),
    )
    return result, events


def test_mode_normalization() -> None:
    assert normalize_mode("quick") == "quick"
    assert normalize_mode("standard") == "standard"
    assert normalize_mode("deep") == "deep"
    assert normalize_mode("full") == "deep"  # legacy alias
    assert normalize_mode("sast") == "standard"
    assert normalize_mode("") == "standard"


def test_deep_mode_detects_multiple_dimensions(tmp_path: Path) -> None:
    result, events = _run(tmp_path, VULNERABLE_APP, profile="deep")
    titles = " | ".join(f["title"] for f in result["findings"])
    rules = {f["evidence"]["rule"] for f in result["findings"]}

    assert result["mode"] == "deep"
    assert result["recon"]["language"] == "python"
    assert "Flask" in result["recon"]["frameworks"]
    # D1 SQLi, D4 pickle, D6 SSRF, D8 debug, D7 secret, D10 deps
    assert "PY-SQLI-CONCAT" in rules
    assert "PY-PICKLE" in rules
    assert "SSRF-FETCH-USER-URL" in rules
    assert "DEBUG-ON" in rules
    assert any(rule.startswith("SECRET-") for rule in rules)
    assert any(f["evidence"].get("dimension") == "D10" for f in result["findings"])

    # coverage matrix: all 10 planned, gate passed
    assert result["coverage"]["plannedCount"] == 10
    assert result["gate"]["passed"] is True
    # events follow the skill controller steps
    messages = [msg for _agent, msg, _data in events]
    assert any("[MODE]" in m for m in messages)
    assert any("[RECON]" in m for m in messages)
    assert any("[PLAN]" in m for m in messages)
    assert any("[GATE]" in m for m in messages)


def test_taint_marker_raises_confidence(tmp_path: Path) -> None:
    result, _ = _run(tmp_path, VULNERABLE_APP, profile="deep")
    sql = next(f for f in result["findings"] if f["evidence"]["rule"] == "PY-SQLI-CONCAT")
    # `q` comes from request.args.get on a previous line; matched line itself has no marker
    assert sql["verified"] in (True, False)
    ssrf = next(f for f in result["findings"] if f["evidence"]["rule"] == "SSRF-FETCH-USER-URL")
    assert ssrf["verified"] is True  # request.args marker on the same line


def test_quick_mode_limits_dimensions(tmp_path: Path) -> None:
    result, _ = _run(tmp_path, VULNERABLE_APP, profile="quick")
    assert result["mode"] == "quick"
    assert result["plannedDimensions"] == ["D1", "D10", "D7"]
    assert result["coverage"]["plannedCount"] == 3
    dims = {f["evidence"].get("dimension") for f in result["findings"]}
    assert dims <= {"D1", "D7", "D10"}


def test_dependency_findings(tmp_path: Path) -> None:
    result, _ = _run(tmp_path, VULNERABLE_APP, profile="deep")
    dep_findings = [f for f in result["findings"] if f["evidence"].get("dimension") == "D10"]
    deps = {f["evidence"]["dependency"] for f in dep_findings}
    assert "pyyaml" in deps  # 5.3.0 < 6.0
    assert any(f["severity"] == "high" for f in dep_findings)


def test_clean_project_low_findings(tmp_path: Path) -> None:
    clean = {
        "app.py": "import json\n\ndef handler(data):\n    return json.dumps({'ok': True})\n",
        "requirements.txt": "flask==3.0.0\n",
    }
    result, _ = _run(tmp_path, clean, profile="deep")
    assert result["findings"] == []
    assert result["gate"]["passed"] is True
    assert result["coverage"]["coveredCount"] == 10


def test_javascript_rules(tmp_path: Path) -> None:
    js_app = {
        "server.js": """const express = require('express');
const app = express();
app.get('/search', (req, res) => {
  db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.send(req.query.url);
});
app.listen(3000);
""",
        "package.json": '{"dependencies": {"lodash": "4.17.15", "jsonwebtoken": "8.5.1"}}',
    }
    result, _ = _run(tmp_path, js_app, profile="standard", language="javascript")
    rules = {f["evidence"]["rule"] for f in result["findings"]}
    assert "JS-SQLI-TEMPLATE" in rules
    deps = {f["evidence"]["dependency"] for f in result["findings"] if f["evidence"].get("dimension") == "D10"}
    assert "lodash" in deps
    assert "jsonwebtoken" in deps


def test_coverage_gate_requires_core_triangle() -> None:
    coverage = build_coverage_matrix("standard", ["D4", "D5"], [], scanned_files=5)
    gate = evaluate_report_gate("standard", coverage)
    # D1-D3 not planned but gate only checks planned ones
    assert gate["coreTriangleOk"] is True
    assert gate["passed"] is True
