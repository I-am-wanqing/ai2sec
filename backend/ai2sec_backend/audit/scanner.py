"""D1-D10 dimension scanners with lightweight taint heuristics."""

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .recon import DEPENDENCY_FILES
from .rules import DEPENDENCY_CVES, SECRET_PATTERNS, Rule, rules_for_language

# Markers that suggest a nearby expression is user-controlled. Skill D1/D6
# judgement rules require "user input reaches the sink" — we approximate by
# raising severity / verified when a marker sits on the same logical line.
TAINT_MARKERS = re.compile(
    r"(?i)\b(request\.(GET|POST|body|query|params|values|data|files)|req\.(query|body|params)|"
    r"input\[|data\.get|form\[|args\.get|params\.get|user[_-]?input|userInput|context\.|\bctx\.)"
)

# Names that indicate a line belongs to test/demo code (lowered false positives)
NOISE_MARKERS = re.compile(r"(?i)(^|/)(tests?|__tests__|examples?|docs?|samples?)/|_test\.|test_.*\.py|\.spec\.|\.test\.|conftest")

MAX_FINDINGS_PER_RULE = 40

DEPENDENCY_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-/]+)\s*[=~<>=^]*\s*[\"']?([0-9][0-9A-Za-z.\-+]*)")


def _line_start(text: str, index: int) -> int:
    return text.rfind("\n", 0, index) + 1


def _line_end(text: str, index: int) -> int:
    end = text.find("\n", index)
    return len(text) if end == -1 else end


def _taint_confidence(line: str, prev_line: str = "") -> bool:
    return bool(TAINT_MARKERS.search(line) or TAINT_MARKERS.search(prev_line))


def _is_noise(relative_path: str) -> bool:
    return bool(NOISE_MARKERS.search(relative_path))


def _finding(
    rule: Rule,
    relative_path: str,
    line_no: int,
    line: str,
    language: str,
    verified: bool,
) -> Dict[str, Any]:
    severity = rule.severity
    if not verified and severity in {"critical", "high"}:
        severity = "high" if severity == "critical" else "medium"
    evidence: Dict[str, Any] = {
        "file": relative_path,
        "line": line_no,
        "rule": rule.rule_id,
        "dimension": rule.dimension,
        "language": language,
        "snippet": line.strip()[:240],
    }
    if rule.rule_id.startswith("SECRET-"):
        evidence.pop("snippet", None)
    return {
        "title": rule.title,
        "severity": severity,
        "source_agent": f"Dimension Agent {rule.dimension}",
        "component": f"{relative_path}:{line_no}",
        "description": rule.description,
        "evidence": evidence,
        "recommendation": rule.recommendation,
        "verified": verified,
        "_dimension": rule.dimension,
    }


def scan_dimensions(
    texts: List[Tuple[str, str]],
    languages: Iterable[str],
    selected_dimensions: List[str] = None,
) -> List[Dict[str, Any]]:
    rules: List[Rule] = []
    for language in languages:
        rules.extend(rules_for_language(language))
    rules.extend(SECRET_PATTERNS)

    findings: List[Dict[str, Any]] = []
    per_rule_hits: Dict[str, int] = {}
    seen: set = set()

    for rule in rules:
        if selected_dimensions and rule.dimension not in selected_dimensions:
            continue
        for relative_path, text in texts:
            if _is_noise(relative_path):
                continue
            for match in rule.pattern.finditer(text):
                rule_key = (rule.rule_id, relative_path, match.start())
                if rule_key in seen:
                    continue
                seen.add(rule_key)
                hits = per_rule_hits.get(rule.rule_id, 0)
                if hits >= MAX_FINDINGS_PER_RULE:
                    break
                line_no = text[: match.start()].count("\n") + 1
                line_start = _line_start(text, match.start())
                line = text[line_start: _line_end(text, match.start())]
                prev_line = text[max(0, text.rfind("\n", 0, line_start - 1) + 1): line_start]
                verified = _taint_confidence(line, prev_line)
                findings.append(_finding(rule, relative_path, line_no, line, ",".join(languages), verified))
                per_rule_hits[rule.rule_id] = hits + 1

    findings.sort(key=lambda item: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(item["severity"], 4))
    return findings


def _parse_version(version: str) -> Tuple[int, ...]:
    parts: List[int] = []
    for chunk in re.split(r"[.\-+]", version):
        if chunk.isdigit():
            parts.append(int(chunk))
        else:
            break
    return tuple(parts)


def _parse_dependency_file(path: Path) -> Dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    if path.suffix == ".json":
        try:
            import json

            data = json.loads(text)
        except ValueError:
            return {}
        deps: Dict[str, str] = {}
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            block = data.get(section) or {}
            if isinstance(block, dict):
                for name, version in block.items():
                    if isinstance(version, str):
                        deps[str(name).lower()] = version.lstrip("^~>=< ")
        return deps
    deps = {}
    for line in text.splitlines():
        match = DEPENDENCY_LINE.match(line)
        if not match:
            continue
        name, version = match.group(1).lower(), match.group(2)
        if name.endswith((".txt", ".json", ".toml", ".lock", ".cfg", ".ini")):
            continue
        deps[name] = version
    return deps


def scan_dependencies(
    files: List[Path],
    language: str,
    selected: bool = True,
) -> List[Dict[str, Any]]:
    if not selected or language not in DEPENDENCY_CVES:
        return []
    names = DEPENDENCY_FILES.get(language, set())
    deps: Dict[str, str] = {}
    for path in files:
        if path.name not in names:
            continue
        deps.update(_parse_dependency_file(path))

    findings: List[Dict[str, Any]] = []
    for dep_name, safe_version, vuln in DEPENDENCY_CVES[language]:
        if dep_name not in deps:
            continue
        installed = deps[dep_name]
        if safe_version is None:
            severity, verified = "critical", True  # no safe version exists
        elif _parse_version(installed) < _parse_version(safe_version):
            severity, verified = "high", True
        else:
            continue
        findings.append(
            {
                "title": f"Dependency {dep_name} {installed} below safe version {safe_version or 'n/a'}",
                "severity": severity,
                "source_agent": "Dimension Agent D10",
                "component": f"{dep_name}=={installed}",
                "description": f"{dep_name} is pinned at {installed}, below the safe version {safe_version}. Known issue: {vuln}.",
                "evidence": {
                    "rule": f"DEP-{dep_name.upper()}",
                    "dimension": "D10",
                    "dependency": dep_name,
                    "installed": installed,
                    "safe_version": safe_version,
                    "issue": vuln,
                },
                "recommendation": f"Upgrade {dep_name} to >= {safe_version} (or remove it) and re-run the audit.",
                "verified": verified,
                "_dimension": "D10",
            }
        )
    return findings


def scan_secrets_only(texts: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen: set = set()
    for rule in SECRET_PATTERNS:
        for relative_path, text in texts:
            for match in rule.pattern.finditer(text):
                key = (rule.rule_id, relative_path, match.start())
                if key in seen:
                    continue
                seen.add(key)
                line_no = text[: match.start()].count("\n") + 1
                findings.append(_finding(rule, relative_path, line_no, "", "any", True))
    return findings
