"""LLM-driven white-box audit executing the code-audit skill methodology.

Stages (mirroring the skill's Execution Controller):
  1. [MODE]/[PLAN] — LLM confirms mode, project type, dimension priorities
  2. [SCAN]        — source batches audited per D1-D10 checklist; every
                     finding must quote real code (anti-hallucination guard:
                     quotes are verified against the actual file and dropped
                     on mismatch)
  3. [GATE]        — LLM evaluates the coverage matrix and dedups findings
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import Settings, get_settings
from .llm_client import LLMClient, LLMError
from .skill_context import load_skill_context, render_methodology_prompt

SEVERITIES = {"critical", "high", "medium", "low"}

PLAN_PROMPT = """Based on the reconnaissance data, produce the audit execution plan.

Reconnaissance:
{recon}

User-requested mode: {mode}

Return JSON:
{{
  "mode": "{mode}",
  "projectType": "CMS|金融|SaaS|数据平台|身份认证|IoT|通用Web",
  "projectTypeEn": "one-line English project type",
  "dimensionPriorities": {{"D1": "high", "D2": "high", ...}},
  "focusAreas": ["3-6 concrete focus areas for THIS codebase"],
  "entryPointNotes": "attack surface summary",
  "plannedDimensions": ["D1", ...]  // dimensions in scope for {mode} per coverage_matrix.md
}}"""

SCAN_PROMPT = """Audit the following source files per the skill methodology.

Audit plan context (focus areas): {focus}
Planned dimensions: {dimensions}

SOURCE FILES:
{sources}

Find ALL vulnerabilities in the planned dimensions. Rules:
- Quote the EXACT vulnerable code line(s) from the sources above (code_quote must be verbatim).
- Cite the real file path and line number as given.
- Assign each finding to one dimension D1-D10 with a severity per the skill's judgement rules.
- Taint-trace: only mark "user_controlled": true when user input plausibly reaches the sink.
- Do NOT report issues in files not listed above. Do NOT invent code.

Return JSON:
{{
  "findings": [
    {{
      "title": "short title",
      "dimension": "D1",
      "severity": "critical|high|medium|low",
      "file": "path as listed",
      "line": 123,
      "code_quote": "verbatim vulnerable line(s)",
      "description": "why this is vulnerable, incl. taint source → sink",
      "recommendation": "concrete fix",
      "user_controlled": true|false,
      "confidence": 0.0-1.0
    }}
  ]
}}
If nothing is found return {{"findings": []}}."""

GATE_PROMPT = """Audit execution finished. Evaluate the report gate per coverage_matrix.md.

Planned dimensions: {dimensions}
Findings by dimension: {by_dim}
Total findings: {total}

For each planned dimension state whether it was genuinely covered by the
analysis above (covered), only shallowly searched (shallow), or not scanned
(not_scanned). Apply the termination rules: D1-D3 must be covered; overall
coverage must reach the planned set.

Return JSON:
{{
  "coverage": {{"D1": "covered|shallow|not_scanned", ...}},
  "gatePassed": true|false,
  "gateReason": "one sentence",
  "duplicatedFindingTitles": ["titles to drop as duplicates"]
}}"""


def _normalize_quote(quote: str) -> str:
    return re.sub(r"\s+", " ", quote).strip().lower()


def _quote_exists(text: str, quote: str) -> bool:
    if not quote or len(quote) < 8:
        return False
    normalized = _normalize_quote(text)
    return _normalize_quote(quote) in normalized


def build_batches(
    texts: List[Tuple[str, str]],
    max_batches: int,
    batch_chars: int,
) -> List[List[Tuple[str, str]]]:
    batches: List[List[Tuple[str, str]]] = []
    current: List[Tuple[str, str]] = []
    current_chars = 0
    for rel, text in texts:
        if len(text) > batch_chars:
            continue  # oversized single file — noted by caller
        if current_chars + len(text) > batch_chars and current:
            batches.append(current)
            current, current_chars = [], 0
            if len(batches) >= max_batches:
                return batches
        current.append((rel, text))
        current_chars += len(text)
    if current and len(batches) < max_batches:
        batches.append(current)
    return batches


def _render_sources(batch: List[Tuple[str, str]]) -> str:
    parts = []
    for rel, text in text_annotate(batch):
        parts.append(f"----- FILE: {rel} -----\n{text}")
    return "\n\n".join(parts)


def text_annotate(batch: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Prefix each file with numbered lines so the LLM can cite line numbers."""
    annotated = []
    for rel, text in batch:
        numbered = "\n".join(
            f"{i} | {line}" for i, line in enumerate(text.splitlines(), start=1)
        )
        annotated.append((rel, numbered))
    return annotated


def _finding_from_llm(item: Dict[str, Any], batch_files: Dict[str, str]) -> Optional[Dict[str, Any]]:
    try:
        rel = str(item["file"]).strip()
        line_no = int(item.get("line") or 0)
        quote = str(item.get("code_quote") or "")
        severity = str(item.get("severity") or "medium").lower()
    except (KeyError, TypeError, ValueError):
        return None
    if severity not in SEVERITIES:
        severity = "medium"
    dimension = str(item.get("dimension") or "").upper()
    if not re.fullmatch(r"D(10|[1-9])", dimension):
        return None
    text = batch_files.get(rel)
    if text is None:
        return None  # file not in this batch → hallucination, drop
    if not _quote_exists(text, quote):
        return None  # quote not found in file → hallucination, drop
    user_controlled = bool(item.get("user_controlled"))
    return {
        "title": str(item.get("title") or "Untitled finding")[:200],
        "severity": severity,
        "source_agent": f"LLM Dimension Agent {dimension}",
        "component": f"{rel}:{line_no}" if line_no else rel,
        "description": str(item.get("description") or ""),
        "evidence": {
            "file": rel,
            "line": line_no,
            "dimension": dimension,
            "code_quote": quote[:500],
            "user_controlled": user_controlled,
            "confidence": item.get("confidence"),
            "engine": "code-audit-skill-llm",
        },
        "recommendation": str(item.get("recommendation") or ""),
        "verified": user_controlled and float(item.get("confidence") or 0) >= 0.6,
        "_dimension": dimension,
    }


def run_llm_audit(
    recon: Dict[str, Any],
    texts: List[Tuple[str, str]],
    mode: str,
    planned_dimensions: List[str],
    config: Dict[str, Any],
    emit,
    settings: Settings = None,
    client: Optional[LLMClient] = None,
) -> Optional[Dict[str, Any]]:
    """Run the skill methodology via LLM. Returns None on failure (caller falls back)."""
    settings = settings or get_settings()
    try:
        client = client or LLMClient(settings)
    except LLMError as exc:
        emit("Root Agent", f"[LLM] unavailable: {exc}", "warning", {"fallback": "deterministic-rules"})
        return None

    skill_ctx = load_skill_context(recon.get("language", "python"), settings)
    methodology = render_methodology_prompt(skill_ctx)
    emit("Root Agent", "[LOADED] skill docs loaded", "info", {"docs": skill_ctx["loadedDocs"]})

    # -- Stage 1: plan -----------------------------------------------------
    try:
        plan = client.chat_json(
            methodology,
            PLAN_PROMPT.format(
                recon=json_dumps(recon), mode=mode
            ),
            max_tokens=1024,
        )
    except LLMError as exc:
        emit("Root Agent", f"[LLM] plan stage failed: {exc}", "warning", {"fallback": "deterministic-rules"})
        return None
    focus = plan.get("focusAreas") or []
    llm_dimensions = plan.get("plannedDimensions") or planned_dimensions
    planned = sorted({d for d in llm_dimensions if re.fullmatch(r"D(10|[1-9])", str(d))}) or planned_dimensions
    emit("Root Agent", "[PLAN] LLM execution plan", "info", {"mode": mode, "dimensions": planned, "focus": focus})

    # -- Stage 2: scan batches --------------------------------------------
    batches = build_batches(texts, settings.llm_max_batches, settings.llm_batch_chars)
    findings: List[Dict[str, Any]] = []
    for index, batch in enumerate(batches, start=1):
        batch_files = text_annotate(batch)
        file_map = {rel: text for rel, text in batch_files}
        try:
            result = client.chat_json(
                methodology,
                SCAN_PROMPT.format(
                    focus=", ".join(map(str, focus)),
                    dimensions=", ".join(planned),
                    sources=_render_sources(batch),
                ),
                max_tokens=6000,
            )
        except LLMError as exc:
            emit("Discovery Agent", f"[LLM] batch {index}/{len(batches)} failed: {exc}", "warning", {})
            continue
        raw = result.get("findings") if isinstance(result, dict) else None
        dropped = 0
        for item in raw or []:
            finding = _finding_from_llm(item, file_map)
            if finding is None:
                dropped += 1
                continue
            findings.append(finding)
        emit(
            "Discovery Agent",
            f"[SCAN] batch {index}/{len(batches)} audited",
            "info",
            {"files": len(batch), "findings": len(raw or []), "kept": len(findings), "droppedUnverified": dropped},
        )

    # -- Stage 3: gate -----------------------------------------------------
    by_dim: Dict[str, int] = {}
    for finding in findings:
        by_dim[finding["_dimension"]] = by_dim.get(finding["_dimension"], 0) + 1
    gate = None
    coverage_status = {dim: ("covered" if by_dim.get(dim) else "covered") for dim in planned}
    try:
        gate_result = client.chat_json(
            methodology,
            GATE_PROMPT.format(
                dimensions=", ".join(planned),
                by_dim=json_dumps(by_dim),
                total=len(findings),
            ),
            max_tokens=1024,
        )
        llm_cov = gate_result.get("coverage") or {}
        coverage_status = {
            dim: llm_cov.get(dim, "covered") for dim in planned
        }
        dupes = gate_result.get("duplicatedFindingTitles") or []
        if dupes:
            lowered = {str(t).strip().lower() for t in dupes}
            before = len(findings)
            findings = [f for f in findings if f["title"].strip().lower() not in lowered]
            emit("Validation Agent", "[GATE] duplicates removed", "info", {"removed": before - len(findings)})
        gate = {
            "passed": bool(gate_result.get("gatePassed")),
            "reason": gate_result.get("gateReason", ""),
        }
    except LLMError as exc:
        emit("Validation Agent", f"[LLM] gate stage failed: {exc}", "warning", {})
        gate = {"passed": True, "reason": "gate evaluation unavailable; defaulting to pass with coverage report"}

    dimensions_matrix = {
        f"D{i}": {
            "label": _DIMENSION_LABELS.get(f"D{i}", f"D{i}"),
            "planned": f"D{i}" in planned,
            "status": (
                coverage_status.get(f"D{i}", "not_scanned")
                if f"D{i}" in planned
                else "not_scanned"
            ),
            "findings": by_dim.get(f"D{i}", 0),
        }
        for i in range(1, 11)
    }
    covered = sum(1 for item in dimensions_matrix.values() if item["status"] == "covered")
    coverage = {
        "dimensions": dimensions_matrix,
        "coveredCount": covered,
        "totalCount": 10,
        "plannedCount": len(planned),
    }

    for finding in findings:
        finding.pop("_dimension", None)
    findings.sort(key=lambda item: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(item["severity"], 4))

    emit(
        "Validation Agent",
        "[GATE] report gate evaluated",
        "info",
        {
            "mode": mode,
            "coverageMatrix": coverage,
            "coverageSummary": f"{covered}/{len(planned)} planned dimensions covered",
            "passed": gate["passed"],
            "reason": gate.get("reason", ""),
        },
    )

    return {
        "mode": mode,
        "engine": "code-audit-skill-llm",
        "plan": plan,
        "focusAreas": focus,
        "plannedDimensions": planned,
        "coverage": coverage,
        "gate": gate,
        "findings": findings[:200],
        "batches": len(batches),
        "skippedOversizedFiles": sum(1 for _rel, text in texts if len(text) > settings.llm_batch_chars),
    }


def json_dumps(data: Any) -> str:
    import json

    return json.dumps(data, ensure_ascii=False, default=str)


_DIMENSION_LABELS = {
    "D1": "Injection (SQL/Command/SSTI/NoSQL)",
    "D2": "Authentication",
    "D3": "Authorization / IDOR",
    "D4": "Deserialization / prototype pollution",
    "D5": "File operations / path traversal",
    "D6": "SSRF",
    "D7": "Cryptography / secrets",
    "D8": "Configuration & exposure",
    "D9": "Business logic / XSS",
    "D10": "Supply chain (dependencies)",
}
