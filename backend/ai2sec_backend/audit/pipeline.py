"""White-box audit pipeline orchestrator.

Implements the code-audit skill's Execution Controller as deterministic code:
mode → recon → dimension scan → coverage matrix → report gate.
"""

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..config import Settings, get_settings
from ..security import safe_extract_archive
from .coverage import MODE_DIMENSIONS, build_coverage_matrix, evaluate_report_gate
from .llm_audit import run_llm_audit
from .recon import collect_source_files, read_text_files, run_recon
from .scanner import scan_dependencies, scan_dimensions

PROFILE_ALIASES = {
    "quick": "quick",
    "standard": "standard",
    "deep": "deep",
    "full": "deep",
    "flow": "deep",
    "sast": "standard",
    "deps": "quick",
}

# quick mode only runs the highest-risk rule tiers per the skill's mode table.
QUICK_SEVERITIES = {"critical", "high"}

EmitFn = Callable[[str, str, str, Any], None]  # (agent, message, level, data)


def normalize_mode(profile: str) -> str:
    return PROFILE_ALIASES.get((profile or "").lower(), "standard")


def run_whitebox_audit(
    archive_path: Path,
    work_dir: Path,
    config: Dict[str, Any],
    emit: Optional[EmitFn] = None,
) -> Dict[str, Any]:
    def _emit(agent: str, message: str, level: str = "info", data: Any = None) -> None:
        if emit:
            emit(agent, message, level, data)

    # -- Step 1: mode determination ----------------------------------------
    mode = normalize_mode(str(config.get("auditProfile", config.get("profile", "standard"))))
    _emit("Root Agent", f"[MODE] {mode}", "info", {"mode": mode})

    # -- Step 3: reconnaissance --------------------------------------------
    source_dir = work_dir / "source"
    files = safe_extract_archive(archive_path, source_dir)
    texts = read_text_files(files, source_dir)
    language_hint = str(config.get("language", "auto")).lower()
    if language_hint in ("typescript", "javascript", "js"):
        language_hint = "javascript" if language_hint == "js" else language_hint
    recon = run_recon(source_dir, files, texts, language_hint)
    _emit(
        "Recon Agent",
        "[RECON] Attack surface mapped",
        "info",
        {
            "fileCount": recon["file_count"],
            "language": recon["language"],
            "frameworks": recon["frameworks"],
            "entryPoints": recon["entry_points"],
        },
    )

    # -- Step 4: execution plan --------------------------------------------
    planned_dimensions = sorted(MODE_DIMENSIONS[mode])
    vulnerability_classes = set(_map_vulnerability_classes(config.get("vulnerabilityClasses") or []))
    if vulnerability_classes:
        planned_dimensions = sorted(set(planned_dimensions) & vulnerability_classes) or planned_dimensions

    settings = get_settings()

    # -- Step 5: LLM-driven skill execution (primary path) ------------------
    # The LLM auditor re-plans dimensions itself per the skill controller;
    # the deterministic plan above stays as the fallback scope.
    if settings.llm_audit_enabled and settings.openai_api_key:
        llm_result = run_llm_audit(
            recon=recon,
            texts=texts,
            mode=mode,
            planned_dimensions=planned_dimensions,
            config=config,
            emit=_emit,
            settings=settings,
        )
        if llm_result is not None:
            # Merge deterministic dependency-CVE scan (exact version math the
            # LLM should not redo) into the LLM findings.
            dep_findings = scan_dependencies(files, recon["language"], "D10" in llm_result["plannedDimensions"])
            for dep in dep_findings:
                dep.pop("_dimension", None)
            llm_result["findings"].extend(dep_findings)
            llm_result["findings"].sort(
                key=lambda item: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(item["severity"], 4)
            )
            if "D10" in llm_result["plannedDimensions"]:
                dims = llm_result["coverage"]["dimensions"]
                dims["D10"]["findings"] += len(dep_findings)
            return {
                "mode": mode,
                "engine": llm_result["engine"],
                "recon": recon,
                "plannedDimensions": llm_result["plannedDimensions"],
                "coverage": llm_result["coverage"],
                "gate": llm_result["gate"],
                "findings": llm_result["findings"][:200],
                "source": {
                    "file_count": recon["file_count"],
                    "text_file_count": recon["text_file_count"],
                    "dependency_files": recon["dependency_files"],
                },
            }
        _emit("Root Agent", "[FALLBACK] LLM audit unavailable, using deterministic rules", "warning", {})

    _emit(
        "Root Agent",
        "[PLAN] Execution plan ready",
        "info",
        {"mode": mode, "dimensions": planned_dimensions, "language": recon["language"]},
    )

    # -- Step 5: dimension scan --------------------------------------------
    languages = [recon["language"]] if recon["language"] != "unknown" else []
    languages = [lang for lang in languages if lang in ("python", "javascript", "typescript", "java", "go", "php")]
    if not languages and recon["languages"]:
        languages = [
            lang
            for lang in recon["languages"]
            if isinstance(recon["languages"].get(lang), int) and lang in ("python", "javascript", "typescript", "java", "go", "php")
        ][:2]

    findings = scan_dimensions(texts, languages, planned_dimensions)
    if mode == "quick":
        findings = [item for item in findings if item["severity"] in QUICK_SEVERITIES or item["evidence"].get("rule", "").startswith("SECRET-")]
    findings.extend(scan_dependencies(files, recon["language"], "D10" in planned_dimensions))

    _emit(
        "Discovery Agent",
        "[SCAN] Dimension scan completed",
        "info",
        {
            "languages": languages or recon["languages"].get("primary"),
            "findingCount": len(findings),
            "dimensions": planned_dimensions,
        },
    )

    # -- Step 6: coverage matrix + report gate -----------------------------
    coverage = build_coverage_matrix(mode, planned_dimensions, findings, scanned_files=len(texts))
    gate = evaluate_report_gate(mode, coverage)
    _emit(
        "Validation Agent",
        "[GATE] Report gate evaluated",
        "info",
        {
            "mode": mode,
            "coverageMatrix": coverage,
            "coverageSummary": f"{coverage['coveredCount']}/{coverage['plannedCount']} planned dimensions covered",
            "coreTriangleOk": gate["coreTriangleOk"],
            "passed": gate["passed"],
        },
    )

    for item in findings:
        item.pop("_dimension", None)

    return {
        "mode": mode,
        "engine": "deterministic-rules",
        "recon": recon,
        "plannedDimensions": planned_dimensions,
        "coverage": coverage,
        "gate": gate,
        "findings": findings[:200],
        "source": {
            "file_count": recon["file_count"],
            "text_file_count": recon["text_file_count"],
            "dependency_files": recon["dependency_files"],
        },
    }


_CLASS_TO_DIMENSION = {
    "sql injection": "D1",
    "rce": "D1",
    "xss": "D9",
    "ssrf": "D6",
    "auth bypass": "D2",
    "file upload": "D5",
    "path traversal": "D5",
    "insecure deserialization": "D4",
}


def _map_vulnerability_classes(classes: List[str]) -> List[str]:
    dims: List[str] = []
    for item in classes:
        dim = _CLASS_TO_DIMENSION.get(str(item).strip().lower())
        if dim:
            dims.append(dim)
    return dims
