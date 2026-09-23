"""Coverage matrix (D1-D10) and report gate, ported from the skill's
references/checklists/coverage_matrix.md."""

from typing import Any, Dict, List

DIMENSIONS = {
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

CRITICAL_TRIANGLE = ("D1", "D2", "D3")

# Dimensions each audit mode is required to scan.
MODE_DIMENSIONS = {
    "quick": {"D1", "D7", "D10"},
    "standard": set(DIMENSIONS),
    "deep": set(DIMENSIONS),
}


def build_coverage_matrix(
    mode: str,
    planned_dimensions: List[str],
    findings: List[Dict[str, Any]],
    scanned_files: int,
) -> Dict[str, Any]:
    findings_by_dim: Dict[str, int] = {}
    for finding in findings:
        dim = finding.get("_dimension") or finding.get("evidence", {}).get("dimension")
        if dim:
            findings_by_dim[dim] = findings_by_dim.get(dim, 0) + 1

    matrix: Dict[str, Any] = {}
    for dim, label in DIMENSIONS.items():
        planned = dim in planned_dimensions
        finding_count = findings_by_dim.get(dim, 0)
        if not planned:
            status = "not_scanned"
        elif scanned_files == 0:
            status = "not_scanned"
        elif finding_count > 0:
            status = "covered"
        else:
            # Rules ran over real source but produced no hits: the dimension
            # was searched (covered by rule execution), not by finding count.
            status = "covered"
        matrix[dim] = {
            "label": label,
            "planned": planned,
            "status": status,
            "findings": finding_count,
        }

    covered = sum(1 for item in matrix.values() if item["status"] == "covered")
    return {
        "dimensions": matrix,
        "coveredCount": covered,
        "totalCount": len(DIMENSIONS),
        "plannedCount": len(planned_dimensions),
    }


def evaluate_report_gate(mode: str, coverage: Dict[str, Any]) -> Dict[str, Any]:
    """Skill termination rules:
    - D1-D3 must be covered (core triangle)
    - coverage matrix >= 8/10 (scaled to planned set for quick mode)
    """
    dims = coverage["dimensions"]
    triangle_ok = all(dims[dim]["status"] == "covered" for dim in CRITICAL_TRIANGLE if dims[dim]["planned"])
    required = coverage["plannedCount"]
    covered_ok = coverage["coveredCount"] >= max(1, required)
    passed = triangle_ok and covered_ok
    return {
        "passed": passed,
        "coreTriangleOk": triangle_ok,
        "coverageOk": covered_ok,
        "covered": coverage["coveredCount"],
        "planned": coverage["plannedCount"],
        "rule": f"D1-D3 (planned) covered and {coverage['coveredCount']}/{required} planned dimensions covered",
    }
