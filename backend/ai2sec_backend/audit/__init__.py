"""Deterministic white-box code audit pipeline.

Ports the methodology of the `code-audit` skill (see code-audit-main/SKILL.md)
into a reproducible, LLM-free backend workflow:

    1. Mode determination   (quick / standard / deep)
    2. Reconnaissance       (tech stack fingerprint, entry points)
    3. Vulnerability hunt   (D1-D10 dimension scanners)
    4. Coverage matrix      (per-dimension coverage / report gate)
    5. Report               (findings + coverage + recon)

Rule semantics are derived from the skill's checklists:
references/checklists/python.md, javascript.md, universal.md, coverage_matrix.md.
"""

from .llm_audit import run_llm_audit
from .pipeline import run_whitebox_audit, normalize_mode

__all__ = ["run_whitebox_audit", "normalize_mode", "run_llm_audit"]
