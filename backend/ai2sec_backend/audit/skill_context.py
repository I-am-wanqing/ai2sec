"""Loads the code-audit skill (SKILL.md + checklists) as LLM methodology context."""

from pathlib import Path
from typing import Any, Dict, List

from ..config import Settings, get_settings

# Methodology documents every mode must carry (skill Execution Controller Step 2).
CORE_DOCS = ["SKILL.md", "references/checklists/coverage_matrix.md", "references/checklists/universal.md"]

LANGUAGE_CHECKLISTS = {
    "python": "references/checklists/python.md",
    "javascript": "references/checklists/javascript.md",
    "typescript": "references/checklists/javascript.md",
    "java": "references/checklists/java.md",
    "go": "references/checklists/go.md",
    "php": "references/checklists/php.md",
    "c_cpp": "references/checklists/c_cpp.md",
    "csharp": "references/checklists/dotnet.md",
    "ruby": "references/checklists/ruby.md",
    "rust": "references/checklists/rust.md",
}

MAX_DOC_CHARS = 24_000


def _read_doc(skill_dir: Path, relative: str) -> str:
    path = skill_dir / relative
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if len(text) > MAX_DOC_CHARS:
        text = text[:MAX_DOC_CHARS] + "\n... [truncated]"
    return text


def load_skill_context(language: str, settings: Settings = None) -> Dict[str, Any]:
    """Return the skill methodology bundle the LLM auditor must follow."""
    settings = settings or get_settings()
    skill_dir = Path(settings.skill_dir)

    docs: List[Dict[str, str]] = []
    for relative in CORE_DOCS:
        content = _read_doc(skill_dir, relative)
        if content:
            docs.append({"name": relative, "content": content})

    checklist = LANGUAGE_CHECKLISTS.get(language)
    if checklist:
        content = _read_doc(skill_dir, checklist)
        if content:
            docs.append({"name": checklist, "content": content})

    return {
        "skillDir": str(skill_dir),
        "language": language,
        "docs": docs,
        "loadedDocs": [doc["name"] for doc in docs],
    }


def render_methodology_prompt(context: Dict[str, Any]) -> str:
    """Render the loaded skill docs into the LLM system prompt."""
    parts = [
        "You are executing the code-audit skill below. Follow its Execution "
        "Controller, Anti-Hallucination Rules and Anti-Confirmation-Bias Rules "
        "exactly. Every finding MUST quote actual code you were given and cite "
        "file:line. Do NOT invent files, code or vulnerabilities. Better to "
        "miss a vulnerability than report a false positive.",
        "",
    ]
    for doc in context["docs"]:
        parts.append(f"===== SKILL DOC: {doc['name']} =====")
        parts.append(doc["content"])
        parts.append("")
    return "\n".join(parts)
