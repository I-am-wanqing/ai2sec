"""Reconnaissance: tech-stack fingerprint and attack-surface mapping."""

import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

LANGUAGE_EXTENSIONS = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx"},
    "java": {".java"},
    "go": {".go"},
    "php": {".php"},
    "c_cpp": {".c", ".h", ".cpp", ".hpp", ".cc"},
    "csharp": {".cs"},
    "ruby": {".rb"},
    "rust": {".rs"},
}

SKIP_DIRS = {
    "node_modules", "vendor", "dist", "build", ".git", "__pycache__",
    ".venv", "venv", "target", "tests", "test",
}

DEPENDENCY_FILES = {
    "python": {"requirements.txt", "pyproject.toml", "Pipfile", "setup.py"},
    "javascript": {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"},
    "typescript": {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"},
    "java": {"pom.xml", "build.gradle"},
    "go": {"go.mod", "go.sum"},
    "php": {"composer.json", "composer.lock"},
    "csharp": {"*.csproj"},
    "ruby": {"Gemfile"},
    "rust": {"Cargo.toml", "Cargo.lock"},
}

ENTRY_POINT_PATTERNS = [
    re.compile(r"@app\.route\(|@blueprint\.route\(|APIRouter\(|@(api\.)?(get|post|put|delete|patch)\s*\("),
    re.compile(r"(?i)(do_get|do_post|@GetMapping|@PostMapping|@RequestMapping|@Controller|@RestController)"),
    re.compile(r"(?i)(func\s+\w*[Hh]andler|http\.HandleFunc|mux\.Handle)"),
    re.compile(r"(?i)(app\.(get|post|put|delete|use)\s*\(|router\.(get|post|put|delete)\s*\()"),
]

FRAMEWORK_HINTS = {
    "flask": ("python", "Flask"),
    "django": ("python", "Django"),
    "fastapi": ("python", "FastAPI"),
    "starlette": ("python", "Starlette"),
    "express": ("javascript", "Express"),
    "koa": ("javascript", "Koa"),
    "nestjs": ("typescript", "NestJS"),
    "react": ("typescript", "React"),
    "vue": ("typescript", "Vue"),
    "spring": ("java", "Spring"),
    "mybatis": ("java", "MyBatis"),
    "gin-gonic": ("go", "Gin"),
    "gorilla/mux": ("go", "Gorilla Mux"),
    "laravel": ("php", "Laravel"),
    "thinkphp": ("php", "ThinkPHP"),
}

MAX_TEXT_FILE_BYTES = 1_000_000


def collect_source_files(source_dir: Path, max_files: int = 20_000) -> List[Path]:
    files: List[Path] = []
    for path in sorted(source_dir.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(source_dir).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        files.append(path)
        if len(files) >= max_files:
            break
    return files


def read_text_files(files: List[Path], source_dir: Path) -> List[Tuple[str, str]]:
    texts: List[Tuple[str, str]] = []
    for path in files:
        try:
            if path.stat().st_size > MAX_TEXT_FILE_BYTES:
                continue
            raw = path.read_bytes()
            if b"\x00" in raw[:4096]:
                continue
            texts.append((str(path.relative_to(source_dir)), raw.decode("utf-8", errors="replace")))
        except OSError:
            continue
    return texts


def detect_language(files: List[Path], texts: List[Tuple[str, str]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for path in files:
        for language, extensions in LANGUAGE_EXTENSIONS.items():
            if path.suffix.lower() in extensions:
                counts[language] = counts.get(language, 0) + 1
                break
    if counts:
        primary = max(counts, key=lambda key: counts[key])
    else:
        primary = "unknown"
    result = dict(sorted(counts.items(), key=lambda item: -item[1]))
    result["primary"] = primary
    return result


def detect_frameworks(dependency_text: str) -> List[str]:
    frameworks: List[str] = []
    lowered = dependency_text.lower()
    for marker, (_lang, name) in FRAMEWORK_HINTS.items():
        if marker in lowered and name not in frameworks:
            frameworks.append(name)
    return frameworks


def count_entry_points(texts: List[Tuple[str, str]]) -> int:
    total = 0
    for _rel, text in texts:
        total += sum(1 for pattern in ENTRY_POINT_PATTERNS for _ in pattern.finditer(text))
    return total


def dependency_file_text(files: List[Path], language: str) -> Tuple[List[str], str]:
    names = DEPENDENCY_FILES.get(language, set())
    found: List[str] = []
    chunks: List[str] = []
    for path in files:
        if path.name in names or path.suffix == ".csproj" and "*.csproj" in names:
            try:
                chunks.append(path.read_text(encoding="utf-8", errors="replace"))
                found.append(path.name)
            except OSError:
                continue
    return found, "\n".join(chunks)


def run_recon(source_dir: Path, files: List[Path], texts: List[Tuple[str, str]], language_hint: str) -> Dict[str, Any]:
    language_stats = detect_language(files, texts)
    primary = language_hint if language_hint in LANGUAGE_EXTENSIONS and language_hint != "auto" else language_stats["primary"]
    dep_names, dep_text = dependency_file_text(files, primary if primary != "unknown" else language_stats["primary"])
    return {
        "file_count": len(files),
        "directory_count": len({path.relative_to(source_dir).parent for path in files}),
        "languages": language_stats,
        "language": primary,
        "frameworks": detect_frameworks(dep_text),
        "dependency_files": dep_names,
        "entry_points": count_entry_points(texts),
        "text_file_count": len(texts),
    }
