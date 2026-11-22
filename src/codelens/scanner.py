"""File discovery and per-file analysis."""

from __future__ import annotations

import ast
import os
from collections.abc import Iterable, Iterator
from fnmatch import fnmatch
from pathlib import Path

from .config import Config
from .context import Context
from .models import Finding, ScanResult
from .rules import generic_rules, js_rules
from .rules.python_rules import PythonAnalyzer

MAX_BYTES = 1_000_000

LANG_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
}
TEXT_EXTS = {
    ".go", ".rs", ".java", ".kt", ".rb", ".php", ".sh", ".bash", ".yml", ".yaml", ".json",
    ".toml", ".cfg", ".ini", ".env", ".c", ".h", ".cpp", ".cs", ".swift", ".tf", ".sql",
}  # fmt: skip
TEXT_NAMES = {".env", "Dockerfile"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock"}
SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build",
    "site-packages", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".eggs",
}  # fmt: skip


def language_of(path: Path) -> str | None:
    if path.name in SKIP_FILES or path.name.endswith(".min.js"):
        return None
    ext = path.suffix.lower()
    if ext in LANG_BY_EXT:
        return LANG_BY_EXT[ext]
    if ext in TEXT_EXTS or path.name in TEXT_NAMES:
        return "text"
    return None


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _excluded(path: Path, config: Config) -> bool:
    rel = _display_path(path)
    return any(fnmatch(rel, pat) or fnmatch(path.name, pat) for pat in config.exclude)


def _walk(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")
        )
        for name in sorted(filenames):
            yield Path(dirpath) / name


def iter_files(paths: Iterable[str | Path], config: Config) -> Iterator[Path]:
    seen: set[Path] = set()
    for raw in paths:
        root = Path(raw)
        for candidate in [root] if root.is_file() else _walk(root):
            key = candidate.resolve()
            if key in seen or language_of(candidate) is None or _excluded(candidate, config):
                continue
            seen.add(key)
            yield candidate


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:2048]:
        return None
    return data.decode("utf-8", errors="replace")


def analyze_source(path: str, source: str, language: str, config: Config) -> list[Finding]:
    """Run every applicable rule over one file's source text."""
    ctx = Context(path, source, config)
    if language == "python":
        _analyze_python(ctx, source)
    elif language == "javascript":
        js_rules.scan(ctx)
    generic_rules.scan(ctx)
    return ctx.findings


def _analyze_python(ctx: Context, source: str) -> None:
    try:
        tree = ast.parse(source, filename=ctx.path)
    except SyntaxError as exc:
        ctx.report("PY000", exc.lineno or 1, f"Syntax error: {exc.msg}")
    except (ValueError, RecursionError) as exc:
        ctx.report("PY000", 1, f"Could not parse file: {exc}")
    else:
        PythonAnalyzer(ctx).run(tree)


def scan(
    paths: Iterable[str | Path], config: Config, only: set[Path] | None = None
) -> ScanResult:
    """Scan files under `paths`. If `only` is given, restrict to those resolved paths."""
    result = ScanResult()
    for file in iter_files(paths, config):
        if only is not None and file.resolve() not in only:
            continue
        source = _read(file)
        language = language_of(file)
        if source is None or language is None:
            continue
        display = _display_path(file)
        result.files_scanned += 1
        result.lines_scanned += source.count("\n") + 1
        result.sources[display] = source
        result.findings.extend(analyze_source(display, source, language, config))
    return result
