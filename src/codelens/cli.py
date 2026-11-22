"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__
from .config import Config, parse_fail_on
from .git import GitError, changed_files
from .models import ScanResult, Severity
from .reporters import render_console, render_json, render_markdown, render_sarif
from .rules.catalog import CATALOG
from .scanner import scan

_TEXT_RENDERERS = {"json": render_json, "markdown": render_markdown, "sarif": render_sarif}
_SEVERITY_NAMES = [s.label for s in Severity]


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser (`review` and `rules` subcommands)."""
    parser = argparse.ArgumentParser(
        prog="codelens", description="AI-assisted code review: static analysis + Claude."
    )
    parser.add_argument("--version", action="version", version=f"codelens {__version__}")
    sub = parser.add_subparsers(dest="command")

    review = sub.add_parser("review", help="review files or directories")
    review.add_argument("paths", nargs="*", default=["."], help="files/dirs (default: .)")
    review.add_argument(
        "-f", "--format", choices=["console", "json", "markdown", "sarif"], default="console"
    )
    review.add_argument("-o", "--output", help="write the report to this file")
    review.add_argument(
        "--fail-on",
        choices=[*_SEVERITY_NAMES, "none"],
        help="exit 1 if any finding is at/above this severity (default: high)",
    )
    review.add_argument("--min-severity", choices=_SEVERITY_NAMES, default="info")
    review.add_argument("--diff", metavar="REF", help="only review files changed since REF")
    review.add_argument("--ai", action="store_true", help="add an LLM review pass (Claude)")
    review.add_argument("--ai-max-files", type=int, default=8, help="max files sent to the LLM")
    review.add_argument("--model", help="model for --ai (default: $CODELENS_MODEL or built-in)")
    review.add_argument("--config", help="path to a .codelens.toml / pyproject.toml")
    review.add_argument("--ignore", action="append", default=[], metavar="RULE")

    sub.add_parser("rules", help="list every rule")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "rules":
        return cmd_rules()
    if args.command == "review":
        return cmd_review(args)
    parser.print_help()
    return 2


def cmd_rules() -> int:
    table = Table(title="codelens rules", show_lines=False)
    for column in ("ID", "Name", "Severity", "Language", "Description"):
        table.add_column(column)
    for meta in CATALOG.values():
        table.add_row(meta.id, meta.name, meta.severity.label, meta.language, meta.description)
    Console().print(table)
    return 0


def _error(message: str) -> int:
    Console(stderr=True).print(Text(f"error: {message}", style="red"))
    return 2


def _warn(message: str) -> None:
    Console(stderr=True).print(Text(f"warning: {message}", style="yellow"))


def _prepare(args: argparse.Namespace) -> tuple[Config, Severity | None, Severity]:
    missing = [p for p in args.paths if not Path(p).exists()]
    if missing:
        raise ValueError(f"path not found: {', '.join(missing)}")
    explicit = Path(args.config) if args.config else None
    config = Config.load(explicit=explicit)
    config.ignore.update(rule.upper() for rule in args.ignore)
    threshold = parse_fail_on(args.fail_on) if args.fail_on else config.fail_on
    return config, threshold, Severity.parse(args.min_severity)


def _run_ai(result: ScanResult, args: argparse.Namespace) -> None:
    from .ai import AIReviewer, AIUnavailable

    try:
        reviewer = AIReviewer(model=args.model, max_files=args.ai_max_files)
    except AIUnavailable as exc:
        _warn(f"AI review skipped: {exc}")
        return
    result.findings.extend(reviewer.review(result.sources, result.findings))
    for message in reviewer.warnings:
        _warn(message)


def _emit(result: ScanResult, fmt: str, output: str | None) -> None:
    if fmt == "console":
        if output:
            with open(output, "w", encoding="utf-8") as handle:
                render_console(result, Console(file=handle, width=100))
        else:
            render_console(result, Console())
        return
    text = _TEXT_RENDERERS[fmt](result)
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def _should_fail(result: ScanResult, threshold: Severity | None) -> bool:
    return threshold is not None and any(f.severity >= threshold for f in result.findings)


def cmd_review(args: argparse.Namespace) -> int:
    """Run a review. Exit codes: 0 clean, 1 findings at/above --fail-on, 2 usage error."""
    try:
        config, threshold, min_severity = _prepare(args)
        only = changed_files(args.diff) if args.diff else None
    except GitError as exc:
        return _error(f"--diff: {exc}")
    except ValueError as exc:  # includes ConfigError
        return _error(str(exc))

    result = scan(args.paths, config, only=only)
    if args.ai:
        _run_ai(result, args)
    result.findings = [
        f for f in result.findings if f.severity >= min_severity and f.rule_id not in config.ignore
    ]
    _emit(result, args.format, args.output)
    return 1 if _should_fail(result, threshold) else 0


if __name__ == "__main__":
    raise SystemExit(main())
