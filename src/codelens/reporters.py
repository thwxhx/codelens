"""Output formats: console (rich), JSON, Markdown (PR comments) and SARIF 2.1.0."""

from __future__ import annotations

import json
from itertools import groupby

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from . import __version__
from .models import Finding, ScanResult, Severity
from .rules.catalog import CATALOG

_STYLES = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_MARKDOWN_ROW_LIMIT = 50


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.path, f.line, -f.severity, f.rule_id))


# ---- console -------------------------------------------------------------------------------
def render_console(result: ScanResult, console: Console) -> None:
    for path, group in groupby(_sorted(result.findings), key=lambda f: f.path):
        console.print()
        console.print(Text(path, style="bold underline"))
        for finding in group:
            _print_finding(console, finding)
    console.print()
    console.print(_summary_panel(result))


def _print_finding(console: Console, finding: Finding) -> None:
    head = Text()
    head.append(f"  {finding.line}:{finding.col + 1}".ljust(9), style="dim")
    head.append(f" {finding.severity.label.upper():<8}", style=_STYLES[finding.severity])
    head.append(f" {finding.rule_id} ", style="bold")
    head.append(finding.message)
    if finding.source == "ai":
        head.append("  ✦ AI", style="magenta")
    console.print(head)
    if finding.snippet:
        console.print(Text(f"           │ {finding.snippet}", style="dim"))
    if finding.suggestion:
        console.print(Text(f"           ↳ {finding.suggestion}", style="green"))


def _grade_style(grade: str) -> str:
    return {"A": "bold green", "B": "green", "C": "yellow", "D": "dark_orange"}.get(
        grade, "bold red"
    )


def _summary_panel(result: ScanResult) -> Panel:
    body = Text()
    body.append(
        f"{result.files_scanned} files · {result.lines_scanned:,} lines · "
        f"{len(result.findings)} findings\n"
    )
    counts = result.counts()
    if result.findings:
        for severity in reversed(Severity):
            if counts[severity]:
                body.append(f"{severity.label} {counts[severity]}  ", style=_STYLES[severity])
        body.append("\n")
    else:
        body.append("✓ No issues found\n", style="green")
    body.append(
        f"Health score: {result.score}/100 ({result.grade})", style=_grade_style(result.grade)
    )
    return Panel(body, title="codelens", border_style=_grade_style(result.grade), expand=False)


# ---- json ----------------------------------------------------------------------------------
def render_json(result: ScanResult) -> str:
    """Machine-readable report: tool info, summary, and every finding."""
    counts = result.counts()
    doc = {
        "tool": {"name": "codelens", "version": __version__},
        "summary": {
            "files": result.files_scanned,
            "lines": result.lines_scanned,
            "findings": len(result.findings),
            "score": result.score,
            "grade": result.grade,
            "by_severity": {s.label: counts[s] for s in reversed(Severity)},
        },
        "findings": [f.to_dict() for f in _sorted(result.findings)],
    }
    return json.dumps(doc, indent=2)


# ---- markdown ------------------------------------------------------------------------------
def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(result: ScanResult) -> str:
    """Pull-request-comment report: score line plus a table of the top findings."""
    lines = ["## 🔎 codelens review", ""]
    files = len({f.path for f in result.findings})
    lines.append(
        f"**Health score: {result.score}/100 ({result.grade})** · "
        f"{len(result.findings)} findings in {files} files "
        f"({result.files_scanned} scanned)"
    )
    lines.append("")
    if not result.findings:
        lines.append("✅ No issues found.")
        return "\n".join(lines) + "\n"
    counts = result.counts()
    lines.append(" · ".join(f"{s.label} **{counts[s]}**" for s in reversed(Severity) if counts[s]))
    lines += ["", "| Severity | Location | Rule | Message |", "|---|---|---|---|"]
    ordered = sorted(result.findings, key=lambda f: (-f.severity, f.path, f.line))
    for finding in ordered[:_MARKDOWN_ROW_LIMIT]:
        badge = " 🤖" if finding.source == "ai" else ""
        message = _md_escape(finding.message)
        if finding.suggestion:
            message += f" _Fix: {_md_escape(finding.suggestion)}_"
        lines.append(
            f"| {finding.severity.label} | `{finding.path}:{finding.line}` | "
            f"{finding.rule_id}{badge} | {message} |"
        )
    hidden = len(ordered) - _MARKDOWN_ROW_LIMIT
    if hidden > 0:
        lines += ["", f"…and {hidden} more."]
    return "\n".join(lines) + "\n"


# ---- sarif ---------------------------------------------------------------------------------
def render_sarif(result: ScanResult) -> str:
    """SARIF 2.1.0 report for GitHub code scanning."""
    used = sorted({f.rule_id for f in result.findings})
    rules = [
        {
            "id": rule_id,
            "name": CATALOG[rule_id].name,
            "shortDescription": {"text": CATALOG[rule_id].description},
            "defaultConfiguration": {"level": _SARIF_LEVEL[CATALOG[rule_id].severity]},
        }
        for rule_id in used
    ]
    results = [
        {
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.message + (f" Fix: {f.suggestion}" if f.suggestion else "")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.path},
                        "region": {"startLine": f.line, "startColumn": f.col + 1},
                    }
                }
            ],
        }
        for f in _sorted(result.findings)
    ]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "codelens", "version": __version__, "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
