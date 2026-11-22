"""Heuristic line-based rules for JavaScript / TypeScript."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..context import Context

# (rule id, pattern, message, suggestion)
_PATTERNS: tuple[tuple[str, re.Pattern[str], str, str], ...] = (
    (
        "JS001",
        re.compile(r"\beval\s*\(|\bnew\s+Function\s*\("),
        "eval()/new Function() executes arbitrary strings as code",
        "Parse data with JSON.parse; avoid dynamic code generation.",
    ),
    (
        "JS002",
        re.compile(r"\.innerHTML\s*=(?!=)|dangerouslySetInnerHTML|\bdocument\.write\s*\("),
        "HTML injected from a string is an XSS sink",
        "Use textContent, or sanitise with DOMPurify first.",
    ),
    (
        "JS003",
        re.compile(r"^\s*var\s+\w"),
        "`var` is function-scoped and hoisted",
        "Use `const`, or `let` if the binding is reassigned.",
    ),
    (
        "JS004",
        re.compile(r"(?<![=!<>])(?:==|!=)(?!=)(?!\s*null\b)"),
        "Loose equality performs type coercion",
        "Use === / !==.",
    ),
    (
        "JS005",
        re.compile(r"\bconsole\.(?:log|debug)\s*\("),
        "console output left in code",
        "Remove it or use a real logger.",
    ),
    (
        "JS006",
        re.compile(r"catch\s*(?:\(\s*\w*\s*\))?\s*\{\s*\}"),
        "Empty catch block hides errors",
        "Handle or log the error.",
    ),
)


def _is_comment(stripped: str) -> bool:
    return stripped.startswith(("//", "/*", "*"))


def scan(ctx: Context) -> None:
    for number, line in enumerate(ctx.lines, start=1):
        if _is_comment(line.strip()):
            continue
        for rule_id, pattern, message, suggestion in _PATTERNS:
            match = pattern.search(line)
            if match:
                ctx.report(rule_id, number, message, col=match.start(), suggestion=suggestion)
