"""Language-agnostic rules: committed secrets and TODO markers."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..context import Context

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("SEC001", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (
        "SEC002",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY"),
        "private key",
    ),
    ("SEC003", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    ("SEC004", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}"), "provider API key"),
)

_CREDENTIAL = re.compile(
    r"(?i)\w*(?:api[_-]?key|secret|token|passwd|password|pwd)\w*[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"
)
_PLACEHOLDERS = (
    "example",
    "changeme",
    "change_me",
    "your",
    "xxx",
    "placeholder",
    "dummy",
    "sample",
    "<",
    "${",
    "{{",
    "env",
    "none",
    "null",
    "todo",
)
_ENTROPY_MIN = 3.0
_TODO = re.compile(r"(?:#|//|/\*|<!--).*\b(TODO|FIXME|HACK|XXX)\b")  # codelens: ignore[GEN001]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    total = len(value)
    return -sum(c / total * math.log2(c / total) for c in Counter(value).values())


def _looks_real(value: str) -> bool:
    lowered = value.lower()
    if any(word in lowered for word in _PLACEHOLDERS):
        return False
    return shannon_entropy(value) >= _ENTROPY_MIN


def _mask(secret: str) -> str:
    return f"{secret[:4]}…"


def scan(ctx: Context) -> None:
    for number, line in enumerate(ctx.lines, start=1):
        _scan_secrets(ctx, number, line)
        todo = _TODO.search(line)
        if todo:
            ctx.report("GEN001", number, f"{todo.group(1)} marker left in code", col=todo.start(1))


def _scan_secrets(ctx: Context, number: int, line: str) -> None:
    for rule_id, pattern, label in _SECRET_PATTERNS:
        match = pattern.search(line)
        if match:
            ctx.report(
                rule_id,
                number,
                f"Possible {label} committed to source ({_mask(match.group(0))})",
                col=match.start(),
                suggestion="Revoke it, remove it from history, and load it from the environment.",
                redact=True,
            )
            return
    match = _CREDENTIAL.search(line)
    if match and _looks_real(match.group(1)):
        ctx.report(
            "SEC005",
            number,
            f"Hard-coded credential ({_mask(match.group(1))})",
            col=match.start(),
            suggestion="Read it from an environment variable or a secrets manager.",
            redact=True,
        )
