"""Per-file analysis context: collects findings and honours inline suppressions."""

from __future__ import annotations

import re

from .config import Config
from .models import Finding
from .rules.catalog import CATALOG

_IGNORE_RE = re.compile(r"codelens:\s*ignore(?:\[([A-Za-z0-9_,\s]+)\])?")
_SNIPPET_MAX = 120


class Context:
    def __init__(self, path: str, source: str, config: Config) -> None:
        self.path = path
        self.lines = source.splitlines()
        self.config = config
        self.findings: list[Finding] = []

    def _suppressed(self, rule_id: str, line: int) -> bool:
        if not 1 <= line <= len(self.lines):
            return False
        match = _IGNORE_RE.search(self.lines[line - 1])
        if match is None:
            return False
        if match.group(1) is None:
            return True
        return rule_id in {rule.strip().upper() for rule in match.group(1).split(",")}

    def _snippet(self, line: int) -> str:
        if not 1 <= line <= len(self.lines):
            return ""
        return self.lines[line - 1].strip()[:_SNIPPET_MAX]

    def report(
        self,
        rule_id: str,
        line: int,
        message: str,
        *,
        col: int = 0,
        suggestion: str | None = None,
        redact: bool = False,
    ) -> None:
        """Record a finding. `redact=True` drops the source snippet (used for secrets)."""
        if rule_id in self.config.ignore or self._suppressed(rule_id, line):
            return
        meta = CATALOG[rule_id]
        self.findings.append(
            Finding(
                rule_id=rule_id,
                message=message,
                severity=meta.severity,
                path=self.path,
                line=line,
                col=col,
                suggestion=suggestion,
                snippet="" if redact else self._snippet(line),
            )
        )
