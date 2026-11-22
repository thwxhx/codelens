"""Core data models shared across the package."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from: {valid})") from None

    @property
    def label(self) -> str:
        return self.name.lower()


# Points deducted per finding when computing the health score.
PENALTY: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 8,
    Severity.CRITICAL: 15,
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    message: str
    severity: Severity
    path: str
    line: int
    col: int = 0
    suggestion: str | None = None
    snippet: str = ""
    source: str = "static"  # "static" or "ai"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.label
        return data


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0
    sources: dict[str, str] = field(default_factory=dict, repr=False)

    def counts(self) -> dict[Severity, int]:
        counts = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @property
    def score(self) -> int:
        """0-100 health score: penalty points per 100 lines of code."""
        penalty = sum(PENALTY[f.severity] for f in self.findings)
        per_100_lines = penalty / max(self.lines_scanned / 100, 1)
        return max(0, round(100 - min(100, per_100_lines * 2.5)))

    @property
    def grade(self) -> str:
        for threshold, letter in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
            if self.score >= threshold:
                return letter
        return "F"
