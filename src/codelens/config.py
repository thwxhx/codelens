"""Configuration loading from `.codelens.toml` or `[tool.codelens]` in pyproject.toml."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Severity

_KEYS = {
    "ignore",
    "exclude",
    "max_complexity",
    "max_function_lines",
    "max_params",
    "max_nesting",
    "fail_on",
}
_INT_KEYS = ("max_complexity", "max_function_lines", "max_params", "max_nesting")


class ConfigError(ValueError):
    """Raised when a config file is unreadable or invalid."""


@dataclass
class Config:
    ignore: set[str] = field(default_factory=set)
    exclude: list[str] = field(default_factory=list)
    max_complexity: int = 10
    max_function_lines: int = 60
    max_params: int = 6
    max_nesting: int = 4
    fail_on: Severity | None = Severity.HIGH

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> Config:
        """Build a Config from parsed TOML, rejecting unknown or invalid options."""
        unknown = set(data) - _KEYS
        if unknown:
            raise ConfigError(f"unknown config option(s): {', '.join(sorted(unknown))}")
        cfg = cls()
        if "ignore" in data:
            cfg.ignore = {str(rule).upper() for rule in data["ignore"]}
        if "exclude" in data:
            cfg.exclude = [str(pattern) for pattern in data["exclude"]]
        for key in _INT_KEYS:
            if key in data:
                setattr(cfg, key, _positive_int(key, data[key]))
        if "fail_on" in data:
            cfg.fail_on = parse_fail_on(str(data["fail_on"]))
        return cfg

    @classmethod
    def load(cls, start: Path | None = None, explicit: Path | None = None) -> Config:
        if explicit is not None:
            return cls.from_mapping(_extract_table(explicit))
        here = (start or Path.cwd()).resolve()
        for folder in (here, *here.parents):
            for name in (".codelens.toml", "pyproject.toml"):
                candidate = folder / name
                if candidate.is_file():
                    table = _extract_table(candidate)
                    if table is not None:
                        return cls.from_mapping(table)
        return cls()


def parse_fail_on(value: str) -> Severity | None:
    """Parse a `--fail-on` value; "none" disables failing."""
    if value.strip().lower() == "none":
        return None
    return Severity.parse(value)


def _positive_int(key: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigError(f"{key} must be a positive integer")
    return value


def _extract_table(path: Path) -> dict[str, Any] | None:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if path.name == "pyproject.toml":
        return data.get("tool", {}).get("codelens")
    return data.get("codelens", data)
