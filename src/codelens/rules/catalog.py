"""Catalog of every rule codelens can emit: id, slug, severity, language, description."""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Severity


@dataclass(frozen=True)
class RuleMeta:
    id: str
    name: str
    severity: Severity
    language: str
    description: str


def _rules(*rows: tuple[str, str, Severity, str, str]) -> dict[str, RuleMeta]:
    return {row[0]: RuleMeta(*row) for row in rows}


S = Severity

CATALOG: dict[str, RuleMeta] = _rules(
    ("PY000", "syntax-error", S.HIGH, "python", "File could not be parsed."),
    ("PY001", "bare-except", S.MEDIUM, "python", "Bare `except:` swallows KeyboardInterrupt."),
    ("PY002", "swallowed-exception", S.MEDIUM, "python", "Exception handler does nothing."),
    ("PY003", "mutable-default-arg", S.MEDIUM, "python", "Mutable default argument is shared."),
    ("PY004", "dangerous-eval", S.HIGH, "python", "eval()/exec() on dynamic input."),
    ("PY005", "shell-injection", S.HIGH, "python", "Command run through a shell."),
    ("PY006", "unsafe-deserialization", S.HIGH, "python", "pickle/marshal/yaml.load on data."),
    ("PY007", "weak-hash", S.MEDIUM, "python", "MD5/SHA-1 are broken for security use."),
    ("PY008", "tls-verification-disabled", S.HIGH, "python", "verify=False disables TLS checks."),
    ("PY009", "sql-injection", S.HIGH, "python", "SQL built with string formatting."),
    ("PY010", "high-complexity", S.MEDIUM, "python", "Cyclomatic complexity over the limit."),
    ("PY011", "long-function", S.LOW, "python", "Function is longer than the limit."),
    ("PY012", "too-many-params", S.LOW, "python", "Function takes too many parameters."),
    ("PY013", "deep-nesting", S.MEDIUM, "python", "Control flow nested too deeply."),
    ("PY014", "insecure-tempfile", S.MEDIUM, "python", "tempfile.mktemp() is racy."),
    ("PY015", "none-comparison", S.LOW, "python", "Compare to None/True/False with `is`."),
    ("PY016", "unused-import", S.LOW, "python", "Imported name is never used."),
    ("PY017", "missing-docstring", S.INFO, "python", "Long public function has no docstring."),
    ("JS001", "dangerous-eval", S.HIGH, "javascript", "eval() or new Function()."),
    ("JS002", "xss-sink", S.MEDIUM, "javascript", "innerHTML / document.write sink."),
    ("JS003", "var-declaration", S.LOW, "javascript", "Prefer let/const over var."),
    ("JS004", "loose-equality", S.LOW, "javascript", "Use === / !== instead of == / !=."),
    ("JS005", "console-log", S.INFO, "javascript", "console.log left in code."),
    ("JS006", "empty-catch", S.MEDIUM, "javascript", "Empty catch block hides errors."),
    ("SEC001", "aws-access-key", S.CRITICAL, "any", "AWS access key id in source."),
    ("SEC002", "private-key", S.CRITICAL, "any", "Private key material in source."),
    ("SEC003", "github-token", S.CRITICAL, "any", "GitHub token in source."),
    ("SEC004", "api-key", S.CRITICAL, "any", "Provider API key (sk-...) in source."),
    ("SEC005", "hardcoded-credential", S.HIGH, "any", "Hard-coded password/secret/token."),
    ("GEN001", "todo-comment", S.INFO, "any", "TODO/FIXME/HACK marker."),
    ("AI001", "ai-review", S.MEDIUM, "any", "Issue found by the LLM reviewer."),
)
