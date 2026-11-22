"""Changed-file detection for `--diff` mode."""

from __future__ import annotations

import subprocess
from pathlib import Path


class GitError(RuntimeError):
    """Raised when a git command fails."""


def _git(args: list[str], cwd: Path | None) -> str:
    try:
        proc = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, check=False
        )
    except FileNotFoundError:
        raise GitError("git is not installed") from None
    if proc.returncode != 0:
        raise GitError(proc.stderr.strip() or f"git {args[0]} failed")
    return proc.stdout


def changed_files(ref: str, cwd: Path | None = None) -> set[Path]:
    """Files added/changed/renamed since the merge-base of `ref` and HEAD (incl. working tree)."""
    top = Path(_git(["rev-parse", "--show-toplevel"], cwd).strip())
    try:
        base = _git(["merge-base", ref, "HEAD"], cwd).strip()
    except GitError:
        base = ref
    out = _git(["diff", "--name-only", "-z", "--diff-filter=ACMR", base], cwd)
    return {(top / name).resolve() for name in out.split("\0") if name}
