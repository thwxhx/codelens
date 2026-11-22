"""AST-based rules for Python source."""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..context import Context

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_BRANCHES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler)
_BLOCKS = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.TryStar, ast.With, ast.AsyncWith)
_SQL_METHODS = {"execute", "executemany", "executescript"}
_UNSAFE_LOADERS = {
    "pickle.load",
    "pickle.loads",
    "cPickle.load",
    "cPickle.loads",
    "marshal.load",
    "marshal.loads",
    "dill.load",
    "dill.loads",
}
_SUBPROCESS_PREFIX = "subprocess."


def dotted_name(node: ast.AST) -> str | None:
    """`a.b.c` for Name/Attribute chains, else None."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _walk_scope(node: ast.AST):
    """Yield descendants of `node` without descending into nested functions/classes."""
    stack = list(ast.iter_child_nodes(node))
    while stack:
        current = stack.pop()
        yield current
        if not isinstance(current, _SCOPES):
            stack.extend(ast.iter_child_nodes(current))


def cyclomatic_complexity(node: ast.AST) -> int:
    score = 1
    for child in _walk_scope(node):
        if isinstance(child, _BRANCHES):
            score += 1
        elif isinstance(child, ast.BoolOp):
            score += len(child.values) - 1
        elif isinstance(child, ast.comprehension):
            score += 1 + len(child.ifs)
        elif isinstance(child, ast.match_case):
            score += 1
    return score


def max_nesting(node: ast.AST) -> int:
    """Deepest nesting of control-flow blocks (`elif` chains do not add depth)."""

    def depth(current: ast.AST, level: int) -> int:
        best = level
        for child in ast.iter_child_nodes(current):
            if isinstance(child, _SCOPES):
                continue
            is_elif = isinstance(current, ast.If) and current.orelse == [child]
            nested = level + 1 if isinstance(child, _BLOCKS) and not is_elif else level
            best = max(best, depth(child, nested))
        return best

    return depth(node, 0)


def _is_test_path(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return "/tests/" in f"/{path}" or name.startswith("test_") or name.endswith("_test.py")


def _is_mutable_default(node: ast.AST) -> bool:
    if isinstance(node, ast.List | ast.Dict | ast.Set):
        return True
    return isinstance(node, ast.Call) and dotted_name(node.func) in {"list", "dict", "set"}


def _is_dynamic_sql(arg: ast.AST) -> bool:
    if isinstance(arg, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) for part in arg.values)
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add | ast.Mod):
        return not (isinstance(arg.left, ast.Constant) and isinstance(arg.right, ast.Constant))
    return (
        isinstance(arg, ast.Call)
        and isinstance(arg.func, ast.Attribute)
        and arg.func.attr == "format"
    )


def _is_ellipsis(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and stmt.value.value is Ellipsis
    )


class PythonAnalyzer(ast.NodeVisitor):
    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx

    def run(self, tree: ast.Module) -> None:
        self.visit(tree)
        self._check_unused_imports(tree)

    # ---- exceptions -------------------------------------------------------------------
    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Flag bare `except:` and handlers that silently swallow the error."""
        if node.type is None:
            self.ctx.report(
                "PY001",
                node.lineno,
                "Bare `except:` also catches KeyboardInterrupt and SystemExit",
                col=node.col_offset,
                suggestion="Catch a specific exception, or `except Exception:` at minimum.",
            )
        if all(isinstance(s, ast.Pass) or _is_ellipsis(s) for s in node.body):
            self.ctx.report(
                "PY002",
                node.lineno,
                "Exception is caught and silently ignored",
                col=node.col_offset,
                suggestion="Log it, re-raise it, or add a comment explaining why it is safe.",
            )
        self.generic_visit(node)

    # ---- functions --------------------------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        cfg = self.ctx.config
        self._check_defaults(node)
        complexity = cyclomatic_complexity(node)
        if complexity > cfg.max_complexity:
            self.ctx.report(
                "PY010",
                node.lineno,
                f"`{node.name}` has cyclomatic complexity {complexity} "
                f"(limit {cfg.max_complexity})",
                col=node.col_offset,
                suggestion="Extract branches into helper functions or use early returns.",
            )
        length = (node.end_lineno or node.lineno) - node.lineno + 1
        if length > cfg.max_function_lines:
            self.ctx.report(
                "PY011",
                node.lineno,
                f"`{node.name}` is {length} lines long (limit {cfg.max_function_lines})",
                col=node.col_offset,
                suggestion="Split it into smaller functions with a single responsibility.",
            )
        params = self._count_params(node)
        if params > cfg.max_params:
            self.ctx.report(
                "PY012",
                node.lineno,
                f"`{node.name}` takes {params} parameters (limit {cfg.max_params})",
                col=node.col_offset,
                suggestion="Group related parameters into a dataclass.",
            )
        depth = max_nesting(node)
        if depth > cfg.max_nesting:
            self.ctx.report(
                "PY013",
                node.lineno,
                f"`{node.name}` nests control flow {depth} levels deep (limit {cfg.max_nesting})",
                col=node.col_offset,
                suggestion="Flatten with guard clauses or extract the inner blocks.",
            )
        self._check_docstring(node, length)

    @staticmethod
    def _count_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
        args = node.args
        named = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        count = sum(1 for a in named if a.arg not in ("self", "cls"))
        return count + bool(args.vararg) + bool(args.kwarg)

    def _check_defaults(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        defaults = [*node.args.defaults, *(d for d in node.args.kw_defaults if d is not None)]
        for default in defaults:
            if _is_mutable_default(default):
                self.ctx.report(
                    "PY003",
                    default.lineno,
                    f"Mutable default argument in `{node.name}` is shared between calls",
                    col=default.col_offset,
                    suggestion="Default to None and create the object inside the function.",
                )

    def _check_docstring(self, node: ast.FunctionDef | ast.AsyncFunctionDef, length: int) -> None:
        if node.name.startswith("_") or length < 15 or ast.get_docstring(node):
            return
        if _is_test_path(self.ctx.path):
            return
        self.ctx.report(
            "PY017",
            node.lineno,
            f"Public function `{node.name}` ({length} lines) has no docstring",
            col=node.col_offset,
        )

    # ---- calls ------------------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        """Dispatch security checks (eval, shell, deserialization, TLS, SQL, temp files)."""
        name = dotted_name(node.func) or ""
        kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        self._check_eval(node, name)
        self._check_shell(node, name, kwargs)
        self._check_deserialization(node, name, kwargs)
        self._check_crypto_and_tls(node, name, kwargs)
        self._check_sql(node)
        if name == "tempfile.mktemp":
            self.ctx.report(
                "PY014",
                node.lineno,
                "tempfile.mktemp() is vulnerable to race conditions",
                col=node.col_offset,
                suggestion="Use tempfile.mkstemp() or NamedTemporaryFile().",
            )
        self.generic_visit(node)

    def _check_eval(self, node: ast.Call, name: str) -> None:
        if name not in {"eval", "exec"}:
            return
        if node.args and isinstance(node.args[0], ast.Constant):
            return
        self.ctx.report(
            "PY004",
            node.lineno,
            f"{name}() on dynamic input can execute arbitrary code",
            col=node.col_offset,
            suggestion="Use ast.literal_eval for data, or a real parser for expressions.",
        )

    def _check_shell(self, node: ast.Call, name: str, kwargs: dict[str, ast.expr]) -> None:
        shell = kwargs.get("shell")
        uses_shell_flag = (
            name.startswith(_SUBPROCESS_PREFIX)
            and isinstance(shell, ast.Constant)
            and shell.value is True
        )
        if uses_shell_flag or name in {"os.system", "os.popen"}:
            self.ctx.report(
                "PY005",
                node.lineno,
                f"{name}() runs through a shell; unsanitised input allows command injection",
                col=node.col_offset,
                suggestion="Pass an argument list and leave shell=False.",
            )

    def _check_deserialization(
        self, node: ast.Call, name: str, kwargs: dict[str, ast.expr]
    ) -> None:
        unsafe = name in _UNSAFE_LOADERS
        if name in {"yaml.load", "yaml.load_all"}:
            loader = kwargs.get("Loader") or (node.args[1] if len(node.args) > 1 else None)
            loader_name = dotted_name(loader) if loader is not None else None
            unsafe = not (loader_name or "").endswith(("SafeLoader", "CSafeLoader"))
        if unsafe:
            self.ctx.report(
                "PY006",
                node.lineno,
                f"{name}() can execute code embedded in untrusted data",
                col=node.col_offset,
                suggestion="Use json, yaml.safe_load, or verify the data source.",
            )

    def _check_crypto_and_tls(
        self, node: ast.Call, name: str, kwargs: dict[str, ast.expr]
    ) -> None:
        if name in {"hashlib.md5", "hashlib.sha1"}:
            flag = kwargs.get("usedforsecurity")
            if not (isinstance(flag, ast.Constant) and flag.value is False):
                self.ctx.report(
                    "PY007",
                    node.lineno,
                    f"{name}() is cryptographically broken",
                    col=node.col_offset,
                    suggestion="Use hashlib.sha256 or better (or usedforsecurity=False).",
                )
        verify = kwargs.get("verify")
        if isinstance(verify, ast.Constant) and verify.value is False:
            self.ctx.report(
                "PY008",
                node.lineno,
                "TLS certificate verification is disabled (verify=False)",
                col=node.col_offset,
                suggestion="Remove verify=False or point it at a CA bundle.",
            )

    def _check_sql(self, node: ast.Call) -> None:
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr in _SQL_METHODS and node.args):
            return
        if _is_dynamic_sql(node.args[0]):
            self.ctx.report(
                "PY009",
                node.lineno,
                "SQL query built with string formatting is open to injection",
                col=node.col_offset,
                suggestion="Use parameterised queries: execute(sql, params).",
            )

    # ---- comparisons ------------------------------------------------------------------
    def visit_Compare(self, node: ast.Compare) -> None:
        """Flag `== None` / `== True` style comparisons."""
        for op, comp in zip(node.ops, node.comparators, strict=True):
            if not isinstance(op, ast.Eq | ast.NotEq):
                continue
            if isinstance(comp, ast.Constant) and (
                comp.value is None or isinstance(comp.value, bool)
            ):
                target = repr(comp.value)
                self.ctx.report(
                    "PY015",
                    node.lineno,
                    f"Comparing to {target} with ==/!=",
                    col=node.col_offset,
                    suggestion=f"Use `is {target}` / `is not {target}`, or just truthiness.",
                )
        self.generic_visit(node)

    # ---- imports ----------------------------------------------------------------------
    def _check_unused_imports(self, tree: ast.Module) -> None:
        if self.ctx.path.endswith("__init__.py"):
            return
        used = _used_names(tree)
        strings = _short_strings(tree)
        for name, line in sorted(_collect_imports(tree).items(), key=lambda item: item[1]):
            if name in used or _mentioned_in_strings(name, strings):
                continue
            self.ctx.report(
                "PY016",
                line,
                f"`{name}` is imported but never used",
                suggestion="Remove the import.",
            )


def _used_names(tree: ast.Module) -> set[str]:
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    return names | _exported_names(tree)


def _short_strings(tree: ast.Module) -> list[str]:
    return [
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) < 120
    ]


def _collect_imports(tree: ast.Module) -> dict[str, int]:
    imported: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.setdefault((alias.asname or alias.name).split(".")[0], node.lineno)
        elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
            for alias in node.names:
                if alias.name != "*":
                    imported.setdefault(alias.asname or alias.name, node.lineno)
    return imported


def _exported_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        targets_all = any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets)
        if targets_all and isinstance(node.value, ast.List | ast.Tuple):
            names.update(
                e.value
                for e in node.value.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
            )
    return names


def _mentioned_in_strings(name: str, strings: list[str]) -> bool:
    """Handles string annotations such as `"Path | None"`."""
    pattern = re.compile(rf"\b{re.escape(name)}\b")
    return any(pattern.search(s) for s in strings)
