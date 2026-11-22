import ast
import textwrap

import pytest

from codelens.config import Config
from codelens.rules.python_rules import cyclomatic_complexity, max_nesting
from codelens.scanner import analyze_source


def run(code: str, **cfg):
    return analyze_source("sample.py", textwrap.dedent(code), "python", Config(**cfg))


def ids(findings):
    return {f.rule_id for f in findings}


FIRES = [
    ("PY000", "def (:\n"),
    ("PY001", "try:\n    pass\nexcept:\n    raise\n"),
    ("PY002", "try:\n    x = 1\nexcept ValueError:\n    pass\n"),
    ("PY003", "def f(x=[]):\n    return x\n"),
    ("PY003", "def f(*, x=dict()):\n    return x\n"),
    ("PY004", "def f(s):\n    return eval(s)\n"),
    ("PY005", "import subprocess\nsubprocess.run('ls', shell=True)\n"),
    ("PY005", "import os\nos.system('ls')\n"),
    ("PY006", "import pickle\npickle.loads(b'')\n"),
    ("PY006", "import yaml\nyaml.load(s)\n"),
    ("PY007", "import hashlib\nhashlib.md5(b'x')\n"),
    ("PY008", "import requests\nrequests.get('u', verify=False)\n"),
    ("PY009", "cur.execute(f'SELECT * FROM t WHERE id={uid}')\n"),
    ("PY009", "cur.execute('SELECT ' + col)\n"),
    ("PY009", "cur.execute('SELECT {}'.format(col))\n"),
    ("PY014", "import tempfile\ntempfile.mktemp()\n"),
    ("PY015", "if x == None:\n    pass\n"),
    ("PY015", "if x != True:\n    pass\n"),
    ("PY016", "import os\nimport sys\nprint(sys.argv)\n"),
]

CLEAN = [
    ("PY004", "import ast\nast.literal_eval('1')\n"),
    ("PY004", "eval('1 + 1')\n"),
    ("PY005", "import subprocess\nsubprocess.run(['ls'])\n"),
    ("PY006", "import yaml\nyaml.safe_load(s)\n"),
    ("PY006", "import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\n"),
    ("PY007", "import hashlib\nhashlib.md5(b'x', usedforsecurity=False)\n"),
    ("PY009", "cur.execute('SELECT * FROM t WHERE id=?', (uid,))\n"),
    ("PY003", "def f(x=None):\n    return x\n"),
    ("PY002", "try:\n    x = 1\nexcept ValueError as e:\n    print(e)\n"),
    ("PY015", "if x == 0:\n    pass\n"),
    ("PY016", "import os\nprint(os.getcwd())\n"),
    ("PY016", "from pathlib import Path\n\ndef f(p: 'Path') -> None:\n    return None\n"),
]


@pytest.mark.parametrize(("rule", "code"), FIRES)
def test_rule_fires(rule, code):
    assert rule in ids(run(code))


@pytest.mark.parametrize(("rule", "code"), CLEAN)
def test_rule_stays_quiet(rule, code):
    assert rule not in ids(run(code))


def test_cyclomatic_complexity_counts_branches():
    fn = ast.parse(
        textwrap.dedent(
            """
            def f(a, b):
                if a and b:
                    return 1
                for i in range(3):
                    pass
                return 2
            """
        )
    ).body[0]
    assert cyclomatic_complexity(fn) == 4  # 1 + if + and + for


def test_high_complexity_flagged():
    body = "".join(f"    if x == {i}:\n        return {i}\n" for i in range(11))
    code = "def f(x):\n" + body + "    return -1\n"
    assert "PY010" in ids(run(code))


def test_deep_nesting_flagged_but_elif_chain_is_not():
    deep = """
    def f(a):
        if a:
            for i in a:
                while i:
                    with open(i):
                        try:
                            pass
                        except OSError as e:
                            print(e)
    """
    assert "PY013" in ids(run(deep))
    chain = "def f(x):\n    if x == 0:\n        pass\n" + "".join(
        f"    elif x == {i}:\n        pass\n" for i in range(1, 7)
    )
    assert "PY013" not in ids(run(chain))
    assert max_nesting(ast.parse(chain).body[0]) == 1


def test_long_function_and_many_params():
    code = "def f(a, b, c, d, e, f, g):\n" + "    x = 1\n" * 10 + "    return x\n"
    found = ids(run(code, max_function_lines=5))
    assert {"PY011", "PY012"} <= found


def test_missing_docstring_only_for_long_public_functions():
    long_fn = "def public():\n" + "    x = 1\n" * 20
    assert "PY017" in ids(run(long_fn))
    assert "PY017" not in ids(run(long_fn.replace("public", "_private")))
    assert "PY017" not in ids(run('def public():\n    """Doc."""\n' + "    x = 1\n" * 20))


def test_inline_suppression_specific_and_blanket():
    assert "PY004" not in ids(run("def f(s):\n    return eval(s)  # codelens: ignore[PY004]\n"))
    assert "PY004" not in ids(run("def f(s):\n    return eval(s)  # codelens: ignore\n"))
    assert "PY004" in ids(run("def f(s):\n    return eval(s)  # codelens: ignore[PY001]\n"))


def test_config_ignore_disables_rule():
    assert "PY004" not in ids(run("def f(s):\n    return eval(s)\n", ignore={"PY004"}))


def test_findings_carry_location_snippet_and_suggestion():
    (finding,) = [f for f in run("def f(s):\n    return eval(s)\n") if f.rule_id == "PY004"]
    assert finding.line == 2
    assert "eval(s)" in finding.snippet
    assert finding.suggestion
