import json
import shutil
import subprocess

import pytest

from codelens.cli import main

BAD = "def run(s):\n    return eval(s)\n"
GOOD = "print('hello')\n"


@pytest.fixture(autouse=True)
def in_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_exit_1_on_high_severity(in_tmp):
    (in_tmp / "bad.py").write_text(BAD)
    assert main(["review", "."]) == 1


def test_exit_0_when_clean(in_tmp):
    (in_tmp / "good.py").write_text(GOOD)
    assert main(["review", "."]) == 0


def test_fail_on_none_and_threshold(in_tmp):
    (in_tmp / "bad.py").write_text(BAD)
    assert main(["review", ".", "--fail-on", "none"]) == 0
    assert main(["review", ".", "--fail-on", "critical"]) == 0
    assert main(["review", ".", "--fail-on", "medium"]) == 1


def test_missing_path_is_usage_error():
    assert main(["review", "nope"]) == 2


def test_json_output(in_tmp, capsys):
    (in_tmp / "bad.py").write_text(BAD)
    main(["review", ".", "-f", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["findings"] == 1
    assert data["findings"][0]["rule_id"] == "PY004"
    assert data["findings"][0]["severity"] == "high"
    assert data["summary"]["grade"] in "ABCDF"


def test_sarif_output_is_valid_shape(in_tmp, capsys):
    (in_tmp / "bad.py").write_text(BAD)
    main(["review", ".", "-f", "sarif"])
    doc = json.loads(capsys.readouterr().out)
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    assert run["tool"]["driver"]["rules"][0]["id"] == "PY004"
    location = run["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "bad.py"
    assert location["region"]["startLine"] == 2


def test_markdown_output_and_file(in_tmp):
    (in_tmp / "bad.py").write_text(BAD)
    main(["review", ".", "-f", "markdown", "-o", "review.md"])
    text = (in_tmp / "review.md").read_text()
    assert "codelens review" in text
    assert "`bad.py:2`" in text


def test_console_output_to_file(in_tmp):
    (in_tmp / "bad.py").write_text(BAD)
    main(["review", ".", "-o", "out.txt"])
    out = (in_tmp / "out.txt").read_text()
    assert "PY004" in out and "Health score" in out


def test_config_file_ignore(in_tmp):
    (in_tmp / "bad.py").write_text(BAD)
    (in_tmp / ".codelens.toml").write_text('[codelens]\nignore = ["PY004"]\n')
    assert main(["review", "."]) == 0


def test_exclude_pattern(in_tmp):
    (in_tmp / "vendor").mkdir()
    (in_tmp / "vendor" / "bad.py").write_text(BAD)
    (in_tmp / ".codelens.toml").write_text('exclude = ["vendor/*"]\n')
    assert main(["review", "."]) == 0


def test_invalid_config_is_usage_error(in_tmp):
    (in_tmp / ".codelens.toml").write_text("bogus = 1\n")
    assert main(["review", "."]) == 2


def test_ignore_flag_and_min_severity(in_tmp):
    (in_tmp / "bad.py").write_text(BAD)
    assert main(["review", ".", "--ignore", "py004"]) == 0
    assert main(["review", ".", "--min-severity", "critical"]) == 0


def test_rules_command(capsys):
    assert main(["rules"]) == 0
    assert "PY004" in capsys.readouterr().out


def test_no_command_prints_help(capsys):
    assert main([]) == 2
    assert "usage" in capsys.readouterr().out.lower()


def test_ai_flag_without_key_degrades_gracefully(in_tmp, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    (in_tmp / "bad.py").write_text(BAD)
    assert main(["review", ".", "--ai", "-f", "json"]) == 1
    captured = capsys.readouterr()
    assert "AI review skipped" in captured.err
    assert json.loads(captured.out)["summary"]["findings"] == 1


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_diff_mode_only_reports_changed_files(in_tmp, capsys):
    def git(*args):
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
            cwd=in_tmp,
            check=True,
            capture_output=True,
        )

    git("init", "-q")
    (in_tmp / "old.py").write_text(BAD)  # already bad, but unchanged
    (in_tmp / "new.py").write_text(GOOD)
    git("add", ".")
    git("commit", "-q", "-m", "init")
    (in_tmp / "new.py").write_text(BAD)  # changed afterwards

    main(["review", ".", "--diff", "HEAD", "-f", "json"])
    paths = {f["path"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert paths == {"new.py"}


def test_diff_outside_git_repo_is_usage_error(in_tmp):
    (in_tmp / "a.py").write_text(GOOD)
    if shutil.which("git"):
        assert main(["review", ".", "--diff", "HEAD"]) == 2
