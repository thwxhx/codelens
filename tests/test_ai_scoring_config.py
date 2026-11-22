import json
from types import SimpleNamespace

import pytest

from codelens.ai import AIReviewer, AIUnavailable, parse_findings
from codelens.config import Config, ConfigError
from codelens.models import Finding, ScanResult, Severity


class FakeClient:
    def __init__(self, reply: str = "[]", error: Exception | None = None):
        self.reply, self.error, self.calls = reply, error, []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=self.reply)])


def finding(rule="PY004", path="a.py", sev=Severity.HIGH):
    return Finding(rule_id=rule, message="m", severity=sev, path=path, line=1)


# ---- AI ------------------------------------------------------------------------------------
def test_parse_findings_handles_fences_and_prose():
    payload = [{"line": 3, "severity": "high", "message": "Race condition", "suggestion": "Lock"}]
    reply = "Here you go:\n```json\n" + json.dumps(payload) + "\n```"
    (item,) = parse_findings(reply, "a.py")
    assert (item.line, item.severity) == (3, Severity.HIGH)
    assert (item.source, item.rule_id) == ("ai", "AI001")
    assert item.suggestion == "Lock"


def test_parse_findings_clamps_severity_and_drops_junk():
    reply = json.dumps(
        [
            {"line": 1, "severity": "critical", "message": "x"},
            {"line": 2, "severity": "banana", "message": "y"},
            {"line": 3, "message": ""},
            "not a dict",
        ]
    )
    items = parse_findings(reply, "a.py")
    assert [i.severity for i in items] == [Severity.HIGH, Severity.MEDIUM]


@pytest.mark.parametrize("reply", ["", "no json here", "[not json]", '{"a": 1}'])
def test_parse_findings_tolerates_garbage(reply):
    assert parse_findings(reply, "a.py") == []


def test_reviewer_ranks_limits_and_numbers_lines():
    client = FakeClient("[]")
    sources = {f"f{i}.py": "x = 1\n" * (i + 1) for i in range(5)}
    AIReviewer(client=client, max_files=2).review(sources, [finding(path="f0.py")])
    assert len(client.calls) == 2
    prompt = client.calls[0]["messages"][0]["content"]
    assert "f0.py" in prompt and "    1 | x = 1" in prompt  # most findings first


def test_reviewer_never_sends_files_with_secrets():
    client = FakeClient("[]")
    reviewer = AIReviewer(client=client)
    reviewer.review({"leak.py": "x = 1\n", "ok.py": "y = 2\n"}, [finding("SEC001", "leak.py")])
    assert len(client.calls) == 1 and "ok.py" in client.calls[0]["messages"][0]["content"]
    assert any("leak.py" in w for w in reviewer.warnings)


def test_reviewer_survives_api_errors():
    reviewer = AIReviewer(client=FakeClient(error=RuntimeError("boom")))
    assert reviewer.review({"a.py": "x = 1\n"}, []) == []
    assert reviewer.warnings and "boom" in reviewer.warnings[0]


def test_reviewer_requires_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(AIUnavailable):
        AIReviewer()


# ---- scoring -------------------------------------------------------------------------------
def test_clean_result_scores_100():
    result = ScanResult(lines_scanned=500)
    assert (result.score, result.grade) == (100, "A")


def test_score_drops_with_severity_density():
    result = ScanResult(findings=[finding(sev=Severity.HIGH)], lines_scanned=100)
    assert (result.score, result.grade) == (80, "B")
    worse = ScanResult(findings=[finding(sev=Severity.CRITICAL)] * 10, lines_scanned=100)
    assert worse.score == 0 and worse.grade == "F"


# ---- config --------------------------------------------------------------------------------
def test_config_from_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.codelens]\nmax_complexity = 5\nfail_on = "medium"\nignore = ["py016"]\n'
    )
    cfg = Config.load(start=tmp_path)
    assert cfg.max_complexity == 5 and cfg.fail_on == Severity.MEDIUM and cfg.ignore == {"PY016"}


def test_config_rejects_bad_values():
    with pytest.raises(ConfigError):
        Config.from_mapping({"max_complexity": 0})
    with pytest.raises(ConfigError):
        Config.from_mapping({"nonsense": True})
    assert Config.from_mapping({"fail_on": "none"}).fail_on is None
