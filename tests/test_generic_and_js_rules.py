from codelens.config import Config
from codelens.scanner import analyze_source


def scan_text(source: str, language: str = "text"):
    return analyze_source("sample.txt", source, language, Config())


def rule_ids(findings):
    return {f.rule_id for f in findings}


def test_aws_key_detected_and_redacted():
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    (finding,) = scan_text(f'aws_key = "{key}"\n')
    assert finding.rule_id == "SEC001"
    assert finding.snippet == ""
    assert key not in finding.message


def test_private_key_detected():
    header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    assert "SEC002" in rule_ids(scan_text(header + "\n"))


def test_github_and_api_key_tokens():
    gh = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    api = "sk-ant-" + "api03-Zk8Jd92Lq0Pz7XcVb3NmRtYu"
    assert "SEC003" in rule_ids(scan_text(f"token: {gh}\n"))
    assert "SEC004" in rule_ids(scan_text(f"KEY={api}\n"))


def test_hardcoded_password_detected():
    assert "SEC005" in rule_ids(scan_text('password = "k8Jd92Lq0Pz7XcVb3NmR"\n'))
    assert "SEC005" in rule_ids(scan_text('{"api_key": "k8Jd92Lq0Pz7XcVb3NmR"}\n'))


def test_placeholders_and_env_lookups_are_not_flagged():
    assert not rule_ids(scan_text('password = "changeme123"\n'))
    assert not rule_ids(scan_text('api_key = "your-api-key-here"\n'))
    assert not rule_ids(scan_text('password = os.environ["DB_PASSWORD"]\n'))
    assert not rule_ids(scan_text('token = "aaaaaaaaaaaa"\n'))  # low entropy


def test_todo_markers():
    assert "GEN001" in rule_ids(scan_text("# TODO: fix this\n"))
    assert "GEN001" in rule_ids(scan_text("// FIXME later\n"))
    assert "GEN001" not in rule_ids(scan_text("x = 'TODO'\n"))


def test_javascript_rules():
    cases = {
        "JS001": "const r = eval(input);",
        "JS002": "el.innerHTML = userInput;",
        "JS003": "var count = 0;",
        "JS004": "if (a == b) {}",
        "JS005": "console.log('debug');",
        "JS006": "try { run(); } catch (e) {}",
    }
    for rule, line in cases.items():
        assert rule in rule_ids(scan_text(line + "\n", "javascript")), rule


def test_javascript_clean_code_and_comments():
    code = "const a = 1;\nif (a === 2 || a != null) {}\n// var x = eval(y);\n"
    assert not rule_ids(scan_text(code, "javascript"))
