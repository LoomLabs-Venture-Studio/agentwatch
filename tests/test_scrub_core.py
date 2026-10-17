"""Core redaction helpers used by `agentwatch scrub` and `audit --pii`."""

from __future__ import annotations

import json
import re

import pytest

from agentwatch.detectors.security.secret_scanner import (
    _find_spans,
    _redact_line,
    _redact_text,
)

# Matches only after JSON-escape decoding: in the raw line the value follows
# the "n" of a "\n" escape, which the lookbehind rejects.
_CUSTOM = [(re.compile(r"(?<![A-Za-z])ZEBRA\d{6}"), "zebra")]


def test_custom_patterns_reach_decoded_escape_pass():
    line = json.dumps({"cmd": "echo hi\nZEBRA123456"})
    new_line, count = _redact_line(line, patterns=_CUSTOM)
    assert count == 1
    assert "ZEBRA123456" not in new_line
    assert json.loads(new_line) == {"cmd": "echo hi\n[REDACTED]"}


def test_default_patterns_ignore_custom_value():
    line = json.dumps({"cmd": "echo hi\nZEBRA123456"})
    assert _redact_line(line) == (line, 0)


def test_find_spans_merges_and_labels():
    text = "a ZEBRA123456 b"
    assert _find_spans(text, _CUSTOM) == [(2, 13, "zebra")]
    assert _redact_text(text, _CUSTOM) == ("a [REDACTED] b", 1)


# A fake key body: random-looking base64 lines (not a real key).
_PEM_BODY = [
    "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun",
    "VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK",
    "LxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo",
]
_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    + "\n".join(_PEM_BODY)
    + "\n-----END RSA PRIVATE KEY-----"
)


def test_pem_block_body_redacted_in_text():
    new, count = _redact_text(f"key:\n{_PEM}\ndone\n")
    assert count == 1
    for body_line in _PEM_BODY:
        assert body_line not in new
    assert new.endswith("-----END RSA PRIVATE KEY-----\ndone\n")


def test_pem_block_body_redacted_in_jsonl_line():
    line = json.dumps({"type": "tool_result", "content": f"cat id_rsa\n{_PEM}\n"})
    new_line, count = _redact_line(line)
    assert count >= 1
    for body_line in _PEM_BODY:
        assert body_line not in new_line
    assert json.loads(new_line).keys() == {"type", "content"}


def test_unterminated_pem_header_redacted_and_fast():
    import time

    text = "-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 1_000_000
    t0 = time.perf_counter()
    new, count = _redact_text(text)
    assert time.perf_counter() - t0 < 2.0
    assert count == 1
    assert "BEGIN RSA PRIVATE KEY" not in new


# QA repro corpus (#scrub-secret-leaks): shell commands quoting their secret.
# Inside JSON the quote before each value is the escape \", which the raw-text
# pass used to take for the value (a 1-char "\" match), leaving the secret.
_QUOTED_SECRETS = [
    ('export PGPASSWORD="S3cretPw0rd99" && psql', "S3cretPw0rd99"),
    ('MYSQL_PWD="S3cretPw0rd98" mysql', "S3cretPw0rd98"),
    ('mysql -u root -p"S3cretPw0rd97"', "S3cretPw0rd97"),
    ('psql --password="S3cretPw0rd96"', "S3cretPw0rd96"),
    ('curl -u "admin:S3cretPw0rd95" https://x.io', "S3cretPw0rd95"),
    ('DB_PASSWORD="S3cretPw0rd94"', "S3cretPw0rd94"),
    ('Authorization: Bearer "abcDEF123456ghiJKL789012mnoPQR"', "abcDEF123456ghiJKL789012mnoPQR"),
    ('TOKEN="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"', "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"),
    # Bug 2: a shell-escaped quote inside the quoted value.
    ('export PGPASSWORD="S3cret\\"Pw0rd99" && psql', 'S3cret\\"Pw0rd99'),
]
_CMDS = [cmd for cmd, _ in _QUOTED_SECRETS]


def _corpus(tmp_path):
    objs = [{"command": cmd} for cmd in _CMDS]
    files = {
        "many.json": json.dumps(objs, indent=1) + "\n",
        "compact.json": json.dumps(objs),
        "many.jsonl": "\n".join(json.dumps(o) for o in objs) + "\n",
        "log.txt": "\n".join(json.dumps(o) for o in objs) + "\n",  # copied JSONL log
        "plain.txt": "\n".join(_CMDS) + "\n",
    }
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return [tmp_path / name for name in files]


def _leaks(text):
    return [s for _, s in _QUOTED_SECRETS for frag in (s, s.split('\\"')[-1]) if frag in text]


@pytest.mark.parametrize(
    "name", ["many.json", "compact.json", "many.jsonl", "log.txt", "plain.txt"]
)
def test_scrub_hides_quoted_secrets_in_every_format(tmp_path, name):
    from agentwatch.detectors.security.secret_scanner import scrub_file

    _corpus(tmp_path)
    path = tmp_path / name
    r = scrub_file(path)
    out = r.output.read_text(encoding="utf-8")
    assert _leaks(out) == []
    assert r.redacted == len(_QUOTED_SECRETS)
    assert len(r.findings) == len(_QUOTED_SECRETS)
    if path.suffix == ".json":
        doc = json.loads(out)
        assert [list(o) for o in doc] == [["command"]] * len(_CMDS)
        assert doc[0]["command"] == 'export PGPASSWORD="[REDACTED]" && psql'
    elif name != "plain.txt":
        assert [list(json.loads(x)) for x in out.splitlines()] == [["command"]] * len(_CMDS)


def test_scrub_json_keeps_formatting_outside_redacted_strings(tmp_path):
    from agentwatch.detectors.security.secret_scanner import scrub_file

    path = tmp_path / "cfg.json"
    path.write_text('{\n  "a": 1,\n  "cmd": "mysql -p\\"S3cretPw0rd97\\""\n}\n', encoding="utf-8")
    out = scrub_file(path).output.read_text(encoding="utf-8")
    assert out == '{\n  "a": 1,\n  "cmd": "mysql -p\\"[REDACTED]\\""\n}\n'


def test_no_short_findings_on_repro_corpus(tmp_path):
    """A 1-2 char "secret" is a mis-anchored match (the backslash of an escaped quote)."""
    from agentwatch.detectors.security.secret_scanner import scrub_file

    for path in _corpus(tmp_path):
        for f in scrub_file(path, dry_run=True).findings:
            m = re.fullmatch(r"\[hidden, (\d+) chars\]", f["preview"])
            assert m is None or int(m.group(1)) >= 4, (path.name, f)


def test_scrub_dry_run_lists_json_findings_by_line(tmp_path):
    from agentwatch.detectors.security.secret_scanner import scrub_file

    path = tmp_path / "many.json"
    path.write_text(json.dumps([{"command": c} for c in _CMDS[:2]], indent=1), encoding="utf-8")
    findings = scrub_file(path, dry_run=True).findings
    assert [(f["line"], f["preview"]) for f in findings] == [
        (3, "[hidden, 13 chars]"),
        (6, "[hidden, 13 chars]"),
    ]


def test_redact_secrets_consumes_escaped_quote_in_value():
    from agentwatch.detectors.security.secret_scanner import redact_secrets

    assert (
        redact_secrets('export PGPASSWORD="S3cret\\"Pw0rd99" && psql')
        == 'export PGPASSWORD="[hidden, 15 chars]" && psql'
    )


def test_scrub_refuses_to_write_invalid_json(tmp_path, monkeypatch):
    from agentwatch.detectors.security import secret_scanner

    path = tmp_path / "a.json"
    path.write_text('{"cmd": "x"}', encoding="utf-8")
    monkeypatch.setattr(secret_scanner, "_redact_line", lambda *a, **k: ('{"cmd": ', 1))
    with pytest.raises(ValueError, match="not be valid JSON"):
        secret_scanner.scrub_file(path)
    assert list(tmp_path.iterdir()) == [path]
