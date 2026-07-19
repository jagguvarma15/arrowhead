from arrowhead.security.secret_scan import scan_text


def test_detects_aws_access_key():
    findings = scan_text("key = AKIAIOSFODNN7EXAMPLE", max_findings=10)
    types = {f.type for f in findings}
    assert "aws_access_key" in types


def test_detects_private_key_header():
    findings = scan_text("-----BEGIN RSA PRIVATE KEY-----", max_findings=10)
    assert any(f.type == "private_key" for f in findings)


def test_detects_email_pii():
    findings = scan_text("contact alice@example.com now", max_findings=10)
    assert any(f.type == "email" for f in findings)


def test_detects_credential_assignment():
    findings = scan_text('password: "hunter2hunter2"', max_findings=10)
    assert any(f.type == "credential_assignment" for f in findings)


def test_raw_value_never_in_finding():
    secret = "AKIAIOSFODNN7EXAMPLE"
    findings = scan_text(f"aws {secret}", max_findings=10)
    for finding in findings:
        assert secret not in finding.redacted
        assert finding.redacted.startswith("[REDACTED:")


def test_same_value_gets_stable_tag():
    a = scan_text("x@y.com", max_findings=10)[0]
    b = scan_text("other line x@y.com", max_findings=10)[0]
    assert a.redacted == b.redacted


def test_line_numbers_reported():
    findings = scan_text("clean\nclean\nalice@example.com", max_findings=10)
    assert findings[0].line == 3


def test_max_findings_bound():
    text = "\n".join("a@b.com" for _ in range(50))
    assert len(scan_text(text, max_findings=5)) == 5


def test_clean_text_has_no_findings():
    assert scan_text("nothing to see here", max_findings=10) == []
