from arrowhead.prompts.library import audit_corpus, summarize_document


def test_summarize_references_the_resource_uri():
    message = summarize_document("notes/plan.md")
    assert "doc://notes/plan.md" in message
    assert "untrusted" in message.lower()


def test_summarize_sanitizes_its_argument():
    message = summarize_document("a\x1b[31mb​c")
    assert "\x1b" not in message
    assert "​" not in message


def test_audit_corpus_points_at_the_scan_tool():
    message = audit_corpus("exports/")
    assert "doc_scan" in message
    assert "exports/" in message
    assert "never echo a raw secret" in message


def test_audit_corpus_handles_empty_prefix():
    message = audit_corpus()
    assert "whole corpus" in message
