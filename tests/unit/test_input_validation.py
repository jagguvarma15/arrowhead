import pytest

from arrowhead.security.input_validation import (
    ValidationError,
    validate_arithmetic_expression,
    validate_document_path,
    validate_relative_path,
    validate_search_query,
    validate_url,
)


class TestArithmeticExpression:
    def test_plain_arithmetic_accepted(self):
        assert validate_arithmetic_expression("2 * (3 + 4)") == "2 * (3 + 4)"

    @pytest.mark.parametrize(
        "payload",
        [
            "1+1; import os",
            "__import__('os').system('id')",
            "open('/etc/passwd')",
            "1 + a",
            "2\n#",
            "$(whoami)",
            "`id`",
        ],
    )
    def test_injection_shapes_rejected(self, payload):
        with pytest.raises(ValidationError):
            validate_arithmetic_expression(payload)

    def test_empty_rejected(self):
        with pytest.raises(ValidationError):
            validate_arithmetic_expression("   ")

    def test_overlong_rejected(self):
        with pytest.raises(ValidationError):
            validate_arithmetic_expression("1+" * 200 + "1", max_length=200)


class TestUrl:
    def test_normal_url_accepted(self):
        assert validate_url("https://example.com/a?b=c")

    def test_control_characters_rejected(self):
        with pytest.raises(ValidationError):
            validate_url("http://example.com/\r\nHost: evil")

    def test_overlong_rejected(self):
        with pytest.raises(ValidationError):
            validate_url("http://example.com/" + "a" * 3000)


class TestRelativePath:
    def test_normal_relative_path_accepted(self):
        assert validate_relative_path("docs/readme.txt") == "docs/readme.txt"

    @pytest.mark.parametrize(
        "payload",
        [
            "../../etc/passwd",
            "..",
            "a/../../b",
            "/etc/passwd",
            "\\windows\\system32",
            "file\x00.txt",
            "",
        ],
    )
    def test_traversal_shapes_rejected(self, payload):
        with pytest.raises(ValidationError):
            validate_relative_path(payload)


class TestDocumentPath:
    @pytest.mark.parametrize(
        "path", ["notes.txt", "sub/dir/data.json", "guide.md"]
    )
    def test_allowed_documents_accepted(self, path):
        assert validate_document_path(path) == path

    @pytest.mark.parametrize(
        "path",
        [
            "../../etc/passwd.txt",
            "secrets.env",
            "script.sh",
            "archive.zip",
            "noextension",
            "config.yaml",
        ],
    )
    def test_disallowed_or_traversal_rejected(self, path):
        with pytest.raises(ValidationError):
            validate_document_path(path)

    def test_custom_extension_allowlist(self):
        allowed = frozenset({".csv"})
        assert validate_document_path("data.csv", allowed_extensions=allowed)
        with pytest.raises(ValidationError):
            validate_document_path("data.txt", allowed_extensions=allowed)


class TestSearchQuery:
    def test_normal_query_accepted(self):
        assert validate_search_query("deadline") == "deadline"

    @pytest.mark.parametrize("payload", ["", "   ", "with\x00null"])
    def test_bad_queries_rejected(self, payload):
        with pytest.raises(ValidationError):
            validate_search_query(payload)

    def test_overlong_query_rejected(self):
        with pytest.raises(ValidationError):
            validate_search_query("a" * 50, max_length=10)
