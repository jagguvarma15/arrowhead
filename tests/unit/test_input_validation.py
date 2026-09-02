import pytest

from arrowhead.security.input_validation import (
    ValidationError,
    validate_arithmetic_expression,
    validate_document_path,
    validate_kv_key,
    validate_memory_id,
    validate_namespace,
    validate_relative_path,
    validate_search_query,
    validate_url,
    validate_write_content,
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


class TestWriteContent:
    def test_normal_content_accepted(self):
        assert validate_write_content("hello", max_bytes=100) == "hello"

    def test_null_byte_rejected(self):
        with pytest.raises(ValidationError):
            validate_write_content("a\x00b", max_bytes=100)

    def test_non_string_rejected(self):
        with pytest.raises(ValidationError):
            validate_write_content(b"bytes", max_bytes=100)

    def test_oversized_rejected(self):
        with pytest.raises(ValidationError):
            validate_write_content("x" * 50, max_bytes=8)


def test_backslash_path_is_rejected():
    with pytest.raises(ValidationError):
        validate_relative_path("a\\..\\..\\etc")


class TestNamespace:
    def test_plain_names_accepted(self):
        for name in ("prefs", "run.2026", "a", "0-agent_state"):
            assert validate_namespace(name) == name

    def test_traversal_shapes_rejected(self):
        for name in ("..", "a/b", "a\\b", "../etc", ".hidden", "a b"):
            with pytest.raises(ValidationError):
                validate_namespace(name)

    def test_uppercase_and_empty_rejected(self):
        for name in ("Prefs", "", "-lead", "_lead"):
            with pytest.raises(ValidationError):
                validate_namespace(name)

    def test_overlong_rejected(self):
        with pytest.raises(ValidationError):
            validate_namespace("a" * 65)


class TestMemoryId:
    def test_minted_shape_accepted(self):
        assert validate_memory_id("ab" * 16) == "ab" * 16

    def test_other_shapes_rejected(self):
        for value in ("", "short", "G" * 32, "ab" * 15 + "..", "AB" * 16):
            with pytest.raises(ValidationError):
                validate_memory_id(value)


class TestKvKey:
    def test_plain_keys_accepted(self):
        for key in ("run:42:state", "checkpoint.7", "A_b-c"):
            assert validate_kv_key(key) == key

    def test_traversal_and_dotfile_shapes_rejected(self):
        for key in ("..", "a/b", "a\\b", ".hidden", ":lead", "", "a b"):
            with pytest.raises(ValidationError):
                validate_kv_key(key)

    def test_overlong_rejected(self):
        with pytest.raises(ValidationError):
            validate_kv_key("k" * 129)
