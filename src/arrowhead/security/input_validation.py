"""Shared input validators.

Every tool argument passes through one of these before it reaches an
evaluator, the filesystem, or the network. Validation is allowlist-based:
inputs are accepted only when they match a known-good shape, never by
searching for known-bad substrings.
"""

import re
from pathlib import PurePosixPath


class ValidationError(Exception):
    """The input does not match the allowed shape."""


_EXPRESSION_PATTERN = re.compile(r"[0-9+\-*/(). \t]+")

MAX_URL_LENGTH = 2000
MAX_PATH_LENGTH = 500


def validate_arithmetic_expression(expression: str, *, max_length: int = 200) -> str:
    """Allow only digits, + - * / ( ) . and whitespace."""
    if not isinstance(expression, str) or not expression.strip():
        raise ValidationError("expression must be a non-empty string")
    if len(expression) > max_length:
        raise ValidationError(f"expression exceeds {max_length} characters")
    if not _EXPRESSION_PATTERN.fullmatch(expression):
        raise ValidationError(
            "expression may only contain digits, + - * / ( ) . and spaces"
        )
    return expression


def validate_url(url: str) -> str:
    """Bound the length and shape of a URL before it is parsed."""
    if not isinstance(url, str) or not url.strip():
        raise ValidationError("url must be a non-empty string")
    if len(url) > MAX_URL_LENGTH:
        raise ValidationError(f"url exceeds {MAX_URL_LENGTH} characters")
    if any(ord(ch) < 0x20 or ch == "\x7f" for ch in url):
        raise ValidationError("url contains control characters")
    return url


def validate_relative_path(path: str) -> str:
    """Allow only a relative path with no parent-directory components."""
    if not isinstance(path, str) or not path.strip():
        raise ValidationError("path must be a non-empty string")
    if len(path) > MAX_PATH_LENGTH:
        raise ValidationError(f"path exceeds {MAX_PATH_LENGTH} characters")
    if "\x00" in path:
        raise ValidationError("path contains a null byte")
    candidate = PurePosixPath(path)
    if candidate.is_absolute() or path.startswith(("/", "\\")):
        raise ValidationError("path must be relative")
    if any(part == ".." for part in candidate.parts):
        raise ValidationError("path may not contain parent-directory components")
    return path


MAX_SEARCH_QUERY_LENGTH = 200


def validate_search_query(
    query: str, *, max_length: int = MAX_SEARCH_QUERY_LENGTH
) -> str:
    """Bound the length and shape of a search query before matching.

    The literal-vs-regex mode and the ReDoS guard are enforced by the
    matcher; this validator only checks the query is a bounded, non-empty
    string free of null bytes.
    """
    if not isinstance(query, str) or not query.strip():
        raise ValidationError("query must be a non-empty string")
    if len(query) > max_length:
        raise ValidationError(f"query exceeds {max_length} characters")
    if "\x00" in query:
        raise ValidationError("query contains a null byte")
    return query


def validate_write_content(content: str, *, max_bytes: int) -> str:
    """Validate content bound for a document write.

    Requires a string free of null bytes and within the byte cap. Format
    validity (valid JSON, and so on) is checked by the write tool, and the
    store enforces the size cap again at write time.
    """
    if not isinstance(content, str):
        raise ValidationError("content must be a string")
    if "\x00" in content:
        raise ValidationError("content contains a null byte")
    if len(content.encode("utf-8")) > max_bytes:
        raise ValidationError(f"content exceeds {max_bytes} bytes")
    return content


DEFAULT_DOC_EXTENSIONS = frozenset({".json", ".md", ".txt"})


def validate_document_path(
    path: str, *, allowed_extensions: frozenset[str] = DEFAULT_DOC_EXTENSIONS
) -> str:
    """Validate a corpus-relative document path with an extension allowlist.

    Builds on validate_relative_path (relative, no parent components, no
    null byte, length cap) and additionally requires a recognized document
    extension, so only .json / .md / .txt files can be addressed.
    """
    validate_relative_path(path)
    suffix = PurePosixPath(path).suffix.lower()
    if suffix not in allowed_extensions:
        allowed = ", ".join(sorted(allowed_extensions))
        raise ValidationError(f"document extension must be one of: {allowed}")
    return path
