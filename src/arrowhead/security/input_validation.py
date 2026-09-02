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
    if "\\" in path:
        # A backslash is a literal character to PurePosixPath, so a segment
        # like "a\\..\\..\\etc" would slip past the ".." check and leave
        # containment as the only defense; refuse it outright.
        raise ValidationError("path may not contain a backslash")
    candidate = PurePosixPath(path)
    if candidate.is_absolute() or path.startswith("/"):
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


_NAMESPACE_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]*")
_MEMORY_ID_PATTERN = re.compile(r"[a-f0-9]{32}")
_KV_KEY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*")

MAX_NAMESPACE_LENGTH = 64
MAX_KV_KEY_LENGTH = 128


def validate_namespace(namespace: str) -> str:
    """Allow only a lowercase namespace name safe to use as a path segment.

    Must start with a letter or digit and continue with letters, digits,
    dots, underscores, or hyphens, so a namespace can never traverse, hide
    as a dotfile, or collide with the store's temporary-file prefix.
    """
    if not isinstance(namespace, str) or not namespace:
        raise ValidationError("namespace must be a non-empty string")
    if len(namespace) > MAX_NAMESPACE_LENGTH:
        raise ValidationError(
            f"namespace exceeds {MAX_NAMESPACE_LENGTH} characters"
        )
    if not _NAMESPACE_PATTERN.fullmatch(namespace):
        raise ValidationError(
            "namespace must start with a lowercase letter or digit and use "
            "only lowercase letters, digits, dots, underscores, and hyphens"
        )
    return namespace


def validate_memory_id(entry_id: str) -> str:
    """Allow only the server-minted memory id shape (32 hex characters)."""
    if not isinstance(entry_id, str) or not entry_id:
        raise ValidationError("id must be a non-empty string")
    if not _MEMORY_ID_PATTERN.fullmatch(entry_id):
        raise ValidationError("id must be 32 lowercase hex characters")
    return entry_id


def validate_kv_key(key: str) -> str:
    """Allow only a key shape safe to use as a single path segment.

    Must start with a letter or digit and continue with letters, digits,
    dots, underscores, colons, or hyphens. Keys land on a case-sensitive
    segment of a jailed tree, so the same POSIX-filesystem assumption the
    other jails document applies.
    """
    if not isinstance(key, str) or not key:
        raise ValidationError("key must be a non-empty string")
    if len(key) > MAX_KV_KEY_LENGTH:
        raise ValidationError(f"key exceeds {MAX_KV_KEY_LENGTH} characters")
    if not _KV_KEY_PATTERN.fullmatch(key):
        raise ValidationError(
            "key must start with a letter or digit and use only letters, "
            "digits, dots, underscores, colons, and hyphens"
        )
    return key


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
