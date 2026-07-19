"""Strict, bounded JSON parsing for untrusted document content.

Python's json.loads does not deserialize to arbitrary classes, so the
gadget-chain risk of CWE-502 does not apply here. What remains is
resource exhaustion and ambiguity: deep nesting can exhaust the stack,
huge structures can exhaust memory, duplicate keys let a value be smuggled
past one layer and used by another, and the parser accepts non-standard
NaN/Infinity by default. This module bounds all of those before returning
a parsed value.
"""

import json

# Depth is checked on the raw text before parsing so a nesting bomb is
# rejected without ever building the structure.
_OPENERS = "[{"
_CLOSERS = "]}"


class JSONSafetyError(Exception):
    """The JSON is invalid or exceeds a safety bound."""


def parse_json(
    text: str,
    *,
    max_bytes: int = 1_000_000,
    max_depth: int = 64,
    max_elements: int = 100_000,
):
    """Parse JSON with size, depth, element-count, and validity bounds."""
    if not isinstance(text, str):
        raise JSONSafetyError("JSON input must be a string")
    if len(text.encode("utf-8")) > max_bytes:
        raise JSONSafetyError(f"JSON exceeds {max_bytes} bytes")
    if _max_bracket_depth(text) > max_depth:
        raise JSONSafetyError(f"JSON nesting exceeds depth {max_depth}")
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError) as exc:
        raise JSONSafetyError("invalid or unsafe JSON") from exc
    _enforce_element_count(parsed, max_elements)
    return parsed


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise JSONSafetyError("duplicate key in JSON object")
        seen.add(key)
    return dict(pairs)


def _reject_constant(constant: str) -> object:
    raise JSONSafetyError(f"non-standard JSON constant: {constant}")


def _max_bracket_depth(text: str) -> int:
    depth = 0
    highest = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in _OPENERS:
            depth += 1
            highest = max(highest, depth)
        elif char in _CLOSERS:
            depth -= 1
    return highest


def _enforce_element_count(value: object, max_elements: int) -> None:
    count = 0
    stack = [value]
    while stack:
        current = stack.pop()
        count += 1
        if count > max_elements:
            raise JSONSafetyError(f"JSON exceeds {max_elements} elements")
        if isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
