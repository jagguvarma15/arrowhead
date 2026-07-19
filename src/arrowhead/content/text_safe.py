"""Sanitize untrusted plain text.

Removes ANSI escape sequences and control characters (which can spoof
clickable links, manipulate a terminal, or drive DoS), strips a byte-order
mark and any null bytes, removes zero-width and bidirectional-override
characters used to smuggle text past filters, and normalizes to NFC. Bytes
are always decoded as UTF-8, which neutralizes charset-differential attacks
such as UTF-7 by construction; an explicit UTF-7 byte-order mark is refused
outright.
"""

import re
import unicodedata

# CSI sequences (ESC [ ... final) and OSC sequences (ESC ] ... terminator).
_ANSI_CSI = re.compile(r"\x1b\[[0-9;?]{0,32}[ -/]{0,8}[@-~]")
_ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]{0,2000}(?:\x07|\x1b\\)")
# C0 and C1 control characters except tab, newline, and carriage return.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
# Zero-width, bidi override, byte-order-mark, and soft-hyphen characters.
_INVISIBLE = re.compile(
    "[​-‏‪-‮⁠-⁤﻿­]"
)

_UTF7_BOM = b"\x2b\x2f\x76"


class TextSafetyError(Exception):
    """The text could not be decoded safely."""


def decode_text(raw: bytes) -> str:
    """Decode bytes as UTF-8, refusing an explicit UTF-7 byte-order mark."""
    if raw.startswith(_UTF7_BOM):
        raise TextSafetyError("UTF-7 encoded content is not accepted")
    return raw.decode("utf-8", errors="replace")


def sanitize_text(value: bytes | str) -> str:
    """Return text with escapes, control, and invisible characters removed."""
    text = decode_text(value) if isinstance(value, bytes) else value
    text = _ANSI_OSC.sub("", text)
    text = _ANSI_CSI.sub("", text)
    text = _CONTROL.sub("", text)
    text = _INVISIBLE.sub("", text)
    return unicodedata.normalize("NFC", text)
