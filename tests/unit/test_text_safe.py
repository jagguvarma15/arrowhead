import pytest

from arrowhead.content.text_safe import (
    TextSafetyError,
    decode_text,
    sanitize_text,
)


def test_ansi_escape_sequences_removed():
    assert sanitize_text("x\x1b[31mred\x1b[0my") == "xredy"


def test_osc_sequence_removed():
    assert sanitize_text("a\x1b]8;;http://evil\x07link\x1b]8;;\x07b") == "alinkb"


def test_control_characters_removed_but_whitespace_kept():
    assert sanitize_text("a\x00b\x07c") == "abc"
    assert sanitize_text("keep\ttab\nand\rreturn") == "keep\ttab\nand\rreturn"


def test_zero_width_and_bidi_removed():
    assert sanitize_text("a​b‮c﻿d­e") == "abcde"


def test_nfc_normalization():
    # 'e' + combining acute accent normalizes to the single precomposed char.
    assert sanitize_text("é") == "é"


def test_utf7_bom_rejected():
    with pytest.raises(TextSafetyError):
        decode_text(b"\x2b\x2f\x76 rest")


def test_bytes_decoded_as_utf8():
    assert sanitize_text("héllo".encode()) == "héllo"


def test_invalid_utf8_replaced_not_raised():
    assert sanitize_text(b"a\xffb") == "a�b"
