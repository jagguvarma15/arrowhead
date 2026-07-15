import pytest

from arrowhead.security.sandbox import SandboxError, evaluate_arithmetic


def test_basic_arithmetic():
    assert evaluate_arithmetic("2 * (3 + 4)") == 14
    assert evaluate_arithmetic("1 + 2 - 3") == 0
    assert evaluate_arithmetic("7 / 2") == 3.5
    assert evaluate_arithmetic("-4 + +1") == -3
    assert evaluate_arithmetic("0.5 * 8") == 4.0


@pytest.mark.parametrize(
    "payload",
    [
        "__import__('os')",
        "().__class__",
        "open('x')",
        "'a' + 'b'",
        "[1,2]",
        "lambda: 1",
        "2 ** 8",
        "1 if 1 else 2",
        "x",
        "1 @ 2",
        "1 % 2",
        "1 // 2",
        "1 << 30",
    ],
)
def test_non_arithmetic_syntax_rejected(payload):
    with pytest.raises(SandboxError):
        evaluate_arithmetic(payload)


def test_boolean_literals_rejected():
    with pytest.raises(SandboxError):
        evaluate_arithmetic("True + 1")


def test_division_by_zero_reported_cleanly():
    with pytest.raises(SandboxError, match="division by zero"):
        evaluate_arithmetic("1 / 0")


def test_oversized_tree_rejected():
    with pytest.raises(SandboxError):
        evaluate_arithmetic("+".join(["1"] * 80))


def test_syntax_error_reported_cleanly():
    with pytest.raises(SandboxError):
        evaluate_arithmetic("2 +")
