"""Arithmetic tool that never touches eval() or a shell.

Two independent layers: a character allowlist rejects anything that is not
plainly arithmetic, then an AST interpreter evaluates only numeric literals
and basic operators. An injection payload has to beat both, and each layer
is tested on its own.
"""

from fastmcp.exceptions import ToolError

from arrowhead.config import get_settings
from arrowhead.security.input_validation import (
    ValidationError,
    validate_arithmetic_expression,
)
from arrowhead.security.sandbox import SandboxError, evaluate_arithmetic


def calculate(expression: str) -> float:
    """Evaluate an arithmetic expression with + - * / and parentheses.
    Example: calculate(expression="2 * (3 + 4)") returns 14.
    """
    settings = get_settings()
    try:
        validate_arithmetic_expression(
            expression, max_length=settings.expression_max_length
        )
        result = evaluate_arithmetic(expression)
    except (ValidationError, SandboxError) as exc:
        raise ToolError(str(exc)) from exc
    return float(result)
