"""Safe arithmetic evaluation.

Never calls eval(), exec(), or a shell. The expression is parsed into an
AST and evaluated by an interpreter that recognizes only numeric literals,
the four basic operators, and unary plus and minus. Anything else, such as
names, calls, attributes, or exponentiation, is rejected even if it slipped
past upstream validation. This is the second layer: character allowlisting
happens first in input_validation, and this walker assumes nothing about it.
"""

import ast


class SandboxError(Exception):
    """The expression cannot be evaluated safely."""


_MAX_NODES = 100

_BINARY_OPERATIONS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a / b,
}


def evaluate_arithmetic(expression: str) -> int | float:
    """Evaluate a vetted arithmetic expression without eval()."""
    try:
        tree = ast.parse(expression, mode="eval")
    except (SyntaxError, ValueError) as exc:
        raise SandboxError("expression is not valid arithmetic") from exc
    if sum(1 for _ in ast.walk(tree)) > _MAX_NODES:
        raise SandboxError("expression is too complex")
    return _evaluate(tree.body)


def _evaluate(node: ast.expr) -> int | float:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            return node.value
        raise SandboxError("only numeric literals are allowed")

    if isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.USub):
            return -_evaluate(node.operand)
        if isinstance(node.op, ast.UAdd):
            return +_evaluate(node.operand)
        raise SandboxError("operator is not allowed")

    if isinstance(node, ast.BinOp):
        operation = _BINARY_OPERATIONS.get(type(node.op))
        if operation is None:
            raise SandboxError("operator is not allowed")
        left = _evaluate(node.left)
        right = _evaluate(node.right)
        try:
            return operation(left, right)
        except ZeroDivisionError as exc:
            raise SandboxError("division by zero") from exc

    raise SandboxError("expression contains disallowed syntax")
