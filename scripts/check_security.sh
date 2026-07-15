#!/usr/bin/env bash
# Local security gate: lint, the adversarial test suite, and a static
# scan if one is installed. Run before pushing.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> ruff"
uv run ruff check src/ tests/

echo "==> adversarial and conformance tests"
uv run pytest tests/security tests/conformance -q

# mcp-scan is optional; run it when present without failing the gate if
# it is not installed.
if command -v mcp-scan >/dev/null 2>&1; then
  echo "==> mcp-scan"
  mcp-scan .
else
  echo "==> mcp-scan not installed, skipping"
fi
