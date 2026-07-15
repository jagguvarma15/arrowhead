#!/usr/bin/env bash
# Run the server over stdio for MCP Inspector. In another terminal:
#   npx @modelcontextprotocol/inspector uv run python -m arrowhead.server
set -euo pipefail
cd "$(dirname "$0")/.."
export ARROWHEAD_TRANSPORT="${ARROWHEAD_TRANSPORT:-stdio}"
exec uv run python -m arrowhead.server
