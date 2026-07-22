"""Command-line entry point for running and inspecting the server.

    arrowhead serve        run the server over the configured transport
    arrowhead list-tools   print each tool and the scope it requires

Configuration is read from the environment (the ARROWHEAD_ prefix); see the
settings module for the full set.
"""

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arrowhead",
        description="Run the hardened MCP server or inspect the tools it exposes.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "serve", help="Run the server over the configured transport."
    )
    subparsers.add_parser(
        "list-tools",
        help="Print each tool this server exposes and the scope it requires.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        return _serve()
    if args.command == "list-tools":
        return _list_tools()
    return 1


def _serve() -> int:
    from arrowhead.server import main as run_server

    run_server()
    return 0


def _list_tools() -> int:
    from arrowhead.tools.catalog import TOOL_SPECS

    for spec in TOOL_SPECS:
        print(f"{spec.name}\t{spec.scope}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
