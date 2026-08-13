"""A walkthrough of the coding surface through the importable facade.

Runs against the small sample repository in this directory, with no server
and no database: it maps the symbols, reads a slice, pins a file into a
working set, packs a token-budgeted context bundle, and runs a snippet in
the sandbox. Every call goes through the same guarded path an HTTP client
would reach, so this doubles as a smoke test of the coding families.

Run it with: uv run python examples/coding_agent/run.py
"""

import asyncio
from pathlib import Path

from arrowhead import Arrowhead, Settings

SAMPLE_REPO = Path(__file__).parent / "sample_repo"


async def main() -> None:
    # Coding profile, execution enabled, and the repo pointed at the sample.
    # A real deployment would also grant the execute action in its policy;
    # with auth off (the default here) the allow-all authorizer stands in.
    settings = Settings(
        profile="coding",
        repo_root=SAMPLE_REPO,
        exec_enabled=True,
    )
    app = Arrowhead(settings=settings)

    print("== symbol_map ==")
    symbols = await app.call("symbol_map", {"path_prefix": ""})
    for symbol in symbols.structured_content["symbols"]:
        print(f"  {symbol['kind']:8} {symbol['name']:20} "
              f"{symbol['path']}:{symbol['line_start']}")

    print("\n== code_read (restock) ==")
    read = await app.call(
        "code_read",
        {"path": "inventory.py", "start_line": 4, "end_line": 8},
    )
    print(read.structured_content["content"])

    print("\n== working set + pack_context ==")
    await app.call(
        "workingset_update",
        {
            "name": "task",
            "action": "pin",
            "items": [{"kind": "repo_file", "identifier": "inventory.py",
                       "note": "the module under review"}],
        },
    )
    packed = await app.call(
        "pack_context",
        {"query": "restock", "working_set": "task", "token_budget": 500},
    )
    bundle = packed.structured_content
    print(f"  {len(bundle['snippets'])} snippet(s), "
          f"~{bundle['token_estimate']} tokens, "
          f"{bundle['redactions']} redaction(s)")
    for snippet in bundle["snippets"]:
        print(f"  [{snippet['kind']}] {snippet['source']}")

    print("\n== run_snippet ==")
    # run_snippet executes in a fresh scratch directory with a scrubbed
    # environment, so the snippet is self-contained. run_tests is the tool
    # that copies an authorized repo subtree in to import from.
    run = await app.call(
        "run_snippet",
        {
            "code": (
                "def restock(counts, item, amount):\n"
                "    counts[item] = max(0, counts.get(item, 0) + amount)\n"
                "    return counts\n"
                "print('total after restock:', "
                "sum(restock({'widget': 2}, 'widget', 3).values()))\n"
            )
        },
    )
    outcome = run.structured_content
    print(f"  exit={outcome['exit_code']} timed_out={outcome['timed_out']}")
    print(f"  stdout: {outcome['stdout'].strip() or '(none)'}")


if __name__ == "__main__":
    asyncio.run(main())
