# Coding agent walkthrough

A single script that exercises the coding surface against the tiny sample
repository in this directory, with no server and no database. Every call goes
through the importable `Arrowhead` facade, which runs the identical guarded path
an HTTP client reaches, so this doubles as a smoke test of the coding families.

```bash
uv run python examples/coding_agent/run.py
```

It demonstrates, in order:

- `symbol_map` over the repository, listing each definition and its line span.
- `code_read` of a line range, returned inside the untrusted framing.
- `workingset_update` pinning a file into a named working set.
- `pack_context` assembling a token-budgeted, secret-scanned, provenance-stamped
  bundle from the pinned file plus retrieval.
- `run_snippet` executing a self-contained snippet in the sandbox and returning
  its bounded, framed output.

The script constructs `Settings(profile="coding", repo_root=..., exec_enabled=True)`,
so it shows how a deployment selects the coding profile and turns execution on.
A real HTTP deployment would additionally grant the `execute` action in its
authorization policy; here auth is off, so the allow-all authorizer stands in.
