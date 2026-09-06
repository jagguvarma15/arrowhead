"""Render the site's reference pages from the code at build time.

MkDocs loads this file as a build hook (the hooks entry in mkdocs.yml) and
the on_files event serves two generated pages that never exist on disk.
reference/tools.md comes from the tool catalog: the description shown for
each tool is the same docstring the server sends over the wire, so the page
cannot drift from the contract. reference/configuration.md comes from
.env.example (the prose) and the Settings model (the defaults), and the two
are cross-checked in both directions so a missing or orphaned variable
fails the strict build. A native hook keeps the docs toolchain to a single
dependency; no generator plugin is involved.
"""

from __future__ import annotations

import html
import inspect
import re
from pathlib import Path

from mkdocs.structure.files import File

from arrowhead.config import Settings
from arrowhead.tools.catalog import PROFILES, TOOL_SPECS

ENV_EXAMPLE = Path(__file__).resolve().parent.parent / ".env.example"
ENV_PREFIX = "ARROWHEAD_"

# Families that require a second, explicit opt-in beyond the profile.
FAMILY_GATES = {
    "exec": (
        "Registered only when `ARROWHEAD_EXEC_ENABLED` is true; the execute "
        "action must additionally be granted in the authorization policy."
    ),
    "notify": (
        "Registered only when `ARROWHEAD_NOTIFY_ALLOWLIST` is non-empty; the "
        "notify action must additionally be granted in the authorization "
        "policy."
    ),
}

HINT_LABELS = (
    ("readOnlyHint", "read-only"),
    ("destructiveHint", "destructive"),
    ("idempotentHint", "idempotent"),
    ("openWorldHint", "open-world"),
)

_VAR_LINE = re.compile(r"^(#\s*)?(ARROWHEAD_[A-Z0-9_]+)=(.*)$")
_BANNER = re.compile(r"^# --- (.+?) ---$")


def _hints(annotations: dict) -> str:
    return ", ".join(label for key, label in HINT_LABELS if annotations.get(key))


def _rate_default(attr: str) -> int:
    return Settings.model_fields[attr].default


def _wire_description(spec) -> str:
    # The wire text is plain prose, not markdown; escape the characters the
    # site renderer would otherwise treat as inline HTML.
    return html.escape(inspect.cleandoc(spec.load().__doc__), quote=False)


def _tools_page() -> str:
    families: dict[str, list] = {}
    for spec in TOOL_SPECS:
        families.setdefault(spec.family, []).append(spec)

    out = ["# Tool reference", ""]
    out.append(
        f"All {len(TOOL_SPECS)} tools in the catalog, grouped by family. This "
        "page is generated from the catalog when the site builds; each "
        "description below is the exact text the server sends to a connected "
        "client, and the per-minute ceilings are the defaults a deployment "
        "can raise or lower per tool."
    )
    out.append("")
    out.append(
        "A deployment exposes families by setting `ARROWHEAD_PROFILE`; a tool "
        "outside the active profile is never registered."
    )
    out.extend(["", "| Profile | Families |", "|---|---|"])
    for profile, members in PROFILES.items():
        shown = (
            "every family"
            if members >= frozenset(families)
            else ", ".join(f"`{name}`" for name in sorted(members))
        )
        out.append(f"| `{profile}` | {shown} |")
    out.append("")

    for family, specs in families.items():
        out.extend([f"## {family}", ""])
        if family in FAMILY_GATES:
            out.extend(["!!! note \"Gated family\"", f"    {FAMILY_GATES[family]}", ""])
        out.extend(["| Tool | Scope | Per minute | Hints |", "|---|---|---|---|"])
        for spec in specs:
            out.append(
                f"| [`{spec.name}`](#{spec.name}) | `{spec.scope}` "
                f"| {_rate_default(spec.rate_limit_attr)} "
                f"| {_hints(spec.annotations)} |"
            )
        out.append("")
        for spec in specs:
            out.extend([f"### {spec.name}", "", _wire_description(spec), ""])
    return "\n".join(out)


def _default_cell(field_name: str) -> str:
    default = Settings.model_fields[field_name].default
    if default is None:
        return "*(unset)*"
    if isinstance(default, bool):
        return f"`{str(default).lower()}`"
    text = str(default)
    return f"`{text}`" if text else "*(empty)*"


def _configuration_page() -> str:
    lines = ENV_EXAMPLE.read_text().splitlines()
    live_vars = {
        match.group(2)
        for line in lines
        if (match := _VAR_LINE.match(line)) and not match.group(1)
    }

    out = ["# Configuration reference", ""]
    out.append(
        "Every setting is an environment variable with the `ARROWHEAD_` "
        "prefix; a local `.env` file is honored for development. The prose "
        "here mirrors the annotated [`.env.example`]"
        "(https://github.com/jagguvarma15/arrowhead/blob/main/.env.example) "
        "in the repository, and the defaults shown are the values the server "
        "uses when a variable is unset."
    )
    out.append("")

    seen: set[str] = set()
    prose: list[str] = []
    table: list[str] = []

    def flush_table() -> None:
        if table:
            out.extend(["| Variable | Default |", "|---|---|", *table, ""])
            table.clear()

    def flush_prose() -> None:
        if prose:
            out.extend([" ".join(prose), ""])
            prose.clear()

    for line in lines[2:]:
        banner = _BANNER.match(line)
        if banner:
            flush_prose()
            flush_table()
            out.extend([f"## {banner.group(1)}", ""])
            continue
        var = _VAR_LINE.match(line)
        if var:
            name = var.group(2)
            seen.add(name)
            if var.group(1) and name in live_vars:
                # A commented example for a variable listed elsewhere; keep
                # it as part of the surrounding prose rather than a row.
                flush_table()
                flush_prose()
                out.extend([f"    {line.lstrip('# ')}", ""])
                continue
            flush_prose()
            table.append(f"| `{name}` | {_default_cell(_field_name(name))} |")
            continue
        if line.startswith("#"):
            flush_table()
            prose.append(html.escape(line.lstrip("# ").rstrip(), quote=False))
            continue
        flush_prose()
        flush_table()
    flush_prose()
    flush_table()

    expected = {ENV_PREFIX + name.upper() for name in Settings.model_fields}
    if seen != expected:
        raise RuntimeError(
            "configuration drift between .env.example and Settings: "
            f"missing {sorted(expected - seen)}, orphaned {sorted(seen - expected)}"
        )
    return "\n".join(out)


def _field_name(env_name: str) -> str:
    return env_name.removeprefix(ENV_PREFIX).lower()


def on_files(files, config):
    """Add the two generated reference pages to the site's file set."""
    files.append(File.generated(config, "reference/tools.md", content=_tools_page()))
    files.append(
        File.generated(
            config, "reference/configuration.md", content=_configuration_page()
        )
    )
    return files
