"""Optional tree-sitter symbol backend.

Imported lazily and only when the treesitter extra is installed; the
import failing simply routes extraction to the line heuristic. Each
recognized language maps to the node types that declare a named
definition, so extraction is a single walk with no per-language query
strings to maintain.
"""

from tree_sitter_language_pack import get_parser

# Suffix to (language, {node_type: kind}) for the languages the pack
# serves well. The name is taken from the node's name field.
_LANGUAGES = {
    ".c": ("c", {"function_definition": "function", "struct_specifier": "type"}),
    ".cpp": (
        "cpp",
        {"function_definition": "function", "class_specifier": "class"},
    ),
    ".go": (
        "go",
        {
            "function_declaration": "function",
            "method_declaration": "function",
            "type_declaration": "type",
        },
    ),
    ".java": (
        "java",
        {
            "class_declaration": "class",
            "interface_declaration": "interface",
            "method_declaration": "function",
        },
    ),
    ".js": (
        "javascript",
        {"function_declaration": "function", "class_declaration": "class"},
    ),
    ".rb": (
        "ruby",
        {"method": "function", "class": "class", "module": "module"},
    ),
    ".rs": (
        "rust",
        {
            "function_item": "function",
            "struct_item": "type",
            "enum_item": "type",
            "trait_item": "trait",
        },
    ),
    ".ts": (
        "typescript",
        {
            "function_declaration": "function",
            "class_declaration": "class",
            "interface_declaration": "interface",
        },
    ),
}


def extract_with_tree_sitter(path: str, suffix: str, text: str):
    """Symbols for one file, or None when the language is not mapped."""
    entry = _LANGUAGES.get(suffix)
    if entry is None:
        return None
    language, kinds = entry
    parser = get_parser(language)
    tree = parser.parse(text.encode("utf-8"))
    symbols = []
    cursor = [tree.root_node]
    while cursor:
        node = cursor.pop()
        kind = kinds.get(node.type)
        if kind is not None:
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                symbols.append(
                    {
                        "path": path,
                        "name": name_node.text.decode(
                            "utf-8", errors="replace"
                        ),
                        "kind": kind,
                        "line_start": node.start_point[0] + 1,
                        "line_end": node.end_point[0] + 1,
                    }
                )
        cursor.extend(node.children)
    symbols.sort(key=lambda symbol: symbol["line_start"])
    return symbols
