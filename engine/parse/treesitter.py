"""Tree-sitter access: the grammar, and the node helpers everything else shares (SPEC §12.1).

Tree-sitter is the **source of truth for structure**. It is error-tolerant, so it parses
the protocols most likely to contain bugs — the ones mid-refactor, missing a dependency, or
pinned to a compiler nobody has. solc is an enrichment pass for *semantics* only, and is
never allowed to become primary (see `solc_ast.py`).

The grammar comes from `tree-sitter-language-pack`, not the standalone
`tree-sitter-solidity` wheel: the standalone package returns a raw integer pointer whose
ABI does not match the tree-sitter core on Windows, and the mismatch surfaces as a crash
rather than an import error.
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

from tree_sitter import Node, Parser, Tree


@lru_cache(maxsize=1)
def solidity_parser() -> Parser:
    """The shared Solidity parser. Cached — grammar loading is not free."""
    from tree_sitter_language_pack import get_parser

    return get_parser("solidity")


def parse_source(source: bytes) -> Tree:
    return solidity_parser().parse(source)


# ── Node helpers ──────────────────────────────────────────────────────────────

def text_of(node: Node | None, source: bytes) -> str:
    """The exact source text a node spans."""
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def line_of(node: Node) -> int:
    """1-indexed start line — humans read lines, tree-sitter counts from zero."""
    return node.start_point[0] + 1


def end_line_of(node: Node) -> int:
    return node.end_point[0] + 1


def named_children(node: Node, *types: str) -> list[Node]:
    """Direct named children, optionally filtered by type."""
    return [c for c in node.named_children if not types or c.type in types]


def first_child(node: Node, *types: str) -> Node | None:
    for child in node.named_children:
        if child.type in types:
            return child
    return None


def child_by_field(node: Node, field: str) -> Node | None:
    return node.child_by_field_name(field)


def walk(node: Node) -> Iterator[Node]:
    """Every named node in the subtree, in source order, including `node` itself."""
    stack = [node]
    while stack:
        current = stack.pop()
        if current.is_named:
            yield current
        stack.extend(reversed(current.children))


def walk_excluding(node: Node, *stop_types: str) -> Iterator[Node]:
    """Like :func:`walk`, but does not descend into nodes of the given types.

    Used to keep a contract's traversal out of its nested function bodies, and a
    function's traversal out of nested definitions.
    """
    stack = [node]
    while stack:
        current = stack.pop()
        if current is not node and current.type in stop_types:
            continue
        if current.is_named:
            yield current
        stack.extend(reversed(current.children))


def descendant_types(node: Node, *types: str) -> Iterator[Node]:
    for child in walk(node):
        if child.type in types:
            yield child


def has_error(node: Node) -> bool:
    return node.has_error


def error_nodes(node: Node) -> list[Node]:
    """The ERROR / MISSING nodes tree-sitter produced, for `ParseError` reporting."""
    found: list[Node] = []
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == "ERROR" or current.is_missing:
            found.append(current)
            continue  # one report per broken region, not per descendant
        stack.extend(current.children)
    return found


# ── NatSpec ───────────────────────────────────────────────────────────────────

def natspec_before(node: Node, source: bytes) -> str | None:
    """The doc comment immediately preceding a declaration.

    Only `///` and `/** … */` count: an ordinary `//` comment above a function is a note
    to the next developer, not documentation of intent, and feeding it to an agent as
    NatSpec would misrepresent it.
    """
    lines: list[str] = []
    sibling = node.prev_sibling

    while sibling is not None and sibling.type == "comment":
        raw = text_of(sibling, source).strip()
        if raw.startswith("///") or raw.startswith("/**"):
            lines.append(raw)
            sibling = sibling.prev_sibling
            continue
        break

    if not lines:
        return None
    return "\n".join(reversed(lines))
