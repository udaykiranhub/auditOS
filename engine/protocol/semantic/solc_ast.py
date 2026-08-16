"""Reading the solc AST the build stage already wrote, and never opened until now.

`engine/build` compiles the repository and dumps one AST per source to
`build/ast/<path>.json`, recording the location on `BuildModel.SourceUnit.ast_path`. Every
semantic stage downstream then ignored it and re-derived what it could from source text with
regular expressions.

That is the single largest missed tool in the phase. The AST carries two things text cannot:

* **`referencedDeclaration`** — every identifier links to the id of its declaration. Names
  resolve exactly. Two contracts that both declare `debt` stop being ambiguous, a local
  shadowing storage is distinguishable from the storage it shadows, and an inherited
  variable resolves to the parent that declared it.
* **`typeDescriptions`** — the real, canonical type of every expression, including the type
  a binary comparison was evaluated at.

With them, `account.totalDebtUsd > account.borrowLimitUsd` is a `BinaryOperation` whose two
operands resolve to struct-field declarations. Without them it is a string that a regex can
match only if it happens to fit the shape the regex anticipated.

This module does the reading only: load, index by declaration id, walk. It builds nothing —
`build.py` turns what it finds into graph nodes and edges.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from engine.core.models.build import BuildModel

#: Comparison operators. `!=` is excluded deliberately: it is a disequality rather than an
#: ordering, and in practice it is authorization (`msg.sender != owner`), which the
#: permission pass already handles.
COMPARISONS = frozenset({">", ">=", "<", "<=", "=="})

#: Negating a comparison. `require(x)` asserts `x`; `if (x) revert` asserts *not* `x`, and
#: reading the second literally records the exact reverse of what the protocol enforces.
NEGATE = {">": "<=", ">=": "<", "<": ">=", "<=": ">", "==": "!=", "!=": "=="}

#: Mirroring, so `a <= b` and `b >= a` become one record.
MIRROR = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}


@dataclass
class Declaration:
    """One declared thing, indexed by the id every reference to it carries."""

    id: int
    node_type: str
    name: str
    type_name: str = ""
    kind: str = ""
    """`VariableDeclaration` sub-shape: `state`, `local`, `parameter`, `field`."""

    contract: str = ""
    """Name of the enclosing contract or struct, when there is one."""

    path: str = ""
    line: int = 0
    is_constant: bool = False
    is_state: bool = False


@dataclass
class Comparison:
    """One `BinaryOperation` that compares two expressions, with both sides resolved.

    `operator` is already normalised: negated when the comparison sits inside an
    `if (…) revert`, and mirrored so the constrained side is on the left.
    """

    operator: str
    left: tuple[int, ...]
    """Declaration ids the left side mentions, in order."""
    right: tuple[int, ...]
    left_text: str
    right_text: str
    literal: str = ""
    """The right side when it is a numeric constant."""
    factor: str = ""
    """A literal multiplier on the right side: the `2` in `debt * 2`."""
    type_name: str = ""
    function_id: int = 0
    line: int = 0
    reverts_when_true: bool = False
    """Whether this came from an `if (…) revert`, before normalisation. Kept for evidence."""

    source: str = ""
    """The comparison as written, for quoting."""


@dataclass
class SourceAst:
    """One parsed source file."""

    path: str
    root: dict[str, Any]
    declarations: dict[int, Declaration] = field(default_factory=dict)


class AstIndex:
    """Every AST the build produced, with declarations resolvable by id across files."""

    def __init__(self, sources: list[SourceAst]) -> None:
        self.sources = sources
        self.declarations: dict[int, Declaration] = {}
        for source in sources:
            self.declarations.update(source.declarations)

    @property
    def available(self) -> bool:
        return bool(self.sources)

    def resolve(self, declaration_id: int) -> Declaration | None:
        return self.declarations.get(declaration_id)

    def name_of(self, declaration_id: int) -> str:
        declaration = self.declarations.get(declaration_id)
        return declaration.name if declaration is not None else ""


def load(build: BuildModel | None, run_dir: Path | None) -> AstIndex:
    """Every AST on disk for this run. Empty when the repository did not compile.

    Never raises: a missing, unreadable or malformed AST degrades the graph to text
    fidelity, which is a worse model but a correct one. Refusing to run because one source
    failed to compile would make the whole semantic layer hostage to the build.
    """
    if build is None or run_dir is None:
        return AstIndex([])

    sources: list[SourceAst] = []
    for unit in build.sources:
        if not unit.ast_path:
            continue
        location = run_dir / unit.ast_path
        try:
            root = json.loads(location.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(root, dict):
            continue
        source = SourceAst(path=unit.path, root=root)
        source.declarations = _declarations(root, unit.path)
        sources.append(source)
    return AstIndex(sources)


def walk(node: Any) -> Iterator[dict[str, Any]]:
    """Every AST node, depth-first. Values that are not nodes are skipped, not inspected."""
    if isinstance(node, dict):
        if "nodeType" in node:
            yield node
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)


def _declarations(root: dict[str, Any], path: str) -> dict[int, Declaration]:
    """Index every declaration in one file by the id its references carry.

    Struct fields are indexed alongside state variables and locals, because a comparison of
    two struct fields is exactly the shape of a lending protocol's health check and the
    field is the name that carries the meaning.
    """
    found: dict[int, Declaration] = {}

    for container in walk(root):
        kind = container.get("nodeType")
        if kind not in ("ContractDefinition", "StructDefinition"):
            continue
        owner = container.get("name", "")

        for node in walk(container):
            if node.get("nodeType") != "VariableDeclaration":
                continue
            identifier = node.get("id")
            if not isinstance(identifier, int) or identifier in found:
                continue
            is_state = bool(node.get("stateVariable"))
            found[identifier] = Declaration(
                id=identifier,
                node_type="VariableDeclaration",
                name=node.get("name", ""),
                type_name=(node.get("typeDescriptions") or {}).get("typeString", ""),
                kind=(
                    "state"
                    if is_state
                    else "field"
                    if kind == "StructDefinition"
                    else "local"
                ),
                contract=owner,
                path=path,
                line=_line(node),
                is_constant=node.get("constant", False)
                or node.get("mutability") in ("constant", "immutable"),
                is_state=is_state,
            )

        for node in walk(container):
            if node.get("nodeType") not in ("FunctionDefinition", "ModifierDefinition"):
                continue
            identifier = node.get("id")
            if isinstance(identifier, int) and identifier not in found:
                found[identifier] = Declaration(
                    id=identifier,
                    node_type=node.get("nodeType", ""),
                    name=node.get("name", ""),
                    kind=node.get("kind", ""),
                    contract=owner,
                    path=path,
                    line=_line(node),
                )
    return found


def _line(node: dict[str, Any]) -> int:
    """solc records `src` as `offset:length:file`, not a line. Offset is what we have.

    Returning the byte offset rather than inventing a line number keeps this honest; the
    graph builder converts it against the real source when it needs a line.
    """
    src = node.get("src", "")
    head = src.partition(":")[0]
    return int(head) if head.isdigit() else 0


# ── Comparisons: where the protocol states its own rules ──────────────────────


def comparisons(source: SourceAst) -> list[Comparison]:
    """Every comparison in this file that a guard enforces, with both sides resolved.

    Only guards — a comparison inside a `return` or a ternary is a computation, not a rule
    the protocol imposes on itself. `require(x)` contributes `x`; `if (x) revert`
    contributes `not x`, negated here rather than left for a reader to get wrong.
    """
    found: list[Comparison] = []
    for function in walk(source.root):
        if function.get("nodeType") not in ("FunctionDefinition", "ModifierDefinition"):
            continue
        function_id = function.get("id", 0)

        for condition, reverts in _guard_conditions(function):
            for node in _conjuncts(condition):
                if node.get("nodeType") != "BinaryOperation":
                    continue
                operator = node.get("operator", "")
                if operator not in COMPARISONS:
                    continue
                comparison = _resolve(node, operator, reverts, function_id)
                if comparison is not None:
                    found.append(comparison)
    return found


def _guard_conditions(function: dict[str, Any]) -> list[tuple[dict[str, Any], bool]]:
    """`(condition, reverts_when_true)` for every guard in this body."""
    found: list[tuple[dict[str, Any], bool]] = []

    for node in walk(function):
        kind = node.get("nodeType")
        if kind == "FunctionCall":
            expression = node.get("expression") or {}
            if expression.get("name") == "require":
                arguments = node.get("arguments") or []
                if arguments and isinstance(arguments[0], dict):
                    found.append((arguments[0], False))
        elif kind == "IfStatement" and _is_revert(node.get("trueBody")):
            condition = node.get("condition")
            if isinstance(condition, dict):
                found.append((condition, True))
    return found


def _is_revert(body: Any) -> bool:
    """Whether an `if` body does nothing but revert.

    A body that reverts *and* does something else is not a guard — the other statement runs
    on some path, and treating the condition as a rule would be wrong.
    """
    if not isinstance(body, dict):
        return False
    if body.get("nodeType") == "RevertStatement":
        return True
    if body.get("nodeType") != "Block":
        return False
    statements = body.get("statements") or []
    return len(statements) == 1 and _is_revert(statements[0])


def _conjuncts(condition: dict[str, Any]) -> list[dict[str, Any]]:
    """Split `a && b` into its parts; refuse `a || b`.

    Each side of an `&&` is independently enforced. Neither side of an `||` is — either may
    be the one that held — so reading one as a rule asserts something the code does not.
    """
    if condition.get("nodeType") == "BinaryOperation":
        operator = condition.get("operator")
        if operator == "||":
            return []
        if operator == "&&":
            return [
                part
                for side in ("leftExpression", "rightExpression")
                if isinstance(condition.get(side), dict)
                for part in _conjuncts(condition[side])
            ]
    return [condition]


def _resolve(
    node: dict[str, Any], operator: str, reverts: bool, function_id: int
) -> Comparison | None:
    """One comparison with both operands resolved to declaration ids."""
    left_node = node.get("leftExpression")
    right_node = node.get("rightExpression")
    if not isinstance(left_node, dict) or not isinstance(right_node, dict):
        return None

    if reverts:
        operator = NEGATE[operator]
    if operator == "!=":
        return None

    left = _referenced(left_node)
    right = _referenced(right_node)
    literal = _literal(right_node)
    factor = _factor(right_node)

    # Orientation follows which side names something, not the operator: mirroring
    # unconditionally on `<` moves the constrained quantity onto the empty side of
    # `cutoffTime <= 64800` and loses the bound entirely.
    left_text, right_text = _text(left_node), _text(right_node)
    if not left and right:
        left, right = right, left
        left_text, right_text = right_text, left_text
        literal, factor = _literal(left_node), _factor(left_node)
        operator = MIRROR.get(operator, operator)
    elif left and right and operator in ("<", "<="):
        left, right = right, left
        left_text, right_text = right_text, left_text
        operator = MIRROR[operator]

    if not left or left == right:
        return None
    if not right and not literal:
        return None

    return Comparison(
        operator=operator,
        left=left,
        right=right,
        left_text=left_text,
        right_text=right_text,
        literal=literal,
        factor=factor,
        type_name=(node.get("commonType") or {}).get("typeString", ""),
        function_id=function_id,
        line=_line(node),
        reverts_when_true=reverts,
        source=f"{left_text} {operator} {right_text or literal}",
    )


def _referenced(node: dict[str, Any]) -> tuple[int, ...]:
    """Declaration ids one side of a comparison denotes, in order and deduplicated.

    This is what the AST buys. `account.totalDebtUsd` resolves to the *field's* declaration
    and `deposits[msg.sender]` to the mapping's, with no scope rules to reimplement and no
    chance of matching the wrong contract's identically-named variable.

    Structure-aware rather than a blind walk over the subtree. A `MemberAccess` mentions its
    base as well as its member, so walking everything rendered the health check as
    `borrowLimitUsd + account >= totalDebtUsd + account` — the temporary struct reported as
    a quantity alongside the field that actually carries the meaning.
    """
    found: list[int] = []

    def collect(inner: Any) -> None:
        if not isinstance(inner, dict):
            return
        kind = inner.get("nodeType")

        if kind == "MemberAccess":
            # The member is the quantity; the base is the container holding it.
            identifier = inner.get("referencedDeclaration")
            if isinstance(identifier, int) and identifier > 0:
                _add(found, identifier)
            return
        if kind == "IndexAccess":
            # `deposits[msg.sender]` is about `deposits`. The key is an accessor, and
            # `msg.sender` is not a quantity this protocol has rules about.
            collect(inner.get("baseExpression"))
            return
        if kind == "Identifier":
            identifier = inner.get("referencedDeclaration")
            if isinstance(identifier, int) and identifier > 0:
                _add(found, identifier)
            return
        if kind in ("BinaryOperation", "UnaryOperation", "TupleExpression"):
            for key in (
                "leftExpression",
                "rightExpression",
                "subExpression",
                "components",
            ):
                value = inner.get(key)
                if isinstance(value, list):
                    for part in value:
                        collect(part)
                else:
                    collect(value)
            return
        # A call, a cast, a conditional: its value is computed, not denoted. Descending
        # into one attributes its arguments to the comparison, which they are not.

    collect(node)
    return tuple(found)


def _add(found: list[int], identifier: int) -> None:
    if identifier not in found:
        found.append(identifier)


def _literal(node: dict[str, Any]) -> str:
    if node.get("nodeType") == "Literal" and node.get("kind") == "number":
        return str(node.get("value", "")).replace("_", "")
    return ""


def _factor(node: dict[str, Any]) -> str:
    """The literal in `debt * 2` — the collateralisation ratio, when written that way."""
    if node.get("nodeType") != "BinaryOperation" or node.get("operator") != "*":
        return ""
    for side in ("leftExpression", "rightExpression"):
        inner = node.get(side)
        if isinstance(inner, dict) and (value := _literal(inner)):
            return value
    return ""


def _text(node: dict[str, Any]) -> str:
    """A readable rendering of an expression: `account.totalDebtUsd`, `debt * 2`.

    Reconstructed from the node, not sliced out of the file, so it stays available when the
    source is not. Only the shapes that appear in guards are rendered; anything else falls
    back to the node type, which is honest about not being readable.
    """
    kind = node.get("nodeType")
    if kind == "Identifier":
        return str(node.get("name", ""))
    if kind == "MemberAccess":
        return f"{_text(node.get('expression') or {})}.{node.get('memberName', '')}".lstrip(
            "."
        )
    if kind == "IndexAccess":
        return f"{_text(node.get('baseExpression') or {})}[…]"
    if kind == "Literal":
        return str(node.get("value", ""))
    if kind == "BinaryOperation":
        left = _text(node.get("leftExpression") or {})
        right = _text(node.get("rightExpression") or {})
        return f"{left} {node.get('operator', '')} {right}".strip()
    if kind == "FunctionCall":
        return f"{_text(node.get('expression') or {})}(…)"
    if kind == "ElementaryTypeNameExpression":
        return str((node.get("typeName") or {}).get("name", ""))
    if kind == "TupleExpression":
        parts = node.get("components") or []
        return f"({', '.join(_text(p) for p in parts if isinstance(p, dict))})"
    return ""


__all__ = [
    "COMPARISONS",
    "AstIndex",
    "Comparison",
    "Declaration",
    "SourceAst",
    "comparisons",
    "load",
    "walk",
]
