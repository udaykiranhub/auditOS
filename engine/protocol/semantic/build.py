"""Stage 12a — assembling the semantic graph.

Turns the solc AST into typed nodes and typed edges, so that every later question is a
*query over what this protocol contains* rather than a lookup in a table keyed by operation
name. That distinction is the whole point: a table gives two protocols with a `deposit` the
same answer, and a graph gives each of them the answer its own code supports.

```
SimpleLending ──declares──▶ borrow(uint256)
                                │
                    ┌───guards──┴──writes──┐
                    ▼                      ▼
             deposits ──constrains──▶ debt
                (×2, from `require(deposits[…] >= amount * 2)`)
```

**Edges carry the enforcement, not a resemblance.** `deposits constrains debt` exists here
because a reverting condition compares them, with the factor read off the multiplication and
the operator already negated for `if (…) revert`. No naming convention participates.

**Storage, struct fields and locals are all first-class.** A lending market's health check
compares two fields of an in-memory struct, and a withdrawal check compares two locals; a
graph that only admitted storage slots would be blind to both, which is exactly what the
earlier text-based passes were.

Locals are kept out of the node list unless a relation touches them — a large function has
dozens, and a graph where nine tenths of the nodes are temporaries is harder to read, not
richer.
"""

from __future__ import annotations

from typing import Any

from engine.core.models.code import CodeModel
from engine.core.models.evidence import Confidence, source_evidence
from engine.core.models.semantic import (
    EdgeKind,
    Fidelity,
    NodeKind,
    SemanticEdge,
    SemanticGraph,
    SemanticNode,
)
from engine.protocol.semantic import solc_ast
from engine.protocol.semantic.solc_ast import AstIndex, Comparison, SourceAst

DETECTOR = "semantic_graph"

#: Assignment operators, and what they do to the quantity on the left.
_EFFECT = {"+=": "increase", "-=": "decrease", "=": "set", "*=": "scale", "/=": "scale"}


def build(index: AstIndex, code: CodeModel) -> SemanticGraph:
    """The graph for the whole protocol.

    `code` supplies the `SolidityID`s that join this graph back to every other artifact, so
    a node found in the AST is addressable by the same key the parser and graph engine use.
    Nodes the AST knows about and `CodeModel` does not — struct fields, locals — carry an
    empty `solidity_id` rather than a fabricated one.
    """
    graph = SemanticGraph(
        fidelity=Fidelity.AST if index.available else Fidelity.TEXT,
        sources_total=len(code.sources) if hasattr(code, "sources") else 0,
        sources_with_ast=len(index.sources),
    )
    if not index.available:
        graph.notes.append(
            "No AST was available, so this graph carries no expression-level relations. "
            "An absent `constrains` edge means the compiler output was missing, not that "
            "the protocol enforces nothing."
        )
        return graph

    builder = _Builder(index, code, graph)
    builder.run()
    graph.nodes.sort(key=lambda n: n.id)
    graph.edges.sort(key=lambda e: (e.source, e.kind.value, e.target, e.order))
    return graph


class _Builder:
    """Accumulates nodes and edges. Split out so the passes can share resolution state."""

    def __init__(self, index: AstIndex, code: CodeModel, graph: SemanticGraph) -> None:
        self.index = index
        self.code = code
        self.graph = graph
        self._nodes: dict[str, SemanticNode] = {}
        self._edges: dict[str, SemanticEdge] = {}
        self._by_declaration: dict[int, str] = {}
        #: Modifier name → its graph node, across every contract. Populated in pass 1.
        self._modifier_nodes: dict[str, str] = {}

        #: Contract name → `SolidityID`. Names are unique per file in practice; where two
        #: files declare the same name the first wins and the second keeps an empty
        #: `solidity_id`, which is visible rather than silently wrong.
        self._contract_ids: dict[str, str] = {}
        for contract in code.contracts:
            self._contract_ids.setdefault(contract.name, contract.id)

        #: (contract name, function name) → `SolidityID`. Overloads share a key; the first
        #: is kept, and the graph node records the AST id so the two stay distinguishable.
        self._function_ids: dict[tuple[str, str], str] = {}
        for contract in code.contracts:
            for function in contract.functions:
                self._function_ids.setdefault((contract.name, function.name), function.id)

    # ── Driving ───────────────────────────────────────────────────────────────

    def run(self) -> None:
        for source in self.index.sources:
            self._declarations(source)
        for source in self.index.sources:
            self._bodies(source)
        self.graph.nodes = list(self._nodes.values())
        self.graph.edges = list(self._edges.values())

    # ── Pass 1: what exists ───────────────────────────────────────────────────

    def _declarations(self, source: SourceAst) -> None:
        for container in solc_ast.walk(source.root):
            kind = container.get("nodeType")
            if kind not in ("ContractDefinition", "StructDefinition"):
                continue
            owner = container.get("name", "")

            if kind == "ContractDefinition":
                self._contract(source, container, owner)

            for node in _children(container, "VariableDeclaration"):
                self._variable(source, node, owner, is_struct=kind == "StructDefinition")

            if kind == "ContractDefinition":
                for node in _children(container, "FunctionDefinition"):
                    self._function(source, node, owner)
                for node in _children(container, "ModifierDefinition"):
                    self._function(source, node, owner, modifier=True)
                    name = node.get("name", "")
                    if name:
                        self._modifier_nodes.setdefault(
                            name,
                            _node_id(NodeKind.FUNCTION, f"{source.path}:{owner}.{name}"),
                        )

    def _contract(self, source: SourceAst, node: dict[str, Any], name: str) -> None:
        contract_id = self._contract_ids.get(name, "")
        self._put(
            SemanticNode(
                id=_node_id(NodeKind.CONTRACT, contract_id or f"{source.path}:{name}"),
                kind=NodeKind.CONTRACT,
                name=name,
                qualified_name=name,
                contract_id=contract_id,
                solidity_id=contract_id,
                type_name=node.get("contractKind", "contract"),
                path=source.path,
                from_ast=True,
            )
        )
        for base in node.get("baseContracts") or []:
            parent = ((base or {}).get("baseName") or {}).get("name", "")
            if parent and parent in self._contract_ids:
                self._link(
                    _node_id(NodeKind.CONTRACT, contract_id or f"{source.path}:{name}"),
                    _node_id(NodeKind.CONTRACT, self._contract_ids[parent]),
                    EdgeKind.INHERITS,
                    detail=f"{name} is {parent}",
                    confidence=Confidence.DERIVED,
                    ref=contract_id,
                )

    def _variable(
        self, source: SourceAst, node: dict[str, Any], owner: str, *, is_struct: bool
    ) -> None:
        identifier = node.get("id")
        if not isinstance(identifier, int):
            return
        name = node.get("name", "")
        if not name:
            return

        is_state = bool(node.get("stateVariable"))
        if not is_state and not is_struct:
            # A local or parameter. Admitted only when a relation reaches it, which
            # `_touch` does on demand — a graph where most nodes are temporaries is harder
            # to read, not richer.
            return

        contract_id = self._contract_ids.get(owner, "")
        kind = NodeKind.STRUCT_FIELD if is_struct else NodeKind.STATE_VAR
        solidity_id = f"{contract_id}#{name}" if contract_id and is_state else ""
        self._put(
            SemanticNode(
                id=_node_id(kind, f"{source.path}:{owner}#{name}"),
                kind=kind,
                name=name,
                qualified_name=f"{owner}.{name}",
                contract_id=contract_id,
                solidity_id=solidity_id,
                type_name=(node.get("typeDescriptions") or {}).get("typeString", ""),
                path=source.path,
                visibility=node.get("visibility", ""),
                is_constant=node.get("mutability") in ("constant", "immutable"),
                from_ast=True,
            ),
            declaration=identifier,
        )

    def _function(
        self, source: SourceAst, node: dict[str, Any], owner: str, *, modifier: bool = False
    ) -> None:
        identifier = node.get("id")
        if not isinstance(identifier, int):
            return
        name = node.get("name") or node.get("kind", "")
        contract_id = self._contract_ids.get(owner, "")
        visibility = node.get("visibility", "")

        self._put(
            SemanticNode(
                id=_node_id(NodeKind.FUNCTION, f"{source.path}:{owner}.{name}"),
                kind=NodeKind.MODIFIER if modifier else NodeKind.FUNCTION,
                name=name,
                qualified_name=f"{owner}.{name}",
                contract_id=contract_id,
                solidity_id=self._function_ids.get((owner, name), ""),
                path=source.path,
                visibility=visibility,
                mutability=node.get("stateMutability", ""),
                is_entrypoint=visibility in ("public", "external") and not modifier,
                modifier_count=len(node.get("modifiers") or []),
                from_ast=True,
            ),
            declaration=identifier,
        )
        if contract_id:
            self._link(
                _node_id(NodeKind.CONTRACT, contract_id),
                _node_id(NodeKind.FUNCTION, f"{source.path}:{owner}.{name}"),
                EdgeKind.DECLARES,
                confidence=Confidence.DERIVED,
                ref=contract_id,
            )

    # ── Pass 2: what happens ──────────────────────────────────────────────────

    def _bodies(self, source: SourceAst) -> None:
        for container in solc_ast.walk(source.root):
            if container.get("nodeType") != "ContractDefinition":
                continue
            owner = container.get("name", "")

            for node in _children(container, "FunctionDefinition") + _children(
                container, "ModifierDefinition"
            ):
                name = node.get("name") or node.get("kind", "")
                function = _node_id(NodeKind.FUNCTION, f"{source.path}:{owner}.{name}")
                if function not in self._nodes:
                    continue
                self._accesses(node, function, source)
                self._calls(node, function, source)

            for comparison in solc_ast.comparisons(source):
                self._constraint(comparison, source)

            self._inherit_modifier_guards(container, source, owner)

    def _inherit_modifier_guards(
        self, container: dict[str, Any], source: SourceAst, owner: str
    ) -> None:
        """A modifier's guards are guards on every function that applies it.

        `onlyWhenSolvent` checks nothing about the modifier — it checks something about the
        function it wraps. Attributing the condition only to the modifier left the guard
        invisible on the eighty functions that actually run it, which is where an agent
        looks.
        """
        # Modifier names resolve across the whole repository, not just this contract:
        # `onlyOwner` is almost never declared where it is used, so a same-container lookup
        # finds nothing on any OpenZeppelin-shaped protocol.
        by_name = self._modifier_nodes
        if not by_name:
            return

        for node in _children(container, "FunctionDefinition"):
            name = node.get("name") or node.get("kind", "")
            function = _node_id(NodeKind.FUNCTION, f"{source.path}:{owner}.{name}")
            if function not in self._nodes:
                continue

            for invocation in node.get("modifiers") or []:
                applied = ((invocation or {}).get("modifierName") or {}).get("name", "")
                modifier = by_name.get(applied)
                if modifier is None:
                    continue
                for edge in list(self._edges.values()):
                    if edge.source != modifier or edge.kind is not EdgeKind.GUARDS:
                        continue
                    self._link(
                        function,
                        edge.target,
                        EdgeKind.GUARDS,
                        detail=edge.detail,
                        operator=edge.operator,
                        confidence=edge.confidence,
                        ref=self._nodes[function].solidity_id,
                    )

    def _accesses(
        self, node: dict[str, Any], function: str, source: SourceAst
    ) -> None:
        """State writes with their delta, and state reads.

        The delta is what makes a write legible: `totalDeposits += amount` says the total
        rises with the deposit, while "writes totalDeposits" says only that it changed.
        """
        order = 0
        for inner in solc_ast.walk(node):
            kind = inner.get("nodeType")

            if kind == "Assignment":
                order += 1
                target = inner.get("leftHandSide") or {}
                right_node = inner.get("rightHandSide") or {}
                effect = _effect_of(inner.get("operator", "="), right_node)
                right = solc_ast._text(right_node)
                for declaration in solc_ast._referenced(target):
                    node_id = self._touch(declaration, source)
                    if node_id is None:
                        continue
                    self._link(
                        function,
                        node_id,
                        EdgeKind.WRITES,
                        detail=(
                            f"{solc_ast._text(target)} "
                            f"{inner.get('operator', '=')} {right}"
                        ),
                        operator=effect,
                        order=order,
                        confidence=Confidence.DERIVED,
                        ref=self._nodes[function].solidity_id,
                    )
                    # Dataflow, one hop: the value written came from this expression.
                    for origin in solc_ast._referenced(inner.get("rightHandSide") or {}):
                        source_id = self._touch(origin, source)
                        if source_id is not None and source_id != node_id:
                            self._link(
                                source_id,
                                node_id,
                                EdgeKind.DERIVES_FROM,
                                detail=right,
                                order=order,
                                confidence=Confidence.DERIVED,
                                ref=self._nodes[function].solidity_id,
                            )

            elif kind == "UnaryOperation" and inner.get("operator") in ("++", "--"):
                # `nextTransferId++` is a state write, and the only one for a counter. It
                # is a `UnaryOperation`, not an `Assignment`, so a pass that looked only at
                # assignments recorded no writer at all — leaving every id counter in the
                # protocol with no direction, no writer and therefore no role.
                order += 1
                operand = inner.get("subExpression") or {}
                increments = inner.get("operator") == "++"
                for declaration in solc_ast._referenced(operand):
                    node_id = self._touch(declaration, source)
                    if node_id is None:
                        continue
                    self._link(
                        function,
                        node_id,
                        EdgeKind.WRITES,
                        detail=f"{solc_ast._text(operand)}{inner.get('operator')}",
                        operator="increase" if increments else "decrease",
                        order=order,
                        confidence=Confidence.DERIVED,
                        ref=self._nodes[function].solidity_id,
                    )

            elif kind in ("Identifier", "MemberAccess"):
                referenced = inner.get("referencedDeclaration")
                if not isinstance(referenced, int):
                    continue
                resolved = self.index.resolve(referenced)
                if resolved is None or resolved.kind not in ("state", "field"):
                    continue
                node_id = self._touch(referenced, source)
                if node_id is not None:
                    self._link(
                        function,
                        node_id,
                        EdgeKind.READS,
                        confidence=Confidence.DERIVED,
                        ref=self._nodes[function].solidity_id,
                    )

    def _calls(self, node: dict[str, Any], function: str, source: SourceAst) -> None:
        order = 0
        for inner in solc_ast.walk(node):
            if inner.get("nodeType") != "FunctionCall":
                continue
            expression = inner.get("expression") or {}
            name = solc_ast._text(expression)
            if not name or name in ("require", "assert", "revert"):
                continue
            order += 1

            declaration = expression.get("referencedDeclaration")
            callee = (
                self._touch(declaration, source)
                if isinstance(declaration, int)
                else None
            )
            if callee is None:
                callee = self._external(name)
            self._link(
                function,
                callee,
                EdgeKind.CALLS,
                detail=f"{name}(…)",
                order=order,
                confidence=Confidence.DERIVED,
                ref=self._nodes[function].solidity_id,
            )

    def _constraint(self, comparison: Comparison, source: SourceAst) -> None:
        """`deposits constrains debt` — the protocol enforcing a rule on itself.

        The strongest relation this graph carries. Both operands are resolved by declaration
        id, the operator is already negated for `if (…) revert`, and the factor is read off
        the multiplication, so the edge states the rule rather than the guard's raw text.
        """
        declaration = self.index.resolve(comparison.function_id)
        function = None
        if declaration is not None:
            function = _node_id(
                NodeKind.FUNCTION,
                f"{declaration.path}:{declaration.contract}.{declaration.name}",
            )
            if function not in self._nodes:
                function = None

        rule = comparison.source
        if comparison.factor:
            rule = f"{comparison.left_text} {comparison.operator} {comparison.right_text}"

        for left in comparison.left:
            bound = self._touch(left, source)
            if bound is None:
                continue

            if function is not None:
                self._link(
                    function,
                    bound,
                    EdgeKind.GUARDS,
                    detail=rule,
                    operator=comparison.operator,
                    confidence=Confidence.DERIVED,
                    ref=self._nodes[function].solidity_id,
                )

            for right in comparison.right:
                constrained = self._touch(right, source)
                if constrained is None or constrained == bound:
                    continue
                self._link(
                    bound,
                    constrained,
                    EdgeKind.CONSTRAINS,
                    detail=rule,
                    operator=comparison.operator,
                    function_id=self._nodes[function].solidity_id if function else "",
                    confidence=Confidence.DERIVED,
                    ref=self._nodes[function].solidity_id if function else "",
                )

    # ── Node and edge bookkeeping ─────────────────────────────────────────────

    def _touch(self, declaration: int | None, source: SourceAst) -> str | None:
        """The node for a declaration, minting a `LOCAL` on demand.

        Locals are admitted only when a relation reaches them. `withdrawAmount > balance`
        makes both worth a node; the other forty temporaries in the same function are not.
        """
        if not isinstance(declaration, int):
            return None
        if declaration in self._by_declaration:
            return self._by_declaration[declaration]

        resolved = self.index.resolve(declaration)
        if resolved is None:
            return None
        if resolved.node_type in ("FunctionDefinition", "ModifierDefinition"):
            node_id = _node_id(
                NodeKind.FUNCTION, f"{resolved.path}:{resolved.contract}.{resolved.name}"
            )
            return node_id if node_id in self._nodes else None

        node_id = _node_id(NodeKind.LOCAL, f"{resolved.path}:{declaration}:{resolved.name}")
        self._put(
            SemanticNode(
                id=node_id,
                kind=NodeKind.LOCAL,
                name=resolved.name,
                qualified_name=f"{resolved.contract}.{resolved.name}"
                if resolved.contract
                else resolved.name,
                contract_id=self._contract_ids.get(resolved.contract, ""),
                type_name=resolved.type_name,
                path=resolved.path,
                is_constant=resolved.is_constant,
                from_ast=True,
            ),
            declaration=declaration,
        )
        return node_id

    def _external(self, name: str) -> str:
        node_id = _node_id(NodeKind.EXTERNAL, name)
        if node_id not in self._nodes:
            self._put(
                SemanticNode(
                    id=node_id, kind=NodeKind.EXTERNAL, name=name, from_ast=True
                )
            )
        return node_id

    def _put(self, node: SemanticNode, declaration: int | None = None) -> None:
        self._nodes.setdefault(node.id, node)
        if declaration is not None:
            self._by_declaration.setdefault(declaration, node.id)

    def _link(
        self,
        source: str,
        target: str,
        kind: EdgeKind,
        *,
        detail: str = "",
        operator: str = "",
        order: int = 0,
        function_id: str = "",
        confidence: Confidence = Confidence.DERIVED,
        ref: str = "",
    ) -> None:
        identifier = f"edge:{kind.value}:{source}->{target}:{detail[:60]}"
        if identifier in self._edges:
            return
        self._edges[identifier] = SemanticEdge(
            id=identifier,
            source=source,
            target=target,
            kind=kind,
            detail=detail,
            operator=operator,
            order=order,
            function_id=function_id,
            confidence=confidence,
            evidence=[source_evidence(ref, detail or kind.value, detector=DETECTOR)]
            if ref
            else [],
        )


def _effect_of(operator: str, right: dict[str, Any]) -> str:
    """What an assignment does to the quantity on the left.

    `+=` and `-=` say it outright. A plain `=` usually does not — but
    `balanceOf[from] = balance - amount` is a decrease, and reading it as a replacement made
    every solmate-style ERC20 balance look like a value that only ever rises. The direction
    is in the arithmetic on the right, so that is where it is read from.
    """
    if operator in _EFFECT and operator != "=":
        return _EFFECT[operator]
    if right.get("nodeType") == "BinaryOperation":
        if right.get("operator") == "-":
            return "decrease"
        if right.get("operator") == "+":
            return "increase"
    return "set"


def _children(container: dict[str, Any], node_type: str) -> list[dict[str, Any]]:
    """Direct members of a contract or struct, not everything nested inside it.

    `walk` would return a function's locals alongside the contract's storage, and a nested
    struct's fields alongside the parent's.
    """
    return [
        node
        for node in (container.get("nodes") or [])
        if isinstance(node, dict) and node.get("nodeType") == node_type
    ]


def _node_id(kind: NodeKind, key: str) -> str:
    return f"node:{kind.value}:{key}"


__all__ = ["DETECTOR", "build"]
