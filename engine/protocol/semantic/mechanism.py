"""The per-contract view: what each function checks, changes, calls and moves.

```
LendingPool
  borrow(address,uint256,address)                                actor: any caller
    conditions      account.borrowLimitUsd >= account.totalDebtUsd
    state changes   _positions[…].borrowShares += shares          ↑
                    reserve.totalBorrowShares += shares           ↑
    reads           _positions, _reserves
    external        IERC20(…).safeTransfer(…)
```

A projection over `SemanticGraph`, computed here rather than in the browser so the CLI, the
API and the UI cannot disagree about what a contract does. Nothing is re-derived: every
field is a set of edges filtered and grouped.

The shape follows the question an auditor asks of a contract — *what must be true to enter
this function, what does it change, and what does it reach* — rather than the shape the
graph happens to store.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from engine.core.models.semantic import EdgeKind, NodeKind, SemanticGraph, SemanticNode


class StateChange(BaseModel):
    """One write, with its direction. `totalDeposits += amount`, not "writes totalDeposits"."""

    model_config = ConfigDict(extra="forbid")

    variable: str
    expression: str
    effect: str  # increase | decrease | set | scale
    order: int = 0


class FunctionMechanism(BaseModel):
    """One function, as the questions an auditor asks of it."""

    model_config = ConfigDict(extra="forbid")

    name: str
    qualified_name: str
    solidity_id: str = ""
    visibility: str = ""
    mutability: str = ""
    is_entrypoint: bool = False
    modifier_count: int = 0

    conditions: list[str] = Field(default_factory=list)
    """Comparisons that must hold to proceed, normalised — an `if (…) revert` appears as the
    rule it establishes, not as the condition that triggers the revert."""

    state_changes: list[StateChange] = Field(default_factory=list)
    reads: list[str] = Field(default_factory=list)
    internal_calls: list[str] = Field(default_factory=list)
    external_calls: list[str] = Field(default_factory=list)
    """Calls that hand control outside this contract. Where every reentrancy question
    starts, and the reason they are separated from internal ones."""

    writes_after_external_call: list[str] = Field(default_factory=list)
    """State written at a position after control first left. A candidate, not a verdict."""


class Relationship(BaseModel):
    """`deposits ──must cover 2×──▶ debt`, with where it is enforced."""

    model_config = ConfigDict(extra="forbid")

    left: str
    right: str
    operator: str
    rule: str
    enforced_in: str = ""


class ContractMechanism(BaseModel):
    """One contract, end to end."""

    model_config = ConfigDict(extra="forbid")

    name: str
    contract_id: str
    path: str = ""
    kind: str = "contract"

    inherits: list[str] = Field(default_factory=list)
    state: list[dict[str, str]] = Field(default_factory=list)
    functions: list[FunctionMechanism] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)

    @property
    def entrypoints(self) -> int:
        return sum(1 for f in self.functions if f.is_entrypoint)


def contracts(graph: SemanticGraph) -> list[ContractMechanism]:
    """Every contract in the graph, in name order."""
    by_id = {node.id: node for node in graph.nodes}
    return sorted(
        (_one(graph, by_id, node) for node in graph.of_kind(NodeKind.CONTRACT)),
        key=lambda c: c.name,
    )


def _one(
    graph: SemanticGraph, by_id: dict[str, SemanticNode], contract: SemanticNode
) -> ContractMechanism:
    functions = [
        by_id[edge.target]
        for edge in graph.out_edges(contract.id, EdgeKind.DECLARES)
        if edge.target in by_id
    ]

    state = sorted(
        (
            {"name": node.name, "type": node.type_name, "visibility": node.visibility}
            for node in graph.of_kind(NodeKind.STATE_VAR)
            if node.contract_id == contract.contract_id and contract.contract_id
        ),
        key=lambda item: item["name"],
    )

    relationships = [
        Relationship(
            left=by_id[edge.source].qualified_name,
            right=by_id[edge.target].qualified_name,
            operator=edge.operator,
            rule=edge.detail,
            enforced_in=edge.function_id.rpartition(":")[2],
        )
        for edge in graph.edges
        if edge.kind is EdgeKind.CONSTRAINS
        and edge.source in by_id
        and edge.target in by_id
        and contract.contract_id
        and contract.contract_id
        in (by_id[edge.source].contract_id, by_id[edge.target].contract_id)
    ]

    depends: set[str] = set()
    for function in functions:
        for edge in graph.out_edges(function.id, EdgeKind.CALLS):
            target = by_id.get(edge.target)
            if target is not None and target.kind is NodeKind.EXTERNAL:
                depends.add(target.name.split("(")[0])

    return ContractMechanism(
        name=contract.name,
        contract_id=contract.contract_id or contract.id,
        path=contract.path,
        kind=contract.type_name or "contract",
        inherits=sorted(
            by_id[e.target].name
            for e in graph.out_edges(contract.id, EdgeKind.INHERITS)
            if e.target in by_id
        ),
        state=state,
        functions=sorted(
            (_mechanism(graph, by_id, node) for node in functions),
            # Entry points first: they are where a reader starts, and an internal helper is
            # only interesting once you know which entrypoint reaches it.
            key=lambda f: (not f.is_entrypoint, f.name),
        ),
        relationships=sorted(relationships, key=lambda r: (r.left, r.right)),
        depends_on=sorted(depends)[:20],
    )


def _mechanism(
    graph: SemanticGraph, by_id: dict[str, SemanticNode], function: SemanticNode
) -> FunctionMechanism:
    external: list[tuple[int, str]] = []
    internal: list[str] = []
    for edge in graph.out_edges(function.id, EdgeKind.CALLS):
        target = by_id.get(edge.target)
        if target is not None and target.kind is NodeKind.EXTERNAL:
            if not _diagnostic(target.name):
                external.append((edge.order, edge.detail))
        else:
            internal.append(edge.detail)

    writes = [
        StateChange(
            variable=by_id[edge.target].name if edge.target in by_id else "",
            expression=edge.detail,
            effect=edge.operator or "set",
            order=edge.order,
        )
        for edge in sorted(
            graph.out_edges(function.id, EdgeKind.WRITES), key=lambda e: e.order
        )
        if edge.target in by_id
    ]

    first_external = min((order for order, _ in external), default=None)
    after = (
        [w.variable for w in writes if w.order > first_external]
        if first_external is not None
        else []
    )

    return FunctionMechanism(
        name=function.name,
        qualified_name=function.qualified_name,
        solidity_id=function.solidity_id,
        visibility=function.visibility,
        mutability=function.mutability,
        is_entrypoint=function.is_entrypoint,
        modifier_count=function.modifier_count,
        conditions=sorted(
            {e.detail for e in graph.out_edges(function.id, EdgeKind.GUARDS) if e.detail}
        ),
        state_changes=writes,
        reads=sorted(
            {
                by_id[e.target].name
                for e in graph.out_edges(function.id, EdgeKind.READS)
                if e.target in by_id
            }
        ),
        internal_calls=sorted(set(internal))[:12],
        external_calls=sorted({detail for _, detail in external})[:12],
        writes_after_external_call=sorted(set(after)),
    )


def _diagnostic(name: str) -> bool:
    """Events, custom errors and type casts are `FunctionCall` nodes and are not calls out."""
    head = name.split("(")[0].strip()
    return not head or head[:1].isupper()


__all__ = ["ContractMechanism", "FunctionMechanism", "Relationship", "StateChange", "contracts"]
