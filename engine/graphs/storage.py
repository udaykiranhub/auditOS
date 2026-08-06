"""Storage read/write graph (SPEC §13.3) and the reentrancy candidates it makes possible.

Bipartite: `Function → StateVar`, labelled read / write. The scope-awareness that makes
this correct (a shadowed local must not count as a state access) already happened in the
parser; this module consumes `Function.accesses`, which is that resolution's output.

The pre-computed candidates are the point of the whole exercise. SPEC §13.2:

> Any path from an entrypoint to `UNTRUSTED_EXTERNAL` and *back* into a state write is a
> reentrancy candidate and must be computed here, deterministically, and handed to the
> agent as a pre-computed candidate path rather than left for the model to find by reading
> code. Deterministic graph work is free and reliable; asking a model to do graph traversal
> in its head is expensive and unreliable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from engine.core.models.code import AccessKind, Contract, Function
from engine.core.models.graph import (
    CALL_KINDS,
    SENTINELS,
    UNKNOWN_EXTERNAL,
    UNTRUSTED_EXTERNAL,
    Edge,
    EdgeKind,
    NodeKind,
    ReentrancyCandidate,
)
from engine.graphs.nodes import _error_id, _event_id

if TYPE_CHECKING:  # avoids a cycle: query imports nothing from here, but this is type-only
    from engine.graphs.query import GraphQuery

#: Modifier names that conventionally take a reentrancy lock. Name-based and therefore
#: evidence, not proof — it is recorded on the candidate so the agent can check whether the
#: guard actually covers the path, and never used to drop a candidate.
REENTRANCY_GUARDS = ("nonreentrant", "nonreentrantreadonly", "lock", "noreentry")

#: Maximum entrypoint paths reported per vulnerable function. A helper called from forty
#: entrypoints yields forty near-identical candidates; the first few carry the signal.
MAX_PATHS_PER_FUNCTION = 4


def storage_edges(contracts: dict[str, Contract], state_var_ids: set[str]) -> list[Edge]:
    """READS / WRITES, plus EMITS and REVERTS_WITH — everything a body touches by name."""
    edges: list[Edge] = []
    for contract_id in sorted(contracts):
        contract = contracts[contract_id]
        events = {event.name: _event_id(contract, event.name) for event in contract.events}
        errors = {error.name: _error_id(contract, error.name) for error in contract.errors}

        for function in (*contract.functions, *contract.modifiers):
            for access in function.accesses:
                if access.state_var_id not in state_var_ids:
                    continue  # declared in a parent we did not select
                edges.append(
                    Edge(
                        source=function.id,
                        target=access.state_var_id,
                        kind=EdgeKind.READS if access.kind is AccessKind.READ else EdgeKind.WRITES,
                        line=access.line,
                        order=access.order,
                        text=access.name,
                    )
                )
            for name in function.emits:
                target = events.get(name)
                if target:
                    edges.append(
                        Edge(source=function.id, target=target, kind=EdgeKind.EMITS, text=name)
                    )
            for name in function.reverts:
                target = errors.get(name)
                if target:
                    edges.append(
                        Edge(
                            source=function.id,
                            target=target,
                            kind=EdgeKind.REVERTS_WITH,
                            text=name,
                        )
                    )
    return edges


# ── Reentrancy candidates ─────────────────────────────────────────────────────


def external_call_edges(query: GraphQuery, function_id: str) -> list[Edge]:
    """The outgoing edges of `function_id` that hand control to code we do not control.

    Computed from the **resolved** graph rather than from `CallSite.kind`, and that
    distinction is the whole point. `_balances[sender].sub(amount)` parses as a member call
    and looks external; once `using SafeMath for uint256` is resolved it is a library call
    that the compiler inlines. Reading the raw kinds turns every SafeMath operation into a
    reentrancy candidate — which is what happens on a real protocol before this fix.
    """
    external: list[Edge] = []
    for edge in query.graph.edges:
        if edge.source != function_id or edge.kind not in CALL_KINDS:
            continue
        # A `staticcall` cannot write, so nothing it reaches can reenter and mutate state.
        if edge.kind is EdgeKind.STATICCALLS:
            continue
        if edge.target in SENTINELS:
            external.append(edge)
            continue

        target = query.nodes.get(edge.target)
        source = query.nodes.get(function_id)
        if target is None or source is None or target.contract_id == source.contract_id:
            continue
        owner = query.nodes.get(target.contract_id or "")
        if owner is not None and owner.kind is NodeKind.LIBRARY:
            continue  # a library call is inlined or delegated to code that is right here
        # Solidity compiles an external `view`/`pure` call to STATICCALL, so the callee
        # cannot reenter into anything that writes. `require(factory.isPool(x))` has the
        # shape of a dangerous call and none of the danger.
        if target.mutability in ("view", "pure"):
            continue
        if target.visibility in ("external", "public"):
            external.append(edge)
    return external


def reentrancy_candidates(
    query: GraphQuery, contracts: dict[str, Contract]
) -> list[ReentrancyCandidate]:
    """Every `entrypoint → … → write-after-external-call`, as a concrete path.

    Restricted to in-scope functions: SPEC §9.3 keeps dependency code in the graph so
    inheritance and calls resolve, but it is never audited, and OpenZeppelin's `_transfer`
    appearing here would bury the protocol's own findings.
    """
    candidates: list[ReentrancyCandidate] = []
    guards = {
        function.id: _guard_of(function)
        for contract in contracts.values()
        for function in contract.functions
    }

    outgoing_writes = _writes_by_function(query)

    for contract_id in sorted(contracts):
        contract = contracts[contract_id]
        if not contract.in_scope:
            continue

        for function in contract.functions:
            external = external_call_edges(query, function.id)
            if not external:
                continue
            first = min(external, key=_danger_first)
            if first.order < 0:
                continue

            writes = sorted(
                {
                    target
                    for target, order in outgoing_writes.get(function.id, ())
                    if order > first.order
                }
            )
            if not writes:
                continue

            paths = query.entrypoint_paths(function.id, MAX_PATHS_PER_FUNCTION) or [
                [function.id]
            ]
            for path in paths:
                guard = next((guards.get(fid) for fid in path if guards.get(fid)), None)
                candidates.append(
                    ReentrancyCandidate(
                        entrypoint=path[0],
                        function=function.id,
                        path=path,
                        external_target=first.target,
                        external_call=first.text,
                        external_line=first.line,
                        writes_after=writes,
                        guard=guard,
                        # `.call` reaches arbitrary code and the callee chooses to reenter;
                        # a typed call to a peer contract may well be trusted. Same shape,
                        # different prior — the agent needs to know which it is looking at.
                        confidence="high"
                        if first.target == UNTRUSTED_EXTERNAL
                        else "medium",
                    )
                )

    candidates.sort(key=lambda c: (c.function, c.entrypoint, c.external_line))
    return candidates


def _danger_first(edge: Edge) -> tuple[int, int]:
    """Earliest call wins; on a tie, report the most dangerous target.

    One call site produces several edges — `IRegistry(r).f()` yields both the resolved
    signature and an `UNKNOWN_EXTERNAL` marker, at the same body order. Reporting whichever
    sorted first would sometimes name the sentinel and sometimes the function for no
    discernible reason.
    """
    order = edge.order if edge.order >= 0 else 1 << 30
    rank = {UNTRUSTED_EXTERNAL: 0, UNKNOWN_EXTERNAL: 2}.get(edge.target, 1)
    return (order, rank)


def _writes_by_function(query: GraphQuery) -> dict[str, list[tuple[str, int]]]:
    writes: dict[str, list[tuple[str, int]]] = {}
    for edge in query.graph.edges:
        if edge.kind is EdgeKind.WRITES:
            writes.setdefault(edge.source, []).append((edge.target, edge.order))
    return writes


def _guard_of(function: Function) -> str | None:
    for name in function.modifiers:
        if name.lower().replace("_", "") in REENTRANCY_GUARDS:
            return name
    return None
