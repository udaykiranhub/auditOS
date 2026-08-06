"""The Graph Engine entry point (SPEC §13).

```
CodeModel  →  GraphModel
```

**Failure — Fatal.** A protocol we cannot make navigable cannot be audited.

Build order is fixed by SPEC and must not be rearranged: **inheritance (+C3) → storage →
calls → imports**. Calls resolve through the MRO, so inheritance has to be correct and
complete before a single call edge is drawn.
"""

from __future__ import annotations

from pathlib import Path

from engine.core.artifacts import save_artifact
from engine.core.errors import FatalError
from engine.core.models.code import CodeModel, Contract
from engine.core.models.graph import (
    Edge,
    GraphModel,
    Node,
    NodeKind,
    Unresolved,
    ViewSummary,
)
from engine.graphs import imports as import_graph
from engine.graphs import nodes as node_builder
from engine.graphs import storage as storage_graph
from engine.graphs import tokens as token_graph
from engine.graphs.calls import CallResolver
from engine.graphs.inheritance import Linearizer, flatten, inheritance_edges
from engine.graphs.query import GraphQuery
from engine.graphs.select import select_contracts
from engine.graphs.storage import reentrancy_candidates
from engine.graphs.validate import GraphCode, validate
from engine.graphs.views import VIEWS

ARTIFACT_NAME = "graph"


def build_graph(code: CodeModel) -> GraphModel:
    """Turn a `CodeModel` into the Code Property Graph."""
    if not code.contracts and not any(source.free_functions for source in code.sources):
        raise FatalError(
            "The CodeModel contains no contracts to graph.",
            code=GraphCode.NO_CODE,
            hint="Run the parser first; a run with zero contracts is not auditable.",
        )

    included, unresolved, notes = select_contracts(code)
    contracts = {c.id: c for c in code.contracts if c.id in included}

    # 1. Inheritance + C3 ─────────────────────────────────────────────────────
    linearizer = Linearizer(contracts)
    linearization = {cid: linearizer.linearize(cid) for cid in sorted(contracts)}
    unresolved.extend(linearizer.unresolved)

    flattened = {cid: flatten(mro, contracts) for cid, mro in linearization.items()}

    # 2. Nodes ────────────────────────────────────────────────────────────────
    nodes, edges = node_builder.build_nodes(code, included)
    known = {node.id for node in nodes}

    inherit_edges, override_chains, inherit_unresolved = inheritance_edges(
        contracts, linearization, flattened
    )
    edges.extend(inherit_edges)
    unresolved.extend(inherit_unresolved)

    # 3. Storage ──────────────────────────────────────────────────────────────
    state_var_ids = {node.id for node in nodes if node.kind is NodeKind.STATE_VAR}
    edges.extend(storage_graph.storage_edges(contracts, state_var_ids))

    # 4. Calls — depends on 1 ─────────────────────────────────────────────────
    resolver = CallResolver(code, included, linearization, flattened)
    call_edges, call_unresolved = resolver.resolve_all()
    edges.extend(call_edges)
    unresolved.extend(call_unresolved)

    # 5. Token flow ───────────────────────────────────────────────────────────
    edges.extend(token_graph.token_edges(contracts, known))

    # 6. Imports — last, lowest value ─────────────────────────────────────────
    files = {node.id for node in nodes if node.kind is NodeKind.FILE}
    file_edges, cycles = import_graph.import_edges(code, files)
    edges.extend(file_edges)

    edges = _prune(edges, known)
    unresolved.extend(_assembly_gaps(contracts))

    graph = GraphModel(
        code_content_hash=code.content_hash,
        nodes=sorted(nodes, key=lambda node: node.id),
        edges=sorted(_dedupe(edges), key=lambda edge: edge.key()),
        linearization=linearization,
        override_chains=override_chains,
        import_cycles=cycles,
        unresolved=sorted(unresolved, key=lambda u: (u.reason, u.function or "", u.line)),
        notes=notes,
    )

    # 7. Reentrancy candidates — needs the finished call graph to trace entrypoints ────
    query = GraphQuery(graph)
    graph.reentrancy_candidates = reentrancy_candidates(query, contracts)

    graph.views = _summarize_views(query)
    graph.notes.extend(validate(graph))
    graph.notes.extend(_coverage_notes(graph))

    return graph.with_content_hash()


def build_and_save(code: CodeModel, run_dir: Path) -> tuple[GraphModel, Path]:
    """`build_graph` + persist to ``run/<run_id>/artifacts/graph.json``."""
    graph = build_graph(code)
    return graph, save_artifact(graph, run_dir, ARTIFACT_NAME)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _assembly_gaps(contracts: dict[str, Contract]) -> list[Unresolved]:
    """Inline assembly is parsed but not interpreted (SPEC §12.2).

    `sload`/`sstore` in Yul is a state access with no READS/WRITES edge behind it, and a
    `delegatecall` in Yul — the entire body of every EIP-1967 proxy — is invisible here.
    Recording the gap is the difference between a graph with known blind spots and a graph
    that is quietly incomplete. Limited to in-scope code, which is what gets audited.
    """
    return [
        Unresolved(
            reason="UNRESOLVED_ASSEMBLY_ACCESS",
            function=function.id,
            detail="inline assembly is not interpreted; storage and calls made in Yul "
            "have no edges",
            line=function.line_start,
        )
        for contract in contracts.values()
        if contract.in_scope
        for function in (*contract.functions, *contract.modifiers)
        if function.has_assembly
    ]


def _prune(edges: list[Edge], known: set[str]) -> list[Edge]:
    """Drop edges whose endpoints are outside the selected subgraph.

    Selection is a closure over in-scope code, so a dependency contract can legitimately
    call something we chose not to graph. That is a pruned edge, not a bug — the validator
    would otherwise reject the whole artifact for it.
    """
    return [edge for edge in edges if edge.source in known and edge.target in known]


def _dedupe(edges: list[Edge]) -> list[Edge]:
    """Collapse identical edges. Two calls on different lines stay distinct — the line is
    part of the key, and CEI analysis needs each call site."""
    seen: set[tuple[str, str, str, int, int, str]] = set()
    out: list[Edge] = []
    for edge in edges:
        key = edge.key()
        if key not in seen:
            seen.add(key)
            out.append(edge)
    return out


def _summarize_views(query: GraphQuery) -> dict[str, ViewSummary]:
    summaries: dict[str, ViewSummary] = {}
    for name in sorted(VIEWS):
        edges = query.view(name)
        touched = {edge.source for edge in edges} | {edge.target for edge in edges}
        summaries[name] = ViewSummary(
            kinds=sorted(VIEWS[name]), nodes=len(touched), edges=len(edges)
        )
    return summaries


def _coverage_notes(graph: GraphModel) -> list[str]:
    """State plainly what the graph could not see. Silence here reads as completeness."""
    notes: list[str] = []
    by_reason: dict[str, int] = {}
    for item in graph.unresolved:
        by_reason[item.reason] = by_reason.get(item.reason, 0) + 1

    if delegatecalls := by_reason.get("UNRESOLVED_DELEGATECALL"):
        notes.append(
            f"{delegatecalls} delegatecall sites target a runtime value; the implementation's "
            "code is NOT in this graph — proxy behaviour is unmodelled"
        )
    if external := by_reason.get("UNRESOLVED_EXTERNAL_CALL"):
        notes.append(f"{external} external calls have an untypeable receiver → UNKNOWN_EXTERNAL")
    if parents := by_reason.get("UNRESOLVED_PARENT"):
        notes.append(
            f"{parents} contracts inherit a parent that is not in the repository; their "
            "inherited members are invisible to call resolution"
        )

    assembly = [node for node in graph.nodes if node.has_assembly]
    if assembly:
        # `CodeModel` records that a function contains assembly, not what the assembly does.
        # An `sstore` in Yul is a state write this graph does not have an edge for.
        notes.append(
            f"{len(assembly)} functions contain inline assembly; storage accessed via "
            "sload/sstore in Yul is not represented as READS/WRITES edges "
            "(UNRESOLVED_ASSEMBLY_ACCESS)"
        )
    return notes


__all__ = ["ARTIFACT_NAME", "GraphModel", "GraphQuery", "Node", "build_and_save", "build_graph"]
