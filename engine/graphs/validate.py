"""Graph integrity checks, run before the artifact is written.

**"No orphan nodes" is not one of them, deliberately.** A library nobody calls, an interface
declared for an external protocol, an unused custom error — all legitimate, all orphans. A
validator that rejects them fails on every real repository and teaches you to disable it.

What *is* checked is the class of defect that makes downstream analysis quietly wrong: an
edge pointing at a node that does not exist, two nodes sharing an ID, an unsorted artifact
(which breaks determinism), or a candidate path referencing something absent.
"""

from __future__ import annotations

from engine.core.errors import FatalError
from engine.core.models.graph import SENTINELS, GraphModel

MAX_REPORTED = 5


class GraphCode:
    """Stable failure codes — part of the CLI/API contract."""

    DANGLING_EDGE = "GRAPH_DANGLING_EDGE"
    DUPLICATE_NODE = "GRAPH_DUPLICATE_NODE"
    UNSORTED = "GRAPH_UNSORTED"
    EMPTY = "GRAPH_EMPTY"
    NO_CODE = "GRAPH_NO_CODE"


def validate(graph: GraphModel) -> list[str]:
    """Raise `FatalError` on structural corruption; return notes for the survivable rest."""
    notes: list[str] = []
    ids = [node.id for node in graph.nodes]
    known = set(ids)

    if len(known) != len(ids):
        duplicates = sorted({nid for nid in ids if ids.count(nid) > 1})
        raise FatalError(
            f"{len(duplicates)} node IDs are declared more than once: "
            f"{', '.join(duplicates[:MAX_REPORTED])}",
            code=GraphCode.DUPLICATE_NODE,
            hint="Two contracts with the same name in the same file, or a SolidityID "
            "built inconsistently between builders.",
        )

    if not graph.nodes:
        raise FatalError(
            "The graph has no nodes.",
            code=GraphCode.EMPTY,
            hint="Parsing produced contracts but none were selected — check the Reader's "
            "scope classification.",
        )

    dangling = [
        edge for edge in graph.edges if edge.source not in known or edge.target not in known
    ]
    if dangling:
        sample = "; ".join(
            f"{edge.kind.value} {edge.source} → {edge.target}" for edge in dangling[:MAX_REPORTED]
        )
        raise FatalError(
            f"{len(dangling)} edges reference nodes that do not exist: {sample}",
            code=GraphCode.DANGLING_EDGE,
            hint="An edge builder resolved a target without adding its node — every "
            "resolution must terminate at a real node or at a sentinel.",
        )

    # Ordering is part of the artifact contract (SPEC §7.1): the same input must produce a
    # byte-identical file. An unsorted graph passes every semantic test and fails that one.
    if ids != sorted(ids):
        raise FatalError(
            "Nodes are not sorted by ID; the artifact would not be reproducible.",
            code=GraphCode.UNSORTED,
        )
    keys = [edge.key() for edge in graph.edges]
    if keys != sorted(keys):
        raise FatalError(
            "Edges are not in canonical order; the artifact would not be reproducible.",
            code=GraphCode.UNSORTED,
        )

    for sentinel in SENTINELS:
        if sentinel not in known:
            notes.append(f"{sentinel} node missing; external-call queries will under-report")

    missing_paths = sum(
        1
        for candidate in graph.reentrancy_candidates
        if any(step not in known for step in candidate.path)
    )
    if missing_paths:
        notes.append(
            f"{missing_paths} reentrancy candidates reference functions outside the graph"
        )

    unlinearized = sum(1 for cid, mro in graph.linearization.items() if mro and mro[0] != cid)
    if unlinearized:
        notes.append(f"{unlinearized} linearizations do not begin with their own contract")

    return notes
