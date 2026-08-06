"""Import graph (SPEC §13.4). File → file, with cycle detection.

"Lowest value of the four; build it last." It is here for dependency ordering and as a
sanity check on `is_dependency` propagation, not because anything reasons over it.
"""

from __future__ import annotations

from engine.core.models.code import CodeModel
from engine.core.models.graph import Edge, EdgeKind


def import_edges(code: CodeModel, files: set[str]) -> tuple[list[Edge], list[list[str]]]:
    edges: list[Edge] = []
    adjacency: dict[str, list[str]] = {}

    for source in code.sources:
        if source.path not in files:
            continue
        for imported in source.imports:
            target = imported.resolved_path
            if not target or target not in files or target == source.path:
                continue
            edges.append(
                Edge(
                    source=source.path,
                    target=target,
                    kind=EdgeKind.IMPORTS,
                    line=imported.line,
                    text=imported.path,
                )
            )
            adjacency.setdefault(source.path, []).append(target)

    return edges, find_cycles(adjacency)


def find_cycles(adjacency: dict[str, list[str]]) -> list[list[str]]:
    """Tarjan's SCCs, iterative — a deep dependency chain must not blow the Python stack.

    Import cycles are legal in Solidity, so these are reported, never raised.
    """
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    counter = 0
    cycles: list[list[str]] = []

    for root in sorted(adjacency):
        if root in index:
            continue
        work: list[tuple[str, int]] = [(root, 0)]
        while work:
            node, child = work[-1]
            if child == 0:
                index[node] = low[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)

            neighbours = adjacency.get(node, [])
            if child < len(neighbours):
                work[-1] = (node, child + 1)
                nxt = neighbours[child]
                if nxt not in index:
                    work.append((nxt, 0))
                elif nxt in on_stack:
                    low[node] = min(low[node], index[nxt])
                continue

            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])

            if low[node] == index[node]:
                component: list[str] = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                if len(component) > 1 or node in adjacency.get(node, []):
                    cycles.append(sorted(component))

    cycles.sort()
    return cycles
