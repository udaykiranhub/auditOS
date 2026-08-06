"""The query API (SPEC §13.5). Agents never traverse raw edges.

> `reaching_entrypoints` is the one to get right first. **An internal function with no path
> from any external entrypoint is, in most cases, not exploitable, and should be heavily
> down-ranked in context.** This single query does more to cut context noise than any
> compression technique.

`GraphQuery` indexes the edge list once and answers from adjacency maps. NetworkX is used
where SPEC asks for it — PageRank centrality — and not where a dict of lists is faster and
clearer, which is everywhere else.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Container, Iterable
from typing import TYPE_CHECKING

from engine.core.models.graph import (
    CALL_KINDS,
    SENTINELS,
    Edge,
    EdgeKind,
    GraphModel,
    Node,
    NodeKind,
    ReentrancyCandidate,
)
from engine.graphs.views import SENTINEL_TARGET_VIEWS, VIEWS

if TYPE_CHECKING:  # NetworkX is imported lazily; only the annotation needs it eagerly
    import networkx as nx

#: Names that conventionally gate privileged state. Used only to *rank*, never to decide.
PRIVILEGED_HINTS = (
    "owner",
    "admin",
    "governance",
    "guardian",
    "pauser",
    "paused",
    "oracle",
    "treasury",
    "fee",
    "role",
    "authority",
    "implementation",
    "beacon",
)

MAX_PATHS = 8
MAX_PATH_DEPTH = 8

PAGERANK_DAMPING = 0.85
PAGERANK_ITERATIONS = 100
PAGERANK_TOLERANCE = 1e-8


class GraphQuery:
    """Indexed read-only access to a `GraphModel`."""

    def __init__(self, graph: GraphModel):
        self.graph = graph
        self.nodes: dict[str, Node] = {node.id: node for node in graph.nodes}

        self._out: dict[str, list[Edge]] = defaultdict(list)
        self._in: dict[str, list[Edge]] = defaultdict(list)
        self._by_kind: dict[EdgeKind, list[Edge]] = defaultdict(list)
        for edge in graph.edges:
            self._out[edge.source].append(edge)
            self._in[edge.target].append(edge)
            self._by_kind[edge.kind].append(edge)

    # ── Views ─────────────────────────────────────────────────────────────────

    def view(self, name: str) -> list[Edge]:
        """One derived view, computed by projection. Raises on an unknown name."""
        kinds = VIEWS.get(name)
        if kinds is None:
            raise KeyError(f"unknown view {name!r}; known views: {sorted(VIEWS)}")
        edges = [edge for kind in sorted(kinds) for edge in self._by_kind.get(kind, [])]
        if name in SENTINEL_TARGET_VIEWS:
            edges = [edge for edge in edges if edge.target in SENTINELS]
        edges.sort(key=lambda edge: edge.key())
        return edges

    def view_nodes(self, name: str) -> list[Node]:
        touched = {edge.source for edge in self.view(name)} | {
            edge.target for edge in self.view(name)
        }
        return [self.nodes[nid] for nid in sorted(touched) if nid in self.nodes]

    # ── Call graph ────────────────────────────────────────────────────────────

    def callees(self, function_id: str) -> list[str]:
        return _targets(self._out.get(function_id, []), CALL_KINDS)

    def callers(self, function_id: str) -> list[str]:
        return _sources(self._in.get(function_id, []), CALL_KINDS)

    def neighborhood(self, function_id: str, depth: int = 2) -> set[str]:
        """Callers + callees, bounded. The default context slice around a function."""
        seen = {function_id}
        frontier = {function_id}
        for _ in range(max(depth, 0)):
            nxt: set[str] = set()
            for node_id in frontier:
                nxt.update(self.callees(node_id))
                nxt.update(self.callers(node_id))
            frontier = nxt - seen
            seen |= frontier
            if not frontier:
                break
        return seen - set(SENTINELS)

    def entrypoints(self) -> list[str]:
        return sorted(nid for nid, node in self.nodes.items() if node.is_entrypoint)

    def reaching_entrypoints(self, function_id: str) -> list[str]:
        """Which externally callable functions can reach this one.

        Empty means: no attacker path exists through the call graph. That function should be
        heavily down-ranked in context — this is the single largest noise reduction available.
        """
        seen = {function_id}
        queue = deque([function_id])
        found: set[str] = set()

        while queue:
            current = queue.popleft()
            node = self.nodes.get(current)
            if node is not None and node.is_entrypoint and current != function_id:
                found.add(current)
            for caller in self.callers(current):
                if caller not in seen:
                    seen.add(caller)
                    queue.append(caller)

        node = self.nodes.get(function_id)
        if node is not None and node.is_entrypoint:
            found.add(function_id)
        return sorted(found)

    def entrypoint_paths(
        self, function_id: str, limit: int = MAX_PATHS
    ) -> list[list[str]]:
        """Concrete `entrypoint → … → function` paths, shortest first, bounded.

        Bounded deliberately: a helper reachable from forty entrypoints produces forty
        near-identical paths, and the first few carry all of the signal.
        """
        paths: list[list[str]] = []
        queue: deque[list[str]] = deque([[function_id]])
        seen_paths: set[tuple[str, ...]] = set()

        while queue and len(paths) < limit:
            path = queue.popleft()
            if len(path) > MAX_PATH_DEPTH:
                continue
            head = path[0]
            node = self.nodes.get(head)
            if node is not None and node.is_entrypoint:
                key = tuple(path)
                if key not in seen_paths:
                    seen_paths.add(key)
                    paths.append(path)
                    continue
            for caller in self.callers(head):
                if caller not in path:  # no cycles
                    queue.append([caller, *path])

        paths.sort(key=lambda p: (len(p), p))
        return paths

    def external_call_paths(self, function_id: str) -> list[Edge]:
        """Edges from this function that leave the repository."""
        return sorted(
            (
                edge
                for edge in self._out.get(function_id, [])
                if edge.target in SENTINELS and edge.kind in CALL_KINDS
            ),
            key=lambda edge: edge.key(),
        )

    def external_calls(self) -> list[Edge]:
        return self.view("external")

    def delegatecall_targets(self) -> list[Edge]:
        return sorted(self._by_kind.get(EdgeKind.DELEGATECALLS, []), key=lambda e: e.key())

    def reentrancy_candidates(self) -> list[ReentrancyCandidate]:
        return list(self.graph.reentrancy_candidates)

    # ── Storage ───────────────────────────────────────────────────────────────

    def state_writes(self, function_id: str) -> list[str]:
        return _targets(self._out.get(function_id, []), {EdgeKind.WRITES})

    def state_reads(self, function_id: str) -> list[str]:
        return _targets(self._out.get(function_id, []), {EdgeKind.READS})

    def writers_of(self, state_var_id: str) -> list[str]:
        """Every function that mutates this variable — seeds the Invariant agent."""
        return _sources(self._in.get(state_var_id, []), {EdgeKind.WRITES})

    def readers_of(self, state_var_id: str) -> list[str]:
        return _sources(self._in.get(state_var_id, []), {EdgeKind.READS})

    def storage_users(self, state_var_id: str) -> list[str]:
        return sorted(set(self.writers_of(state_var_id)) | set(self.readers_of(state_var_id)))

    def privileged_variables(self) -> list[str]:
        return sorted(
            nid
            for nid, node in self.nodes.items()
            if node.kind is NodeKind.STATE_VAR
            and any(hint in node.name.lower() for hint in PRIVILEGED_HINTS)
        )

    def privileged_writes(self) -> list[str]:
        """Externally reachable functions that write a privilege-bearing variable."""
        found: set[str] = set()
        for variable in self.privileged_variables():
            for writer in self.writers_of(variable):
                node = self.nodes.get(writer)
                if node is not None and (node.is_entrypoint or self.reaching_entrypoints(writer)):
                    found.add(writer)
        return sorted(found)

    # ── Permissions, inheritance, tokens ──────────────────────────────────────

    def permissions(self, function_id: str) -> list[str]:
        return _targets(self._out.get(function_id, []), {EdgeKind.MODIFIED_BY})

    def guarded_by(self, modifier_id: str) -> list[str]:
        return _sources(self._in.get(modifier_id, []), {EdgeKind.MODIFIED_BY})

    def inheritance(self, contract_id: str) -> list[str]:
        """The C3 MRO, most-derived first — Solidity's real dispatch order."""
        return list(self.graph.linearization.get(contract_id, [contract_id]))

    def override_chain(self, function_id: str) -> list[str]:
        return list(self.graph.override_chains.get(function_id, []))

    def token_flows(self, function_id: str | None = None) -> list[Edge]:
        edges = self.view("token_flow")
        if function_id is None:
            return edges
        return [edge for edge in edges if edge.source == function_id]

    def emits(self, function_id: str) -> list[str]:
        return _targets(self._out.get(function_id, []), {EdgeKind.EMITS})

    # ── Dependencies and ranking ──────────────────────────────────────────────

    def function_dependencies(self, function_id: str) -> list[str]:
        """Everything this function needs to be understood: callees + state it touches."""
        edges = self._out.get(function_id, [])
        kinds = CALL_KINDS | {EdgeKind.READS, EdgeKind.WRITES, EdgeKind.MODIFIED_BY}
        return _targets(edges, kinds)

    def variable_dependencies(self, state_var_id: str) -> list[str]:
        """Variables written by any function that reads this one — a coupling proxy.

        Not data flow: it says these variables move together, not that a value propagates.
        Real propagation needs expression-level parsing the `CodeModel` does not carry.
        """
        found: set[str] = set()
        for reader in self.readers_of(state_var_id):
            found.update(self.state_writes(reader))
        found.discard(state_var_id)
        return sorted(found)

    def program_slice(self, function_id: str, depth: int = 2) -> dict[str, list[str]]:
        """A call-graph slice: the functions and state around one function.

        A *call-graph* slice, not a program slice in the dataflow sense — it answers "what
        else must I read to understand this", which is what the Context Builder needs.
        """
        functions = sorted(self.neighborhood(function_id, depth))
        state = sorted({v for fid in functions for v in self.function_dependencies(fid)
                        if self.nodes.get(v) and self.nodes[v].kind is NodeKind.STATE_VAR})
        return {
            "functions": functions,
            "state_vars": state,
            "entrypoints": self.reaching_entrypoints(function_id),
            "external": [edge.target for edge in self.external_call_paths(function_id)],
        }

    def centrality(self, top: int = 0) -> dict[str, float]:
        """Weighted PageRank over calls + inheritance (SPEC §13.5).

        Power iteration in plain Python rather than `nx.pagerank`, which now delegates to
        SciPy and so drags NumPy + SciPy — ~100 MB — into a local-first engine for one
        ranking function. Iterating in a fixed node order also keeps the result
        bit-for-bit reproducible, which the SciPy path does not guarantee across builds.
        """
        weights = {EdgeKind.INHERITS: 2.0, EdgeKind.IMPLEMENTS: 2.0}
        outgoing: dict[str, dict[str, float]] = defaultdict(dict)
        for edge in self.graph.edges:
            if edge.kind not in CALL_KINDS and edge.kind not in weights:
                continue
            row = outgoing[edge.source]
            row[edge.target] = row.get(edge.target, 0.0) + weights.get(edge.kind, 1.0)

        if not outgoing:
            return {}

        nodes = sorted(set(self.nodes) | set(outgoing))
        count = len(nodes)
        rank = dict.fromkeys(nodes, 1.0 / count)
        totals = {source: sum(row.values()) for source, row in outgoing.items()}
        sinks = [node for node in nodes if node not in outgoing]

        for _ in range(PAGERANK_ITERATIONS):
            leaked = sum(rank[node] for node in sinks) / count
            nxt = dict.fromkeys(nodes, (1.0 - PAGERANK_DAMPING) / count + PAGERANK_DAMPING * leaked)
            for source in nodes:
                targets = outgoing.get(source)
                if not targets:
                    continue
                share = PAGERANK_DAMPING * rank[source] / totals[source]
                for target, weight in targets.items():
                    nxt[target] += share * weight
            delta = sum(abs(nxt[node] - rank[node]) for node in nodes)
            rank = nxt
            if delta < PAGERANK_TOLERANCE:
                break

        ordered = sorted(rank.items(), key=lambda item: (-item[1], item[0]))
        return dict(ordered[:top] if top else ordered)

    def contract_centrality(self, top: int = 0) -> dict[str, float]:
        """Centrality aggregated to the contract — what "core contracts" ranks on."""
        totals: dict[str, float] = defaultdict(float)
        for node_id, rank in self.centrality().items():
            node = self.nodes.get(node_id)
            if node is None:
                continue
            owner = node.contract_id if node.kind is not NodeKind.CONTRACT else node.id
            if owner:
                totals[owner] += rank
        ordered = sorted(totals.items(), key=lambda item: (-item[1], item[0]))
        return dict(ordered[:top] if top else ordered)

    def to_networkx(self) -> nx.MultiDiGraph:
        """The whole CPG as a NetworkX `MultiDiGraph`, for ad-hoc analysis."""
        import networkx as nx

        graph = nx.MultiDiGraph()
        for node in self.graph.nodes:
            graph.add_node(node.id, **node.model_dump(mode="json", exclude={"id"}))
        for edge in self.graph.edges:
            graph.add_edge(
                edge.source,
                edge.target,
                key=edge.kind.value,
                **edge.model_dump(mode="json", exclude={"source", "target"}),
            )
        return graph


def _targets(edges: Iterable[Edge], kinds: Container[EdgeKind]) -> list[str]:
    return sorted({edge.target for edge in edges if edge.kind in kinds})


def _sources(edges: Iterable[Edge], kinds: Container[EdgeKind]) -> list[str]:
    return sorted({edge.source for edge in edges if edge.kind in kinds})
