"""`GraphModel` — the Code Property Graph (SPEC §7.5, §13).

```
CodeModel  →  Graph Engine  →  GraphModel
```

**One graph, many views.** SPEC §7.5 sketches five separate `DiGraph`s; this module stores
a *single* typed node/edge set instead and exposes the five as **projections over edge
kind**. The content is identical — inheritance, calls, storage reads/writes, imports — but
a function that both reads a variable and calls a peer exists once rather than three times.
At the scale we actually see (a real protocol parsed to 45k functions) five materialized
graphs is several hundred megabytes of duplicated JSON and three opportunities for the
copies to disagree. `to_networkx()` still hands NetworkX the graph SPEC asks for, so
PageRank and path queries use the library SPEC mandates.

**What this artifact deliberately does not contain:** control-flow edges, expression-level
data flow, and taint paths. `CodeModel` records *which* calls and state accesses a function
makes and in *what order* — not a statement tree (SPEC §12.2 names expression-level AST
modeling "the single biggest scope trap in the project"). A CFG cannot be invented from an
ordered reference list, and a graph that claims control flow it cannot see is worse than
one that omits it. See `engine/graphs/README.md` for what unlocks them.

Every node ID is a `SolidityID` (§7.2) or a sentinel, so this artifact joins `CodeModel`,
`BuildModel`, static-analyzer output, `ContextBundle` and `Finding` without translation.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0.0"

# ── Sentinels (SPEC §13.2) ────────────────────────────────────────────────────
# "The two sentinel nodes are load-bearing, not bookkeeping." Every call that leaves the
# repository terminates at one of these, so "does this reach untrusted code?" is a graph
# question with an answer rather than a reading exercise.

UNTRUSTED_EXTERNAL = "@UNTRUSTED_EXTERNAL"
"""Low-level `call`/`delegatecall`/`staticcall`. Reentrancy, oracle manipulation and
untrusted callbacks all live here."""

UNKNOWN_EXTERNAL = "@UNKNOWN_EXTERNAL"
"""A typed external call whose target is not in the repository."""

SENTINELS = (UNTRUSTED_EXTERNAL, UNKNOWN_EXTERNAL)

Confidence = Literal["high", "medium", "low"]


class NodeKind(StrEnum):
    FILE = "file"
    CONTRACT = "contract"
    INTERFACE = "interface"
    LIBRARY = "library"
    FUNCTION = "function"
    MODIFIER = "modifier"
    STATE_VAR = "state_var"
    EVENT = "event"
    ERROR = "error"
    SENTINEL = "sentinel"


class EdgeKind(StrEnum):
    """Typed relationships. Every edge carries the source location it was read from."""

    # ── Structural ────────────────────────────────────────────────────────────
    CONTAINS = "contains"  # file → contract, contract → function/state_var/event
    IMPORTS = "imports"  # file → file
    INHERITS = "inherits"  # contract → direct parent contract
    IMPLEMENTS = "implements"  # contract → interface it inherits
    OVERRIDES = "overrides"  # function → the function it overrides (MRO-resolved)

    # ── Calls (SPEC §13.2) ────────────────────────────────────────────────────
    CALLS = "calls"  # function → function | sentinel
    DELEGATECALLS = "delegatecalls"  # `delegatecall` / `callcode`
    STATICCALLS = "staticcalls"  # `staticcall`
    CREATES = "creates"  # `new C(...)`
    MODIFIED_BY = "modified_by"  # function → modifier — the permission graph
    SENDS_VALUE = "sends_value"  # call carrying ETH: `{value: …}`, `.transfer`, `.send`

    # ── Storage (SPEC §13.3) ──────────────────────────────────────────────────
    READS = "reads"  # function → state_var
    WRITES = "writes"  # function → state_var

    # ── Observability ─────────────────────────────────────────────────────────
    EMITS = "emits"  # function → event
    REVERTS_WITH = "reverts_with"  # function → custom error

    # ── Token flow — signature-derived, never business-semantic ───────────────
    # `transfer(address,uint256)` is an ERC-20 transfer by signature; that is a fact.
    # "deposit() MINTS shares" is an interpretation, and interpretation belongs to
    # Protocol Understanding, which is where SPEC puts it.
    TRANSFERS = "transfers"  # transfer / safeTransfer
    TRANSFERS_FROM = "transfers_from"  # transferFrom / safeTransferFrom
    APPROVES = "approves"  # approve / safeApprove / permit
    MINTS = "mints"  # mint / _mint
    BURNS = "burns"  # burn / _burn


#: Edge kinds whose target is reached by leaving this function's own frame.
CALL_KINDS = frozenset(
    {EdgeKind.CALLS, EdgeKind.DELEGATECALLS, EdgeKind.STATICCALLS, EdgeKind.CREATES}
)

#: Edge kinds that move value or token balances.
TOKEN_KINDS = frozenset(
    {
        EdgeKind.TRANSFERS,
        EdgeKind.TRANSFERS_FROM,
        EdgeKind.APPROVES,
        EdgeKind.MINTS,
        EdgeKind.BURNS,
        EdgeKind.SENDS_VALUE,
    }
)


class Node(BaseModel):
    """One program element. `id` is a `SolidityID` for everything but sentinels."""

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: NodeKind
    name: str
    path: str = ""
    contract_id: str | None = None
    line: int = 0

    visibility: str | None = None
    mutability: str | None = None
    type: str | None = None  # state-var type
    slot: int | None = None  # solc enrichment, when a build ran

    in_scope: bool = False
    is_dependency: bool = False
    is_entrypoint: bool = False
    is_implemented: bool = True
    has_assembly: bool = False


class Edge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    kind: EdgeKind
    confidence: Confidence = "high"

    line: int = 0
    order: int = -1  # position within the caller's body; CEI needs the sequence
    via: str | None = None  # interface, library or receiver the edge was resolved through
    text: str = ""  # the expression as written — every edge traces back to source

    def key(self) -> tuple[str, str, str, int, int, str]:
        """Deterministic sort key. Ordering is part of the artifact contract (§7.1)."""
        return (self.kind.value, self.source, self.target, self.order, self.line, self.via or "")


class ReentrancyCandidate(BaseModel):
    """A pre-computed `entrypoint → external call → state write` path (SPEC §13.2).

    A *candidate*, not a finding. `guard` records a reentrancy-guard modifier if one is
    applied; the agent decides whether it actually covers this path.
    """

    model_config = ConfigDict(extra="forbid")

    entrypoint: str
    function: str  # where the write-after-call occurs
    path: list[str]  # entrypoint → … → function, inclusive
    external_target: str  # sentinel or resolved callee
    external_call: str  # the expression as written
    external_line: int
    writes_after: list[str]  # state vars written after the call
    guard: str | None = None  # `nonReentrant`-style modifier on any function in the path
    confidence: Confidence = "high"


class Unresolved(BaseModel):
    """Something the graph could not resolve. Never silently dropped (SPEC §13.2)."""

    model_config = ConfigDict(extra="forbid")

    reason: Literal[
        "UNRESOLVED_DELEGATECALL",
        "UNRESOLVED_ASSEMBLY_ACCESS",
        "UNRESOLVED_EXTERNAL_CALL",
        "UNRESOLVED_INTERNAL_CALL",
        "UNRESOLVED_PARENT",
        "AMBIGUOUS_LINEARIZATION",
        "INTERFACE_FANOUT_CAPPED",
    ]
    function: str | None = None
    detail: str = ""
    line: int = 0


class ViewSummary(BaseModel):
    """Size of a derived view. The *edges* are not duplicated here — call
    `GraphQuery.view(name)`; this exists so a reader can see the shape without loading it."""

    model_config = ConfigDict(extra="forbid")

    kinds: list[EdgeKind]
    nodes: int
    edges: int


class GraphModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    content_hash: str = ""
    code_content_hash: str = ""

    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)

    # ── Inheritance, resolved (SPEC §13.1) ────────────────────────────────────
    linearization: dict[str, list[str]] = Field(default_factory=dict)
    """contract_id → C3 MRO, most-derived first. Solidity's actual dispatch order."""

    override_chains: dict[str, list[str]] = Field(default_factory=dict)
    """function_id (the most-derived definition) → every definition it overrides, in MRO
    order. A direct input to the Access Control and Business Logic agents."""

    # ── Pre-computed candidates and honesty about what failed ─────────────────
    reentrancy_candidates: list[ReentrancyCandidate] = Field(default_factory=list)
    unresolved: list[Unresolved] = Field(default_factory=list)
    import_cycles: list[list[str]] = Field(default_factory=list)

    views: dict[str, ViewSummary] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)

    # ── Accessors ─────────────────────────────────────────────────────────────

    @property
    def counts(self) -> dict[str, int]:
        by_kind: dict[str, int] = {}
        for node in self.nodes:
            by_kind[node.kind.value] = by_kind.get(node.kind.value, 0) + 1
        for edge in self.edges:
            by_kind[edge.kind.value] = by_kind.get(edge.kind.value, 0) + 1
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "entrypoints": sum(n.is_entrypoint for n in self.nodes),
            "reentrancy_candidates": len(self.reentrancy_candidates),
            "unresolved": len(self.unresolved),
            "import_cycles": len(self.import_cycles),
            **by_kind,
        }

    def node(self, node_id: str) -> Node | None:
        return self._by_id.get(node_id)

    @property
    def _by_id(self) -> dict[str, Node]:
        # Rebuilt per access rather than cached: `GraphModel` is a frozen-in-spirit artifact
        # that callers may `model_copy(update=…)`, and a stale cache there is a silent bug.
        # Anything hot goes through `GraphQuery`, which indexes once.
        return {node.id: node for node in self.nodes}

    def hash_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"content_hash"})

    def with_content_hash(self) -> GraphModel:
        from engine.core.artifacts import content_hash as _hash

        return self.model_copy(update={"content_hash": _hash(self.hash_payload())})
