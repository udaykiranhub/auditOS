"""The semantic graph — every contract, function, variable and the relations between them.

```
LendingPool ──declares──▶ borrow(address,uint256,address)
                              │
              ┌───reads───────┼───────writes───┐
              ▼               ▼                ▼
        _reserves      totalDebtUsd      totalBorrowShares
                              │
                        ┌─guards─┐
                        ▼        ▼
             borrowLimitUsd >= totalDebtUsd     ← BinaryOperation, from the solc AST
```

**Why a graph and not more fields.** The previous design answered every question with a
lookup table: operation kind → risk surfaces, state role pair → relationship. Two protocols
with a `deposit` therefore received identical output, which is the opposite of understanding
them. A graph makes each answer a *query over what this protocol actually contains*, so the
result varies because the code varies.

**Why the AST.** `referencedDeclaration` on every identifier resolves a name to its
declaration exactly — no scope guessing, no collisions between two contracts that both have
a `debt`. `typeDescriptions` gives the real type. Neither is recoverable from source text,
which is why the text-based passes could see configuration bounds but not the health check
that is the entire point of a lending market.

Built AST-first and degraded honestly: when a repository does not compile, the graph is
still assembled from `CodeModel` and `GraphModel`, `NodeKind.LOCAL` nodes are absent, and
`SemanticGraph.fidelity` says so rather than letting a thinner graph read as a complete one.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from engine.core.models.evidence import Claim

SCHEMA_VERSION = "1.0.0"
ARTIFACT_NAME = "semantic"


class NodeKind(StrEnum):
    """What a node *is*. The kinds are deliberately concrete — every one corresponds to
    something a reader can open in the source."""

    CONTRACT = "contract"
    FUNCTION = "function"
    MODIFIER = "modifier"
    STATE_VAR = "state_var"
    STRUCT_FIELD = "struct_field"
    """A field of a struct the protocol declares. Real invariants live here: a lending
    pool's health check compares two fields of an in-memory `AccountData`, never two
    storage slots."""

    LOCAL = "local"
    """A local or parameter. Present only with AST fidelity."""

    CONSTANT = "constant"
    EVENT = "event"
    ERROR = "error"
    EXTERNAL = "external"
    """Something outside this repository: an interface, an unresolved callee."""


class EdgeKind(StrEnum):
    """How two nodes relate. Direction always reads source → target."""

    DECLARES = "declares"
    INHERITS = "inherits"

    READS = "reads"
    WRITES = "writes"
    CALLS = "calls"
    EMITS = "emits"
    REVERTS_WITH = "reverts_with"

    GUARDS = "guards"
    """A comparison stands between the caller and the rest of the body. The edge runs from
    the guarded function to each quantity the condition mentions."""

    CONSTRAINS = "constrains"
    """One quantity bounds another, established by a guard that reverts. `borrowLimitUsd
    constrains totalDebtUsd`. The strongest relation this graph carries, because the
    protocol enforces it."""

    DERIVES_FROM = "derives_from"
    """The target's value was assigned from an expression mentioning the source. One hop of
    dataflow — enough to connect a local back to the storage it came from, which is what
    makes a guard over locals meaningful."""

    TRANSFERS = "transfers"
    RETURNS = "returns"


class Fidelity(StrEnum):
    """How the graph was built. Read this before trusting an absence."""

    AST = "ast"
    """From the solc AST. Names resolved by declaration id; types exact."""

    TEXT = "text"
    """From `CodeModel` and source text. Locals and expression structure are unavailable,
    so an absent `CONSTRAINS` edge means "not visible", not "not present"."""

    MIXED = "mixed"
    """Some sources compiled and some did not. `SemanticNode.from_ast` says which."""


class SemanticNode(BaseModel):
    """One addressable thing in the protocol."""

    model_config = ConfigDict(extra="forbid")

    id: str
    """`node:<kind>:<key>`. Stable across runs; never a positional index."""

    kind: NodeKind
    name: str = ""
    qualified_name: str = ""
    """`LendingPool.borrow` / `AccountData.totalDebtUsd` — what a reader recognises."""

    contract_id: str = ""
    solidity_id: str = ""
    """The `SolidityID` this node corresponds to, when it has one. The join back to
    `CodeModel`, and empty for nodes that exist only in the AST (locals, struct fields)."""

    type_name: str = ""
    path: str = ""
    line: int = 0
    from_ast: bool = False

    visibility: str = ""
    mutability: str = ""
    is_entrypoint: bool = False
    is_privileged: bool = False
    is_constant: bool = False
    modifier_count: int = 0
    """How many modifiers are applied. Load-bearing for any pattern that reasons from
    the *absence* of a guard: authorization is usually written as `msg.sender != owner`
    inside a modifier, which this graph deliberately does not record as a `CONSTRAINS`
    edge — so "no guards" must not be read as "unguarded" while a modifier is
    applied."""


class SemanticEdge(Claim):
    """One directed relation, with the evidence that produced it.

    A `Claim`, unlike the nodes: a node is a thing that demonstrably exists, while an edge
    is an assertion *about* the code and must carry how strongly it is held. A `CONSTRAINS`
    edge read off a reverting comparison is `DERIVED`; a `DERIVES_FROM` edge inferred
    through a text-mode fallback is `INFERRED`.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    source: str
    target: str
    kind: EdgeKind

    detail: str = ""
    """The expression as written, when the edge came from one."""

    operator: str = ""
    """For `CONSTRAINS`: the normalised comparison, already negated for `if (…) revert`."""

    function_id: str = ""
    """Where the relation is enforced or observed."""

    order: int = 0
    """Position within the function body, so the sequence survives into the graph."""

    line: int = 0


class SemanticGraph(BaseModel):
    """Every contract, function and quantity in the protocol, and how they relate."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    content_hash: str = ""
    fidelity: Fidelity = Fidelity.TEXT

    nodes: list[SemanticNode] = Field(default_factory=list)
    edges: list[SemanticEdge] = Field(default_factory=list)

    sources_total: int = 0
    sources_with_ast: int = 0
    notes: list[str] = Field(default_factory=list)

    # ── Lookups ───────────────────────────────────────────────────────────────

    def node(self, node_id: str) -> SemanticNode | None:
        return next((n for n in self.nodes if n.id == node_id), None)

    def of_kind(self, kind: NodeKind) -> list[SemanticNode]:
        return [n for n in self.nodes if n.kind is kind]

    def out_edges(self, node_id: str, kind: EdgeKind | None = None) -> list[SemanticEdge]:
        return [
            e
            for e in self.edges
            if e.source == node_id and (kind is None or e.kind is kind)
        ]

    def in_edges(self, node_id: str, kind: EdgeKind | None = None) -> list[SemanticEdge]:
        return [
            e
            for e in self.edges
            if e.target == node_id and (kind is None or e.kind is kind)
        ]

    def neighbours(self, node_id: str, kind: EdgeKind | None = None) -> list[str]:
        return sorted(
            {e.target for e in self.out_edges(node_id, kind)}
            | {e.source for e in self.in_edges(node_id, kind)}
        )

    def in_contract(self, contract_id: str) -> list[SemanticNode]:
        return [n for n in self.nodes if n.contract_id == contract_id]

    @property
    def counts(self) -> dict[str, int]:
        by_node: dict[str, int] = {}
        for node in self.nodes:
            by_node[node.kind.value] = by_node.get(node.kind.value, 0) + 1
        for edge in self.edges:
            by_node[edge.kind.value] = by_node.get(edge.kind.value, 0) + 1
        return by_node


__all__ = [
    "ARTIFACT_NAME",
    "SCHEMA_VERSION",
    "EdgeKind",
    "Fidelity",
    "NodeKind",
    "SemanticEdge",
    "SemanticGraph",
    "SemanticNode",
]
