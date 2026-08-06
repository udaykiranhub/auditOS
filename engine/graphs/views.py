"""Derived views — projections of the one graph, never copies of it.

Each view is a *set of edge kinds*. `GraphQuery.view(name)` filters the edge list; the
artifact stores only the resulting sizes (`ViewSummary`), because materializing thirteen
subgraphs into the JSON would duplicate the same edges thirteen times and give thirteen
chances for the copies to drift apart.

Views not defined here, and why:

- **control flow** — needs a statement tree. `CodeModel` records ordered *references*, not
  statements (SPEC §12.2). A CFG faked from call order would be confidently wrong.
- **data flow / taint** — same root cause: propagation needs expression-level assignment,
  which the parser deliberately does not model.
- **lifecycle** — "what are the protocol's states" is a protocol question, not a syntactic
  one; it belongs to Protocol Understanding.

Adding them means extending the Parser to emit a block skeleton per function body. That is
a real, scoped piece of work — see `engine/graphs/README.md`.
"""

from __future__ import annotations

from engine.core.models.graph import EdgeKind

VIEWS: dict[str, frozenset[EdgeKind]] = {
    "call": frozenset(
        {
            EdgeKind.CALLS,
            EdgeKind.DELEGATECALLS,
            EdgeKind.STATICCALLS,
            EdgeKind.CREATES,
        }
    ),
    "storage": frozenset({EdgeKind.READS, EdgeKind.WRITES}),
    "state": frozenset({EdgeKind.WRITES}),
    "inheritance": frozenset(
        {EdgeKind.INHERITS, EdgeKind.IMPLEMENTS, EdgeKind.OVERRIDES}
    ),
    "dependency": frozenset({EdgeKind.IMPORTS}),
    "permission": frozenset({EdgeKind.MODIFIED_BY}),
    "event": frozenset({EdgeKind.EMITS, EdgeKind.REVERTS_WITH}),
    "token_flow": frozenset(
        {
            EdgeKind.TRANSFERS,
            EdgeKind.TRANSFERS_FROM,
            EdgeKind.APPROVES,
            EdgeKind.MINTS,
            EdgeKind.BURNS,
            EdgeKind.SENDS_VALUE,
        }
    ),
    "external": frozenset(
        {EdgeKind.CALLS, EdgeKind.DELEGATECALLS, EdgeKind.STATICCALLS, EdgeKind.SENDS_VALUE}
    ),
    "upgrade": frozenset({EdgeKind.DELEGATECALLS}),
    "structure": frozenset({EdgeKind.CONTAINS}),
}

#: Views restricted to edges that *leave the repository* — the target must be a sentinel.
#: The kinds alone do not express this, since `CALLS` covers both internal and external.
SENTINEL_TARGET_VIEWS = frozenset({"external"})
