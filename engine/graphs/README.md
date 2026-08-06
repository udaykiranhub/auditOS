# graphs/ — Graph Engine (SPEC §13)

`CodeModel → GraphModel`. **One** Code Property Graph; the four graphs SPEC names are
**views** over it. This is the substrate the Context Builder walks — **its quality caps the
quality of everything above it.** Failure = Fatal.

**Build order (do NOT reorder — calls depends on inheritance):**
`select → inheritance (+C3) → nodes → storage → calls → tokens → imports → candidates`.

| File             | Responsibility |
|------------------|----------------|
| `select.py`      | which contracts enter the graph: in-scope + inheritance/interface closure |
| `inheritance.py` | C3 linearization, flattened members, override chains, INHERITS/OVERRIDES |
| `nodes.py`       | every program element as a node; CONTAINS skeleton; the two sentinels |
| `storage.py`     | READS/WRITES/EMITS edges, and the reentrancy candidates |
| `calls.py`       | the call-resolution ladder (§13.2) |
| `tokens.py`      | signature-derived token-flow edges |
| `imports.py`     | file → file, cycle detection (lowest value, built last) |
| `views.py`       | the derived views, as edge-kind projections |
| `query.py`       | the §13.5 query API — agents call this, never the edge list |
| `validate.py`    | integrity checks before the artifact is written |
| `build.py`       | assembles the above into `GraphModel` |

## One graph, not thirteen

SPEC §7.5 sketches five `DiGraph`s. Storing them separately means a function that reads a
variable and calls a peer exists three times, in three files, with three chances to drift
apart. So the artifact stores one node/edge set and `GraphQuery.view(name)` projects.
`GraphQuery.to_networkx()` hands NetworkX the graph SPEC mandates when something wants it.

The artifact records only each view's **size** (`ViewSummary`). Materializing thirteen
subgraphs into the JSON would be the same duplication in a different costume.

## The two sentinel nodes are load-bearing (§13.2)

- `@UNTRUSTED_EXTERNAL` — low-level `call`/`delegatecall`. Arbitrary code runs.
- `@UNKNOWN_EXTERNAL` — typed external call whose target is not in the repository.

Every path `entrypoint → external call → state write` is computed **here**, deterministically,
and handed to the agent as a `ReentrancyCandidate` with a concrete path. *Deterministic
graph work is free and reliable; asking a model to traverse graphs in its head is expensive
and unreliable.*

Precision matters more than recall here, because false candidates crowd out real ones. On a
3,765-file protocol the count went **108 → 7** by fixing four things, each a real defect:
a `using L for T` call resolving as external, dependency code being reported at all, an
external `view` call (which compiles to STATICCALL and cannot reenter) counting as
dangerous, and `new bytes32[]` — a memory allocation — counting as contract creation.

## What this phase deliberately does NOT build

Not scope cuts made to save time — things `CodeModel` cannot support:

| Not built | Why |
|---|---|
| Control-flow graph | `CodeModel` records ordered *references*, not statements. SPEC §12.2 names expression-level AST modeling "the single biggest scope trap in the project". A CFG faked from call order would be confidently wrong. |
| Data-flow / taint analysis | Propagation needs expression-level assignment, which the parser does not model. |
| Business-semantic edges (`deposit —MINTS→ shares`) | That is protocol *interpretation*: it needs to know this is a vault and that `shares` is the receipt token. SPEC assigns it to Protocol Understanding, which sees the whole system and has an LLM pass. `tokens.py` emits only what a **signature** proves. |
| Assembly interpretation | `sload`/`sstore` in Yul is a state access with no edge. Recorded as `UNRESOLVED_ASSEMBLY_ACCESS`, never dropped. |
| Proxy implementation merging | A delegatecall target is a runtime value. Recorded as `UNRESOLVED_DELEGATECALL`; merging an implementation's functions into the proxy would fabricate a call graph nobody wrote. |

**What unlocks CFG, data flow and taint:** extending the Parser to emit a lightweight
*statement skeleton* per function body — block, branch, loop and assignment nodes with
source order — while still refusing full expression trees. That is a scoped piece of Parser
work, not Graph work, and it should be decided on its own merits.

## Orphans are legitimate

The validator rejects dangling edges, duplicate IDs and unsorted output. It does **not**
reject orphan nodes: an uncalled library, an interface for an external protocol, an unused
custom error. A validator that fails on every real repository is a validator you disable.

## Derived queries (§13.5)

```python
reaching_entrypoints(fn_id)   # get this right FIRST — cuts more noise than any compression
entrypoint_paths(fn_id)       # the concrete attack path, bounded
neighborhood(fn_id, depth=2)
writers_of(state_var_id)      # seeds the Invariant agent
privileged_writes()           # seeds the Access Control agent
external_call_paths(fn_id)
reentrancy_candidates()
centrality() / contract_centrality()   # weighted PageRank on call+inherit
program_slice(fn_id)          # a *call-graph* slice, not a dataflow slice
```

An internal function with no path from any external entrypoint is usually not exploitable →
heavily down-rank it.
