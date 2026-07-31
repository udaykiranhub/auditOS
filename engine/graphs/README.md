# graphs/ — Graph Engine (SPEC §13)

`CodeModel → GraphModel`. Four graphs that make the protocol **navigable** — the substrate the
Context Builder walks. **Its quality caps the quality of everything above it.** Failure = Fatal.

**Implementation order (do NOT reorder — calls depends on inheritance):**
`inheritance (+C3) → storage → calls → imports`.

| File             | Graph | Node → Edge |
|------------------|-------|-------------|
| `inheritance.py` | inheritance | contract → parent (C3-linearized order preserved) |
| `storage.py`     | storage r/w | function → StateVar, labeled read / write (scope-aware!) |
| `calls.py`       | call graph  | caller fn → callee fn (+ two sentinel nodes, below) |
| `imports.py`     | import graph| file → file, cycle detection (lowest value, build last) |
| `build.py`       | assembles all four into `GraphModel` (NetworkX `node_link_data` serialization) |

## Inheritance must compute C3 linearization (§13.1)

Solidity's MRO. Needed to answer "which implementation of `_beforeTransfer` actually runs?" — a
question underneath a large fraction of real inheritance bugs. Store `flattened_functions(contract)`
and `override_chains(function)` on the graph; surface them in context, do **not** ask the model to
recompute them. *Common mistake:* building the call graph on the **unlinearized** contract, so
`super.f()` resolves wrong. Golden-test against a nasty diamond-inheritance fixture.

## The two sentinel nodes are load-bearing (§13.2)

- `UNKNOWN_EXTERNAL` — external call to an unknown address.
- `UNTRUSTED_EXTERNAL` — low-level `call`/`delegatecall`/`staticcall`. **Flag prominently.**

Reentrancy, oracle manipulation, and untrusted-callback bugs live here. Any path
`entrypoint → UNTRUSTED_EXTERNAL → back into a state write` is a reentrancy candidate and must be
computed **here, deterministically**, and handed to the agent as a pre-computed candidate path.
**Deterministic graph work is free and reliable; asking a model to traverse graphs in its head is
expensive and unreliable.** Do this for every pattern you can enumerate — highest-return work in the codebase.

## Derived queries the Context Builder needs — build these now (§13.5)

```python
neighborhood(fn_id, depth=2)      # callers + callees, bounded
reaching_entrypoints(fn_id)       # how does an attacker get here?  ← get this right FIRST
writers_of(state_var_id)
external_call_paths(fn_id)        # → UNTRUSTED_EXTERNAL
reentrancy_candidates()           # §13.2
privileged_writes()
centrality(contract_id)           # weighted PageRank on call+inherit
```

`reaching_entrypoints` cuts more context noise than any compression technique: an internal function
with no path from any external entrypoint is usually not exploitable → heavily down-rank it.
