# context/ — Context Builder (SPEC §6; full spec in Part 2)

## THE CORE VALUE OF THE ENTIRE SYSTEM

> **Context is the product** (P3). The scarce resource is not compute or tokens — it is the
> *reader's attention*, where the reader is a model with a fixed window and no persistence. Any code
> that decides **what goes into a prompt** is core business logic and deserves the rigor of a
> consensus algorithm.

`all upstream artifacts + ContextRequest → ContextBundle`. Deterministic. Failure = Fatal per request.

| File          | Stage | Purpose |
|---------------|-------|---------|
| `builder.py`  | —     | entrypoint; serves a `ContextRequest`, returns a `ContextBundle` |
| `select.py`   | 1     | **relevance** — which artifacts are even candidates |
| `rank.py`     | 2     | **importance** — order candidates (uses `reaching_entrypoints`, centrality, static hits) |
| `compress.py` | 3     | **summarize / elide** — fit more signal per token |
| `dedupe.py`   | 4     | drop duplicate/near-duplicate slices (e.g. inherited bodies) |
| `budget.py`   | 5     | **token accounting** — hard budget enforcement |

## The one rule that keeps this module honest

**The Context Builder is AGENT-AGNOSTIC.** It serves declarative `ContextRequest`s; it does not know
*who* is asking beyond the request. *Common mistake:* putting agent-specific logic in here. If you
find yourself writing `if agent == "reentrancy"`, the design is wrong — push it into the agent's
`ContextRequest` instead.

Static findings enter here as framed **hints**, never as answers (see `../analysis/README.md` §11.3).

> `ContextRequest` / `ContextBundle` schemas, the selection/ranking algorithms, compression, and
> how context quality is **measured rather than asserted** are specified in **Part 2** of the SPEC.
