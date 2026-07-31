# analysis/ — Static Analysis Adapters (SPEC §11)

**Purpose: cheap, deterministic, high-recall priors. Not findings. _Priors._**

| File            | Purpose |
|-----------------|---------|
| `base.py`       | `StaticAnalyzer` protocol: `available()` + `run(repo, build) -> list[StaticFinding]` |
| `slither/adapter.py` | Slither JSON → normalized `StaticFinding[]` (primary; requires compilation) |
| `aderyn/adapter.py`  | Aderyn JSON → normalized `StaticFinding[]` (secondary; AST-based, more tolerant) |

Run all available analyzers **concurrently**. A missing binary is a warning, not an error.

## The whole difficulty is `target` mapping

Each tool emits its own element addressing. The adapter's job is to map it to our `SolidityID`
(§7.2). If this is sloppy, static corroboration silently stops working and you won't notice — the
findings just get quietly less accurate. **Unit-test the mapping against fixtures explicitly.**

```python
class StaticFinding(BaseModel):
    tool: Literal["slither","aderyn"]
    detector: str            # e.g. "reentrancy-eth"
    tool_severity: str
    target: list[str]        # SolidityIDs — the hard part
    lines: list[int]
    message: str
    raw: dict
```

## The opinionated rule: static findings are CONTEXT, not OUTPUT (§11.3)

**Raw Slither/Aderyn output NEVER reaches `report.md`.** Three uses only:

1. **Context signal** — injected into an agent's `ContextBundle` as a hint block, explicitly framed:
   *"A static analyzer flagged the following. These have high false-positive rates on
   business-logic patterns. Verify or dismiss each against the protocol's actual invariants."*
2. **Corroboration** — an agent finding that overlaps a static finding's target+class populates
   `Finding.static_corroboration` → confidence boost in validation.
3. **Ranking prior** — functions with static hits get a small context-importance boost.

Rationale: the user can run Slither themselves in 30s. The product's value is exclusively in what
Slither *cannot* find. **Track the counter-risk:** if agents routinely fail to rediscover valid
static findings, reverse this to a clearly-labeled appendix section.
