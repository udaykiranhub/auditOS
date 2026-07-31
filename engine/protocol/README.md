# protocol/ — Protocol Understanding (SPEC §7.6, full spec in Part 2)

`CodeModel + GraphModel + RepoModel.readme → ProtocolModel`. The join of graphs + deterministic
heuristics + **one** LLM synthesis pass. **Failure = Fatal** (P1: nothing downstream works without it).

> **This runs BEFORE the Context Builder, and its output is an input to every context request.
> Agents never see raw repos; they see a protocol.**

| Path            | Purpose |
|-----------------|---------|
| `understand.py` | orchestrates heuristics + the single LLM synthesis call → `ProtocolModel` |
| `heuristics/`   | **deterministic** archetype detectors (ERC20, vault/ERC4626, oracle, AMM, staking, lending…) — no LLM |

## `ProtocolModel` (§7.6)

```python
class ProtocolModel(BaseModel):
    summary: str            # 200-400 words: "what is this"
    archetype: list[str]    # ["lending","vault","amm","staking",...]
    actors: list[Actor]     # user, admin, keeper, liquidator, oracle
    assets: list[Asset]     # tokens, shares, collateral
    entrypoints: list[str]  # SolidityIDs — external/public, non-view
    privileged: list[str]   # entrypoints gated by admin roles
    value_flows: list[ValueFlow]   # who can move what, under what condition
    invariants: list[Invariant]    # candidate — heuristic + LLM-proposed
    trust_assumptions: list[str]
    core_contracts: list[str]      # ranked; drives context selection
    external_deps: list[str]       # oracles, DEXes, bridges
```

Heuristics run first and cheaply; the LLM pass synthesizes/labels what heuristics can't
(archetype nuance, invariants, trust assumptions). Keep the LLM call to **one**.

> Full schemas, the heuristic catalog, and the synthesis prompt are specified in **Part 2** of the SPEC.
