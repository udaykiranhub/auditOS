# core/ — the spine (SPEC §7)

**SLOW-MOVING. Review every change carefully.** This is the shared vocabulary of the whole
engine: the Pydantic artifact models plus the cross-cutting utilities every module needs.

## Artifact rules (§7.1) — enforced mechanically

1. Every artifact is a **Pydantic v2** model with a `schema_version: str`.
2. Every artifact serializes to JSON at `run/<run_id>/artifacts/<name>.json`.
3. Every artifact has a `content_hash` derived from its inputs → enables caching + resume.
4. **Append-only within a run.** A module never mutates an upstream artifact; it produces a new one.

## Files

| File            | Purpose |
|-----------------|---------|
| `models/`       | The artifact models — see `models/README.md` |
| `models/ids.py` | `SolidityID` + a single `make_id()`. The **join key** for the entire system (§7.2). Property-test round-tripping. |
| `artifacts.py`  | save / load / hash / version artifacts to disk. The cache doubles as the resume mechanism. |
| `errors.py`     | `FatalError` vs `DegradedError` (P6). Fatal = cannot continue; Degraded = proceed + record the gap. |
| `logging.py`    | Structured, run-scoped logging. Every log line is attributable to a run_id + module. |

## Why `SolidityID` is implemented once, here

```
Contract : "src/vault/Vault.sol:Vault"
Function : "src/vault/Vault.sol:Vault.deposit(uint256,address)"
StateVar : "src/vault/Vault.sol:Vault#totalAssets"
Modifier : "src/vault/Vault.sol:Vault.onlyOwner"
```

It joins `CodeModel`, `GraphModel`, Slither output, `ContextBundle`, and `Finding`. If two modules
compute it differently, static corroboration and context selection silently break. So: POSIX
repo-relative paths, canonical solc type names (`uint256` not `uint`), overloads disambiguated by
full signature, inherited functions addressed by their **defining** contract.
