# AuditOS — Engine

The backend audit engine. **Local-first, single-user.** Fully usable from a CLI with no
frontend running (the frontend is just a client of the same API a human could `curl`).

## The one idea

> **Detection quality is a function of context quality. Everything else is plumbing.**

The engine does not "run Slither." It *understands the protocol* first, then hands every LLM
call a deliberately constructed, minimal, ranked, deduplicated context window.

## The spine: artifacts, not calls

Modules do **not** call each other's internals. They **transform artifacts**. Each arrow below
is a pure-ish function with a versioned Pydantic schema.

```
RepoModel → CodeModel → GraphModel → ProtocolModel → ContextBundle → Finding[] → Report
```

If you ever want module A to import module B's internals, you have missed an artifact.

## Directory map (which SPEC section owns each)

| Dir             | Role                                                        | SPEC |
|-----------------|-------------------------------------------------------------|------|
| `core/`         | SLOW-MOVING. Pydantic artifact models, IDs, errors, logging | §7   |
| `ingest/`       | ZIP/folder/git → `RepoModel`; project detection; build      | §9–10|
| `analysis/`     | Slither/Aderyn adapters → normalized `StaticFinding[]`      | §11  |
| `parse/`        | tree-sitter (+ solc AST enrichment) → `CodeModel`           | §12  |
| `graphs/`       | inheritance/calls/storage/imports → `GraphModel`           | §13  |
| `protocol/`     | graphs + heuristics + 1 LLM pass → `ProtocolModel` (Part 2)  | §7.6 |
| `context/`      | **THE CORE VALUE.** select→rank→compress→dedupe→budget (Pt2)| §6   |
| `agents/`       | FAST-MOVING. Declarative security agents, hot-loadable      | §8   |
| `orchestrator/` | DAG execution, bounded parallelism, retries, recovery       | §6   |
| `validate/`     | schema → falsifiability → dedupe → confidence               | §8   |
| `report/`       | validated findings + protocol → `report.md`                | §6   |
| `llm/`          | `LLMProvider` ABC — **the ONLY place SDKs are imported**    | §4   |
| `api/`          | FastAPI routes + SSE progress stream                        | §6   |

## Module contract registry (§8) — the truth table

| Module        | Reads                                | Writes             | Deterministic | On failure |
|---------------|--------------------------------------|--------------------|---------------|------------|
| Repo Reader   | raw input                            | `RepoModel`        | ✅            | **Fatal**  |
| Builder       | `RepoModel`                          | build artifacts    | ✅            | Degraded   |
| Static Anal.  | `RepoModel` + build                  | `StaticFinding[]`  | ✅            | Degraded   |
| Parser        | `RepoModel` (+ solc AST)             | `CodeModel`        | ✅            | Fatal if 0 |
| Graph Engine  | `CodeModel`                          | `GraphModel`       | ✅            | **Fatal**  |
| Protocol Und. | `CodeModel`,`GraphModel`,readme      | `ProtocolModel`    | ⚠️ 1 LLM call | **Fatal**  |
| Context Build | all above + `ContextRequest`         | `ContextBundle`    | ✅            | Fatal/req  |
| Agent         | `ContextBundle`                      | `Finding[]` (raw)  | ❌            | Degraded   |
| Validation    | raw `Finding[]`                      | validated findings | ✅            | **Fatal**  |
| Report        | validated findings, `ProtocolModel`  | `report.md`        | ✅            | **Fatal**  |

Everything is deterministic **except two boxes** (Protocol Understanding + Agent). Those two are
wrapped in schema validation on the way out. That is the whole architecture.

## Architecture principles (§3) — every decision traces to one

- **P1** The Data Model is the Architecture (transform artifacts, don't call internals).
- **P2** Deterministic core, probabilistic edge (LLM output is untrusted until validated).
- **P3** Context is the product (what goes into a prompt is core business logic).
- **P4** Agents are prompts + contracts, not classes with cleverness.
- **P5** Every finding must be falsifiable (no `attack_path` → rejected before the report).
- **P6** Fail loud in the core, fail soft at the edge (a failed subsystem is *stated*, never silently omitted).
- **P7** Two speeds of code: slow core vs fast edge. Never let edge concerns leak into the core.

## Implementation order

`core/models` → `ingest` → `parse` → `graphs` → (Part 2: `protocol` → `context` → `agents` → `orchestrator` → `validate` → `report`).

## Non-goals (V1) — do NOT build these "in case"

Auth · billing · multi-user · dashboards · databases · job persistence across restarts ·
non-Solidity languages · exploit PoC generation · CI integration · public API stability.



pedda@lenova MINGW64 /x/auditos (main)
$ engine/.venv/Scripts/python -m uvicorn engine.api.routes:app --reload --port 8000


pedda@lenova MINGW64 /x/auditos/frontend (main)
$ npm run dev

