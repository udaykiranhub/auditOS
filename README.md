# AuditOS

An AI smart-contract security engine. It ingests an arbitrary Solidity protocol
(**ZIP / folder / git URL**) and produces an audit-grade `report.md` of high-signal,
protocol-aware findings — **not a linter dump**.

> **Thesis:** *Detection quality is a function of context quality. Everything else is plumbing.*
> The engine **understands the protocol before it reasons about it**, and hands every LLM call a
> deliberately constructed, minimal, ranked, deduplicated context window.

Single-user, local-first. **Ethereum / Solidity only** for now (other VMs are a future add).

| Document | What it covers |
|---|---|
| [SPEC.md](SPEC.md) | The engineering specification — **authoritative** for all design decisions |
| [engine/README.md](engine/README.md) | Backend internals: module map, contract registry, implementation order |
| this file | Orientation, prerequisites, setup, how to run |

## How it works

The engine computes as much as possible deterministically, then spends its LLM budget
on reasoning rather than on rediscovering structural facts:

```
ZIP | Folder | Git URL
        ↓
Repo Reader        → RepoModel      files in scope, project kind, remappings
        ↓
Build (optional)   → solc AST, storage layout, method IDs   (degrades gracefully)
        ↓
Parser             → CodeModel      contracts, functions, state, modifiers
        ↓
Graph Engine       → GraphModel     inheritance, calls, storage, imports
        ↓
Protocol Under.    → ProtocolModel  actors, assets, entry points, value flows
        ↓
Context Builder    → ContextBundle  select → rank → compress → dedupe → budget
        ↓
Orchestrator       → runs the applicable security agents (DAG, bounded parallelism)
        ↓
Validation         → schema → falsifiability → dedupe → confidence
        ↓
Report             → report.md
```

Every arrow is a versioned Pydantic artifact. Modules transform artifacts; they never call
each other's internals.

Two consequences that are easy to miss:

1. **Protocol Understanding runs before the Context Builder**, and its output feeds every
   context request. Agents never see a raw repo — they see a protocol.
2. **Static analysis is a context source, not a finding source.** Slither output reaches the
   report only after an agent has reasoned about it and the validator has accepted it. Raw
   analyzer output is never emitted to the user.

## Repository layout

```
auditos/
├── engine/            # Python backend — the audit engine
│   ├── core/          #   Pydantic artifact models, IDs, errors
│   ├── ingest/        #   ZIP/folder/git → RepoModel; detection; ingest/build/ → forge|hardhat
│   ├── parse/         #   tree-sitter (+ solc AST enrichment) → CodeModel
│   ├── graphs/        #   inheritance / calls / storage / imports → GraphModel
│   ├── protocol/      #   graphs + heuristics + one LLM pass → ProtocolModel
│   ├── context/       #   THE CORE VALUE — select/rank/compress/dedupe/budget
│   ├── analysis/      #   Slither + Aderyn adapters → normalized StaticFinding[]
│   ├── agents/        #   declarative security agents (prompts + contracts)
│   ├── orchestrator/  #   DAG execution, retries, recovery
│   ├── validate/      #   schema, falsifiability, dedupe, confidence
│   ├── report/        #   validated findings + protocol → report.md
│   ├── llm/           #   LLMProvider ABC — the ONLY place LLM SDKs are imported
│   └── api/           #   FastAPI routes + SSE progress stream
├── frontend/          # React + Vite + TS client — 4 screens (Upload/Progress/Logs/Download)
├── tests/             # golden-file tests + reference protocol fixtures
├── docs/              # design notes
├── run/               # per-run temp dirs + JSON artifact cache (gitignored)
├── reports/           # generated report.md output (gitignored)
├── SPEC.md            # the engineering specification (authoritative)
└── .env.example       # copy to .env and add API keys
```

## Prerequisites

| Tool | Purpose | Status |
|---|---|---|
| Python 3.11+ (dev machine: 3.13) | backend | ✅ |
| Node 22 / npm | frontend | ✅ |
| Foundry (`forge`) | build + storage layout + solc AST | ✅ |
| Slither | primary static analyzer (a *prior*, not a finding source) | ✅ (installed in `engine/.venv`) |
| solc 0.8.28 (via `solc-select`) | RAW / direct-solc build path | ✅ |
| Aderyn | secondary static analyzer | ⏳ deferred — optional; a missing binary is a warning, not an error |

## Setup

### Backend

```bash
cd engine
python -m venv .venv
source .venv/Scripts/activate      # Git Bash;  .venv\Scripts\activate on cmd/PowerShell
pip install -r requirements.txt -r requirements-dev.txt
```

> **Windows note:** the Solidity grammar comes from `tree-sitter-language-pack`, not the
> standalone `tree-sitter-solidity` wheel — the latter's ABI mismatches the tree-sitter core.
> Import it as `from tree_sitter_language_pack import get_parser`.

### Frontend

```bash
cd frontend
npm install
```

### Secrets

```bash
cp .env.example .env
```

Then fill in `ANTHROPIC_API_KEY` (primary provider). `OPENAI_API_KEY` is optional — it backs
the fallback / second-opinion path. `.env` also carries model selection, API host/port, and the
run directory; see [.env.example](.env.example) for the full list. Keys are read only inside
`engine/llm/`.

## Running

The engine is a CLI first. Today one stage is implemented — the Repository Reader:

```bash
python -m engine ingest <path | file.zip | git-url>
```

```
Project: FOUNDRY   (origin: folder)
Solidity: 0.8.28  [foundry.toml]

Solidity files: 8
In scope:       4
Tests:          3
Mocks:          1
Dependencies:   1
Interfaces:     1

RepoModel written to:
  run/<run_id>/artifacts/repo.json
```

Useful flags: `--ref` (git branch/tag/commit), `--include GLOB` / `--exclude GLOB` (override the
scope heuristics; exclude wins), `--run-root` (where run directories live).

There is also a **Phase 1 harness** — upload a repo in the browser and inspect the
`RepoModel` the reader produced. Two terminals, both from the repository root:

```bash
# 1. API (ingest endpoints only — the rest of the pipeline doesn't exist yet)
engine/.venv/Scripts/python -m uvicorn engine.api.routes:app --reload --port 8000

# 2. Frontend — http://localhost:5173, proxies /audits → :8000
cd frontend && npm run dev
```

The backend is fully usable from the CLI with no frontend running. The frontend is a client of
the same API a human could `curl` — that is a hard rule, not a convention.

## Tests

```bash
cd engine && pytest        # golden-file snapshot tests for the deterministic core
```

## Design principles (SPEC §3)

Every decision in this repo traces to one of these:

- **P1** The data model is the architecture — transform artifacts, don't call internals.
- **P2** Deterministic core, probabilistic edge — LLM output is untrusted until validated.
- **P3** Context is the product — what goes into a prompt is core business logic.
- **P4** Agents are prompts + contracts, not classes with cleverness.
- **P5** Every finding must be falsifiable — no attack path, no report entry.
- **P6** Fail loud in the core, fail soft at the edge — a failed subsystem is *stated*, never silently omitted.
- **P7** Two speeds of code — slow core, fast edge; edge concerns never leak inward.

A finding is only accepted if it carries a concrete target, a concrete actor, preconditions, an
ordered attack path, a consequence, source evidence, and the broken invariant where applicable.

## Scope

**V1 covers:** Solidity · Foundry + Hardhat detection · repository ingestion · tree-sitter parsing ·
solc enrichment · call / storage / inheritance / import graphs · protocol modeling · context
engineering · Slither integration · specialized security agents · validation · deduplication ·
Markdown report generation.

**Explicitly out of scope for V1:** auth · billing · multi-user · dashboards · databases · job
persistence across restarts · non-Solidity languages · exploit PoC generation · CI integration ·
public API stability.

## Status

🚧 **Early development.** Modules land in artifact order — each one is finished and tested
before the next begins:

| Stage | Artifact | Status |
|---|---|---|
| `core/models`, `core/artifacts`, `core/errors` | — | ✅ |
| `ingest` — Repository Reader | `RepoModel` | ✅ |
| `ingest/build` — Foundry / Hardhat | solc AST, storage layout | ⏳ next |
| `parse` | `CodeModel` | ⏳ |
| `graphs` | `GraphModel` | ⏳ |
| `protocol` → `context` → `agents` → `orchestrator` → `validate` → `report` | … → `report.md` | ⏳ |

## Disclaimer

AuditOS is an experimental security research tool. AI-generated results may contain false
positives, false negatives, or incorrect reasoning. Findings must be reviewed by an experienced
security researcher before being treated as confirmed vulnerabilities.

## Author

**Uday Kiran Pedda** — Blockchain & MERN developer, smart-contract security researcher
([`udaykiranhub`](https://github.com/udaykiranhub))

## License

To be determined.
