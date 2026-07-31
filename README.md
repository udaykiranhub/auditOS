# AuditOS

An AI smart-contract security engine. It ingests an arbitrary Solidity protocol
(**ZIP / folder / git URL**) and produces an audit-grade `report.md` of high-signal,
protocol-aware findings — **not a linter dump**.

> **Thesis:** *Detection quality is a function of context quality. Everything else is plumbing.*
> The engine **understands the protocol before it reasons about it**, and hands every LLM call a
> deliberately constructed, minimal, ranked, deduplicated context window.

Single-user, local-first. **Ethereum / Solidity only** for now (other VMs are a future add).
Full design in [SPEC.md](SPEC.md) (Part 1 of 4).

## Repository layout

```
auditos/
├── engine/        # Python backend — the audit engine (see engine/README.md)
├── frontend/      # React + Vite + TS client — 4 screens (Upload/Progress/Logs/Download)
├── tests/         # golden-file tests + reference protocol fixtures
├── docs/          # design notes
├── run/           # per-run temp dirs + JSON artifact cache (gitignored)
├── reports/       # generated report.md output (gitignored)
├── SPEC.md        # the engineering specification (authoritative)
├── .env.example   # copy to .env and add API keys
└── .gitignore
```

The data-model spine (each arrow is a versioned Pydantic artifact):

```
RepoModel → CodeModel → GraphModel → ProtocolModel → ContextBundle → Finding[] → Report
```

## Prerequisites (verified installed)

| Tool     | Purpose                                  | Status |
|----------|------------------------------------------|--------|
| Python 3.13 | backend                               | ✅ |
| Node 22 / npm | frontend                            | ✅ |
| Foundry (`forge`) | build + storage layout + solc AST | ✅ |
| Slither  | primary static analyzer (a *prior*, not a finding source) | ✅ (in venv) |
| solc 0.8.28 (via solc-select) | RAW / direct-solc build path | ✅ |
| Aderyn   | secondary static analyzer                | ⏳ deferred (optional; missing binary = warning, not error) |

## Setup

### Backend
```bash
cd engine
python -m venv .venv
source .venv/Scripts/activate      # Windows (Git Bash);  .venv\Scripts\activate on cmd/PowerShell
pip install -r requirements.txt -r requirements-dev.txt
```

### Frontend
```bash
cd frontend
npm install
```

### Secrets
```bash
cp .env.example .env               # then add ANTHROPIC_API_KEY (primary) / OPENAI_API_KEY (fallback)
```

## Run (once code exists — scaffolding stage now)

```bash
# Backend API (the engine is fully usable from the CLI with no frontend — SPEC §4)
cd engine && uvicorn api.routes:app --reload --port 8000

# Frontend (proxies /audits → localhost:8000)
cd frontend && npm run dev
```

## Tests
```bash
cd engine && pytest          # golden-file snapshot tests for the deterministic core
```

## Design principles (SPEC §3)

P1 Data model is the architecture · P2 Deterministic core, probabilistic edge ·
P3 Context is the product · P4 Agents are prompts + contracts · P5 Every finding must be falsifiable ·
P6 Fail loud in core, soft at edge · P7 Two speeds of code (slow core / fast edge).

## Implementation order

`core/models` → `ingest` → `parse` → `graphs` → `protocol` → `context` → `agents` → `orchestrator` → `validate` → `report`.
