# AI Smart Contract Security Engine — Engineering Specification

**Document type:** AI-First Engineering Specification
**Status:** Part 1 of 4 (Foundation + Ingestion/Graph layer)
**Audience:** Human implementer and AI coding agent (Claude Code)
**Rule for this document:** every section states a *contract*. If a section does not constrain an interface, an algorithm, or an acceptance criterion, it does not belong here.

---

## Table of Contents

**Part 1 (this document)**
1. Vision
2. Goals / Non-Goals
3. Architecture Philosophy
4. Technology Stack
5. Folder Structure
6. The Canonical Pipeline
7. The Data Model (the spine of the system)
8. Module Contract Registry
9. Repository Reader
10. Build Pipeline (Foundry / Hardhat)
11. Static Analysis Adapters (Slither / Aderyn)
12. Parsing Engine (Tree-sitter → AST)
13. Graph Engine (Inheritance / Call / Storage / Dependency)

**Part 2 (next)** — Protocol Understanding, Context Engineering (the 35%), Retrieval, Compression, Ranking
**Part 3** — Agent Framework, Agent Registry/Lifecycle, all security agents
**Part 4** — Orchestrator, Validation/Confidence/Dedup, Report Generator, Frontend, Roadmap

---

# 1. Vision

A single-user, local-first engine that ingests an arbitrary Solidity protocol (ZIP / folder / git URL) and produces an audit-grade `report.md` containing high-signal, protocol-aware findings — not a linter dump.

The differentiating claim of this system is **not** that it runs Slither. It is that it *understands the protocol* before it reasons about it, and that every LLM call receives a deliberately constructed, minimal, ranked, deduplicated context window rather than a pile of source files.

**One-line thesis:** *Detection quality is a function of context quality. Everything else is plumbing.*

---

# 2. Goals / Non-Goals

## 2.1 Goals

| # | Goal | Measurable form |
|---|---|---|
| G1 | Understand protocol before auditing | A `ProtocolModel` is produced and is a required input to every security agent |
| G2 | High-signal findings | Business-logic / economic / accounting classes of bug, not gas or style |
| G3 | Context engineering as a first-class subsystem | Context Builder is independently testable and independently measurable |
| G4 | Extensibility | A new agent is added by dropping one file + one registry entry, with **zero** changes to the orchestrator |
| G5 | Determinism where possible | Everything up to the LLM boundary (parse, graph, context selection) is deterministic and snapshot-testable |
| G6 | Auditability of the engine itself | Every finding carries the exact context slice, prompt hash, and agent version that produced it |

## 2.2 Non-Goals (V1)

Auth. Billing. Multi-user. Dashboards. Databases. Job persistence across restarts. Non-Solidity languages (Vyper, Move, Rust). Automatic exploit PoC generation. CI integration. Public API stability.

> **Do not design for these.** Do not add abstraction layers "in case." Every speculative abstraction is a maintenance tax paid in advance for a feature that may never exist.

## 2.3 Explicit anti-goals

- **Do not optimize for latency.** A 20-minute audit that finds a logic bug beats a 40-second audit that finds 11 reentrancy false positives.
- **Do not chase coverage metrics.** "Number of findings" is an anti-metric. It rewards noise.
- **Do not build a chat interface.** The engine is a pipeline, not a conversation.

---

# 3. Architecture Philosophy

Seven principles. Every design decision in this document traces back to one of them.

### P1 — The Data Model is the Architecture
Modules do not call each other. Modules **transform artifacts**. `RepoModel → CodeModel → GraphModel → ProtocolModel → ContextBundle → Findings → Report`. Each arrow is a pure-ish function with a versioned schema. This is what makes the system testable, resumable, and drift-proof.

*Consequence:* if you find yourself wanting Module A to import Module B's internals, you have missed an artifact.

### P2 — Deterministic Core, Probabilistic Edge
Everything before the LLM is deterministic. Everything the LLM touches is treated as untrusted output requiring validation. The LLM is a *component*, not the system.

*Consequence:* the parse/graph/context layers get golden-file tests. The agent layer gets schema validation + validators, not equality tests.

### P3 — Context is the Product
The scarce resource is not compute or tokens; it is *the reader's attention* — where "the reader" is a model with a fixed window and no persistence. Any code that decides **what goes into a prompt** is core business logic and deserves the same rigor as a consensus algorithm.

### P4 — Agents are Prompts + Contracts, not Classes with Cleverness
An agent is a declarative record: what context it needs, what schema it emits, what it must ignore. The framework does everything else (retries, validation, budgeting, logging). Agents contain **no orchestration logic**. If an agent knows about another agent, the design is wrong.

### P5 — Every Finding Must Be Falsifiable
A finding without a concrete state, a concrete actor, and a concrete consequence is noise. The schema enforces this: no `attack_path` → the finding is rejected before it reaches the report.

### P6 — Fail Loud in the Core, Fail Soft at the Edge
A parse error is fatal (you cannot audit what you cannot read). An agent timeout is degraded-but-survivable (report proceeds, agent marked `FAILED`, report states the gap explicitly). *A report must never silently omit a subsystem that failed.*

### P7 — Two Speeds of Code
- **Slow-moving core:** data model, graph engine, context builder, orchestrator. Changed rarely, reviewed carefully, heavily tested.
- **Fast-moving edge:** agents, prompts, heuristics. Changed constantly, hot-loadable, versioned.

Never let edge concerns leak into the core. This is the single most important structural rule in the document.

---

# 4. Technology Stack

| Layer | Choice | Rationale / constraint |
|---|---|---|
| Backend | Python 3.11+, FastAPI | Async orchestration, native to the security tooling ecosystem |
| Concurrency | `asyncio` + bounded semaphores | Agents are IO-bound (LLM calls). No multiprocessing in V1. |
| Parser | Tree-sitter (`tree-sitter-solidity`) | Error-tolerant, fast, works on non-compiling code. **Primary.** |
| Compiler AST | `solc --ast-compact-json` via Foundry | Precise types, resolved references. **Secondary/enrichment.** See §12.1 |
| Graph | NetworkX | Adequate at protocol scale (<5k nodes). Do not reach for a graph DB. |
| Static analysis | Slither (primary), Aderyn (secondary) | Adapters, not dependencies — see §11 |
| Build | Foundry (`forge build`) | Hardhat supported via detection, but Foundry is the happy path |
| LLM | Anthropic Claude API (primary), OpenAI (fallback/second-opinion) | Both behind one `LLMProvider` interface. **No SDK types may leak past this interface.** |
| Validation | Pydantic v2 | Every artifact is a Pydantic model. This is non-negotiable — it is how P1 and P2 are enforced mechanically. |
| Storage | Temp dirs + JSON artifact cache on disk | No DB in V1. The artifact cache doubles as the resume mechanism. |
| Frontend | React + Vite + TypeScript | Four screens total: Upload, Progress, Logs, Download |

**Hard rule:** the backend must be usable entirely from a CLI with no frontend running. The frontend is a client of the same API a human could `curl`.

---

# 5. Folder Structure

```
engine/
  core/                      # SLOW-MOVING. Review carefully.
    models/                  # Pydantic artifacts — the spine (§7)
      repo.py                # RepoModel, SourceFile, ProjectKind
      code.py                # CodeModel, Contract, Function, StateVar
      graphs.py              # GraphModel + typed edge/node records
      protocol.py            # ProtocolModel, Actor, Asset, Invariant
      context.py             # ContextBundle, ContextItem, Budget
      findings.py            # Finding, AttackPath, Confidence, Severity
      report.py              # ReportModel
    artifacts.py             # save/load/hash/version artifacts to disk
    errors.py                # FatalError vs DegradedError (P6)
    logging.py               # structured, run-scoped

  ingest/
    reader.py                # ZIP / folder / git → RepoModel
    detect.py                # ProjectKind detection
    build/
      foundry.py
      hardhat.py
      base.py                # Builder interface

  analysis/
    slither/adapter.py       # → normalized StaticFinding[]
    aderyn/adapter.py
    base.py                  # StaticAnalyzer interface

  parse/
    treesitter.py            # source → CodeModel
    solc_ast.py              # enrichment pass
    normalize.py             # merge + canonicalize

  graphs/
    inheritance.py
    calls.py
    storage.py
    imports.py
    build.py                 # → GraphModel

  protocol/                  # Part 2
    understand.py            # GraphModel + CodeModel → ProtocolModel
    heuristics/              # deterministic detectors (ERC20, vault, oracle…)

  context/                   # Part 2 — THE CORE VALUE
    builder.py
    select.py                # relevance
    rank.py                  # importance
    compress.py              # summarize / elide
    budget.py                # token accounting
    dedupe.py

  agents/                    # FAST-MOVING. Hot-loadable.
    framework/
      base.py                # Agent ABC
      registry.py
      lifecycle.py
      spec.py                # AgentSpec (declarative)
    security/
      access_control.py
      business_logic.py
      math.py
      oracle.py
      ...                    # one file per agent
    prompts/                 # prompt templates, versioned, NOT in .py

  orchestrator/
    engine.py                # DAG execution
    scheduler.py
    recovery.py

  validate/
    schema.py
    dedupe.py
    confidence.py
    falsifiability.py        # P5 enforcement

  report/
    generate.py
    templates/

  llm/
    provider.py              # LLMProvider ABC — the ONLY place SDKs are imported
    anthropic.py
    openai.py
    budget.py

  api/
    routes.py                # upload, status, logs, report
    stream.py                # SSE progress

frontend/
  src/{pages,components,hooks,api}/

tests/
  golden/                    # snapshot tests for deterministic core
  fixtures/protocols/        # real protocols, checked in as submodules or ZIPs
```

**Developer Notes**
- *Implementation order:* `core/models` → `ingest` → `parse` → `graphs` → (Part 2)
- *Common mistake:* putting agent-specific logic in `context/`. Context Builder must be agent-agnostic; it serves *requests*, it does not know who is asking beyond a declarative `ContextRequest`.
- *Common mistake:* importing `anthropic` outside `llm/`. Grep for this in CI.

---

# 6. The Canonical Pipeline

```
  ZIP | Folder | Git URL
          │
          ▼
   ┌──────────────┐
   │ Repo Reader  │──► RepoModel        (files, kind, config, remappings)
   └──────────────┘
          │
          ├────────────────────────────────┐
          ▼                                ▼
   ┌──────────────┐                 ┌──────────────┐
   │ Build (opt.) │                 │   Parser     │──► CodeModel
   │ forge build  │                 │  tree-sitter │    (contracts, fns,
   └──────────────┘                 └──────────────┘     state, modifiers)
          │                                │
          │  solc AST (enrichment)         │
          └───────────────┬────────────────┘
                          ▼
                  ┌──────────────┐
                  │ Graph Engine │──► GraphModel
                  └──────────────┘    (inherit, calls, storage, imports)
                          │
          ┌───────────────┴───────────────┐
          ▼                               ▼
  ┌──────────────┐               ┌─────────────────┐
  │ Static Anal. │──► Static     │   Protocol      │──► ProtocolModel
  │ Slither/Ade. │    Findings   │  Understanding  │    (actors, assets,
  └──────────────┘               └─────────────────┘     flows, invariants)
          │                               │
          └───────────────┬───────────────┘
                          ▼
                  ┌──────────────┐
                  │   Context    │◄──── ContextRequest (from each agent spec)
                  │   Builder    │────► ContextBundle  (ranked, compressed,
                  └──────────────┘                      deduped, budgeted)
                          │
                          ▼
                  ┌──────────────┐
                  │ Orchestrator │  DAG, bounded parallelism, retries
                  └──────────────┘
                          │
              ┌───────────┼───────────┐
              ▼           ▼           ▼
          Agent A     Agent B     Agent N     (each: LLM call → Finding[])
              │           │           │
              └───────────┼───────────┘
                          ▼
                  ┌──────────────┐
                  │  Validation  │  schema → falsifiability → dedupe → confidence
                  └──────────────┘
                          │
                          ▼
                  ┌──────────────┐
                  │    Report    │──► report.md
                  └──────────────┘
```

**Two facts this diagram encodes that are easy to miss:**
1. **Protocol Understanding runs *before* the Context Builder, and its output is an input to every context request.** Agents never see raw repos; they see a protocol.
2. **Static analysis is a *context source*, not a finding source.** Slither output enters the report only after an agent has reasoned about it and the validator has accepted it. Raw Slither output is never emitted to the user. (See §11.3 — this is a deliberate, opinionated choice.)

---

# 7. The Data Model (the spine)

> This is the most important section in Part 1. Every subsequent module is defined by which of these it reads and which it writes. Get this wrong and every downstream section inherits the error.

## 7.1 Artifact rules

1. Every artifact is a Pydantic v2 model with `schema_version: str`.
2. Every artifact is serializable to JSON and written to `run/<run_id>/artifacts/<name>.json`.
3. Every artifact has a `content_hash` derived from its inputs → enables caching and resume.
4. **Artifacts are append-only within a run.** A module never mutates an upstream artifact; it produces a new one.

## 7.2 Identity: the `SolidityID`

Everything is addressed by a stable, human-readable ID. Do this once, correctly, or you will fight ambiguity forever.

```
Contract : "src/vault/Vault.sol:Vault"
Function : "src/vault/Vault.sol:Vault.deposit(uint256,address)"
StateVar : "src/vault/Vault.sol:Vault#totalAssets"
Modifier : "src/vault/Vault.sol:Vault.onlyOwner"
```

Rules: path is repo-relative and POSIX; function signature uses canonical solc type names (`uint256` not `uint`); overloads are disambiguated by the full signature; inherited functions are addressed by their **defining** contract, never the inheriting one.

*This ID is the join key between CodeModel, GraphModel, Slither output, ContextBundle, and Findings.* Every module must produce it identically. Implement it **once**, in `core/models/ids.py`, with a single `make_id()` and property-based tests for round-tripping.

## 7.3 `RepoModel`

```python
class SourceFile(BaseModel):
    path: str                 # repo-relative, POSIX
    sha256: str
    loc: int
    is_test: bool
    is_mock: bool
    is_dependency: bool       # lib/, node_modules/, openzeppelin, etc.
    is_interface_only: bool

class RepoModel(BaseModel):
    schema_version: str
    root: str                 # absolute temp path
    origin: Literal["zip", "folder", "git"]
    kind: ProjectKind         # FOUNDRY | HARDHAT | RAW | UNKNOWN
    files: list[SourceFile]
    solidity_version: str | None
    remappings: dict[str, str]
    config_raw: dict          # foundry.toml / hardhat.config parsed
    readme: str | None
    docs: list[str]           # paths to /docs, *.md specs
```

**`is_dependency` / `is_test` / `is_mock` are the highest-leverage fields in this model.** They are what stop the engine from auditing OpenZeppelin for the tenth time. See §9.3.

## 7.4 `CodeModel`

```python
class Function(BaseModel):
    id: str                          # SolidityID
    name: str
    contract_id: str
    visibility: Literal["public","external","internal","private"]
    mutability: Literal["pure","view","nonpayable","payable"]
    is_constructor: bool
    is_fallback: bool
    is_receive: bool
    modifiers: list[str]
    params: list[Param]
    returns: list[Param]
    src_start: int; src_end: int     # byte offsets
    line_start: int; line_end: int
    body_hash: str                   # for dedupe across inheritance
    raw: str                         # the actual source text. Yes, store it.

class StateVar(BaseModel):
    id: str
    name: str
    type: str
    slot: int | None                 # from storage layout, if built
    is_constant: bool
    is_immutable: bool
    visibility: str

class Contract(BaseModel):
    id: str
    name: str
    path: str
    kind: Literal["contract","interface","library","abstract"]
    inherits: list[str]              # direct parents, as SolidityIDs
    functions: list[Function]
    state_vars: list[StateVar]
    modifiers: list[Function]
    events: list[str]
    natspec: str | None
    is_dependency: bool              # propagated from SourceFile

class CodeModel(BaseModel):
    schema_version: str
    contracts: list[Contract]
    parse_errors: list[ParseError]   # non-fatal; tree-sitter is error-tolerant
```

**Design note — why `raw: str` is on `Function` and not fetched lazily from disk:** the Context Builder slices at *function* granularity, hundreds of times per run. Making that an IO operation guarded by offsets is a false economy that will produce off-by-one bugs at scale. Store the text. A large protocol is a few MB.

## 7.5 `GraphModel`

Four graphs, one artifact. All node IDs are `SolidityID`s so they join with everything else.

```python
class GraphModel(BaseModel):
    schema_version: str
    inheritance: DiGraph   # Contract → parent Contract (C3-linearized order preserved)
    calls: DiGraph         # Function → Function; edge attrs: kind, is_external, is_delegate, via_interface
    storage_reads: DiGraph # Function → StateVar
    storage_writes: DiGraph# Function → StateVar
    imports: DiGraph       # File → File
```

Serialization: NetworkX `node_link_data`. Do not invent your own format.

## 7.6 `ProtocolModel` (defined fully in Part 2, declared here)

The join of graphs + heuristics + one LLM synthesis pass. Declared now because every later contract depends on it:

```python
class ProtocolModel(BaseModel):
    summary: str                     # 200-400 words, the "what is this"
    archetype: list[str]             # ["lending","vault","amm","staking",...]
    actors: list[Actor]              # user, admin, keeper, liquidator, oracle
    assets: list[Asset]              # tokens, shares, collateral
    entrypoints: list[str]           # SolidityIDs — external/public, non-view
    privileged: list[str]            # entrypoints gated by admin roles
    value_flows: list[ValueFlow]     # who can move what, under what condition
    invariants: list[Invariant]      # candidate, LLM-proposed + heuristic
    trust_assumptions: list[str]
    core_contracts: list[str]        # ranked; drives context selection
    external_deps: list[str]         # oracles, DEXes, bridges
```

## 7.7 `Finding`

```python
class AttackPath(BaseModel):
    preconditions: list[str]         # concrete state required
    actor: str                       # who calls it
    steps: list[str]                 # ordered, each references a SolidityID
    consequence: str                 # what is lost / broken
    profitability: str | None        # for economic findings

class Finding(BaseModel):
    id: str                          # deterministic hash of (agent, target, title)
    agent: str
    agent_version: str
    severity: Literal["critical","high","medium","low","info"]
    title: str
    target: list[str]                # SolidityIDs — REQUIRED, ≥1
    description: str
    attack_path: AttackPath          # REQUIRED (P5). No path → rejected.
    invariant_broken: str | None
    confidence: float                # 0..1, computed by validator, NOT by the agent
    evidence: list[str]              # code excerpts w/ line refs
    static_corroboration: list[str]  # slither/aderyn detector IDs that agree
    provenance: Provenance           # prompt_hash, context_bundle_id, model, tokens
```

**`confidence` is computed by the validation layer, never self-reported by the agent.** Models are systematically overconfident and their self-reported confidence is uncorrelated with correctness. See Part 4 §Confidence.

---

# 8. Module Contract Registry

The one-page truth table. If a module's actual imports disagree with this table, the module is wrong.

| Module | Reads | Writes | Deterministic? | Failure mode (P6) |
|---|---|---|---|---|
| Repo Reader | raw input | `RepoModel` | ✅ | **Fatal** |
| Builder | `RepoModel` | build artifacts, storage layout | ✅ | **Degraded** (proceed w/o solc AST) |
| Static Analysis | `RepoModel` + build | `StaticFinding[]` | ✅ | **Degraded** |
| Parser | `RepoModel` (+ solc AST) | `CodeModel` | ✅ | **Fatal** if 0 contracts parsed |
| Graph Engine | `CodeModel` | `GraphModel` | ✅ | **Fatal** |
| Protocol Understanding | `CodeModel`, `GraphModel`, `RepoModel.readme` | `ProtocolModel` | ⚠️ 1 LLM call | **Fatal** (P1: nothing downstream works without it) |
| Context Builder | all above + `ContextRequest` | `ContextBundle` | ✅ | **Fatal** per-request |
| Agent | `ContextBundle` | `Finding[]` (raw) | ❌ | **Degraded** |
| Validation | raw `Finding[]` | validated `Finding[]` | ✅ | **Fatal** |
| Report | validated `Finding[]`, `ProtocolModel` | `report.md` | ✅ | **Fatal** |

**Read this column-wise once:** everything is deterministic except two boxes. That is the whole architecture. The two probabilistic boxes are wrapped in schema validation on the way out.

---

# 9. Repository Reader

**Purpose** — Turn any of three input shapes into one `RepoModel`, and make the single most consequential judgment in the pipeline: *what code is in scope*.

**Input** — `ZIP bytes | local path | git URL (+ optional ref)`
**Output** — `RepoModel`
**Dependencies** — none
**Failure** — Fatal

## 9.1 Algorithm

1. **Materialize** into `run/<run_id>/repo/`.
   - ZIP: extract with **zip-slip protection** (reject any entry whose resolved path escapes root). Reject archives >200MB or >20k entries.
   - Git: `git clone --depth 1`. If the repo has submodules and is Foundry, `--recurse-submodules` (Foundry deps *are* submodules — skipping this breaks the build).
   - Folder: copy, do not symlink (the run must be immutable against user edits mid-run).
2. **Detect** `ProjectKind` (§9.2).
3. **Enumerate** `*.sol`, compute hashes/LOC.
4. **Classify** each file: test / mock / dependency / interface-only (§9.3).
5. **Extract config**: `foundry.toml` → `src`, `out`, `libs`, `remappings.txt`; `hardhat.config.*` → best-effort regex for `paths` and `solidity.version` (do **not** execute the config file — it is arbitrary JS. Parse it as text.).
6. **Locate docs**: `README*`, `/docs/**/*.md`, `SPEC*`, whitepaper PDFs (record path only; PDF parsing is out of scope for V1).

## 9.2 Project detection

| Signal | Kind | Confidence |
|---|---|---|
| `foundry.toml` present | FOUNDRY | high |
| `hardhat.config.{js,ts}` present | HARDHAT | high |
| both present | FOUNDRY | high — prefer Foundry, note in log |
| `package.json` w/ `hardhat` dep | HARDHAT | medium |
| only `*.sol` files | RAW | — parse-only mode, no build, no Slither-with-compile |
| no `*.sol` files | **fatal** | abort with a clear error |

## 9.3 Scope classification — the highest-leverage heuristic in the system

```
is_dependency  ← path matches: lib/, node_modules/, /vendor/, /external/,
                 or package is a known library (openzeppelin, solmate,
                 solady, forge-std, ds-test, chainlink, uniswap-v2/v3-core,
                 permit2, layerzero, create3)
is_test        ← path matches test/, tests/, *.t.sol, *Test.sol, script/, *.s.sol
is_mock        ← path or contract name matches mock/, Mock*, Fake*, Stub*, Harness*
is_interface_only ← file contains only `interface` declarations
```

**Then:** *in-scope = not dependency AND not test AND not mock.*

**Developer Notes**
- *Why this matters more than it looks:* on a real protocol, 85–95% of `.sol` files are out of scope. Getting this wrong doesn't just waste tokens — it actively poisons the audit, because agents will "find" bugs in OpenZeppelin, mocks contain deliberately broken code, and test files contain attack code that pattern-matches as vulnerable.
- **Do not delete out-of-scope files.** They are still needed for: compilation, inheritance resolution (a Vault inheriting `ERC4626` needs the parent parsed), and call-graph completeness. They are *parsed and graphed but never audited and rarely contextualized.* The flag propagates; it does not filter.
- *Escape hatch:* the API must accept a `scope_override: {include: [...], exclude: [...]}`. Heuristics will be wrong on some protocol and the user must be able to fix it without editing code.
- *Common mistake:* treating a fork/vendored copy of a known library (e.g. a *modified* OZ ERC20 pasted into `src/`) as a dependency. It is in `src/`, it is modified, it is **in scope**. Classify by *path first*, name second. Never by name alone.

## 9.4 Acceptance criteria

- Given the same input, `RepoModel` is byte-identical across runs (modulo `root`).
- Zip-slip payload is rejected with a `FatalError`, not an exception trace.
- On 5 checked-in reference protocols (one Foundry, one Hardhat, one raw, one monorepo, one with heavy submodules), `kind` and in-scope file count match a hand-labeled golden file.

## 9.5 Extension points

Additional origins (IPFS, Etherscan verified-source pull by address) implement the same `Reader` interface → `RepoModel`. Etherscan-by-address is the highest-value future addition and should be kept in mind, but not built.

---

# 10. Build Pipeline

**Purpose** — Obtain the two things only a compiler can give you: a **resolved AST** and a **storage layout**. Everything else the parser can do alone.

**Input** — `RepoModel`
**Output** — `solc` standard-JSON AST per file; storage layout per contract; compiler version
**Failure** — **Degraded.** A protocol that does not compile must still be auditable. This is not optional: audit targets are frequently mid-refactor, missing deps, or pinned to unavailable solc versions.

## 10.1 Algorithm

```
if kind == FOUNDRY:
    forge build --extra-output storageLayout evm.methodIdentifiers --ast
    read out/**/*.json
elif kind == HARDHAT:
    try: npx hardhat compile  (timeout 300s, no network → likely fails)
    on failure → fall back to direct solc
else:
    direct solc: resolve version from pragma, fetch via solc-select, compile with
                 --standard-json, remappings synthesized from lib/ + node_modules/
```

On any failure: log `BUILD_DEGRADED`, set `build_available = False`, continue.

## 10.2 What degrades when the build fails

| Capability | Build OK | Build failed |
|---|---|---|
| Contract/function/state extraction | ✅ | ✅ (tree-sitter) |
| Inheritance graph | ✅ | ✅ (textual resolution, ~95% accurate) |
| Call graph — internal | ✅ | ✅ |
| Call graph — external/interface | ✅ precise | ⚠️ heuristic (name+arity matching) |
| **Storage slots / packing** | ✅ | ❌ **lost** |
| Type resolution (aliases, user-defined types) | ✅ | ⚠️ textual |
| Slither | ✅ | ❌ (Slither requires compilation) |
| Aderyn | ✅ | ✅ (AST-based, more tolerant) |

**The report must state, in a "Coverage & Limitations" section, exactly which of these degraded.** An audit that silently ran without storage layout while a Storage/Upgradeability agent claimed to check slot collisions is worse than no audit. (P6.)

**Developer Notes**
- *Timeouts:* `forge build` on a large monorepo can exceed 5 minutes cold. 600s timeout, stream logs to the progress channel — the user must see it working.
- *Common mistake:* running `forge build` in a network-restricted environment and getting a submodule failure that looks like a compile failure. Distinguish these in the error message; they have different fixes.

---

# 11. Static Analysis Adapters

**Purpose** — Cheap, deterministic, high-recall priors. Not findings. **Priors.**

**Input** — `RepoModel` + build artifacts
**Output** — `list[StaticFinding]` — normalized, tool-agnostic
**Failure** — Degraded

## 11.1 The normalized `StaticFinding`

```python
class StaticFinding(BaseModel):
    tool: Literal["slither","aderyn"]
    detector: str            # e.g. "reentrancy-eth"
    tool_severity: str
    target: list[str]        # SolidityIDs — the adapter's job is this mapping
    lines: list[int]
    message: str
    raw: dict
```

**The entire difficulty of this module is `target`.** Slither's JSON emits its own element addressing; mapping it to your `SolidityID` (§7.2) is fiddly and must be unit-tested against fixtures. If this mapping is sloppy, static corroboration silently stops working and you will not notice — the findings just get quietly less accurate. Test it explicitly.

## 11.2 Adapter interface

```python
class StaticAnalyzer(Protocol):
    name: str
    def available(self) -> bool: ...
    def run(self, repo: RepoModel, build: BuildArtifacts | None) -> list[StaticFinding]: ...
```

Run all available analyzers concurrently. A missing binary is a warning, not an error.

## 11.3 The opinionated part: static findings are context, not output

Raw Slither output **never** reaches `report.md`.

Three uses only:
1. **Context signal.** `StaticFinding[]` for a given contract is injected into that agent's `ContextBundle` as a *hint block*, explicitly framed to the model as: *"A static analyzer flagged the following. Static analyzers have high false-positive rates on business-logic-relevant patterns. Verify or dismiss each with reference to the protocol's actual invariants."*
2. **Corroboration.** If an agent independently produces a finding that overlaps a static finding's target+class, `Finding.static_corroboration` is populated → confidence boost in validation.
3. **Ranking prior.** Functions with static hits get a small boost in context importance ranking (§Part 2).

**Rationale:** the user can run Slither themselves in 30 seconds. The product's value is exclusively in what Slither *cannot* find. Emitting Slither's output as findings would (a) add zero value, (b) drown the real findings in noise, and (c) make the report's precision indistinguishable from a linter's. This is a deliberate product decision, and it should be revisited only with data.

**Counter-consideration, stated honestly:** this means a true positive that *only* Slither found (and no agent independently rediscovered) will be dropped. Mitigation: the Reentrancy/Access agents receive the static hints in context specifically so they have the chance to rediscover them with reasoning attached. Track this: if agents routinely fail to rediscover valid static findings, the decision above is wrong and should be reversed to "static findings appear in an appendix section, clearly labeled and separated."

---

# 12. Parsing Engine

**Purpose** — `RepoModel (+solc AST) → CodeModel`.

## 12.1 Two-source strategy

| | Tree-sitter | solc AST |
|---|---|---|
| Works on broken code | ✅ | ❌ |
| Precise types | ❌ | ✅ |
| Resolved references | ❌ | ✅ |
| Speed | fast | slow |
| Availability | always | only if build succeeded |

**Rule: tree-sitter is the source of truth for *structure*; solc is an *enrichment* pass for *semantics*.**

```
CodeModel = normalize( treesitter_parse(files) ⊕ solc_enrich(ast) )
```

Never invert this. If you make solc primary, the whole engine breaks on the exact protocols most likely to have bugs (the ones that don't cleanly build). If you skip solc entirely, you lose storage slots and type resolution. Merge, with tree-sitter winning on structure and solc winning on types/slots.

Merge conflicts (a contract solc knows about that tree-sitter missed, or vice versa) → log at WARNING, keep the union, flag in `parse_errors`. Do not silently drop.

## 12.2 Extraction requirements

Per contract: name, kind, direct parents, NatSpec.
Per function: signature, visibility, mutability, modifiers, params/returns, **raw source text**, line span, `body_hash`.
Per state var: name, type, constant/immutable, visibility, slot (solc only).

**Do not attempt full expression-level AST modeling in `CodeModel`.** You will be tempted. Resist. The LLM reads the raw source; you do not need a symbolic representation of every expression, and building one is a multi-month detour. `CodeModel` exists to make code *addressable, sliceable, and graphable* — not to make it *interpretable*. That's the model's job.

This is the single biggest scope trap in the project.

## 12.3 Acceptance criteria

- Golden-file test: for each of the 5 reference protocols, `CodeModel` contract/function counts match hand-labeled expectations exactly.
- Every `Function.id` round-trips through `make_id()` unchanged.
- On a deliberately broken `.sol` file (missing brace), the parser produces a partial `CodeModel` + a `ParseError`, and does not raise.

---

# 13. Graph Engine

**Purpose** — Turn `CodeModel` into the four graphs that make the protocol *navigable*. This is the substrate the Context Builder walks. Its quality caps the quality of everything above it.

**Input** — `CodeModel` **Output** — `GraphModel` **Failure** — Fatal

## 13.1 Inheritance graph

Node: contract. Edge: `child → parent`, ordered.

Must compute **C3 linearization** (Solidity's MRO). Reason: to answer "which implementation of `_beforeTransfer` actually runs?" — a question that sits underneath a large fraction of real inheritance bugs. Without linearization, a `virtual`/`override` chain is guesswork, and the Upgradeability/Storage agents cannot reason about parent state layout.

Derived, and stored on the graph:
- `flattened_functions(contract)` → the resolved function set including inherited, with each entry pointing at its *defining* contract.
- `override_chains(function)` → the ordered list of implementations. **This is a direct input to the Access Control and Business Logic agents** and should be surfaced in context, not recomputed by the model.

## 13.2 Call graph

Node: function. Edge: caller → callee.

| Edge kind | How resolved | Confidence |
|---|---|---|
| internal / `this.f()` | direct name resolution within linearized scope | high |
| `super.f()` | via C3 linearization | high |
| library call (`using for`) | resolve `using X for Y` directives | medium |
| external via typed interface (`IVault(a).f()`) | interface → all implementing contracts in repo | medium — **fan-out** |
| external to unknown address | → `UNKNOWN_EXTERNAL` sentinel node | low |
| low-level (`call`, `delegatecall`, `staticcall`) | → `UNTRUSTED_EXTERNAL` sentinel node | **flag prominently** |

**The two sentinel nodes are load-bearing, not bookkeeping.** `UNTRUSTED_EXTERNAL` is where reentrancy, oracle manipulation, and untrusted-callback bugs live. Any path from an entrypoint to `UNTRUSTED_EXTERNAL` and *back* into a state write is a reentrancy candidate and must be computed here, deterministically, and handed to the agent as a *pre-computed candidate path* rather than left for the model to find by reading code. **Deterministic graph work is free and reliable; asking a model to do graph traversal in its head is expensive and unreliable.**

Do this for every such pattern you can enumerate. It is the highest-return work in the entire codebase.

## 13.3 Storage read/write graph

Bipartite: `Function → StateVar`, labeled `read` / `write`.

Resolved from tree-sitter identifier resolution (scope-aware: shadowed locals must not be counted as state access — this is a real bug source, test it).

Enables, deterministically:
- Which functions mutate a given invariant-relevant variable → **directly seeds the Invariant agent.**
- CEI-violation candidates: write-after-external-call within one function body.
- Which privileged variables (`owner`, `paused`, `oracle`, fee params) are writable from where → **seeds the Access Control agent.**

## 13.4 Import graph

File → file. Cycle detection. Used for dependency-order and for `is_dependency` propagation sanity checks. Lowest value of the four; build it last.

## 13.5 Derived queries the Context Builder will need (build these now, as functions on `GraphModel`)

```python
neighborhood(fn_id, depth=2)            -> set[Function]   # callers + callees, bounded
reaching_entrypoints(fn_id)             -> list[Function]  # how does an attacker get here?
writers_of(state_var_id)                -> list[Function]
external_call_paths(fn_id)              -> list[Path]      # → UNTRUSTED_EXTERNAL
reentrancy_candidates()                 -> list[Path]      # §13.2
privileged_writes()                     -> list[Function]
centrality(contract_id)                 -> float           # weighted PageRank on call+inherit
```

`reaching_entrypoints` is the one to get right first. **An internal function with no path from any external entrypoint is, in most cases, not exploitable, and should be heavily down-ranked in context.** This single query does more to cut context noise than any compression technique.

**Developer Notes**
- *Implementation order:* inheritance (+C3) → storage → calls → imports. Calls depends on inheritance being correct; do not reorder.
- *Estimated complexity:* C3 linearization and interface fan-out are the two hard parts. Budget real time for them. Everything else is mechanical.
- *Common mistake:* building the call graph on the *unlinearized* contract, so `super.f()` and inherited-function calls resolve to the wrong (or no) target. This produces a graph that looks fine and is quietly wrong — the worst failure mode there is. Golden-test the call graph against a fixture with a deliberately nasty diamond-inheritance case.
- *Performance:* fine on NetworkX to ~5k nodes. If a monorepo blows past that, filter to in-scope + their transitive parents before graphing, not after.

---

*End of Part 1.*

**Part 2 will cover:** Protocol Understanding (`ProtocolModel` in full, the heuristic detectors, the single LLM synthesis call and its prompt), and Context Engineering — `ContextRequest`/`ContextBundle` schemas, selection, importance ranking, compression, deduplication, token budgeting, and how context quality is *measured* rather than asserted.
