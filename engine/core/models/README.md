# core/models/ — the artifact schemas (SPEC §7)

Every file here is one stage of the spine. **Get these right and downstream modules fall out; get
them wrong and every downstream section inherits the error.**

| File          | Artifact(s)                                          | Written by         |
|---------------|------------------------------------------------------|--------------------|
| `ids.py`      | `SolidityID`, `make_id()` (the universal join key)   | everyone           |
| `repo.py`     | `RepoModel`, `SourceFile`, `ProjectKind`             | Repo Reader (§9)   |
| `code.py`     | `CodeModel`, `Contract`, `Function`, `StateVar`, `Param`, `ParseError` | Parser (§12) |
| `graphs.py`   | `GraphModel` (4 DiGraphs) + typed edge/node records  | Graph Engine (§13) |
| `protocol.py` | `ProtocolModel`, `Actor`, `Asset`, `Invariant`, `ValueFlow` | Protocol (§7.6, Part 2) |
| `context.py`  | `ContextBundle`, `ContextItem`, `ContextRequest`, `Budget` | Context Builder (Part 2) |
| `findings.py` | `Finding`, `AttackPath`, `Provenance`, Confidence/Severity | Agents + Validation (§7.7) |
| `report.py`   | `ReportModel`                                        | Report (§6)        |

## Two non-negotiable design notes from the SPEC

- **`Function.raw: str` stores the actual source text** (§7.4). The Context Builder slices at
  function granularity hundreds of times per run; making that a guarded IO+offset operation is a
  false economy that produces off-by-one bugs at scale. A large protocol is a few MB — store the text.

- **`Finding.confidence` is computed by the validation layer, never self-reported by the agent**
  (§7.7). Models are systematically overconfident and their self-reported confidence is
  uncorrelated with correctness.

## Falsifiability is a schema constraint (P5)

`Finding.attack_path` is **required** and `Finding.target` must have ≥1 `SolidityID`. A finding
without a concrete precondition, actor, and consequence is noise and is rejected *before* the report.

## The highest-leverage fields in the whole model

`SourceFile.is_dependency / is_test / is_mock` (§7.3, §9.3). These are what stop the engine from
auditing OpenZeppelin for the tenth time. They **propagate**; they never filter (out-of-scope code
is still parsed and graphed for inheritance/compile completeness — just never audited).
