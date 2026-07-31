# tests/ — the safety net for a deterministic core (SPEC P2, §9.4/§12.3/§13)

P2 splits the codebase in two, and each half gets a different kind of test:

- **Deterministic core** (parse / graph / context selection) → **golden-file / snapshot tests**.
- **Probabilistic edge** (agents) → **schema validation + validators**, never equality tests.

| Path                   | Purpose |
|------------------------|---------|
| `golden/`              | snapshot tests: given fixed input, artifacts are byte-identical across runs (modulo `root`) |
| `fixtures/protocols/`  | real protocols checked in as ZIPs or submodules — the ground truth for acceptance |

## The 5 reference protocols (§9.4, §12.3)

Check in five, hand-label them, and hold the pipeline to them:
one **Foundry**, one **Hardhat**, one **RAW** (`.sol` only), one **monorepo**, one **heavy-submodules**.

Acceptance criteria they enforce:

- `RepoModel`: `kind` + in-scope file count match the hand-labeled golden file.
- Zip-slip payload → rejected with a `FatalError`, not an exception trace.
- `CodeModel`: contract/function counts match hand-labels exactly; every `Function.id` round-trips
  through `make_id()`; a broken `.sol` yields a partial model + `ParseError` and does not raise.
- Call graph: golden-tested against a deliberately nasty **diamond-inheritance** fixture (§13 common mistake).
- Slither/Aderyn `target` → `SolidityID` mapping: unit-tested against fixtures (§11.1).

Run with `pytest` (config in `pyproject.toml`).
