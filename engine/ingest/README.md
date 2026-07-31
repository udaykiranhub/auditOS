# ingest/ — Repository Reader + Build (SPEC §9–10)

Turn any of three input shapes into one `RepoModel`, and make the single most consequential
judgment in the pipeline: **what code is in scope.**

## Files

| File            | Purpose | Failure |
|-----------------|---------|---------|
| `reader.py`     | ZIP / folder / git URL → `RepoModel` (§9)                    | **Fatal** |
| `detect.py`     | `ProjectKind` detection: FOUNDRY / HARDHAT / RAW / UNKNOWN (§9.2) | — |
| `build/base.py` | `Builder` interface                                          | — |
| `build/foundry.py` | `forge build --extra-output storageLayout ... --ast` (§10) | Degraded |
| `build/hardhat.py` | `npx hardhat compile`, fall back to direct solc (§10)     | Degraded |

## Reader must (§9.1)

- **ZIP**: extract with **zip-slip protection** (reject any entry escaping root). Reject archives
  >200MB or >20k entries. Reject with a `FatalError`, never a raw exception trace.
- **Git**: `git clone --depth 1`; if Foundry + submodules, `--recurse-submodules` (Foundry deps
  *are* submodules — skipping this breaks the build).
- **Folder**: copy, do not symlink (the run must be immutable against user edits mid-run).
- **Config**: parse `foundry.toml` / `hardhat.config.*` **as text** — never execute it (arbitrary JS).

## Scope classification — the highest-leverage heuristic in the system (§9.3)

```
is_dependency     ← lib/, node_modules/, /vendor/, /external/, or known libs
                    (openzeppelin, solmate, solady, forge-std, ds-test, chainlink,
                     uniswap-v2/v3-core, permit2, layerzero, create3)
is_test           ← test/, tests/, *.t.sol, *Test.sol, script/, *.s.sol
is_mock           ← mock/, Mock*, Fake*, Stub*, Harness*
is_interface_only ← file contains only `interface` declarations

in_scope = NOT dependency AND NOT test AND NOT mock
```

On a real protocol **85–95% of `.sol` files are out of scope.** Getting this wrong doesn't just
waste tokens — it *poisons* the audit (agents "find" bugs in OZ, mocks contain deliberately broken
code, tests contain attack code that pattern-matches as vulnerable).

- **Classify by path first, name second. Never by name alone** — a *modified* OZ ERC20 pasted into
  `src/` is in scope.
- **Do not delete out-of-scope files** — they are still needed for compilation, inheritance
  resolution, and call-graph completeness. The flag propagates; it does not filter.
- The API must accept `scope_override: {include, exclude}` so the user can fix a bad heuristic
  without editing code.

## Build degrades, never dies (§10.2)

A protocol that does not compile must still be auditable (targets are often mid-refactor). On any
build failure: log `BUILD_DEGRADED`, set `build_available = False`, continue. What is lost when the
build fails: **storage slots/packing** and Slither (needs compilation). The report's "Coverage &
Limitations" section must state exactly what degraded.
