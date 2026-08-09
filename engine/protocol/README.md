# protocol/ — Protocol Understanding (SPEC §7.6, §8)

`RepoModel + CodeModel + GraphModel + docs → ProtocolModel`. The first artifact in the
pipeline that contains **interpretation**, and a required input to every security agent.
Failure = Fatal.

> **This runs BEFORE the Context Builder, and its output is an input to every context
> request. Agents never see raw repos; they see a protocol.** (SPEC §6, hard ordering rule.)

Everything upstream is syntax. `CodeModel` knows `deposit(uint256)` exists, writes
`totalAssets` and calls `transferFrom`. It does not know this is a **vault**, that
`totalAssets` is an **accounting total**, that the caller is **untrusted**, or that
`shares × totalAssets / totalShares` is the relationship an attacker will attack. Without
this artifact every agent re-derives all of it, badly, once per agent, at inference cost.

## Layout

```
python -m engine protocol <path|zip|git-url>        # no API key needed
python -m engine protocol <path> --enrich --verify  # optional layers
```

| File | Responsibility | Stage |
|---|---|---|
| `../core/models/protocol.py` | the schema | all 17 |
| `../core/models/evidence.py` | `Claim`, `Confidence`, `Evidence` | 16 |
| `ids.py` | `ProtocolID` — stable identity for semantic entities | — |
| `order.py` | canonical ordering, so artifacts are byte-reproducible | 17 |
| `validate.py` | structural checks (fatal) + epistemic checks (notes) | 17 |
| `assemble.py` | canonicalize → label → measure → validate → hash | 17 |
| `understand.py` | the stage pipeline that drives the detectors | 1–17 |
| `heuristics/signatures.py` | the shared, inheritance-flattened index | — |
| `heuristics/standards.py` | ERC-20 / 4626 / 721 / proxies / access control | 3 |
| `heuristics/roles.py` | contract roles → archetype → components | 2, 1 |
| `heuristics/actors.py` | who can act, and with what authority | 4 |
| `heuristics/boundaries.py` | where trust domains meet | 5 |
| `heuristics/assets.py` | what has value | 6 |
| `heuristics/flows.py` | who sends what to whom | 7 |
| `heuristics/operations.py` | entrypoints in protocol terms | 8 |
| `heuristics/state.py` | what storage means, and how operations move it | 9, 10 |
| `heuristics/dependencies.py` | what outside this repo correctness rests on | 11 |
| `heuristics/accounting.py` | the numbers, and how they relate | 12 |
| `heuristics/economics.py` | where value is created, lost, redistributed | 13 |
| `heuristics/docs.py` | what the docs claim, and whether code agrees | 14 |
| `heuristics/invariants.py` | candidate invariants and their assumptions | 15 |
| `heuristics/gaps.py` | the questions this pass could not answer | 16 |
| `enrich/` | **optional**: gap → small context → LLM → validated claim | H |
| `verify/` | **optional**: candidate invariant → Forge run → PASS/FAIL | I |

**Stage order is a dependency order, not a preference.** Standards run before roles because
a confirmed ERC-4626 is the strongest role signal there is. Assets run before flows because
a flow moves an asset. State runs before operations, which reference state items. Accounting
runs before invariants, because a candidate invariant is a relation someone asserted should
hold. Reordering does not produce a worse model — it produces an empty one.

## Three rules the schema enforces mechanically

**1. Interpretation is labelled as such.** Every semantic record inherits `Claim`, so it
carries a `confidence` and a list of `evidence` pointers. The ladder is
`REFUTED < PROPOSED < INFERRED < DERIVED < STATED < VERIFIED`, and the distinction that
earns its keep is `DERIVED` (a documented rule over an upstream artifact, right by
construction) versus `INFERRED` (a heuristic over names, plausible and falsifiable). The
default is `INFERRED` — a record nobody justified must not read as a derivation.

`Confidence.weakest()` is the only sound way to combine: a `DERIVED` operation over an
`INFERRED` asset is `INFERRED`. Propagating the stronger value is how a naming guess
launders itself into a certainty two stages later.

**Looks similar ≠ compliant.** `StandardClaim.compliance` distinguishes `COMPLIANT`,
`PARTIAL`, `DECLARED_ONLY` and `DIVERGENT`, with `satisfied` / `missing` / `divergences` as
receipts. Claiming ERC-4626 on a contract that merely has `deposit` and `withdraw` sends
every downstream agent hunting for inflation attacks in a protocol that never promised
those semantics.

**2. Candidates, never verdicts.** `Invariant.status` starts at `CANDIDATE`;
`RiskSurface` and `EconomicSurface` say *where to look*, phrased as questions. This
artifact contains no findings. Naming a vulnerability here would let a `PROPOSED` guess
reach the report without ever meeting the `Finding` validator (SPEC §7.7, P5). Nothing
deterministic may promote past `SUPPORTED`; only an executed Forge run (Phase I) produces
`VERIFIED`.

**3. The deterministic pass must be able to fill this in alone.** V1 produces a complete
`ProtocolModel` **with no API key**. What the deterministic pass cannot answer becomes a
`SemanticGap` — a specific question with a minimal `context_ids` set — rather than a guess.

Three places this rule cost something and was kept anyway, because each is where the
tempting shortcut produces a confident wrong answer:

- **No invented formulas.** If the code never divides by `totalShares`, no ratio is
  recorded, however vault-shaped the contract is. A relation invented from the archetype
  becomes an invariant that is false *for this protocol*, and an agent that "confirms" a
  false invariant produces a confident wrong finding.
- **No fabricated concrete traces.** `StateTransition.delta_expr` holds the assignment as
  written (`totalAssets += amount`); before/after *values* would require execution, which
  is Phase I. A made-up trace is the most convincing way there is to mislead an agent.
- **Types constrain what names may mean.** `IERC20 collateralToken` contains "collateral"
  and is a handle, not a balance. Reading it as one produced a solvency invariant about a
  token address — nonsense handed downstream as a candidate.

## Where AI belongs, and why not at the root

```
RepoModel + CodeModel + GraphModel
        ↓
Deterministic ProtocolModel        ← no API key, no LLM, no network
        ↓
find semantic gaps
        ↓
small context per gap  →  AI  →  structured response
        ↓
Pydantic validation → evidence validation → confidence
        ↓
updated ProtocolModel
```

Building AI in at the root would make `deterministic vs enriched` impossible to diff, and
every regression unattributable. Keeping enrichment as a layer over a complete
deterministic model is what makes "did the model actually help?" a measurable question.

**Four gates, and an answer must pass all of them** (`enrich/apply.py`). Any single failure
rejects it and increments `Enrichment.gaps_rejected` — the metric that tells you the prompt
or the gap framing is wrong:

1. **Parseable** — JSON with the expected keys.
2. **Schema-valid** — a legal value for a real field. An invented `AssetKind` is rejected,
   never coerced; coercion would silently turn a confabulation into a fact.
3. **Evidence-grounded** — every `SolidityID` it cites was in the context we sent. This is
   the gate that catches confabulation: a model cannot cite a function it never saw.
4. **Confidence-capped** — written as `PROPOSED`, whatever the model says about its own
   certainty. Self-reported confidence is uncorrelated with correctness (SPEC §7.7), so it
   is not read at all.

Nothing here can *remove* a deterministic finding: `_apply` refuses to overwrite a role,
state meaning or operation kind the deterministic pass already resolved. A model disagreeing
with a `DERIVED` fact loses, because the derivation is checkable and the opinion is not.

`NullProvider` is the default. A run with no credentials is the supported path, not an
error path, and a provider outage degrades rather than raising.

## Phase I — the only route to `VERIFIED`

`verify/forge.py` generates Forge invariant tests from candidates, runs them, and records
`PASS` / `FAIL` / `ERROR`. Every other stage reasons about what *should* hold; this one runs
code, which is why `InvariantStatus.VERIFIED` is reachable from nowhere else and why a
`FAIL` here outweighs any amount of static reasoning — Forge found a concrete counterexample.

Only `SUPPLY` and `MONOTONICITY` invariants translate. "No account may withdraw collateral
while it backs an obligation" needs a model of what the protocol means by *healthy*, and a
test that asserts an approximation produces a confident `FAIL` on correct code — a false
refutation is more damaging than a missing check, because it looks like evidence. The rest
stay `CANDIDATE` and say so.

The generated supply check is **sound but incomplete**: Solidity cannot enumerate a mapping,
so it sums balances over the actors the campaign touched. A violation is real; a pass is
inconclusive. The test says so in its own comment.

**Divergence from SPEC §7.6, stated deliberately.** SPEC describes "one LLM synthesis pass"
producing the `ProtocolModel`, and marks Protocol Understanding as the pipeline's single
probabilistic box. This module instead makes the artifact fully deterministic and moves the
model to a Phase H enrichment layer that answers `SemanticGap`s individually. The §7.6
field contract is preserved exactly — `summary`, `archetype`, `value_flows`,
`trust_assumptions`, `external_deps` are all present, several as views over richer records
— so nothing downstream is affected. What changes is that the box is no longer
probabilistic by construction. The heuristic catalog and the enrichment prompts remain
specified in **Part 2** of the SPEC.

## Identity: two ID schemes, never mixed

`SolidityID` (`core/models/ids.py`) addresses what the compiler knows about. `ProtocolID`
(`ids.py`) addresses what it does not — actors, assets, flows, invariants.

```
readable   role:src/Vault.sol:Vault      natural key exists → embed it
digest     flow:9f4b21c0a8de             composite key → 12 hex of its parts
```

`validate.py` rejects a cross-reference pointing into the wrong namespace, which is what
catches a `SolidityID` written where a `ProtocolID` belongs — at the artifact boundary,
rather than inside an agent prompt three phases later.

**Invariants carry both an `id` and a `label`.** `id` is content-derived and stable across
runs; `label` (`INV-001`) is an ordinal assigned in canonical order at assembly. Using the
ordinal as identity would renumber every invariant whenever one was added upstream,
silently invalidating every citation in a stored report.

## Validation: fatal vs note

| Fatal (`FatalError`) | Note (recorded on the artifact) |
|---|---|
| duplicate `ProtocolID` | a `DERIVED`+ claim with no evidence |
| dangling cross-reference | `VERIFIED` with no test/build/static evidence |
| reference into the wrong namespace | an invariant marked verified with no executed run |
| an invariant with no targets | documentation rules never reconciled |
| a list out of canonical order | blocking semantic gaps |

The split is the point. Structural corruption makes the artifact unusable or
irreproducible. Epistemic weakness is a *legitimate outcome* — a protocol we understood
poorly is still worth auditing, it just must not look fully understood. A validator that
rejected a sparse model would only teach us to inflate confidence to get past it, which is
the exact failure this artifact exists to prevent.

Nothing here requires that every contract has a role, every variable a meaning, or that any
invariants were found at all. `Coverage` reports what was actually managed, with
denominators from `CodeModel`: "we classified 4 contracts" means nothing without "out of
47", and `unmodelled` names the blind spots because silence reads as completeness.

## Canonical ordering is not cosmetic

Seventeen stages append in *discovery* order, which is stable within a process and not
across them. `content_hash` would then differ between two runs over identical input — and
because caching and resume key on that hash, the artifact does not fail loudly, it just
quietly never caches. `order.py` defines one order per list and `validate.py` refuses to
write anything else. The one exception is `core_contracts`, which is a **ranking**: sorting
it would destroy the only information it carries.
