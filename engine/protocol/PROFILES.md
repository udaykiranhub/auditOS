# Schema 1.2 — the contract-level view

1.1 produced a good description of a *protocol*. Handed to an agent, it still read like this:

```
LendingPool
role: lending_market
98 operations · 5 assets · 10 flows · 43 risk surfaces
```

Every number is true and none of it is usable. An agent given that has to open the
repository and re-derive what the pass already knew, which defeats the purpose of having a
semantic layer at all. 1.2 adds the missing chain — `contract → function → state → flow →
relationship` — so the artifact answers "what do I need to know to investigate X" without a
second read of the source.

## Three passes, one stage

Stage 16 runs after gaps, because a profile indexes the whole model *including* the
questions it left open, and a stage cannot index what has not been emitted yet.

| Pass | File | Produces |
|---|---|---|
| 16a | `heuristics/behavior.py` | `FunctionBehavior` — one body as an ordered effect sequence |
| 16b | `heuristics/relationships.py` | `ContractRelationship` — directed A → B, with call sites |
| 16c | `heuristics/profiles.py` | `ContractProfile` — one per contract, plus `Permission` |

## What a profile is, and what it deliberately is not

**An index, not a copy.** `operation_ids`, `state_ids`, `invariant_ids` and the rest are
`ProtocolID`s into the global lists. Only `functions` and `permissions` live on the profile,
because they are per-contract facts with nowhere else to go. A profile therefore cannot
disagree with the model it describes — there is nothing in it to drift. `test_profile_
indexes_rather_than_copies` asserts every cited ID resolves.

**`purpose` is assembled, never authored.** A fixed template filled from the role
assignment, the standards claims, the state roles, the operation kinds and the dependency
records — each of which is a `Claim` with its own evidence. So the sentence is exactly as
good as its inputs, it is byte-identical across runs, and there is no path by which a
plausible-sounding description of a protocol we did not understand can appear. A contract
whose role is `UNKNOWN`, whose state roles are all `UNKNOWN` and which exposes no classified
operation produces an **empty purpose**, which is the correct output.

**The sequence is the content.** Reentrancy is a WRITE after an EXTERNAL_CALL; a CEI
violation is visible in the order and invisible in any unordered summary of the same facts.
`CodeModel` numbers calls and state accesses from one counter as it walks the body, so the
two axes interleave correctly without inventing a control-flow graph (SPEC §12.2 rules that
out).

**`writes_after_external_call` is a candidate, not a finding.** A reentrancy guard may cover
it. Deciding that is the agent's job.

## Three semantic defects found by running it on Arcadia

None of these were visible in the tests; all three came from reading real output.

### 1. A guard recognised by name only

`FunctionBehavior` derived `caller_requirements` from a list of conventional modifier names
(`onlyOwner`, `onlyRole`, …). `Permission` read the modifier's *body*. So one artifact said
both of these about `LendingPool.auctionRepay`:

```
behaviour:   is_privileged = false, caller_requirements = []
permission:  mechanism = contract_only, is_privileged = true
```

`onlyLiquidator` is in no convention list. Its body is `if (msg.sender != LIQUIDATOR)
revert`. The behaviour record stated "anyone may call this" about a function only the
liquidator may call — the error in the direction that matters, and one a reader had no way
to settle.

Both views now derive from one source: `ProtocolIndex.modifier_table`, with a modifier
counting as a guard when its name matches convention **or** its body contains an
authorization check. `test_behaviour_and_permission_agree_on_privilege` pins it.

### 2. Library calls typed as trust boundaries

`SafeCastLib.safeCastTo128(x)` and, through `using FixedPointMathLib for uint256`,
`amount.mulDivUp(a, b)` are syntactically indistinguishable from external calls. Both were
typed `EXTERNAL_CALL`, which put a phantom trust-boundary crossing in the middle of every
accounting function — and made every state write after an arithmetic helper a CEI candidate.

The existing library check only fired when the graph resolved a call to a *function*. It
resolved `Math.mulDiv` to the *contract* `src/Pool.sol:Math`, the owner lookup failed, and
the call fell outward. The structural test now also accepts a resolved library contract, a
receiver naming an in-repo `library`, and a member name bound by a `using` directive.

`delegatecall` is excluded: it transfers control into code this contract does not own,
executing against its own storage, and is never in-frame.

The asymmetry is otherwise preserved deliberately — an unresolved call still falls outward.
A wrong `EXTERNAL_CALL` costs an agent one wasted question; a wrong `INTERNAL_CALL` hides
the reentrancy precondition entirely.

### 3. Base constructors reported as guards

`constructor(…) Owned(owner_)` puts base-contract invocations in the modifier slot, and the
parser records them there because that is where the grammar puts them. They initialise
parents and gate nothing. `LendingPool.constructor` was reported with
`modifiers: [LendingPoolGuardian, Creditor, DebtToken]` and a matching
`modifier Creditor` precondition — which reads as an access-controlled constructor.

They are now filtered out of `modifiers`, `caller_requirements` and `preconditions`, and
kept in `steps` as `INTERNAL_CALL`, where they belong: real calls into parent code, and
where immutables get set.

### Measured effect (arcadia `lending-v2`, 7 contracts, 139 described functions)

| | before | after |
|---|---|---|
| functions with a recognised guard | 17 | **21** |
| functions with external calls | 58 | **44** |
| external call sites | 90 | **67** |
| CEI candidates | 14 | **12** |
| permission records | 98 | 98 |

23 phantom trust-boundary crossings removed (−26%), 4 real guards recovered, 2 spurious CEI
candidates gone. Permissions were already correct, and stayed correct.

## Coverage on real repositories

| | `lending-v2` | `accounts-v2` |
|---|---|---|
| contracts profiled | 7 / 7 | 35 / 35 |
| functions described | 139 | 459 / 476 |
| purposes stated | 7 | 35 |
| contract relationships | 50 | 257 |

Byte-identical `content_hash` across repeat runs on both.

## Migration from 1.1

Purely additive. Nothing was removed or renamed.

| 1.1 | 1.2 | action |
|---|---|---|
| — | `ProtocolModel.profiles` | new list; empty on a 1.1 artifact |
| — | `ProtocolModel.contract_relationships` | new list; empty on a 1.1 artifact |
| `Coverage` | `+ contracts_profiled`, `functions_described`, `functions_total`, `purposes_stated` | read as `0` on a 1.1 artifact |
| — | `GET /protocol/profiles`, `GET /protocol/profiles/{contract}` | new endpoints |
| `/protocol/summary` | `+ profiles[]` (names only) | additive |

A 1.1 artifact loads under 1.2 with both lists empty and `contracts_profiled` at `0` —
absence reported as absence, rather than as a completeness that pass never had.

## Known limitations

- **`ContractProfile.purpose` is a template.** It reads well on vault- and lending-shaped
  code because those roles and state roles are the ones the earlier stages infer confidently.
  On a contract whose role is `UNKNOWN` it is empty, by design.
- **Inherited state is listed on every implementer.** `Tranche` and `TrancheWrapper` both
  show the `ERC4626` share accounting. That is correct — each deployment has its own copy —
  but it inflates `state_ids` relative to what is locally declared.
- **17 of 60 `lending-v2` state variables still have no semantic role**, so the profiles
  that own them name that in `unknowns` rather than guessing. This is the same root cause
  that keeps economic relationships empty (see [REFINEMENT.md](REFINEMENT.md)), and it is
  the highest-value thing left to improve in the stages *below* this one.
- **Inline assembly is invisible.** 23 `accounts-v2` functions use Yul; storage and calls
  made there appear in no sequence. Named in `unknowns` on the affected profiles.
- **`steps` is capped.** `steps_truncated` is non-zero when the sequence is a prefix, which a
  reader must know before concluding "nothing happens after the external call".
