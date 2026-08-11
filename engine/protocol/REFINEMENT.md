# Schema 1.1 — the semantic-quality refinement pass

Everything here was driven by running the 1.0 implementation against **Arcadia Finance**
(`accounts-v2`, 35 contracts; `lending-v2`, 7 contracts) and reading what came out. Each
change fixes a defect that was observed, not one that was imagined.

| metric | accounts-v2 | lending-v2 |
|---|---|---|
| contracts classified | 26 → **29** | 5 → 5 |
| distinct roles found | 4 → **6** | 3 → **4** |
| contracts called "vault" | **23 → 0** | 4 → **3** |
| assets | 19 → **8** | 6 → **2** |
| invariants | 2 → 2 | 6 → **3** |
| duplicate surface titles | **60 → 0** | **10 → 0** |
| open questions | 49 → **34** | 39 → **37** |

## The defect that caused most of the others

**21 of 35 contracts were classified as vaults**, including every price oracle, every
valuation adapter and the registry. Two causes, both now fixed:

1. **Substring matching.** `getUsdValueExposureToUnderlyingAssetAfterDeposit` matched the
   vault signal `deposit`; `assetToAssetInformation` matched `asset`. Signals now match on
   **camelCase word boundaries** (`signatures.has_token`), and a role's *defining* actions
   must appear in **prefix** position — a function named for an action performs it, one
   that merely mentions it reports on it.
2. **Unnormalized scores.** Raw hit counts reward size, so a 40-function registry outscored
   a 6-function vault. Each role now scores as its **share of the signals that role
   defines**, and `RoleRule.excluded_by` lets a stronger role rule out an implausible one
   rather than demoting it to secondary.

Roles that had to exist for this to work: `PRICING_MODULE`, `ACCOUNT`, `GUARDIAN`,
`MIGRATOR`, `HOOK`. Without them the deposit-shaped names had nowhere else to go.

Because roles feed assets, invariants, operations and surfaces, this one fix accounts for
most of the numbers above.

## What changed, by required refinement

**1 · Invariant deduplication.** `Invariant.semantic_key` is derived from *structure* —
kind, source, the normalized shape of the expression, the roles of the quantities involved
— never from wording. Two sentences that read alike but constrain different quantities stay
separate; two that read differently but assert the same rule collapse. Merging unions
targets, operations, quantities and evidence onto the survivor, so the merged record cites
strictly more than any input did, and `supporting_contracts` / `occurrences` record where
the rule was seen. Lending's three solvency invariants over three totals became one; its
ERC-4626 clause, emitted once per implementer, became one holding in two contracts.

Also fixed here: `MAX_TOTAL_PENALTY` — a `constant` — was read as an accounting total and
earned a solvency invariant asserting the protocol's assets must cover a compile-time
constant. Mutability now beats naming in `state.classify_role`.

**2 · Asset normalization.** Three axes were collapsed into one and are now separate:
`AssetKind` (what it *is*), `AssetRole` (what it is *for*), `AssetIdentity` (whether we
know *which* token it is). The merge rule runs in both directions:

- same name is not same asset — two contracts each declaring `IERC20 public asset` receive
  their address at construction, so they stay separate, share an `identity_group`, and
  generate **one** open question;
- different name is not different asset — handles resolving to the same in-repo contract
  merge, with every name kept in `aliases`.

`erc20Balance[account][token]` (an exposure ledger inside a smart account) and
`maxReward` / `originationFee` / `borrowIndex` (parameters) are no longer assets.

**3 · Contract role quality.** `ContractClassification.roles` is a ranked list of
`RoleAssignment`s, each with its own score and evidence. `is_ambiguous` flags a near-tie so
a coin-flip classification is visible rather than presented as confident.

**4 · Operation semantics.** `related_operations` links each operation to its inverse and to
anything writing the same critical state — every accounting bug lives in that gap. Views are
settled before name matching, so `getUsdValueAfterDeposit` is a view, not a deposit.

**5 · Risk surfaces.** `suggested_agents` is **gone**. It named agents, which is a decision
the model has no basis for, and derived them from incidental facts — a `centralization`
surface acquired the reentrancy agent because the enclosing function happened to contain an
external call. `domains: list[SurfaceDomain]` replaces it: `accounting`, `access_control`,
`external_interaction`, `pricing`, `precision`, `upgradeability`, `incentives`, `liquidity`,
`ordering`. The Orchestrator matches those against its agent registry's declared
capabilities. Surface titles are now qualified by contract, because nine contracts each
exposing `addAsset` produced nine identically-titled surfaces — and a reader who dismisses
them as duplicates dismisses eight real ones.

**6 · Fact / inference / unknown.** `Confidence.UNKNOWN` is a distinct state, ranked below
`REFUTED` (a refutation is a finding; an unknown is the absence of one). It exists because
`Asset.is_fee_on_transfer = False` on an external token is not an observation, and the type
default made that indistinguishable from one.

**7 · Economic relationships.** `EconomicModel.relationships` pairs quantities —
`assets ↕ shares`, `collateral ↕ debt` — with a `RelationshipStatus`: `FORMULA` (the source
combines them; quoted verbatim), `STRUCTURAL` (they move under the same operations; observed
coupling, not a law), or `EXPECTED_MISSING` (conventional for the shape, absent from the
code, so an open question and **never** a defect).

**8 · Open questions.** Collapsed on `(field, question)` — the question, not the subject —
because one answer resolves every sighting. Subjects are never dropped: each joins
`affected`. `resolution_confidence` says how sure we are the gap is *genuinely* unresolved
rather than merely undetected.

**9 · Downstream context readiness.** `ProtocolQuery.around(anchor)` returns a connected
`ProtocolSlice`: contract, operation, related operations, state, assets, flows, accounting,
invariants, surfaces, open questions, evidence. `anchors_for_domain()` answers "given an
agent whose capability is `accounting`, where should it start?" using the model's own
ranking. **This is not the Context Builder** — no ranking, no budgeting, no compression, no
prompt assembly. It exists so the relationships are provably navigable, tested here rather
than discovered missing in an agent prompt three phases later.

## Migration from 1.0

Nothing in the JSON was removed. `ContractClassification.role` and `.secondary_roles` are
`computed_field`s over `roles`, so they still serialize — a bare property would have made
them vanish from `protocol.json` and broken every consumer silently. A `model_validator`
drops them on the way back in, because `extra="forbid"` would otherwise reject the artifact
this model itself just wrote.

| 1.0 | 1.1 | action |
|---|---|---|
| `contracts[].role` | unchanged in JSON; now a view over `roles` | none |
| `risk_surfaces[].suggested_agents` | **removed** → `domains` | map domains to agents in the Orchestrator |
| `assets[].kind` | unchanged; `role` and `identity` added | read `role` for purpose |
| `invariants[]` | fewer records, each with `supporting_contracts` | read `occurrences` |
| `gaps[]` | fewer records, each with `affected` | iterate `affected`, not `subject` |

## Known limitations after this pass

- **Economic relationships are empty on both Arcadia repos.** They require paired accounting
  quantities, and quantity extraction depends on state-role inference, which still returns
  `unknown` for 61 of 155 Arcadia variables. The pairing logic is tested and fires on
  vault-shaped code; enriching state roles is the lever that would make it fire on Arcadia.
- **`accounts-v2` still yields only 2 invariants.** Same root cause: too few quantities.
- **Archetype on `accounts-v2`** now reports `oracle, account_abstraction`. Closer than
  `vault`, still not "isolated-margin lending" — though that logic genuinely lives in
  `lending-v2`, so this may be correct for the repository as scoped.
- **Asset identity is never resolved for constructor-assigned handles.** That is honest
  rather than fixable from source; it is what the `assets.identity` open question is for.
