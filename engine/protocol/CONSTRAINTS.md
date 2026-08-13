# Schema 1.3 — the couplings, read out of the code that enforces them

1.2 described every contract and every function. Handed a small lending market, it still
produced a *list*: four operations, four state variables, two invariants, six risk surfaces —
each correct, none connected. The question an agent actually has is the one nothing answered:

> How does `deposits` relate to `debt`?

## The contract this pass was built against

```solidity
function borrow(uint256 amount) external {
    require(deposits[msg.sender] >= amount * 2);
    debt[msg.sender] += amount;
    totalDebt += amount;
    asset.transfer(msg.sender, amount);
}

function withdraw(uint256 amount) external {
    require(deposits[msg.sender] >= amount);
    require(deposits[msg.sender] - amount >= debt[msg.sender] * 2);
    ...
}
```

## Why the previous design missed it

Relationships were paired from a table of `StateRole` couples:

```python
(COLLATERAL_RECORD, DEBT_RECORD, "debt against collateral")
```

This protocol calls its collateral `deposits`, which infers as `USER_BALANCE`. No pair
matched, and `economics.relationships` came back empty on the one relationship the contract
is *about*.

Widening the table would have been worse. `(USER_BALANCE, DEBT_RECORD)` asserts that a user
balance backs a debt on the strength of a guess about two names — and it would then fire on
every protocol with a balance and a debt, related or not. That is the invented semantics
this artifact exists to avoid.

## What the pass does instead

`require(deposits[msg.sender] - amount >= debt[msg.sender] * 2)` is not a guess. It is the
protocol stating the relationship itself, in a line that reverts when it fails. So
`heuristics/constraints.py` reads relations out of the conditions the code already enforces:

```
require(deposits[…] - amount >= debt[…] * 2)
         └───┬────┘                └──┬──┘ └┬┘
           left                    right  factor

→ AccountingRelation   BOUND, expression quoted verbatim
→ EconomicRelationship deposits ──must cover 2x debt──▶ debt, status=FORMULA
→ Invariant            SOLVENCY, quoting the condition
```

One fact, three records, all pointing at the same line of source.

**Precedence.** Guard-derived pairings overwrite role-table pairings, including
`EXPECTED_MISSING` ones. A relationship the protocol enforces in a reverting condition
outranks one inferred from two quantities sharing an operation, and it certainly outranks an
open question asking whether the link exists — it demonstrably does.

**What it will not do.** It does not evaluate, simplify or solve expressions. `CodeModel`
does not model expressions (SPEC §12.2) and writing a parser here is the scope trap that
section warns about. It matches a few shapes, quotes the source, and leaves the rest alone.
An unrecognised guard produces no relation, never a guessed one. Specifically:

- `||` between clauses produces nothing — either side may be the one that held, so neither
  is enforced on its own.
- A side mentioning two quantities produces nothing — it is ambiguous which the rule is about.
- A side mentioning none (`>= amount`, a parameter) produces nothing.

## Conservation: a total against its mapping

`totalDeposits == Σ deposits[account]` is derived from a **complete** correspondence, not a
resemblance between the names. Every operation that changes one must change the other in the
same direction, and neither may ever be written alone:

```
deposit()   deposits ↑   totalDeposits ↑     ✓
withdraw()  deposits ↓   totalDeposits ↓     ✓
skim()                   totalBalances ↓     ✗ disqualifies the pair
```

One unmatched write is exactly the case where the sum does not hold, so it rejects the
pairing rather than being averaged away. `test_a_total_written_without_its_mapping_is_not_
paired` pins that.

## The second defect the example exposed: invented surfaces

Run against the lending market above, 1.2 reported:

```
first_depositor  "the first deposit sets the initial exchange rate"
rounding         "shares minted for assets supplied"
share_pricing    "the exchange rate at the moment of exit"
oracle_pricing   "collateral is valued at borrow time"
```

The contract has **no shares and no oracle**. These are conventional hazards of the *vault*
archetype, fired on operation kind alone, describing a protocol that does not exist.

`REQUIRES` now gates each such surface on machinery the protocol demonstrably has — a
share-supply state role, a priced quantity, a `RATIO` relation, an oracle dependency — every
one read off a record another stage produced with its own evidence. The gate discriminates
rather than suppresses: a real ERC-4626 vault still gets its first-depositor surface, which
`test_the_gate_does_not_suppress_surfaces_a_vault_really_has` pins.

## Measured on the example

| | before | after |
|---|---|---|
| economic relationships | 0 | **1** (`deposits ──must cover 2x debt──▶ debt`) |
| invariants | 2 | **5** |
| — collateral bound | ✗ | `require(deposits[…] - amount >= debt[…] * 2)` |
| — `totalDeposits == Σ deposits` | ✗ | ✓ |
| — `totalDebt == Σ debt` | ✗ | ✓ |
| risk surfaces | 6 | **1** (5 were about shares and an oracle that do not exist) |
| open questions | 2 | **1** ("how are totalDeposits and totalDebt related" is now answered) |

A third defect surfaced while checking the output: the invariant builder read relation
operands off a model-ordered list, producing `deposits must equal the sum of totalDeposits
across all accounts` — the rule stated backwards, which is worse than not stating it.
Operands are now read in relation order, and `BOUND`/`SUM` relations are no longer sorted,
because `a >= b` is not `b >= a`.

## Migration from 1.2

Purely additive.

| 1.2 | 1.3 | action |
|---|---|---|
| `RiskSurface.description` | `+ RiskSurface.questions` | read the list; `description` still holds them joined |
| `Operation.postconditions` (always empty) | now populated | none |
| `economics.relationships` | may contain `FORMULA` entries from guards | check `status` before trusting `formula` |
| `/protocol/summary` | `+ relationships[]`, `+ questions` on surfaces | additive |

## Making it work on real protocols

The first version of this pass worked on the example above and produced **nothing** on
Arcadia. Three design errors, all found by dumping real guards rather than by reading code:

### 1. Keyed on quantities instead of storage

`AccountingQuantity` exists only where the state pass inferred a role it recognises. On
Arcadia that is **3 variables out of 49** — so the matcher had almost nothing to look at.
Every constraint is now keyed on `StateItem`, which exists for all 49.
`AccountingRelation.state_ids` was added for this; `quantity_ids` still carries the
formula- and coupling-derived relations unchanged.

### 2. Two operands, bare names, and only entrypoints

Real guards are not `a >= b`. Dumping every condition in Arcadia's lending market gave:

```
if (initiationWeight_ + penaltyWeight_ + terminationWeight_ > MAX_TOTAL_PENALTY) revert
if (startPriceMultiplier_ < 10_000) revert            ← a validated setter
if (realisedLiquidityOf[msg.sender] < assets) revert  ← storage vs parameter
```

The pass now reads guards from **every implemented function**, not just classified
entrypoints — because the validation that proves a configuration range lives in an
`onlyOwner` setter — supports summed sides, resolves names contract-scoped with inheritance
flattening (so two contracts with a `debt` no longer collide and get dropped), and accepts a
known function parameter as a benign term so `deposits[…] - amount >= debt[…] * 2` still
relates the two storage variables.

### 3. `if (x) revert` recorded as if it asserted `x`

The worst of the three, because the output looked plausible. `require(x)` asserts `x`; `if
(x) revert` asserts **not x**. The pass was recording `cutoffTime > 64800` as a rule when
the code establishes `cutoffTime <= 64800` — the exact reverse. Conditions from `if…revert`
are now negated, and the relation carries the *normalised rule* while the guard as written
stays on the evidence, which is where a quotation belongs.

### Bounded configuration

That unlocked the shape most of a real protocol's checkable properties live in. Two guards
on consecutive lines are one rule, so they are merged on the variable they constrain:

```
if (startPriceMultiplier_ < 10_000) revert
if (startPriceMultiplier_ > 30_000) revert
→ startPriceMultiplier must remain at most 30000 and at least 10000
```

A range may only be claimed when the bound is checked on the path that **writes** the
variable — the parameter is validated and then stored. `if (auctionsInProgress > 0) revert`
inside `addTranche` is a precondition of that operation and says nothing about what the
variable may hold in general; reporting it as "auctionsInProgress must remain at most 0"
would be simply false. `WRITE_ENFORCED` marks the distinction and
`test_an_operation_precondition_is_not_a_standing_range` pins it.

### Measured on Arcadia `lending-v2` (real, 7 contracts, 49 state variables)

| | before | after |
|---|---|---|
| accounting relations | 0 | **13** |
| invariants | 4 | **8** |
| — bounded-configuration ranges | 0 | **4**, merged across `LiquidatorL1`/`L2` |
| false invariants | — | 0 (the precondition-as-range case is excluded) |

```
startPriceMultiplier must remain at most 30000 and at least 10000   ×2 contracts
cutoffTime           must remain at most 64800 and at least 3600    ×2 contracts
minPriceMultiplier   must remain at most 9000                       ×2 contracts
minRewardWeight      must remain at most 5000
```

## Known limitations

- **Arcadia still produces no two-variable *relationships*.** The configuration ranges land;
  the `deposits ↕ debt` shape does not, because Arcadia's cross-variable guards compare call
  results (`ICreditor(creditor).riskManager()`) and struct fields, which this pass drops
  rather than guess at. Small and mid-size protocols that compare storage directly get them.
- **The factor must be a literal.** `debt * COLLATERAL_FACTOR / 1e18` is not matched. Reading
  it means resolving a constant and modelling the scaling — expression evaluation.
- **Guards inside modifiers are not read here.** A rule enforced by a shared modifier
  produces no relation yet. The modifier bodies are already indexed
  (`ProtocolIndex.modifier_table`), so this is reachable.
- **Struct fields are not distinguished.** `auctionInformation_.startTime` resolves to the
  struct, not the field, so field-level constraints are not separated.
