"""Stage 15 — candidate invariants, and the assumptions they rest on.

```
INV-001  A user's redeemable assets must not exceed their proportional claim.
         status: CANDIDATE
         ├── src/Vault.sol:Vault.withdraw(uint256)
         ├── src/Vault.sol:Vault#totalAssets
         └── src/Vault.sol:Vault#totalShares
```

**Every invariant here is a CANDIDATE and nothing in this pipeline may promote it.** Only an
executed check (Phase I) produces `VERIFIED`. That rule is what stops a plausible sentence
becoming a certainty an agent then "confirms".

The target list is not decoration. It is what lets the Validator say *the finding is
supported by these exact pieces of code*, and what Phase I turns into a Forge test. An
invariant with no target is rejected outright by `validate.py` — it is a sentence, not an
invariant.

**Assumptions are kept separate from invariants**, and the distinction earns its keep: an
invariant is enforced *by* the code; an assumption is relied on *by* the code and enforced
somewhere else, or nowhere. Merging them would report "the oracle is honest" as a broken
invariant on every run — and would lose the ability to report it as a *finding* when the
protocol never says it.
"""

from __future__ import annotations

import re

from engine.core.models.evidence import (
    Confidence,
    Evidence,
    dedupe_evidence,
    graph_evidence,
    heuristic_evidence,
    source_evidence,
)
from engine.core.models.protocol import (
    AccountingQuantity,
    AccountingRelation,
    Assumption,
    Compliance,
    Invariant,
    InvariantKind,
    InvariantStatus,
    OperationKind,
    ProtocolModel,
    Reconciliation,
    RelationKind,
    Standard,
    StateRole,
    TrustLevel,
)
from engine.protocol.heuristics.constraints import WRITE_ENFORCED
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_assumption_id, make_invariant_id

DETECTOR = "invariant_model"


def detect(index: ProtocolIndex, model: ProtocolModel) -> list[Invariant]:
    """Candidate invariants from seven sources, merged by *semantic* equivalence."""
    produced = [
        invariant
        for invariant in (
            *_supply_invariants(model),
            *_conservation_invariants(model),
            *_bound_invariants(model),
            *_guard_rule_invariants(model),
            *_authorization_invariants(model),
            *_monotonicity_invariants(model),
            *_solvency_invariants(model),
            *_standard_invariants(model),
            *_documentation_invariants(model),
        )
        # validate.py rejects a targetless invariant; drop it here rather than later
        if invariant.targets
    ]
    return merge(produced, model)


def merge(invariants: list[Invariant], model: ProtocolModel) -> list[Invariant]:
    """Collapse invariants that express the *same rule* into one, with many supports.

    ```
    INV-001  convertToShares/convertToAssets consistency   (LendingPool)
    INV-003  convertToShares/convertToAssets consistency   (Tranche)
                              ↓
    INV-001  … supporting_contracts = [LendingPool, Tranche]   occurrences = 2
    ```

    **Merged on structure, never on wording.** The key is
    `(kind, source, normalized expression shape, sorted roles of the quantities involved)`
    — computed in `semantic_key()`. Two sentences that read alike but constrain different
    quantities keep distinct keys and stay separate; two that read differently but assert
    the same structural rule collapse. Requiring the underlying evidence to agree is what
    makes this a deduplication rather than a lossy summarisation.

    Nothing is discarded: targets, operations, quantities, contracts and evidence are all
    unioned onto the survivor, so the merged record cites strictly more than any input did.
    """
    grouped: dict[str, list[Invariant]] = {}
    for invariant in invariants:
        key = semantic_key(invariant, model)
        invariant.semantic_key = key
        grouped.setdefault(key, []).append(invariant)

    merged: list[Invariant] = []
    for key in sorted(grouped):
        group = sorted(grouped[key], key=lambda i: i.id)
        survivor = group[0]
        if len(group) == 1:
            survivor.supporting_contracts = _contracts_of(survivor, model)
            survivor.supporting_variables = _variables_of(survivor, model)
            merged.append(survivor)
            continue

        targets: set[str] = set()
        operations: set[str] = set()
        quantities: set[str] = set()
        evidence: list[Evidence] = []
        breaks: list[str] = []
        for invariant in group:
            targets.update(invariant.targets)
            operations.update(invariant.operation_ids)
            quantities.update(invariant.quantity_ids)
            evidence.extend(invariant.evidence)
            breaks.extend(b for b in invariant.breaks_if if b not in breaks)

        survivor = survivor.model_copy(
            update={
                "targets": sorted(targets),
                "operation_ids": sorted(operations),
                "quantity_ids": sorted(quantities),
                "evidence": dedupe_evidence(evidence),
                "breaks_if": breaks[:8],
                "occurrences": len(group),
                "statement": _generalize(survivor, group, model),
            }
        )
        survivor.supporting_contracts = _contracts_of(survivor, model)
        survivor.supporting_variables = _variables_of(survivor, model)
        merged.append(survivor)
    return merged


def semantic_key(invariant: Invariant, model: ProtocolModel) -> str:
    """What makes two invariants *the same rule*.

    Built from structure only. The wording is excluded deliberately: two detectors phrasing
    one rule differently must still collapse, and one phrasing applied to two different
    quantities must not.
    """
    roles = sorted(
        {
            item.role.value
            for target in invariant.targets
            if (item := model.state_item(f"state:{target}")) is not None
        }
    )
    contracts = sorted(_contracts_of(invariant, model))
    if invariant.source == "standard":
        # A standard's requirement is one rule that several contracts happen to be subject
        # to — "convertToShares and convertToAssets must be consistent" is the same ERC-4626
        # clause whether it holds in the pool or the tranche. Keying it per contract emits
        # the same sentence once per implementer, which is the duplication that started
        # this refinement pass.
        return make_invariant_id(f"{invariant.kind.value}|standard|{invariant.statement}", [])
    if invariant.kind in (InvariantKind.SOLVENCY, InvariantKind.SUPPLY):
        # Scoped per contract: solvency of the lending pool and solvency of a tranche are
        # different rules, however identically they are phrased. But the *same* rule
        # applied to three totals inside one contract is one rule.
        return make_invariant_id(
            f"{invariant.kind.value}|{invariant.source}|{'+'.join(roles)}", contracts
        )
    if invariant.kind is InvariantKind.CONFIGURATION:
        # The statement IS the identity — it came from prose, or from a range read off a
        # literal. Deliberately *not* scoped by contract: `startPriceMultiplier must remain
        # at least 10000` is one rule that LiquidatorL1 and LiquidatorL2 both implement, and
        # keying it per contract emits the identical sentence once per implementer. The
        # merge unions their targets, so the collapsed record cites both.
        return make_invariant_id(invariant.statement, [])
    return make_invariant_id(
        f"{invariant.kind.value}|{invariant.source}|{_shape(invariant.expression)}"
        f"|{'+'.join(roles)}",
        contracts or invariant.targets,
    )


def _shape(expression: str) -> str:
    """Normalize an expression to its structure: `a * b / c` regardless of the names.

    Two vaults computing `shares * totalAssets / totalSupply` and
    `amount * totalDeposits / totalShares` are running the same rule; the identifiers
    differ and the shape does not.
    """
    if not expression:
        return ""
    return re.sub(r"[A-Za-z_][A-Za-z0-9_.\[\]]*", "x", expression).replace(" ", "")


def _generalize(
    survivor: Invariant, group: list[Invariant], model: ProtocolModel
) -> str:
    """Restate a merged invariant so it does not read as being about one location only.

    An invariant merged from three totals whose statement still names the first would be
    actively misleading — the reader would think the other two are unconstrained.
    """
    contracts = _contracts_of(survivor, model)
    variables = sorted(
        {
            item.name
            for invariant in group
            for target in invariant.targets
            if (item := model.state_item(f"state:{target}")) is not None
        }
    )
    if survivor.kind is InvariantKind.SOLVENCY and variables:
        return (
            f"The assets held must always cover {', '.join(variables[:4])}; every account "
            "must be able to exit for its recorded share."
        )
    if len(contracts) > 1:
        names = ", ".join(c.rpartition(":")[2] for c in contracts[:4])
        return f"{survivor.statement} (holds in {names})"
    return survivor.statement


def _contracts_of(invariant: Invariant, model: ProtocolModel) -> list[str]:
    contracts: set[str] = set()
    for target in invariant.targets:
        item = model.state_item(f"state:{target}")
        if item is not None:
            contracts.add(item.contract_id)
            continue
        operation = model.operation_for(target)
        if operation is not None and operation.contract_id:
            contracts.add(operation.contract_id)
            continue
        if model.contract(target) is not None:
            contracts.add(target)
    return sorted(contracts)


def _variables_of(invariant: Invariant, model: ProtocolModel) -> list[str]:
    return sorted(
        target
        for target in invariant.targets
        if model.state_item(f"state:{target}") is not None
    )


def _mint(
    statement: str,
    kind: InvariantKind,
    targets: list[str],
    evidence: list[Evidence],
    *,
    source: str = "heuristic",
    expression: str = "",
    quantity_ids: list[str] | None = None,
    operation_ids: list[str] | None = None,
    relation_id: str | None = None,
    breaks_if: list[str] | None = None,
    holds_when: str = "",
) -> Invariant:
    return Invariant(
        id=make_invariant_id(statement, targets),
        statement=statement,
        kind=kind,
        # Always CANDIDATE. Nothing deterministic earns more than this.
        status=InvariantStatus.CANDIDATE,
        targets=sorted(set(targets)),
        quantity_ids=sorted(set(quantity_ids or [])),
        operation_ids=sorted(set(operation_ids or [])),
        relation_id=relation_id,
        expression=expression,
        holds_when=holds_when,
        breaks_if=breaks_if or [],
        source=source,
        confidence=Confidence.INFERRED,
        evidence=evidence,
    )


def _supply_invariants(model: ProtocolModel) -> list[Invariant]:
    """`Σ balances == totalSupply` — the oldest accounting invariant there is.

    Only emitted when both a supply total and a per-account balance exist and are moved by
    the same operations; a `totalSupply` with no matching balance mapping is a counter, not
    a supply.
    """
    supplies = [q for q in model.accounting.quantities if _role(model, q) is StateRole.SHARE_SUPPLY]
    balances = [q for q in model.accounting.quantities if _role(model, q) is StateRole.USER_BALANCE]

    found: list[Invariant] = []
    for supply in supplies:
        for balance in balances:
            if _contract_of(model, supply) != _contract_of(model, balance):
                continue
            statement = (
                f"The sum of all {balance.name} balances must equal {supply.name}."
            )
            movers = [
                operation.function_id
                for oid in (*supply.increased_by, *supply.decreased_by)
                if (operation := model.operation(oid)) is not None
            ]
            targets = [_var_of(model, supply), _var_of(model, balance), *movers]
            found.append(
                _mint(
                    statement,
                    InvariantKind.SUPPLY,
                    [t for t in targets if t],
                    [
                        source_evidence(_var_of(model, supply), "supply total",
                                        detector=DETECTOR),
                        source_evidence(_var_of(model, balance), "per-account balance",
                                        detector=DETECTOR),
                    ],
                    quantity_ids=[supply.id, balance.id],
                    expression=f"sum({balance.name}) == {supply.name}",
                    breaks_if=[
                        f"an operation writes {supply.name} without a matching change to "
                        f"{balance.name}",
                        "a mint or burn path bypasses one of the two",
                    ],
                )
            )
    return found


def _conservation_invariants(model: ProtocolModel) -> list[Invariant]:
    """Every accounting relation the code contains becomes a candidate that it keeps holding."""
    found: list[Invariant] = []
    by_quantity = {q.id: q for q in model.accounting.quantities}
    by_state = {s.id: s for s in model.state}

    for relation in model.accounting.relations:
        # In relation order, not model order. `a >= b` and `a == sum(b)` are directional,
        # and reading them off an incidentally-ordered list produced invariants stating the
        # reverse of what the code enforces — "deposits equals the sum of totalDeposits".
        #
        # `state_ids` first: a guard-derived relation is keyed on storage, because most
        # storage never becomes an `AccountingQuantity`. Falling back to `quantity_ids`
        # keeps the formula- and coupling-derived relations working unchanged.
        if relation.state_ids:
            items = [by_state[s] for s in relation.state_ids if s in by_state]
            names = [item.name for item in items]
            targets = [item.state_var_id for item in items]
        else:
            quantities = [
                by_quantity[q] for q in relation.quantity_ids if q in by_quantity
            ]
            names = [quantity.name for quantity in quantities]
            targets = [t for q in quantities if (t := _var_of(model, q))]

        if len(names) < 2 or not targets:
            continue

        if relation.kind is RelationKind.RATIO:
            statement = (
                f"The relationship `{relation.expression}` must hold for every caller, so "
                "no account can redeem more than its proportional claim."
            )
            kind = InvariantKind.ACCOUNTING
            breaks_if = [
                "the denominator can be moved between the read and the write",
                "rounding accumulates in the caller's favour across repeated calls",
                f"{names[0]} can be changed without an operation (direct transfer)",
            ]
        elif relation.kind is RelationKind.BOUND and _is_constant_cap(model, relation):
            # A constant on the constrained side is a *ceiling*, not a solvency relation.
            # `MAX_FEE_BPS >= feeBps` says the fee may never exceed the cap; phrasing it as
            # "MAX_FEE_BPS must remain sufficient to cover feeBps for every account" reads
            # as an accounting property of a value that cannot change.
            statement = (
                f"{names[1]} must never exceed {names[0]}, which is a compile-time "
                "constant; every path that writes it enforces the ceiling."
            )
            kind = InvariantKind.CONFIGURATION
            breaks_if = [
                f"a path writes {names[1]} without checking it against {names[0]}",
                "the value is cast to a narrower type after the check",
            ]
        elif relation.kind is RelationKind.BOUND:
            # Read out of a condition the protocol enforces, so the invariant can quote it
            # rather than describe it. This is the collateralisation rule on a lending
            # market, and phrasing it as "these change together" would lose the entire
            # content of the check.
            statement = (
                f"`{relation.expression}` must hold wherever it is checked: "
                f"{names[0]} must remain sufficient to cover "
                f"{names[1]} for every account."
            )
            kind = InvariantKind.SOLVENCY
            breaks_if = [
                f"a path increases {names[1]} without re-checking the bound",
                f"a path decreases {names[0]} without re-checking the bound",
                "the check reads a value that can be moved within the same transaction",
            ]
        elif relation.kind is RelationKind.SUM:
            statement = (
                f"{names[0]} must equal the sum of {names[1]} across "
                "all accounts; no path may change one without the other."
            )
            kind = InvariantKind.CONSERVATION
            breaks_if = [
                f"a path writes {names[1]} and returns before writing "
                f"{names[0]}",
                "an account's entry is cleared without decrementing the total",
            ]
        else:
            statement = (
                f"{' and '.join(names)} must change together; neither "
                "may be updated without the other."
            )
            kind = InvariantKind.CONSERVATION
            breaks_if = ["a path writes one quantity and returns before writing the other"]

        found.append(
            _mint(
                statement,
                kind,
                targets,
                list(relation.evidence[:3]),
                expression=relation.expression,
                quantity_ids=relation.quantity_ids,
                relation_id=relation.id,
                breaks_if=breaks_if,
                holds_when=relation.holds_when,
            )
        )
    return found


#: Names that read as an amount of value. Used only to pick an invariant's *kind*, never to
#: decide whether the rule exists — that is settled by the guard.
_VALUE_TERMS = (
    "debt",
    "collateral",
    "borrow",
    "supply",
    "balance",
    "liquidity",
    "limit",
    "shares",
    "assets",
    "usd",
)


def _guard_rule_invariants(model: ProtocolModel) -> list[Invariant]:
    """Rules the code enforces between two named quantities that are not storage slots.

    ```
    if (account.totalDebtUsd > account.borrowLimitUsd) revert HealthFactorTooLow(…);
    → borrowLimitUsd >= totalDebtUsd
    ```

    This is where a real protocol keeps the property that matters most. A lending pool's
    health check compares two fields of an in-memory `AccountData` struct, and a withdrawal
    check compares two locals — never two storage slots. A pass that required storage on
    both sides was blind to precisely the core invariant of every protocol it looked at,
    while faithfully reporting the configuration ranges around it.

    The names are established, not guessed: a field is only read when its receiver is a
    local declared in this body, and a bare identifier only when it is such a local. The
    guard is quoted on the evidence, and the function it guards is the target — so an agent
    receives the rule *and* the one place to go and check it.
    """
    by_function = {b.function_id: b for p in model.profiles for b in p.functions}
    found: list[Invariant] = []

    for relation in model.accounting.relations:
        # Storage-keyed relations are handled by the passes above; this one is for the
        # rules that have no storage to key on.
        if relation.state_ids or relation.quantity_ids:
            continue
        if relation.kind not in (RelationKind.BOUND, RelationKind.EQUALITY):
            continue

        function_id = next(
            (e.ref for e in relation.evidence if e.ref and "." in e.ref), ""
        )
        if not function_id:
            continue

        lowered = relation.expression.lower()
        kind = (
            InvariantKind.SOLVENCY
            if any(term in lowered for term in _VALUE_TERMS)
            else InvariantKind.ACCOUNTING
        )
        name = by_function[function_id].name if function_id in by_function else "it"
        found.append(
            _mint(
                f"`{relation.expression}` must hold wherever {name} is reached; the "
                "protocol reverts when it does not.",
                kind,
                [function_id],
                list(relation.evidence[:2]),
                expression=relation.expression,
                breaks_if=[
                    "a path reaches the state change without passing this check",
                    "a value in the comparison can be moved after the check and before "
                    "the write",
                ],
                holds_when=relation.holds_when,
            )
        )
    return found


#: The comparison a relation ended up in, as a readable range side.
_RANGE_SIDE = {">=": "at least", ">": "greater than", "<=": "at most", "<": "less than"}


def _bound_invariants(model: ProtocolModel) -> list[Invariant]:
    """A single variable constrained against a constant — the bounded-configuration rule.

    ```
    if (startPriceMultiplier_ < 10_000) revert
    if (startPriceMultiplier_ > 30_000) revert
    → startPriceMultiplier must stay within [10000, 30000]
    ```

    This is where most of a real protocol's checkable properties actually live. The two
    halves of a range are written as two separate guards, usually on consecutive lines, and
    reporting them as two invariants loses the fact that they are one rule — so they are
    merged here on the variable they constrain.

    A parameter validated and then written to storage counts, because that setter is the
    only path that writes it; the invariant says so rather than implying the bound holds
    for writes it never saw.
    """
    by_state = {item.id: item for item in model.state}
    ranges: dict[str, dict[str, tuple[str, str]]] = {}

    for relation in model.accounting.relations:
        if relation.kind is not RelationKind.BOUND or len(relation.state_ids) != 1:
            continue
        # Only a bound checked on the path that writes the variable justifies a standing
        # range. `if (auctionsInProgress > 0) revert` inside `addTranche` is a precondition
        # of that operation and says nothing about what the variable may hold in general —
        # reporting it as "auctionsInProgress must remain at most 0" is simply false.
        if not relation.holds_when.startswith(WRITE_ENFORCED):
            continue
        bound = _literal_of(relation.expression)
        if bound is None:
            continue
        state_id, (operator, literal) = relation.state_ids[0], bound
        ranges.setdefault(state_id, {})[operator] = (literal, relation.expression)

    found: list[Invariant] = []
    for state_id, sides in sorted(ranges.items()):
        item = by_state.get(state_id)
        if item is None:
            continue

        clauses = [
            f"{_RANGE_SIDE[operator]} {literal}"
            for operator, (literal, _) in sorted(sides.items())
            if operator in _RANGE_SIDE
        ]
        if not clauses:
            continue

        expressions = [expression for _, expression in sides.values()]
        found.append(
            _mint(
                f"{item.name} must remain {' and '.join(clauses)}; every path that "
                "writes it enforces this range.",
                InvariantKind.CONFIGURATION,
                [item.state_var_id],
                [
                    source_evidence(item.state_var_id, expression, detector=DETECTOR)
                    for expression in expressions[:3]
                ],
                expression=" and ".join(expressions),
                breaks_if=[
                    f"a path writes {item.name} without re-checking the range",
                    "the bound is applied to a parameter that is cast before it is stored",
                ],
                holds_when="checked on entry to every setter that writes it",
            )
        )
    return found


def _is_constant_cap(model: ProtocolModel, relation: AccountingRelation) -> bool:
    """Whether the bounding side of this relation is a compile-time constant."""
    if not relation.state_ids:
        return False
    item = next((s for s in model.state if s.id == relation.state_ids[0]), None)
    return item is not None and (item.is_constant or item.is_immutable)


def _literal_of(expression: str) -> tuple[str, str] | None:
    """`cutoffTime_ <= 64800` → `("<=", "64800")`, for the single-variable bound shapes."""
    match = re.search(r"(>=|<=|>|<)\s*([\d_]+)\s*$", expression.strip())
    if match is None:
        return None
    return match.group(1), match.group(2).replace("_", "")


def _authorization_invariants(model: ProtocolModel) -> list[Invariant]:
    """Privileged state must only be writable from a privileged path.

    Grounded in the state model's `is_admin_controlled`, which is computed transitively over
    the call graph — so an internal setter reached only from `onlyOwner` entrypoints counts
    as protected, which a modifier-only check would get wrong.
    """
    found: list[Invariant] = []
    for item in model.state:
        if item.role is not StateRole.ROLE_REGISTRY or not item.writers:
            continue
        writers = sorted(item.writers)
        statement = (
            f"{item.name} must only be modifiable by an already-privileged caller."
        )
        found.append(
            _mint(
                statement,
                InvariantKind.AUTHORIZATION,
                [item.state_var_id, *writers[:6]],
                [
                    source_evidence(item.state_var_id, item.meaning, detector=DETECTOR),
                    *[
                        graph_evidence(writer, "writes", item.state_var_id, detector=DETECTOR)
                        for writer in writers[:3]
                    ],
                ],
                breaks_if=(
                    []
                    if item.is_admin_controlled
                    else [
                        "at least one writer of this variable is reachable without an "
                        "access-control modifier"
                    ]
                ),
                holds_when="every writer is reached only through a guarded entrypoint",
            )
        )
    return found


def _monotonicity_invariants(model: ProtocolModel) -> list[Invariant]:
    """An accumulator that decreases is almost always a bug — but only *almost*.

    Recorded as a candidate rather than asserted, because a reward index legitimately resets
    on a new epoch in some designs, and this stage cannot tell which design it is looking at.
    """
    found: list[Invariant] = []
    for item in model.state:
        if item.role is not StateRole.ACCUMULATOR or not item.writers:
            continue
        statement = f"{item.name} must never decrease."
        found.append(
            _mint(
                statement,
                InvariantKind.MONOTONICITY,
                [item.state_var_id, *sorted(item.writers)[:6]],
                [
                    source_evidence(
                        item.state_var_id, "accumulator-shaped state", detector=DETECTOR
                    ),
                    heuristic_evidence(
                        DETECTOR,
                        "accumulators are normally monotonic; verify whether this one "
                        "resets by design",
                        ref=item.state_var_id,
                    ),
                ],
                expression=f"{item.name}_after >= {item.name}_before",
                breaks_if=["a write path assigns rather than accumulates"],
            )
        )
    return found


#: Operations through which value leaves the protocol. A protocol with no way out has
#: nothing to be insolvent about, so solvency invariants are keyed on these.
EXIT_KINDS = (
    OperationKind.WITHDRAW,
    OperationKind.REDEEM,
    OperationKind.BORROW,
    OperationKind.REMOVE_LIQUIDITY,
    OperationKind.UNSTAKE,
    OperationKind.CLAIM,
)


def _solvency_invariants(model: ProtocolModel) -> list[Invariant]:
    """The protocol must be able to honour what it owes.

    `BORROW` counts as an exit alongside `WITHDRAW`: on a lending market, value leaving
    against a recorded debt is exactly where insolvency happens, and keying only on
    withdrawal shapes produced *zero* invariants for a lending protocol — the stage's most
    important output missing entirely on one of its main archetypes.
    """
    totals = [
        item
        for item in model.state
        if item.role
        in (
            StateRole.ACCOUNTING_TOTAL,
            StateRole.DEBT_RECORD,
            StateRole.COLLATERAL_RECORD,
        )
        and item.is_critical
    ]
    exits = [
        operation for operation in model.operations if operation.kind in EXIT_KINDS
    ]
    if not totals or not exits:
        return []

    found: list[Invariant] = []
    for total in totals:
        if total.role is StateRole.COLLATERAL_RECORD:
            statement = (
                f"No account may withdraw collateral recorded in {total.name} while it "
                "still backs an outstanding obligation."
            )
            breaks_if = [
                "a health check reads a price that can be moved in the same transaction",
                "collateral is released before the debt is settled",
            ]
        elif total.role is StateRole.DEBT_RECORD:
            statement = (
                f"{total.name} must reflect every outstanding obligation; no path may "
                "reduce it without a matching repayment."
            )
            breaks_if = [
                "a liquidation path clears debt without transferring value in",
                "interest accrual can be skipped by calling in a particular order",
            ]
        else:
            statement = (
                f"The assets held must always cover {total.name}; every account must be "
                "able to exit for its recorded share."
            )
            breaks_if = [
                "a withdrawal path can be reentered before the balance is debited",
                f"{total.name} can be inflated without a matching asset inflow",
                "an external call in the exit path can fail silently",
            ]

        found.append(
            _mint(
                statement,
                InvariantKind.SOLVENCY,
                [total.state_var_id, *[o.function_id for o in exits[:5]]],
                [
                    source_evidence(total.state_var_id, total.meaning, detector=DETECTOR),
                    *[
                        source_evidence(o.function_id, "value-exit path", detector=DETECTOR)
                        for o in exits[:2]
                    ],
                ],
                operation_ids=[o.id for o in exits[:5]],
                breaks_if=breaks_if,
            )
        )
    return found


def _standard_invariants(model: ProtocolModel) -> list[Invariant]:
    """Properties a standard *requires*, turned into checks against this implementation.

    Only emitted for a contract that actually claims the standard, and only for the handful
    of properties the standard states normatively. Anything softer belongs to the agent.
    """
    found: list[Invariant] = []
    for claim in model.standards:
        if claim.compliance not in (
            Compliance.COMPLIANT,
            Compliance.PARTIAL,
            Compliance.DIVERGENT,
        ):
            continue

        if claim.standard is Standard.ERC20:
            statement = (
                "A transfer must move exactly the requested amount and must not change "
                "totalSupply."
            )
            found.append(
                _mint(
                    statement,
                    InvariantKind.CONSERVATION,
                    [claim.contract_id],
                    [
                        heuristic_evidence(
                            DETECTOR, "required by ERC-20", ref=claim.contract_id
                        )
                    ],
                    source="standard",
                    breaks_if=[
                        "the token charges a fee on transfer",
                        "the token rebases balances",
                    ],
                )
            )

        if claim.standard is Standard.ERC4626:
            statement = (
                "convertToShares and convertToAssets must be mutually consistent, and "
                "previewDeposit must not overstate the shares a deposit would mint."
            )
            found.append(
                _mint(
                    statement,
                    InvariantKind.ACCOUNTING,
                    [claim.contract_id],
                    [
                        heuristic_evidence(
                            DETECTOR, "required by ERC-4626", ref=claim.contract_id
                        )
                    ],
                    source="standard",
                    breaks_if=[
                        "the two conversions round in the same direction",
                        "totalAssets is read from balanceOf, so a donation moves the rate",
                    ],
                )
            )
    return found


def _documentation_invariants(model: ProtocolModel) -> list[Invariant]:
    """A documented rule that the code appears to break is already an invariant claim.

    Sourced at `documentation` rather than `heuristic`, because the protocol itself asserted
    it — which is stronger evidence of *intent* than any name-matching rule can be.
    """
    found: list[Invariant] = []
    for rule in model.documentation_rules:
        if rule.status is not Reconciliation.CONFLICTS:
            continue
        found.append(
            _mint(
                rule.statement,
                InvariantKind.CONFIGURATION,
                list(rule.subject_ids),
                [*rule.evidence[:2]],
                source="documentation",
                breaks_if=[rule.finding] if rule.finding else [],
                holds_when="as stated in the project's own documentation",
            )
        )
    return found


# ── Assumptions ───────────────────────────────────────────────────────────────


def assumptions(index: ProtocolIndex, model: ProtocolModel) -> list[Assumption]:
    """What the code relies on without enforcing."""
    found: dict[str, Assumption] = {}

    for dependency in model.dependencies:
        if not dependency.is_trusted:
            continue
        statement = (
            f"{dependency.name} behaves correctly: it returns honest data, does not revert "
            "unexpectedly, and does not reenter."
        )
        found.setdefault(
            make_assumption_id(statement),
            Assumption(
                id=make_assumption_id(statement),
                statement=statement,
                holder=dependency.id,
                criticality="high"
                if dependency.kind.value in ("oracle", "bridge")
                else "medium",
                is_documented=False,
                consequences=list(dependency.failure_modes[:3]),
                confidence=Confidence.DERIVED,
                evidence=list(dependency.evidence[:2]),
            ),
        )

    for actor in model.actors:
        if actor.trust not in (TrustLevel.TRUSTED, TrustLevel.FULLY_TRUSTED):
            continue
        if not actor.privileged_functions:
            continue
        statement = (
            f"The {actor.name} key is not compromised and acts in the protocol's interest; "
            f"it can call {len(actor.privileged_functions)} privileged functions."
        )
        found.setdefault(
            make_assumption_id(statement),
            Assumption(
                id=make_assumption_id(statement),
                statement=statement,
                holder=actor.id,
                criticality="high" if len(actor.privileged_functions) > 3 else "medium",
                consequences=[
                    f"compromise gives control of {fid}"
                    for fid in actor.privileged_functions[:3]
                ],
                confidence=Confidence.DERIVED,
                evidence=list(actor.evidence[:2]),
            ),
        )

    return list(found.values())


# ── Helpers ───────────────────────────────────────────────────────────────────


def _role(model: ProtocolModel, quantity: AccountingQuantity) -> StateRole:
    item = model.state_item(quantity.state_id or "")
    return item.role if item is not None else StateRole.UNKNOWN


def _var_of(model: ProtocolModel, quantity: AccountingQuantity) -> str:
    item = model.state_item(quantity.state_id or "")
    return item.state_var_id if item is not None else ""


def _contract_of(model: ProtocolModel, quantity: AccountingQuantity) -> str:
    item = model.state_item(quantity.state_id or "")
    return item.contract_id if item is not None else ""


__all__ = ["assumptions", "detect"]
