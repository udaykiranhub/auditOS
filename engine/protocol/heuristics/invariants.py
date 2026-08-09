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

from engine.core.models.evidence import (
    Confidence,
    Evidence,
    graph_evidence,
    heuristic_evidence,
    source_evidence,
)
from engine.core.models.protocol import (
    AccountingQuantity,
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
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_assumption_id, make_invariant_id

DETECTOR = "invariant_model"


def detect(index: ProtocolIndex, model: ProtocolModel) -> list[Invariant]:
    """Candidate invariants from five independent sources, deduped by content hash."""
    found: dict[str, Invariant] = {}
    for invariant in (
        *_supply_invariants(model),
        *_conservation_invariants(model),
        *_authorization_invariants(model),
        *_monotonicity_invariants(model),
        *_solvency_invariants(model),
        *_standard_invariants(model),
        *_documentation_invariants(model),
    ):
        if invariant.targets:  # validate.py rejects a targetless invariant; drop it here
            found.setdefault(invariant.id, invariant)
    return list(found.values())


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
    for relation in model.accounting.relations:
        quantities = [
            q for q in model.accounting.quantities if q.id in relation.quantity_ids
        ]
        if len(quantities) < 2:
            continue
        targets = [_var_of(model, q) for q in quantities]
        targets = [t for t in targets if t]
        if not targets:
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
                f"{quantities[0].name} can be changed without an operation (direct transfer)",
            ]
        else:
            statement = (
                f"{' and '.join(q.name for q in quantities)} must change together; neither "
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
