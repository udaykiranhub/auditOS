"""Stage 13 — where value is created, destroyed, redistributed, or lost to arithmetic.

```
convertToShares  →  SHARE_PRICING, ROUNDING
deposit          →  FIRST_DEPOSITOR, DONATION, INFLATION
liquidate        →  LIQUIDATION_INCENTIVE, MEV
getPrice         →  ORACLE_PRICING
upgradeTo        →  UPGRADE, CENTRALIZATION
```

**A map, not a verdict.** "`deposit` rounds shares down" tells the Business Logic agent where
to point its attention; whether that rounding is exploitable *here* is its job. Naming a
vulnerability at this stage would let an interpretation reach the report without ever meeting
the `Finding` validator (SPEC §7.7, P5) — so every surface carries `questions`, phrased as
questions, because a question survives being wrong and an assertion does not.

`RiskSurface` overlaps `EconomicSurface` by design: the economic one answers *where does
value move*, the risk one answers *where should an agent spend its budget*. They share the
`surface:` ID namespace precisely because they are the same place seen through two lenses,
and `validate.py` allows that collision only between these two lists.
"""

from __future__ import annotations

from engine.core.models.evidence import (
    Confidence,
    heuristic_evidence,
    source_evidence,
)
from engine.core.models.protocol import (
    Accounting,
    AccountingQuantity,
    Asset,
    AssetKind,
    ContractClassification,
    Dependency,
    DependencyKind,
    EconomicModel,
    EconomicRelationship,
    EconomicSurface,
    Invariant,
    Operation,
    OperationKind,
    RelationKind,
    RelationshipStatus,
    RiskSurface,
    StateItem,
    StateRole,
    SurfaceDomain,
    SurfaceKind,
)
from engine.protocol.heuristics.constraints import GuardRelation
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_relationship_id, make_surface_id

DETECTOR = "economic_model"

#: Operation kind → the surfaces it opens, with the questions worth asking at each.
#: These are the *conventional* hazards of each operation shape, attached to the concrete
#: function where they would be felt. Not predictions — a checklist with an address.
BY_OPERATION: dict[OperationKind, tuple[tuple[SurfaceKind, str, tuple[str, ...]], ...]] = {
    OperationKind.DEPOSIT: (
        (
            SurfaceKind.FIRST_DEPOSITOR,
            "the first deposit sets the initial exchange rate",
            (
                "can the first depositor mint 1 wei of shares and then donate to inflate "
                "the rate?",
                "is there a minimum initial deposit, dead shares, or virtual offset?",
            ),
        ),
        (
            SurfaceKind.ROUNDING,
            "shares minted for assets supplied",
            (
                "does the share calculation round in the protocol's favour?",
                "can repeated small deposits accumulate rounding in the caller's favour?",
            ),
        ),
        (
            SurfaceKind.DONATION,
            "a direct token transfer can change the accounting without an operation",
            (
                "is totalAssets read from a stored value or from balanceOf(address(this))?",
                "can an unsolicited transfer move the exchange rate?",
            ),
        ),
    ),
    OperationKind.WITHDRAW: (
        (
            SurfaceKind.ROUNDING,
            "assets returned for shares burned",
            (
                "does withdrawal round in the protocol's favour?",
                "can a user withdraw more than their proportional claim?",
            ),
        ),
        (
            SurfaceKind.SHARE_PRICING,
            "the exchange rate at the moment of exit",
            ("can the rate be moved within the same transaction as the withdrawal?",),
        ),
    ),
    OperationKind.REDEEM: (
        (
            SurfaceKind.ROUNDING,
            "assets returned for shares redeemed",
            ("does redeem round down where withdraw rounds up (or the reverse)?",),
        ),
    ),
    OperationKind.LIQUIDATE: (
        (
            SurfaceKind.LIQUIDATION_INCENTIVE,
            "the bonus paid to whoever liquidates",
            (
                "can a position be liquidated when it is still healthy?",
                "does the bonus exceed the collateral, making the position unliquidatable?",
                "can the liquidator choose the price at which they are paid?",
            ),
        ),
        (SurfaceKind.MEV, "liquidation is a race", ("is liquidation front-runnable?",)),
    ),
    OperationKind.BORROW: (
        (
            SurfaceKind.ORACLE_PRICING,
            "collateral is valued at borrow time",
            (
                "is the collateral price manipulable within one transaction?",
                "is a stale price rejected?",
            ),
        ),
    ),
    OperationKind.SWAP: (
        (
            SurfaceKind.SLIPPAGE,
            "output amount depends on pool state at execution",
            (
                "is a minimum-output enforced, and by the caller or by the contract?",
                "is there a deadline?",
            ),
        ),
        (SurfaceKind.MEV, "swaps are sandwichable", ("can the trade be sandwiched?",)),
    ),
    OperationKind.CLAIM: (
        (
            SurfaceKind.REWARD_EMISSION,
            "rewards accrued and paid out",
            (
                "can rewards be claimed twice, or claimed for a period not staked?",
                "is the accumulator updated before the balance changes?",
            ),
        ),
    ),
    OperationKind.HARVEST: (
        (
            SurfaceKind.REWARD_EMISSION,
            "yield realised into the accounting",
            ("can a harvest be front-run to capture yield the caller did not earn?",),
        ),
    ),
    OperationKind.FLASH_LOAN: (
        (
            SurfaceKind.FLASH_LOAN,
            "arbitrary code runs with borrowed capital",
            (
                "what protocol state can the borrower move while holding the funds?",
                "is the fee taken before or after the callback?",
            ),
        ),
    ),
    OperationKind.UPGRADE: (
        (
            SurfaceKind.UPGRADE,
            "the implementation can be replaced",
            (
                "who can upgrade, and is it behind a timelock?",
                "does the new implementation preserve the storage layout?",
            ),
        ),
    ),
    OperationKind.CONFIGURE: (
        (
            SurfaceKind.CENTRALIZATION,
            "a privileged party can change protocol parameters",
            ("is the parameter bounded?", "can it be set to a value that traps user funds?"),
        ),
    ),
}

#: Surfaces that only exist if the protocol has the machinery they are about, and the
#: machinery that counts. Absent from this table means "the operation shape is enough".
#:
#: Without this gate, every `deposit` reported a first-depositor share-inflation surface and
#: every `borrow` reported an oracle-manipulation surface — including on protocols with no
#: shares and no oracle. Those are conventional hazards of the *archetype*, and asserting
#: them against a contract that has neither is describing a protocol that does not exist.
REQUIRES: dict[SurfaceKind, frozenset[str]] = {
    SurfaceKind.FIRST_DEPOSITOR: frozenset({"shares"}),
    SurfaceKind.SHARE_PRICING: frozenset({"shares"}),
    SurfaceKind.INFLATION: frozenset({"shares"}),
    SurfaceKind.ROUNDING: frozenset({"shares", "rate"}),
    SurfaceKind.ORACLE_PRICING: frozenset({"oracle", "price"}),
    SurfaceKind.SLIPPAGE: frozenset({"dex"}),
}


def _machinery(
    accounting: Accounting, assets: list[Asset], dependencies: list[Dependency]
) -> frozenset[str]:
    """Which of the mechanisms in `REQUIRES` this protocol demonstrably has.

    Every membership below is read off a record another stage produced with its own
    evidence — a share-supply state role, a priced quantity, an oracle dependency — never
    off a contract name or an archetype label.
    """
    present: set[str] = set()

    for quantity in accounting.quantities:
        lowered = quantity.name.lower()
        if quantity.unit == "shares" or "share" in lowered:
            present.add("shares")
        if quantity.unit == "ratio" or "price" in lowered or "rate" in lowered:
            present.add("rate")
            present.add("price")

    if any(asset.kind is AssetKind.SHARE for asset in assets):
        present.add("shares")

    for relation in accounting.relations:
        # A division combining two quantities is where rounding is felt, whether or not the
        # protocol calls the result a share.
        if relation.kind is RelationKind.RATIO:
            present.add("rate")

    for dependency in dependencies:
        if dependency.kind is DependencyKind.ORACLE:
            present.add("oracle")
            present.add("price")
        if dependency.kind is DependencyKind.DEX:
            present.add("dex")

    return frozenset(present)


#: Surfaces implied by a dependency rather than by an operation.
BY_DEPENDENCY: dict[DependencyKind, tuple[SurfaceKind, str]] = {
    DependencyKind.ORACLE: (SurfaceKind.ORACLE_PRICING, "prices come from outside"),
    DependencyKind.DEX: (SurfaceKind.SLIPPAGE, "execution price is set by an external pool"),
    DependencyKind.BRIDGE: (SurfaceKind.GRIEFING, "delivery depends on an external system"),
}

#: What kind of *reasoning* each surface calls for — a property of the surface itself, not
#: of the code around it. Replaces the old `suggested_agents` mapping, which named agents
#: and derived them from incidental facts: a `centralization` surface picked up the
#: reentrancy agent because the enclosing function happened to contain an external call,
#: which is a cross-domain claim with no evidence behind it.
DOMAINS: dict[SurfaceKind, tuple[SurfaceDomain, ...]] = {
    SurfaceKind.SHARE_PRICING: (SurfaceDomain.ACCOUNTING, SurfaceDomain.PRICING),
    SurfaceKind.ROUNDING: (SurfaceDomain.PRECISION, SurfaceDomain.ACCOUNTING),
    SurfaceKind.PRECISION_LOSS: (SurfaceDomain.PRECISION,),
    SurfaceKind.FEE: (SurfaceDomain.ACCOUNTING, SurfaceDomain.INCENTIVES),
    SurfaceKind.DONATION: (SurfaceDomain.ACCOUNTING,),
    SurfaceKind.FIRST_DEPOSITOR: (SurfaceDomain.ACCOUNTING, SurfaceDomain.PRECISION),
    SurfaceKind.INFLATION: (SurfaceDomain.ACCOUNTING,),
    SurfaceKind.SLIPPAGE: (SurfaceDomain.PRICING, SurfaceDomain.ORDERING),
    SurfaceKind.INTEREST_ACCRUAL: (SurfaceDomain.ACCOUNTING,),
    SurfaceKind.LIQUIDATION_INCENTIVE: (SurfaceDomain.INCENTIVES, SurfaceDomain.PRICING),
    SurfaceKind.REWARD_EMISSION: (SurfaceDomain.INCENTIVES, SurfaceDomain.ACCOUNTING),
    SurfaceKind.ORACLE_PRICING: (SurfaceDomain.PRICING, SurfaceDomain.EXTERNAL_INTERACTION),
    SurfaceKind.FLASH_LOAN: (SurfaceDomain.EXTERNAL_INTERACTION, SurfaceDomain.ORDERING),
    SurfaceKind.MEV: (SurfaceDomain.ORDERING,),
    SurfaceKind.GRIEFING: (SurfaceDomain.LIQUIDITY, SurfaceDomain.EXTERNAL_INTERACTION),
    SurfaceKind.CENTRALIZATION: (SurfaceDomain.ACCESS_CONTROL,),
    SurfaceKind.UPGRADE: (SurfaceDomain.UPGRADEABILITY, SurfaceDomain.ACCESS_CONTROL),
}

MAX_SURFACES_PER_KIND = 8


def detect(
    index: ProtocolIndex,
    operations: list[Operation],
    accounting: Accounting,
    assets: list[Asset],
    classifications: list[ContractClassification],
    guards: list[GuardRelation] | None = None,
    dependencies: list[Dependency] | None = None,
    state: list[StateItem] | None = None,
) -> EconomicModel:
    """How value enters, moves and leaves — plus the surfaces where it can go wrong."""
    surfaces: dict[str, EconomicSurface] = {}
    present = _machinery(accounting, assets, dependencies or [])

    for operation in operations:
        if operation.is_view:
            continue
        for kind, description, questions in BY_OPERATION.get(operation.kind, ()):
            # A conventional hazard of the operation *shape* is only a surface here if the
            # protocol has the machinery the hazard is about. `SimpleLending` has no shares
            # and no oracle, and reporting "the first deposit sets the initial exchange
            # rate" or "collateral is valued at borrow time" against it describes a
            # different protocol — the invented semantics this artifact exists to avoid.
            if kind in REQUIRES and not (REQUIRES[kind] & present):
                continue
            surface_id = make_surface_id(kind.value, operation.function_id)
            surfaces.setdefault(
                surface_id,
                EconomicSurface(
                    id=surface_id,
                    kind=kind,
                    target=operation.id,
                    description=f"{operation.name}: {description}",
                    actors=list(operation.actor_ids),
                    assets=sorted({*operation.inputs, *operation.outputs}),
                    function_ids=[operation.function_id],
                    questions=list(questions),
                    confidence=Confidence.INFERRED,
                    evidence=[
                        source_evidence(
                            operation.function_id,
                            f"{operation.kind.value} operation",
                            detector=DETECTOR,
                        ),
                        heuristic_evidence(
                            DETECTOR,
                            f"{kind.value} is a conventional surface of {operation.kind.value}",
                            ref=operation.id,
                        ),
                    ],
                ),
            )

    # A rounding surface on any relation whose direction the code never states. This is the
    # one place a *missing* fact is itself the signal.
    for relation in accounting.relations:
        if relation.rounding != "unspecified":
            continue
        surface_id = make_surface_id(SurfaceKind.PRECISION_LOSS.value, relation.id)
        surfaces.setdefault(
            surface_id,
            EconomicSurface(
                id=surface_id,
                kind=SurfaceKind.PRECISION_LOSS,
                target=relation.id,
                description=f"{relation.expression} — rounding direction not stated",
                questions=[
                    "which party absorbs the truncated remainder?",
                    "can the remainder be accumulated across many small operations?",
                ],
                confidence=Confidence.DERIVED,
                evidence=list(relation.evidence[:2]),
            ),
        )

    return EconomicModel(
        summary=_summary(operations, assets),
        fee_sources=_fee_sources(index, accounting),
        reward_sources=_reward_sources(assets),
        incentives=_incentives(operations),
        value_capture=_value_capture(accounting),
        relationships=relationships(
            accounting, operations, classifications, guards or [], state
        ),
        surfaces=list(surfaces.values()),
    )


#: The pairings an auditor reasons in. Each is (left role, right role, what the coupling is)
#: — deliberately about *quantities*, not about contracts, because the same pairing spans
#: several contracts in every non-trivial protocol.
EXPECTED_PAIRS: tuple[tuple[StateRole, StateRole, str], ...] = (
    (StateRole.ACCOUNTING_TOTAL, StateRole.SHARE_SUPPLY, "assets per share"),
    (StateRole.COLLATERAL_RECORD, StateRole.DEBT_RECORD, "debt against collateral"),
    (StateRole.DEBT_RECORD, StateRole.ACCUMULATOR, "debt against accrued interest"),
    (StateRole.USER_BALANCE, StateRole.SHARE_SUPPLY, "an account's share of the supply"),
    (StateRole.ACCOUNTING_TOTAL, StateRole.EXCHANGE_RATE, "the rate the total is valued at"),
)


def relationships(
    accounting: Accounting,
    operations: list[Operation],
    classifications: list[ContractClassification],
    guards: list[GuardRelation] | None = None,
    state: list[StateItem] | None = None,
) -> list[EconomicRelationship]:
    """The `assets ↕ shares`, `collateral ↕ debt` pairings, with their status stated.

    Three statuses, and the third is the one that earns this stage its keep. `FORMULA` means
    the source combines them and the expression is quoted. `STRUCTURAL` means they move
    under the same operations — observed coupling, not a proven law. `EXPECTED_MISSING`
    means the archetype implies a link the code does not show, which is recorded as an open
    question and **never** as a defect: a vault whose share price is computed off-chain is
    unusual, not broken, and saying otherwise would be the Protocol Model diagnosing.
    """
    by_role: dict[StateRole, list[AccountingQuantity]] = {}
    role_of: dict[str, StateRole] = {}
    for quantity in accounting.quantities:
        role = _role_of(quantity, accounting)
        role_of[quantity.id] = role
        by_role.setdefault(role, []).append(quantity)

    # Only relations that *quote* the source count as formulas. The accounting stage also
    # emits `PROPORTIONAL` relations meaning "these move together", which is an observation
    # about coupling and not an expression — reporting one as a formula would put a
    # `DERIVED` label on a structural guess and hand an agent a formula nobody wrote.
    formulas = {
        frozenset(relation.quantity_ids): relation
        for relation in accounting.relations
        if relation.expression and relation.confidence.rank >= Confidence.DERIVED.rank
    }
    movers = {
        quantity.id: set(quantity.increased_by) | set(quantity.decreased_by)
        for quantity in accounting.quantities
    }

    found: dict[str, EconomicRelationship] = {}
    for left_role, right_role, nature in EXPECTED_PAIRS:
        lefts = by_role.get(left_role, [])
        rights = by_role.get(right_role, [])
        if not lefts or not rights:
            continue

        for left in lefts:
            for right in rights:
                if left.id == right.id:
                    continue
                relation = formulas.get(frozenset({left.id, right.id}))
                shared = movers.get(left.id, set()) & movers.get(right.id, set())

                if relation is not None:
                    status, formula, evidence = (
                        RelationshipStatus.FORMULA,
                        relation.expression,
                        list(relation.evidence[:2]),
                    )
                    confidence = Confidence.DERIVED
                    question = ""
                elif shared:
                    status, formula, confidence, question = (
                        RelationshipStatus.STRUCTURAL,
                        "",
                        Confidence.INFERRED,
                        "",
                    )
                    evidence = [
                        heuristic_evidence(
                            DETECTOR,
                            f"both change under {len(shared)} shared operations",
                            ref=left.id,
                        )
                    ]
                else:
                    status, formula, confidence = (
                        RelationshipStatus.EXPECTED_MISSING,
                        "",
                        Confidence.UNKNOWN,
                    )
                    question = (
                        f"How are {left.name} and {right.name} related? A {nature} link is "
                        "conventional for this shape, and no expression combining them "
                        "appears in the source this pass could read."
                    )
                    evidence = [
                        heuristic_evidence(
                            DETECTOR,
                            f"{left.name} and {right.name} share no operation and no formula",
                            ref=left.id,
                        )
                    ]

                relationship = EconomicRelationship(
                    id=make_relationship_id(
                        f"economic:{nature}", sorted([left.id, right.id])
                    ),
                    left=left.id,
                    right=right.id,
                    nature=nature,
                    status=status,
                    formula=formula,
                    relation_ids=[relation.id] if relation is not None else [],
                    operation_ids=sorted(shared)[:6],
                    open_question=question,
                    confidence=confidence,
                    evidence=evidence,
                )
                found.setdefault(relationship.id, relationship)

    # Guard-derived pairings last in code, first in precedence: `setdefault` above has
    # already claimed the role-table pairings, so these overwrite them deliberately. A
    # relationship the protocol *enforces* in a reverting condition outranks one inferred
    # from two quantities sharing an operation, and outranks an `EXPECTED_MISSING` question
    # asking whether the link exists — it demonstrably does.
    for relationship in _from_guards(guards or [], state or []):
        found[relationship.id] = relationship

    return sorted(found.values(), key=lambda r: r.id)


def _from_guards(
    guards: list[GuardRelation], state: list[StateItem]
) -> list[EconomicRelationship]:
    """Pairings the source states outright, in a condition that reverts when it fails.

    Keyed on storage rather than on `AccountingQuantity`: a quantity exists only where the
    state pass inferred a role it recognises, which on a real protocol is a small minority
    of its variables. Every constrained variable has a `StateItem`, so keying here is what
    lets the pass say anything at all about code that is not vault-shaped.

    A relationship whose bounding side is a literal (`startPriceMultiplier >= 10000`) is a
    *range on one variable*, not a pairing between two, and is left to the invariant pass —
    this list is about how two parts of the protocol constrain each other.
    """
    by_id = {item.id: item for item in state}
    produced: dict[str, EconomicRelationship] = {}

    for guard in guards:
        if not guard.right:
            continue
        left = by_id.get(guard.left[0])
        right = by_id.get(guard.right[0])
        if left is None or right is None:
            continue

        nature = _nature_of(guard, _joined(guard.left, by_id), _joined(guard.right, by_id))
        identifier = make_relationship_id(
            "economic:guard", [*guard.left, *guard.right]
        )
        produced[identifier] = EconomicRelationship(
            id=identifier,
            left=left.id,
            right=right.id,
            nature=nature,
            status=RelationshipStatus.FORMULA,
            formula=guard.expression,
            operation_ids=[guard.operation_id] if guard.operation_id else [],
            # `DERIVED`, not `STATED`: the condition is quoted from code that enforces it,
            # but nobody wrote it down as a rule the protocol promises.
            confidence=Confidence.DERIVED,
            evidence=[
                source_evidence(
                    guard.function_id,
                    guard.expression,
                    detector=DETECTOR,
                )
            ],
        )
    return list(produced.values())


def _joined(ids: tuple[str, ...], by_id: dict[str, StateItem]) -> str:
    """`initiationWeight + penaltyWeight + terminationWeight` — a summed side, readably."""
    names = [by_id[i].name for i in ids if i in by_id]
    return " + ".join(names)


def _nature_of(guard: GuardRelation, left: str, right: str) -> str:
    """How the two are coupled, in the vocabulary an auditor uses.

    Descriptive only. It never says the coupling is wrong, exploitable, or insufficient —
    `nature` is what the relationship *is*, and judging it belongs to an agent.
    """
    if guard.kind is RelationKind.EQUALITY:
        return f"{left} equals {right}"
    if guard.factor:
        return f"{left} must cover {guard.factor}x {right}"
    return f"{left} bounds {right}"


def _role_of(quantity: AccountingQuantity, accounting: Accounting) -> StateRole:
    """The state role behind a quantity, inferred from its unit and name when absent."""
    lowered = quantity.name.lower()
    if "share" in lowered or quantity.unit == "shares":
        return StateRole.SHARE_SUPPLY
    if "debt" in lowered or "borrow" in lowered:
        return StateRole.DEBT_RECORD
    if "collateral" in lowered:
        return StateRole.COLLATERAL_RECORD
    if "index" in lowered or "cumulative" in lowered:
        return StateRole.ACCUMULATOR
    if "rate" in lowered or "price" in lowered:
        return StateRole.EXCHANGE_RATE
    if lowered.startswith("total"):
        return StateRole.ACCOUNTING_TOTAL
    return StateRole.USER_BALANCE


def _summary(operations: list[Operation], assets: list[Asset]) -> str:
    kinds = sorted({o.kind.value for o in operations if o.kind is not OperationKind.UNKNOWN})
    symbols = sorted({a.symbol for a in assets})[:6]
    if not kinds:
        return ""
    return (
        f"Value enters and leaves through {', '.join(kinds[:8])}. "
        f"Assets tracked: {', '.join(symbols)}."
    )


def _fee_sources(index: ProtocolIndex, accounting: Accounting) -> list[str]:
    return sorted(
        {
            f"{quantity.name} ({quantity.unit or 'unit unknown'})"
            for quantity in accounting.quantities
            if "fee" in quantity.name.lower()
        }
    )


def _reward_sources(assets: list[Asset]) -> list[str]:
    return sorted({asset.symbol for asset in assets if asset.kind is AssetKind.REWARD})


def _incentives(operations: list[Operation]) -> list[str]:
    """Behaviours the protocol pays third parties to perform."""
    paid = {
        OperationKind.LIQUIDATE: "liquidation is paid a bonus from the seized collateral",
        OperationKind.HARVEST: "harvesting may pay the caller a share of realised yield",
        OperationKind.REBALANCE: "rebalancing is expected to be called by a keeper",
    }
    return sorted(
        {
            text
            for operation in operations
            if (text := paid.get(operation.kind)) is not None
        }
    )


def _value_capture(accounting: Accounting) -> list[str]:
    return sorted(
        {
            f"{quantity.name} accrues to the protocol"
            for quantity in accounting.quantities
            if any(word in quantity.name.lower() for word in ("fee", "treasury", "reserve"))
        }
    )


# ── Risk surfaces ─────────────────────────────────────────────────────────────


def risk_surfaces(
    index: ProtocolIndex,
    operations: list[Operation],
    classifications: list[ContractClassification],
    economics: EconomicModel,
    dependencies: list[Dependency],
) -> list[RiskSurface]:
    """Where an agent should spend its budget, ranked.

    `priority` is what the Context Builder sorts on. It is composed from things that are
    actually observable — reachability by an untrusted actor, custody of funds, an external
    call in the body — rather than from a severity guess, because severity is a property of
    a finding and no finding exists yet.
    """
    by_contract = {c.contract_id: c for c in classifications}
    surfaces: dict[str, RiskSurface] = {}

    for economic in economics.surfaces:
        operation = next(
            (o for o in operations if o.id == economic.target), None
        )
        priority = 0.4
        targets = list(economic.function_ids)
        contract_id = ""
        # Domains come from what the surface *is*, never from what happens to surround it.
        domains = set(DOMAINS.get(economic.kind, ()))

        if operation is not None:
            contract_id = operation.contract_id or ""
            classification = by_contract.get(contract_id)
            if classification is not None and classification.holds_funds:
                priority += 0.25
            if operation.is_permissionless:
                priority += 0.2
            if operation.external_calls:
                priority += 0.15
                # Evidence-backed: this operation really does hand control outside. That
                # is a fact about the code, and it is recorded as the domain it is —
                # "control leaves here" — not as an agent assignment.
                domains.add(SurfaceDomain.EXTERNAL_INTERACTION)
            if operation.is_privileged:
                domains.add(SurfaceDomain.ACCESS_CONTROL)
            targets = [operation.function_id]

        surfaces[economic.id] = RiskSurface(
            id=economic.id,
            kind=economic.kind,
            # Qualified by contract: nine contracts each with an `addAsset` produced nine
            # surfaces titled identically, which reads as duplication and is not.
            title=_title(economic.description, contract_id),
            description=" ".join(economic.questions),
            # Carried as a list, not only flattened into `description`. An agent consuming
            # this needs them one at a time — each is a separate thing to go and check.
            questions=list(economic.questions),
            targets=targets,
            contract_id=contract_id,
            actors=list(economic.actors),
            assets=list(economic.assets),
            priority=round(min(priority, 1.0), 3),
            domains=sorted(domains, key=lambda d: d.value),
            confidence=economic.confidence,
            evidence=list(economic.evidence),
        )

    for dependency in dependencies:
        mapped = BY_DEPENDENCY.get(dependency.kind)
        if mapped is None:
            continue
        kind, description = mapped
        surface_id = make_surface_id(kind.value, dependency.id)
        surfaces.setdefault(
            surface_id,
            RiskSurface(
                id=surface_id,
                kind=kind,
                title=f"{dependency.name}: {description}",
                description=" ".join(dependency.failure_modes),
                targets=dependency.used_by[:8],
                priority=0.55,
                domains=sorted(
                    {*DOMAINS.get(kind, ()), SurfaceDomain.EXTERNAL_INTERACTION},
                    key=lambda d: d.value,
                ),
                confidence=Confidence.DERIVED,
                evidence=list(dependency.evidence[:2]),
            ),
        )

    # A contract nobody can pause, upgradeable by one key, is a centralization surface even
    # if no single operation looks dangerous.
    for classification in classifications:
        if not classification.is_upgradeable:
            continue
        surface_id = make_surface_id(
            SurfaceKind.CENTRALIZATION.value, classification.contract_id
        )
        surfaces.setdefault(
            surface_id,
            RiskSurface(
                id=surface_id,
                kind=SurfaceKind.CENTRALIZATION,
                title=f"{classification.name} is upgradeable",
                description=(
                    "whoever controls the upgrade path controls every user's funds in this "
                    "contract; check who that is and what delay stands in the way"
                ),
                targets=[classification.contract_id],
                contract_id=classification.contract_id,
                priority=0.6,
                domains=[SurfaceDomain.ACCESS_CONTROL, SurfaceDomain.UPGRADEABILITY],
                confidence=Confidence.DERIVED,
                evidence=list(classification.evidence[:2]),
            ),
        )

    return list(surfaces.values())


def link_invariants(surfaces: list[RiskSurface], invariants: list[Invariant]) -> None:
    """Attach each invariant to the surfaces that share a target.

    Done after both exist: a surface cannot reference an invariant that has not been minted,
    and `validate.py` rejects a dangling reference.
    """
    for surface in surfaces:
        targets = set(surface.targets)
        surface.invariant_ids = sorted(
            {
                invariant.id
                for invariant in invariants
                if targets & set(invariant.targets)
            }
        )


def _title(description: str, contract_id: str) -> str:
    """Qualify a surface title with its contract.

    Nine contracts each exposing `addAsset` produced nine surfaces all titled "addAsset: a
    privileged party can change protocol parameters". They are nine genuinely distinct
    surfaces on nine distinct functions, but an unqualified title makes them read as one
    record emitted nine times — and the reader who dismisses them as duplicates dismisses
    eight real ones.
    """
    contract = contract_id.rpartition(":")[2]
    return f"{contract}.{description}"[:160] if contract else description[:160]


__all__ = [
    "BY_DEPENDENCY",
    "BY_OPERATION",
    "DOMAINS",
    "detect",
    "link_invariants",
    "risk_surfaces",
]
