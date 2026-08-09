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
    Evidence,
    heuristic_evidence,
    source_evidence,
)
from engine.core.models.protocol import (
    Accounting,
    Asset,
    AssetKind,
    ContractClassification,
    Dependency,
    DependencyKind,
    EconomicModel,
    EconomicSurface,
    Invariant,
    Operation,
    OperationKind,
    RiskSurface,
    SurfaceKind,
)
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_surface_id

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

#: Surfaces implied by a dependency rather than by an operation.
BY_DEPENDENCY: dict[DependencyKind, tuple[SurfaceKind, str]] = {
    DependencyKind.ORACLE: (SurfaceKind.ORACLE_PRICING, "prices come from outside"),
    DependencyKind.DEX: (SurfaceKind.SLIPPAGE, "execution price is set by an external pool"),
    DependencyKind.BRIDGE: (SurfaceKind.GRIEFING, "delivery depends on an external system"),
}

MAX_SURFACES_PER_KIND = 8


def detect(
    index: ProtocolIndex,
    operations: list[Operation],
    accounting: Accounting,
    assets: list[Asset],
    classifications: list[ContractClassification],
) -> EconomicModel:
    """How value enters, moves and leaves — plus the surfaces where it can go wrong."""
    surfaces: dict[str, EconomicSurface] = {}

    for operation in operations:
        if operation.is_view:
            continue
        for kind, description, questions in BY_OPERATION.get(operation.kind, ()):
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
        surfaces=list(surfaces.values()),
    )


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
        agents = ["business_logic"]

        if operation is not None:
            classification = by_contract.get(operation.contract_id or "")
            if classification is not None and classification.holds_funds:
                priority += 0.25
            if operation.is_permissionless:
                priority += 0.2
            if operation.external_calls:
                priority += 0.15
                agents.append("reentrancy")
            if operation.is_privileged:
                agents.append("access_control")
            targets = [operation.function_id]

        surfaces[economic.id] = RiskSurface(
            id=economic.id,
            kind=economic.kind,
            title=economic.description[:120],
            description=" ".join(economic.questions),
            targets=targets,
            actors=list(economic.actors),
            assets=list(economic.assets),
            priority=round(min(priority, 1.0), 3),
            suggested_agents=sorted(set(agents)),
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
                suggested_agents=["business_logic", "oracle"],
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
                priority=0.6,
                suggested_agents=["access_control"],
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


def _evidence(ref: str, detail: str) -> list[Evidence]:
    return [heuristic_evidence(DETECTOR, detail, ref=ref)]


__all__ = ["BY_DEPENDENCY", "BY_OPERATION", "detect", "link_invariants", "risk_surfaces"]
