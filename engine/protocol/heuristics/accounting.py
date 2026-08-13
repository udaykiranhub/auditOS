"""Stage 12 — the numbers the protocol's correctness depends on, and how they relate.

```
totalAssets  (unit: asset)   ↑ deposit  ↓ withdraw
totalShares  (unit: shares)  ↑ deposit  ↓ withdraw
                                    │
                    RATIO: shares * totalAssets / totalSupply   ← only if the code says so
```

**Only assert what the implementation shows.** This is the rule that makes or breaks the
stage. If the code never divides by `totalShares`, no ratio is recorded, however
vault-shaped the contract is. A relationship invented from the archetype produces an
invariant that is false *for this protocol*, and an agent that "confirms" a false invariant
produces a confident wrong finding — the worst output the system can make.

So relations come from two places only, and both are grounded:

* **structural** — two quantities moved by the same set of operations in opposite directions
  is a conservation candidate, `INFERRED` and labelled as such;
* **textual** — an expression in the source that actually combines the quantities, copied
  verbatim, `DERIVED` because it is quoting code.

`unit` exists because unit confusion between a share amount and an asset amount is a whole
vulnerability class, and it is invisible unless someone writes the unit down.
"""

from __future__ import annotations

import re

from engine.core.models.evidence import (
    Confidence,
    Evidence,
    heuristic_evidence,
    source_evidence,
)
from engine.core.models.protocol import (
    Accounting,
    AccountingQuantity,
    AccountingRelation,
    Asset,
    Operation,
    RelationKind,
    StateItem,
    StateRole,
    StateTransition,
)
from engine.protocol.heuristics import constraints
from engine.protocol.heuristics.constraints import GuardRelation
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_quantity_id, make_relationship_id

DETECTOR = "accounting_model"

#: Roles that name a quantity worth tracking. A `paused` flag is state; it is not a number
#: any invariant is written over, and including it would bury the ones that are.
QUANTITY_ROLES = frozenset(
    {
        StateRole.ACCOUNTING_TOTAL,
        StateRole.SHARE_SUPPLY,
        StateRole.USER_BALANCE,
        StateRole.DEBT_RECORD,
        StateRole.COLLATERAL_RECORD,
        StateRole.EXCHANGE_RATE,
        StateRole.ACCUMULATOR,
    }
)

#: A division combining two tracked quantities. This is what distinguishes a real
#: share-price formula from one we assumed the protocol must have.
_RATIO = re.compile(
    r"([A-Za-z_][A-Za-z0-9_.\[\]]*)\s*\*\s*([A-Za-z_][A-Za-z0-9_.\[\]]*)\s*/\s*"
    r"([A-Za-z_][A-Za-z0-9_.\[\]]*)"
)

#: `mulDiv(a, b, c)` and `a.mulDiv(b, c)` — the same formula written through a library,
#: which is how every production vault actually spells it.
_MULDIV = re.compile(r"mulDiv\w*\s*\(\s*([^,]+),\s*([^,]+),\s*([^,)]+)")


def detect(
    index: ProtocolIndex,
    state: list[StateItem],
    assets: list[Asset],
    operations: list[Operation],
    transitions: list[StateTransition],
) -> tuple[Accounting, list[GuardRelation]]:
    """Quantities from the state model, relations from the source that combines them.

    Returns the guard-derived relations alongside the model: they carry a factor and a call
    site that `AccountingRelation` cannot hold, and the economics and invariant passes both
    need them. Recomputing them downstream would risk the two copies disagreeing.
    """
    asset_by_id = {asset.id: asset for asset in assets}
    quantities = _quantities(state, asset_by_id, operations)
    by_name = {q.name.lower(): q for q in quantities}

    # Guard-derived relations come first: they quote a condition the protocol enforces,
    # which is stronger evidence than a formula matched out of a body or a coupling
    # inferred from two quantities moving together.
    guard_relations, guards = constraints.detect(index, state, operations)
    relations = [
        *guard_relations,
        *constraints.conservation(state, transitions),
        *_textual_relations(index, by_name),
        *_conservation_relations(quantities, operations),
    ]
    return Accounting(
        quantities=quantities,
        relations=relations,
        unit_conflicts=_unit_conflicts(quantities, relations, by_name),
    ), guards


def _quantities(
    state: list[StateItem],
    asset_by_id: dict[str, Asset],
    operations: list[Operation],
) -> list[AccountingQuantity]:
    by_state = {item.id: item for item in state}
    increased: dict[str, set[str]] = {}
    decreased: dict[str, set[str]] = {}

    for operation in operations:
        for state_id in operation.writes:
            item = by_state.get(state_id)
            if item is None:
                continue
            # Direction comes from the transition stage's reading of the assignment
            # operator; an operation that only ever `=`-assigns is recorded in neither.
            bucket = increased if _increases(operation, item) else decreased
            if _direction_known(operation, item):
                bucket.setdefault(state_id, set()).add(operation.id)

    quantities: list[AccountingQuantity] = []
    for item in state:
        if item.role not in QUANTITY_ROLES:
            continue
        asset = asset_by_id.get(item.asset_id or "")
        quantities.append(
            AccountingQuantity(
                id=make_quantity_id(item.state_var_id),
                name=item.name,
                state_id=item.id,
                asset_id=item.asset_id,
                unit=_unit(item, asset),
                description=item.meaning,
                increased_by=sorted(increased.get(item.id, ())),
                decreased_by=sorted(decreased.get(item.id, ())),
                confidence=Confidence.DERIVED,
                evidence=[
                    source_evidence(
                        item.state_var_id, f"{item.type} {item.name}", detector=DETECTOR
                    )
                ],
            )
        )
    return quantities


def _unit(item: StateItem, asset: Asset | None) -> str:
    """What one of these *is*. `USDC (6dp)`, `shares`, `bps` — never blank if avoidable."""
    if asset is not None:
        decimals = f" ({asset.decimals}dp)" if asset.decimals is not None else ""
        return f"{asset.symbol}{decimals}"
    if item.role is StateRole.SHARE_SUPPLY:
        return "shares"
    if item.role is StateRole.EXCHANGE_RATE:
        return "ratio"
    if item.role is StateRole.ACCUMULATOR:
        return "accumulated per unit"
    if "bps" in item.name.lower() or "fee" in item.name.lower():
        return "bps"
    return ""


def _increases(operation: Operation, item: StateItem) -> bool:
    from engine.core.models.protocol import OperationKind

    inflow = {
        OperationKind.DEPOSIT,
        OperationKind.MINT,
        OperationKind.STAKE,
        OperationKind.BORROW,
        OperationKind.ADD_LIQUIDITY,
    }
    return operation.kind in inflow


def _direction_known(operation: Operation, item: StateItem) -> bool:
    from engine.core.models.protocol import OperationKind

    return operation.kind is not OperationKind.UNKNOWN


def _textual_relations(
    index: ProtocolIndex, by_name: dict[str, AccountingQuantity]
) -> list[AccountingRelation]:
    """Ratio formulas the code actually contains, quoted verbatim.

    `DERIVED`, because it is a quotation. The rounding direction is read from the library
    call when the code names it (`mulDivDown`, `mulDivUp`) and left `unspecified` otherwise —
    and "unspecified" is itself worth reporting, since it is where the dust goes.
    """
    found: dict[str, AccountingRelation] = {}
    for contract in index.audited:
        for function in contract.functions:
            for pattern in (_RATIO, _MULDIV):
                for match in pattern.finditer(function.raw):
                    operands = [_base(group) for group in match.groups()]
                    matched = [by_name[name] for name in operands if name in by_name]
                    if len(matched) < 2:
                        continue  # a formula over locals, not over tracked quantities
                    expression = " ".join(match.group(0).split())[:200]
                    relation = AccountingRelation(
                        id=make_relationship_id(
                            RelationKind.RATIO.value, [q.id for q in matched]
                        ),
                        kind=RelationKind.RATIO,
                        expression=expression,
                        quantity_ids=sorted({q.id for q in matched}),
                        holds_when=f"evaluated in {function.name}",
                        rounding=_rounding(match.group(0)),
                        confidence=Confidence.DERIVED,
                        evidence=[
                            source_evidence(
                                function.id,
                                expression,
                                path=contract.path,
                                line=function.line_start,
                                excerpt=expression,
                                detector=DETECTOR,
                            )
                        ],
                    )
                    found.setdefault(relation.id, relation)
    return list(found.values())


def _rounding(text: str) -> str:
    lowered = text.lower()
    if "down" in lowered or "floor" in lowered:
        return "down"
    if "up" in lowered or "ceil" in lowered:
        return "up"
    # Solidity integer division truncates, so a bare `/` rounds down — but *who benefits*
    # depends on which side of the accounting it sits on, which this stage cannot decide.
    return "unspecified"


def _conservation_relations(
    quantities: list[AccountingQuantity], operations: list[Operation]
) -> list[AccountingRelation]:
    """Two quantities moved by exactly the same operations move together.

    A *candidate* conservation law, `INFERRED` and labelled so: moving together is not the
    same as being conserved, and the evidence says only what was observed.
    """
    found: list[AccountingRelation] = []
    tracked = [q for q in quantities if q.increased_by or q.decreased_by]

    for i, left in enumerate(tracked):
        for right in tracked[i + 1 :]:
            if left.unit == right.unit:
                continue  # same unit: likely the same thing counted twice, not a relation
            if set(left.increased_by) != set(right.increased_by):
                continue
            if set(left.decreased_by) != set(right.decreased_by):
                continue
            found.append(
                AccountingRelation(
                    id=make_relationship_id(
                        RelationKind.PROPORTIONAL.value, sorted([left.id, right.id])
                    ),
                    kind=RelationKind.PROPORTIONAL,
                    expression=f"{left.name} and {right.name} move together",
                    quantity_ids=sorted([left.id, right.id]),
                    holds_when="every operation that changes one changes the other",
                    confidence=Confidence.INFERRED,
                    evidence=[
                        heuristic_evidence(
                            DETECTOR,
                            f"both changed by {len(left.increased_by) + len(left.decreased_by)} "
                            "identical operations",
                            ref=left.id,
                        )
                    ],
                )
            )
    return found


def _unit_conflicts(
    quantities: list[AccountingQuantity],
    relations: list[AccountingRelation],
    by_name: dict[str, AccountingQuantity],
) -> list[str]:
    """Places where quantities in different units meet without an evident conversion.

    A ratio *should* mix units — that is what a ratio is. A sum should not, and a sum that
    does is where a share amount got added to an asset amount.
    """
    conflicts: list[str] = []
    by_id = {q.id: q for q in quantities}
    for relation in relations:
        if relation.kind not in (RelationKind.SUM, RelationKind.EQUALITY):
            continue
        units = {
            by_id[qid].unit for qid in relation.quantity_ids if qid in by_id and by_id[qid].unit
        }
        if len(units) > 1:
            conflicts.append(
                f"{relation.expression} combines {', '.join(sorted(units))} without a "
                "visible conversion"
            )
    return conflicts


def _base(expression: str) -> str:
    """`shares[msg.sender]` → `shares`; `self.totalAssets` → `totalassets`."""
    return expression.split("[")[0].split(".")[-1].strip().lower()


def _evidence(function_id: str, text: str) -> list[Evidence]:
    return [source_evidence(function_id, text, detector=DETECTOR)]


__all__ = ["QUANTITY_ROLES", "detect"]
