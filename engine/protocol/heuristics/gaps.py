"""Stage 16 — the questions the deterministic pass could not answer.

This is the seam between V1 and Phase H, and it is deliberately narrow. Enrichment is **not**
"send the repo to a model and ask what it does" — it is *this* question, with *these* few
`SolidityID`s as context, answered into *that* field. Small context, checkable answer,
evidence required on the way back in.

A gap is emitted where three things are true at once:

1. a field materially affects downstream reasoning;
2. the deterministic pass could not fill it, or filled it with a default that would be read
   as a fact;
3. a model plausibly *could* answer it from a small slice of code.

The second condition is the one that matters most. `Asset.is_fee_on_transfer` defaults to
`False`, and for an external token that default is not an observation — it is an absence
dressed as a finding. The gap is what stops the default being trusted.

`context_ids` is kept minimal because it is the entire cost-control mechanism for Phase H,
and `id` is content-keyed so the same unanswered question is never paid for twice.
"""

from __future__ import annotations

from engine.core.models.evidence import Confidence
from engine.core.models.protocol import (
    Archetype,
    AssetIdentity,
    AssetKind,
    ContractRole,
    OperationKind,
    ProtocolModel,
    RelationshipStatus,
    SemanticGap,
    StateRole,
)
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_gap_id

#: Cap per category. A repository with 300 unclassified variables produces one useful gap
#: about that, not 300 — and an enrichment budget spent on the 300 would starve the rest.
MAX_PER_CATEGORY = 12


def detect(index: ProtocolIndex, model: ProtocolModel) -> list[SemanticGap]:
    """Every specific, answerable question this run left open — each asked once."""
    produced = [
        *_token_behaviour(model),
        *_asset_identity(model),
        *_unclassified_contracts(model),
        *_unclassified_state(model),
        *_unknown_operations(model),
        *_missing_relations(model),
        *_missing_economic_links(model),
        *_unverifiable_docs(model),
        *_archetype(model),
    ]
    return collapse(produced)


def collapse(gaps: list[SemanticGap]) -> list[SemanticGap]:
    """One canonical question per distinct thing being asked.

    ```
    "Does the token behind REWARD_TOKEN charge a fee on transfer?"   ×4
                                  ↓
    one question, affected = [4 assets], occurrences = 4
    ```

    Keyed on `(field, question text)` — the question itself, not the subject — because
    "does this token charge a fee?" asked about four staking modules is one question whose
    answer resolves all four. Paying an enrichment call four times for it is budget spent
    on an answer already in hand.

    Subjects are *never* dropped: every one joins `affected`, so an answer can be applied
    back to each. What collapses is the asking, not the scope.
    """
    grouped: dict[tuple[str, str], list[SemanticGap]] = {}
    for gap in gaps:
        grouped.setdefault((gap.field, gap.question), []).append(gap)

    collapsed: list[SemanticGap] = []
    for (field, question), group in grouped.items():
        ordered = sorted(group, key=lambda g: g.id)
        survivor = ordered[0]
        if len(ordered) == 1:
            survivor.affected = [survivor.subject]
            collapsed.append(survivor)
            continue

        collapsed.append(
            survivor.model_copy(
                update={
                    "affected": sorted({g.subject for g in ordered}),
                    "context_ids": sorted(
                        {cid for g in ordered for cid in g.context_ids}
                    )[:6],
                    "occurrences": len(ordered),
                    # More sightings means more of the model hangs on the answer.
                    "priority": round(
                        min(max(g.priority for g in ordered) + 0.05 * (len(ordered) - 1), 1.0),
                        3,
                    ),
                    "blocking": any(g.blocking for g in ordered),
                }
            )
        )
        assert field == survivor.field and question == survivor.question
    return collapsed


def _gap(
    subject: str,
    question: str,
    field: str,
    context_ids: list[str],
    priority: float,
    *,
    blocking: bool = False,
    resolution_confidence: Confidence = Confidence.UNKNOWN,
) -> SemanticGap:
    return SemanticGap(
        id=make_gap_id(subject, question),
        subject=subject,
        question=question,
        field=field,
        context_ids=sorted(set(c for c in context_ids if c))[:6],
        priority=round(priority, 3),
        blocking=blocking,
        resolution_confidence=resolution_confidence,
    )


def _token_behaviour(model: ProtocolModel) -> list[SemanticGap]:
    """Rebasing and fee-on-transfer are unknowable from an interface, and both break
    accounting silently. The default `False` must never be mistaken for a finding of fact."""
    gaps: list[SemanticGap] = []
    for asset in model.assets:
        if not asset.is_external or asset.kind is not AssetKind.ERC20:
            continue
        gaps.append(
            _gap(
                asset.id,
                "Does this external token charge a fee on transfer or rebase balances? "
                "Either would make a stored balance disagree with the real one.",
                "assets.is_fee_on_transfer",
                asset.state_var_ids,
                0.8,
                # Blocking: every conservation invariant over this asset is unsound if the
                # answer is yes, so reporting them as candidates without asking is misleading.
                blocking=True,
                # A rule established that this is unanswerable from source — the token's
                # implementation is not in this repository. The gap is genuine, not a
                # detector that failed to look.
                resolution_confidence=Confidence.DERIVED,
            )
        )
    return gaps[:MAX_PER_CATEGORY]


def _asset_identity(model: ProtocolModel) -> list[SemanticGap]:
    """Are these separately-declared handles actually the same token?

    Raised once per identity group, never once per handle. The asset stage deliberately
    refuses to merge them — that would assert an identity nobody established — so the
    honest follow-up is a single question naming all of the members.
    """
    groups: dict[str, list[str]] = {}
    for asset in model.assets:
        if asset.identity is AssetIdentity.UNRESOLVED and asset.identity_group:
            groups.setdefault(asset.identity_group, []).append(asset.id)

    gaps: list[SemanticGap] = []
    for group, members in sorted(groups.items()):
        if len(members) < 2:
            continue
        declared = group.split("#")[0]
        gaps.append(
            _gap(
                sorted(members)[0],
                f"Are these {len(members)} `{declared}` handles the same token, or "
                "different ones? Each is assigned at construction, so the source does not "
                "say — and conservation reasoning across them depends on the answer.",
                "assets.identity",
                _context_of(model, sorted(members)[:3]),
                0.7,
                resolution_confidence=Confidence.DERIVED,
            )
        )
    return gaps[:MAX_PER_CATEGORY]


def _context_of(model: ProtocolModel, asset_ids: list[str]) -> list[str]:
    """The declarations an answer about these assets would need to see."""
    context: list[str] = []
    for asset_id in asset_ids:
        asset = model.asset(asset_id)
        if asset is not None:
            context.extend(asset.state_var_ids[:2])
    return context


def _missing_economic_links(model: ProtocolModel) -> list[SemanticGap]:
    """A conventional pairing the code does not show. Carried from stage 13 verbatim."""
    return [
        _gap(
            relationship.id,
            relationship.open_question,
            "economics.relationships",
            [relationship.left, relationship.right],
            0.65,
        )
        for relationship in model.economics.relationships
        if relationship.status is RelationshipStatus.EXPECTED_MISSING
        and relationship.open_question
    ][:MAX_PER_CATEGORY]


def _unclassified_contracts(model: ProtocolModel) -> list[SemanticGap]:
    unknown = [c for c in model.contracts if c.role is ContractRole.UNKNOWN]
    return [
        _gap(
            classification.id,
            f"What is {classification.name} for? No role signals matched its interface, "
            "storage or name.",
            "contracts.role",
            [classification.contract_id],
            0.5 + min(classification.centrality * 5, 0.4),
        )
        for classification in sorted(unknown, key=lambda c: -c.centrality)[:MAX_PER_CATEGORY]
    ]


def _unclassified_state(model: ProtocolModel) -> list[SemanticGap]:
    """Only variables that something actually writes. An unused variable nobody touches is
    not worth an inference call."""
    unknown = [
        item
        for item in model.state
        if item.role is StateRole.UNKNOWN and item.writers and not item.is_constant
    ]
    ranked = sorted(unknown, key=lambda item: -(len(item.writers) + len(item.readers)))
    return [
        _gap(
            item.id,
            f"What does {item.name} ({item.type}) represent? It is written by "
            f"{len(item.writers)} functions but its role is unclear from its name.",
            "state.role",
            [item.state_var_id, *item.writers[:3]],
            0.4 + min(len(item.writers) * 0.05, 0.3),
        )
        for item in ranked[:MAX_PER_CATEGORY]
    ]


def _unknown_operations(model: ProtocolModel) -> list[SemanticGap]:
    unknown = [
        operation
        for operation in model.operations
        if operation.kind is OperationKind.UNKNOWN and not operation.is_view
    ]
    ranked = sorted(unknown, key=lambda o: -(len(o.writes) + len(o.external_calls)))
    return [
        _gap(
            operation.id,
            f"What does {operation.name} do in protocol terms? It writes "
            f"{len(operation.writes)} state items and makes "
            f"{len(operation.external_calls)} external calls.",
            "operations.kind",
            [operation.function_id],
            0.45 + min(len(operation.writes) * 0.05, 0.35),
        )
        for operation in ranked[:MAX_PER_CATEGORY]
    ]


def _missing_relations(model: ProtocolModel) -> list[SemanticGap]:
    """A vault with tracked quantities but no relation between them.

    The deterministic pass refuses to invent a share-price formula it cannot see in the
    source — which is correct, and leaves a real hole. This is exactly the shape of question
    enrichment is for: the code is small, the answer is checkable, and the guess would
    otherwise be unfalsifiable.
    """
    if model.accounting.relations:
        return []

    # Grouped per contract: two contracts each having a `totalSupply` is not a relationship
    # between them, and asking "how are totalSupply and totalSupply related?" wastes an
    # enrichment call on a question with no answer.
    by_contract: dict[str, list[tuple[str, str]]] = {}
    for quantity in model.accounting.quantities:
        item = model.state_item(quantity.state_id or "")
        if item is None or item.role not in (
            StateRole.SHARE_SUPPLY,
            StateRole.ACCOUNTING_TOTAL,
        ):
            continue
        by_contract.setdefault(item.contract_id, []).append(
            (quantity.name, item.state_var_id)
        )

    gaps: list[SemanticGap] = []
    for contract_id, tracked in sorted(by_contract.items()):
        if len(tracked) < 2:
            continue
        names = ", ".join(name for name, _ in tracked[:4])
        gaps.append(
            _gap(
                contract_id,
                f"How are {names} related in {contract_id.rpartition(':')[2]}? The "
                "contract tracks them together but no formula combining them appears in "
                "the source this pass could read.",
                "accounting.relations",
                [var_id for _, var_id in tracked[:4]],
                0.85,
                blocking=True,
            )
        )
    return gaps


def _unverifiable_docs(model: ProtocolModel) -> list[SemanticGap]:
    from engine.core.models.protocol import Reconciliation

    unverifiable = [
        rule
        for rule in model.documentation_rules
        if rule.status is Reconciliation.UNVERIFIABLE and rule.subject_ids
    ]
    return [
        _gap(
            rule.id,
            f'Does the code satisfy this documented rule: "{rule.statement[:200]}"?',
            "documentation_rules.status",
            list(rule.subject_ids[:4]),
            0.6,
        )
        for rule in unverifiable[:MAX_PER_CATEGORY]
    ]


def _archetype(model: ProtocolModel) -> list[SemanticGap]:
    if not any(claim.archetype is Archetype.UNKNOWN for claim in model.archetypes):
        return []
    return [
        _gap(
            model.identity.id or "protocol:unknown",
            "What kind of protocol is this? No contract matched a known role.",
            "archetypes",
            model.core_contracts[:5],
            0.95,
            blocking=True,
        )
    ]


__all__ = ["MAX_PER_CATEGORY", "collapse", "detect"]
