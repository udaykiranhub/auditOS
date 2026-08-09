"""`ProtocolModel` integrity checks, run before the artifact is written.

The Protocol Model is the first artifact in the pipeline that contains **interpretation**.
Everything before it can only be wrong by being incomplete; this one can be wrong by being
confidently mistaken, and a confident mistake here is amplified by every agent downstream.
So the checks below fall into two groups with two different consequences:

* **Structural corruption → `FatalError`.** A duplicate ID, a cross-reference to something
  that does not exist, an unsorted list. These make the artifact unusable or
  irreproducible, and shipping one produces failures three phases away that look like agent
  bugs.

* **Epistemic defects → notes.** A claim above `INFERRED` with no evidence, an invariant
  marked `VERIFIED` that no test ran, a claim citing only heuristics. These are recorded on
  the artifact and surfaced in the report's coverage section rather than raised, because a
  partially-grounded model is still worth auditing — it just must not *look* fully grounded.

**Not checked, deliberately:** that every contract has a role, that every state variable has
a meaning, that any invariants were found at all. A protocol we understood poorly is a
legitimate outcome and `Coverage` is where it is reported. A validator that rejected it
would only teach us to invent classifications to get past the validator, which is the exact
failure this artifact exists to prevent.
"""

from __future__ import annotations

from engine.core.errors import FatalError
from engine.core.models.code import CodeModel
from engine.core.models.evidence import Confidence, EvidenceKind
from engine.core.models.protocol import (
    Claim,
    InvariantStatus,
    ProtocolModel,
    Reconciliation,
)
from engine.protocol.ids import is_protocol_id, namespace_of
from engine.protocol.order import canonical_order_violations

MAX_REPORTED = 5


class ProtocolCode:
    """Stable failure codes — part of the CLI/API contract."""

    DUPLICATE_ID = "PROTOCOL_DUPLICATE_ID"
    DANGLING_REF = "PROTOCOL_DANGLING_REF"
    BAD_NAMESPACE = "PROTOCOL_BAD_NAMESPACE"
    UNSORTED = "PROTOCOL_UNSORTED"
    INVARIANT_WITHOUT_TARGET = "PROTOCOL_INVARIANT_WITHOUT_TARGET"
    NO_INPUT = "PROTOCOL_NO_INPUT"


#: Which namespace each cross-reference field must point into. This table is the reason a
#: `SolidityID` written into an actor field, or an operation ID written where an asset ID
#: belongs, fails at the artifact boundary instead of at an agent prompt.
_EXPECTED: dict[str, str] = {
    "actor_ids": "actor",
    "asset_id": "asset",
    "backing_asset_id": "asset",
    "component_id": "component",
    "flow_ids": "flow",
    "operation_id": "op",
    "operation_ids": "op",
    "quantity_ids": "qty",
    "relation_id": "rel",
    "state_id": "state",
    "transition_ids": "transition",
    "invariant_ids": "inv",
}


def validate(model: ProtocolModel, code: CodeModel | None = None) -> list[str]:
    """Raise `FatalError` on structural corruption; return notes for the survivable rest.

    `code` is optional so the validator runs on a `ProtocolModel` loaded from disk in
    isolation. When it is supplied, every `SolidityID` the model cites is checked to exist —
    the strongest available guarantee that the semantic layer is talking about real code.
    """
    _check_ids(model)
    _check_references(model)
    _check_order(model)

    notes: list[str] = []
    notes.extend(_evidence_notes(model))
    notes.extend(_status_notes(model))
    if code is not None:
        notes.extend(_code_notes(model, code))
    return notes


# ── Structural: fatal ─────────────────────────────────────────────────────────


def _check_ids(model: ProtocolModel) -> None:
    """Every `ProtocolID` is unique across the whole artifact and correctly namespaced.

    Global uniqueness rather than per-list: cross-references are untyped strings, so two
    records sharing an ID in different lists would silently resolve to whichever the
    resolver looked at first.
    """
    # `RiskSurface` and `EconomicSurface` share the `surface:` namespace by design — the
    # same place seen through two lenses, ranked differently — so an ID appearing in both
    # lists is correct. Counting each list once is what keeps that legal.
    surfaces = {s.id for s in model.economics.surfaces} | {s.id for s in model.risk_surfaces}

    ids = [
        *sorted(surfaces),
        *(c.id for c in model.components),
        *(c.id for c in model.contracts),
        *(s.id for s in model.standards),
        *(a.id for a in model.actors),
        *(b.id for b in model.trust_boundaries),
        *(a.id for a in model.assets),
        *(f.id for f in model.asset_flows),
        *(o.id for o in model.operations),
        *(s.id for s in model.state),
        *(t.id for t in model.state_transitions),
        *(d.id for d in model.dependencies),
        *(q.id for q in model.accounting.quantities),
        *(r.id for r in model.accounting.relations),
        *(r.id for r in model.documentation_rules),
        *(a.id for a in model.assumptions),
        *(i.id for i in model.invariants),
        *(g.id for g in model.gaps),
    ]
    duplicates = sorted({pid for pid in ids if ids.count(pid) > 1})
    if duplicates:
        raise FatalError(
            f"{len(duplicates)} ProtocolIDs are declared more than once: "
            f"{', '.join(duplicates[:MAX_REPORTED])}",
            code=ProtocolCode.DUPLICATE_ID,
            hint="Two detectors minted an ID for the same entity, or an ID was built from "
            "a key that is not unique. Mint IDs only via engine/protocol/ids.py.",
        )

    unnamespaced = sorted({pid for pid in ids if not is_protocol_id(pid)})
    if unnamespaced:
        raise FatalError(
            f"{len(unnamespaced)} IDs are not ProtocolIDs: "
            f"{', '.join(unnamespaced[:MAX_REPORTED])}",
            code=ProtocolCode.BAD_NAMESPACE,
            hint="Semantic entities are addressed by ProtocolID, never by name or by "
            "SolidityID. See engine/protocol/ids.py.",
        )


def _check_references(model: ProtocolModel) -> None:
    """Every cross-reference resolves, and points into the namespace its field expects."""
    known: set[str] = {
        *(c.id for c in model.components),
        *(c.id for c in model.contracts),
        *(a.id for a in model.actors),
        *(a.id for a in model.assets),
        *(f.id for f in model.asset_flows),
        *(o.id for o in model.operations),
        *(s.id for s in model.state),
        *(t.id for t in model.state_transitions),
        *(d.id for d in model.dependencies),
        *(q.id for q in model.accounting.quantities),
        *(r.id for r in model.accounting.relations),
        *(i.id for i in model.invariants),
        *(s.id for s in model.economics.surfaces),
        *(s.id for s in model.risk_surfaces),
        *(b.id for b in model.trust_boundaries),
    }

    dangling: list[str] = []
    mistyped: list[str] = []

    def check(owner: str, field: str, value: str | None) -> None:
        if not value:
            return
        expected = _EXPECTED.get(field)
        if expected and namespace_of(value) != expected:
            mistyped.append(f"{owner}.{field} = {value} (expected {expected}:…)")
        elif value not in known:
            dangling.append(f"{owner}.{field} → {value}")

    # `Component.contract_ids` and `Component.entrypoints` hold SolidityIDs, not
    # ProtocolIDs; they are checked against the CodeModel in `_code_notes` instead.
    for classification in model.contracts:
        check(classification.id, "component_id", classification.component_id)

    for asset in model.assets:
        check(asset.id, "backing_asset_id", asset.backing_asset_id)

    for flow in model.asset_flows:
        check(flow.id, "asset_id", flow.asset_id)
        check(flow.id, "operation_id", flow.operation_id)
        # `source`/`target` are heterogeneous by design (actor, role or dependency), so the
        # namespace is unconstrained — existence is still required.
        for field, value in (("source", flow.source), ("target", flow.target)):
            if value and value not in known:
                dangling.append(f"{flow.id}.{field} → {value}")

    for operation in model.operations:
        check(operation.id, "component_id", operation.component_id)
        for actor_id in operation.actor_ids:
            check(operation.id, "actor_ids", actor_id)
        for flow_id in operation.flow_ids:
            check(operation.id, "flow_ids", flow_id)
        for transition_id in operation.transition_ids:
            check(operation.id, "transition_ids", transition_id)
        for state_id in (*operation.reads, *operation.writes):
            check(operation.id, "state_id", state_id)
        for asset_id in (*operation.inputs, *operation.outputs):
            check(operation.id, "asset_id", asset_id)

    for item in model.state:
        check(item.id, "asset_id", item.asset_id)

    for transition in model.state_transitions:
        check(transition.id, "operation_id", transition.operation_id)
        check(transition.id, "state_id", transition.state_id)

    for quantity in model.accounting.quantities:
        check(quantity.id, "state_id", quantity.state_id)
        check(quantity.id, "asset_id", quantity.asset_id)
        for operation_id in (*quantity.increased_by, *quantity.decreased_by):
            check(quantity.id, "operation_id", operation_id)

    for relation in model.accounting.relations:
        for quantity_id in relation.quantity_ids:
            check(relation.id, "quantity_ids", quantity_id)

    for invariant in model.invariants:
        check(invariant.id, "relation_id", invariant.relation_id)
        for quantity_id in invariant.quantity_ids:
            check(invariant.id, "quantity_ids", quantity_id)
        for operation_id in invariant.operation_ids:
            check(invariant.id, "operation_ids", operation_id)

    for surface in model.risk_surfaces:
        for invariant_id in surface.invariant_ids:
            check(surface.id, "invariant_ids", invariant_id)

    for boundary in model.trust_boundaries:
        for field, value in (("inner", boundary.inner), ("outer", boundary.outer)):
            if value and value not in known:
                dangling.append(f"{boundary.id}.{field} → {value}")

    if mistyped:
        raise FatalError(
            f"{len(mistyped)} cross-references point into the wrong namespace: "
            f"{'; '.join(mistyped[:MAX_REPORTED])}",
            code=ProtocolCode.BAD_NAMESPACE,
            hint="A SolidityID was written where a ProtocolID belongs, or two entity kinds "
            "were mixed up. Mint IDs via engine/protocol/ids.py.",
        )
    if dangling:
        raise FatalError(
            f"{len(dangling)} cross-references point at records that do not exist: "
            f"{'; '.join(dangling[:MAX_REPORTED])}",
            code=ProtocolCode.DANGLING_REF,
            hint="A stage referenced an entity another stage did not emit. Assemble in "
            "stage order; a later stage may reference an earlier one, never the reverse.",
        )

    missing_targets = [i.id for i in model.invariants if not i.targets]
    if missing_targets:
        raise FatalError(
            f"{len(missing_targets)} invariants name nothing they constrain: "
            f"{', '.join(missing_targets[:MAX_REPORTED])}",
            code=ProtocolCode.INVARIANT_WITHOUT_TARGET,
            hint="An invariant with no target cannot be checked, cited by the Validator, "
            "or turned into a Forge test — it is a sentence, not an invariant.",
        )


def _check_order(model: ProtocolModel) -> None:
    violations = canonical_order_violations(model)
    if violations:
        raise FatalError(
            f"{len(violations)} lists are not in canonical order "
            f"({', '.join(violations[:MAX_REPORTED])}); the artifact would not be "
            "reproducible.",
            code=ProtocolCode.UNSORTED,
            hint="Call engine.protocol.order.canonicalize() before writing the artifact.",
        )


# ── Epistemic: notes ──────────────────────────────────────────────────────────


def _evidence_notes(model: ProtocolModel) -> list[str]:
    """Where the artifact claims more than it can show. Reported, never raised.

    The rule enforced here is the one that makes the whole evidence model worth having:
    **confidence above `INFERRED` requires a pointer**. A `DERIVED` claim asserts a
    deterministic rule produced it, so it can always name the edge or declaration it came
    from; if it cannot, either the rule is not deterministic or the confidence is inflated.
    """
    notes: list[str] = []
    unsupported = [
        claim
        for claim in model.claims()
        if claim.confidence.rank > Confidence.INFERRED.rank and not claim.evidence
    ]
    if unsupported:
        sample = ", ".join(sorted(_label(c) for c in unsupported)[:MAX_REPORTED])
        notes.append(
            f"{len(unsupported)} claims are marked {Confidence.DERIVED.value} or higher with "
            f"no evidence; treat them as inferred ({sample})"
        )

    guessed = [
        claim
        for claim in model.claims()
        if claim.confidence is Confidence.VERIFIED
        and not any(
            item.kind in (EvidenceKind.TEST, EvidenceKind.BUILD, EvidenceKind.STATIC)
            for item in claim.evidence
        )
    ]
    if guessed:
        notes.append(
            f"{len(guessed)} claims are marked verified without an independent check "
            "(test, build or static analysis) behind them"
        )

    heuristic_only = sum(
        1
        for claim in model.claims()
        if claim.evidence
        and all(item.kind is EvidenceKind.HEURISTIC for item in claim.evidence)
        and claim.confidence.rank > Confidence.INFERRED.rank
    )
    if heuristic_only:
        notes.append(
            f"{heuristic_only} claims rest only on name-matching heuristics but are ranked "
            "above inferred"
        )
    return notes


def _status_notes(model: ProtocolModel) -> list[str]:
    """Statuses that assert more than the pipeline is allowed to produce."""
    notes: list[str] = []

    unearned = [
        i.id
        for i in model.invariants
        if i.status is InvariantStatus.VERIFIED
        and not any(item.kind is EvidenceKind.TEST for item in i.evidence)
    ]
    if unearned:
        notes.append(
            f"{len(unearned)} invariants are marked verified with no executed check; only "
            "a Forge run (Phase I) can promote a candidate to verified"
        )

    proposed = [c for c in model.claims() if c.confidence is Confidence.PROPOSED]
    if proposed and not model.enrichment.applied:
        notes.append(
            f"{len(proposed)} claims are marked proposed but no enrichment pass ran; "
            "proposed is reserved for model-generated claims"
        )

    unchecked = sum(
        1 for r in model.documentation_rules if r.status is Reconciliation.NOT_CHECKED
    )
    if unchecked:
        notes.append(
            f"{unchecked} documentation rules were never reconciled against the code"
        )

    blocking = [g.id for g in model.gaps if g.blocking]
    if blocking:
        notes.append(
            f"{len(blocking)} semantic gaps are marked blocking; the affected fields are "
            "incomplete until an enrichment pass answers them"
        )
    return notes


def _code_notes(model: ProtocolModel, code: CodeModel) -> list[str]:
    """Every `SolidityID` this model cites must name real code.

    A note rather than a fatal: a `ProtocolModel` may legitimately be validated against a
    *different* `CodeModel` than it was built from (a re-parse, a narrowed scope). Making
    that fatal would reject a correct artifact for a mismatched input, so the mismatch is
    reported and the hashes on the model say which pairing was intended.
    """
    known = {c.id for c in code.contracts}
    known |= {
        f.id
        for c in code.contracts
        for f in (*c.functions, *c.modifiers)
    }
    known |= {v.id for c in code.contracts for v in c.state_vars}
    known |= {f.id for s in code.sources for f in s.free_functions}

    cited: set[str] = {
        *(c.contract_id for c in model.contracts),
        *(s.contract_id for s in model.standards),
        *(o.function_id for o in model.operations),
        *(s.state_var_id for s in model.state),
        *model.entrypoints,
        *model.privileged,
        *model.core_contracts,
        *(target for i in model.invariants for target in i.targets),
        *(
            capability.function_id
            for actor in model.actors
            for capability in actor.capabilities
        ),
    }
    missing = sorted(ref for ref in cited if ref and ref not in known)
    notes: list[str] = []
    if missing:
        notes.append(
            f"{len(missing)} SolidityIDs cited by the protocol model are absent from the "
            f"CodeModel ({', '.join(missing[:MAX_REPORTED])})"
        )
    if model.code_content_hash and model.code_content_hash != code.content_hash:
        notes.append(
            "protocol model was built against a different CodeModel "
            f"({model.code_content_hash[:12]} vs {code.content_hash[:12]})"
        )
    return notes


def _label(claim: Claim) -> str:
    identifier = getattr(claim, "id", "")
    return str(identifier) if identifier else type(claim).__name__


__all__ = ["ProtocolCode", "validate"]
