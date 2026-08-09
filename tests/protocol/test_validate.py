"""Validation — structural corruption is fatal, epistemic weakness is a note.

The split is the point. A dangling reference makes the artifact unusable and must stop the
run; a poorly-grounded claim is a legitimate outcome that must be *reported* rather than
suppressed, because a validator that rejects an honest partial model only teaches us to
inflate confidence to get past it.
"""

from __future__ import annotations

import pytest

from engine.core.errors import FatalError
from engine.core.models.evidence import Confidence, source_evidence
from engine.core.models.protocol import (
    Assumption,
    Component,
    DocumentationRule,
    Invariant,
    InvariantStatus,
    ProtocolModel,
    SemanticGap,
)
from engine.protocol import canonicalize, validate
from engine.protocol.ids import make_component_id
from engine.protocol.validate import ProtocolCode
from tests.protocol.conftest import WITHDRAW


def check(model: ProtocolModel) -> list[str]:
    return validate(canonicalize(model))


# ── Fatal: structural ─────────────────────────────────────────────────────────


def test_a_clean_model_passes(vault_model: ProtocolModel):
    assert check(vault_model) == []


def test_duplicate_ids_are_fatal(vault_model: ProtocolModel):
    vault_model.assumptions = [
        Assumption(id="assume:x", statement="a"),
        Assumption(id="assume:x", statement="b"),
    ]
    with pytest.raises(FatalError) as exc:
        check(vault_model)
    assert exc.value.code == ProtocolCode.DUPLICATE_ID


def test_an_unnamespaced_id_is_fatal(vault_model: ProtocolModel):
    """Catches a SolidityID used where a ProtocolID belongs."""
    vault_model.components = [Component(id="src/Vault.sol:Vault", name="core")]
    with pytest.raises(FatalError) as exc:
        check(vault_model)
    assert exc.value.code == ProtocolCode.BAD_NAMESPACE


def test_a_reference_into_the_wrong_namespace_is_fatal(vault_model: ProtocolModel):
    vault_model.operations[0].actor_ids = ["asset:usdc"]
    with pytest.raises(FatalError) as exc:
        check(vault_model)
    assert exc.value.code == ProtocolCode.BAD_NAMESPACE


def test_a_dangling_reference_is_fatal(vault_model: ProtocolModel):
    vault_model.operations[0].component_id = make_component_id("nonexistent")
    with pytest.raises(FatalError) as exc:
        check(vault_model)
    assert exc.value.code == ProtocolCode.DANGLING_REF


def test_a_flow_pointing_at_an_undeclared_asset_is_fatal(vault_model: ProtocolModel):
    vault_model.asset_flows[0].asset_id = "asset:ghost"
    with pytest.raises(FatalError) as exc:
        check(vault_model)
    assert exc.value.code == ProtocolCode.DANGLING_REF


def test_an_invariant_with_no_target_is_fatal(vault_model: ProtocolModel):
    vault_model.invariants[0].targets = []
    with pytest.raises(FatalError) as exc:
        check(vault_model)
    assert exc.value.code == ProtocolCode.INVARIANT_WITHOUT_TARGET


def test_an_unsorted_model_is_fatal(vault_model: ProtocolModel):
    """Unsorted passes every semantic test and silently breaks caching."""
    ordered = canonicalize(vault_model)
    ordered.operations.reverse()
    with pytest.raises(FatalError) as exc:
        validate(ordered)
    assert exc.value.code == ProtocolCode.UNSORTED


def test_the_two_surface_lists_may_share_ids(vault_model: ProtocolModel):
    """`surface:` is shared by design — the same place seen through two lenses."""
    from engine.core.models.protocol import EconomicSurface, RiskSurface, SurfaceKind

    surface_id = "surface:rounding:" + WITHDRAW
    vault_model.economics.surfaces = [
        EconomicSurface(id=surface_id, kind=SurfaceKind.ROUNDING, target=WITHDRAW)
    ]
    vault_model.risk_surfaces = [RiskSurface(id=surface_id, kind=SurfaceKind.ROUNDING)]
    assert check(vault_model) == []


# ── Notes: epistemic ──────────────────────────────────────────────────────────


def test_confidence_above_inferred_requires_evidence(vault_model: ProtocolModel):
    vault_model.assumptions = [
        Assumption(id="assume:x", statement="the oracle is honest", confidence=Confidence.DERIVED)
    ]
    notes = check(vault_model)
    assert any("no evidence" in note for note in notes)


def test_an_inferred_claim_with_no_evidence_is_not_flagged(vault_model: ProtocolModel):
    """Inferred already says "this is a guess"; demanding evidence for it would just
    encourage detectors to attach a token citation."""
    vault_model.assumptions = [
        Assumption(id="assume:x", statement="a guess", confidence=Confidence.INFERRED)
    ]
    assert check(vault_model) == []


def test_verified_without_an_independent_check_is_flagged(vault_model: ProtocolModel):
    vault_model.contracts[0].confidence = Confidence.VERIFIED
    vault_model.contracts[0].evidence = [source_evidence("src/SimpleVault.sol:SimpleVault")]
    notes = check(vault_model)
    assert any("verified without an independent check" in note for note in notes)


def test_only_an_executed_run_may_mark_an_invariant_verified(vault_model: ProtocolModel):
    vault_model.invariants[0].status = InvariantStatus.VERIFIED
    notes = check(vault_model)
    assert any("no executed check" in note for note in notes)


def test_proposed_claims_without_an_enrichment_pass_are_flagged(vault_model: ProtocolModel):
    vault_model.invariants[0].confidence = Confidence.PROPOSED
    notes = check(vault_model)
    assert any("no enrichment pass ran" in note for note in notes)


def test_unreconciled_documentation_is_reported(vault_model: ProtocolModel):
    vault_model.documentation_rules = [
        DocumentationRule(id="docrule:x", statement="shares are proportional")
    ]
    notes = check(vault_model)
    assert any("never reconciled" in note for note in notes)


def test_blocking_gaps_are_reported(vault_model: ProtocolModel):
    vault_model.gaps = [
        SemanticGap(id="gap:x", subject="asset:usdc", question="fee on transfer?", blocking=True)
    ]
    notes = check(vault_model)
    assert any("blocking" in note for note in notes)


# ── Against a CodeModel ───────────────────────────────────────────────────────


def test_solidity_ids_are_checked_against_the_code_model(vault_model: ProtocolModel):
    from engine.core.models.code import CodeModel

    notes = validate(canonicalize(vault_model), CodeModel())
    assert any("absent from the CodeModel" in note for note in notes)


def test_a_mismatched_code_model_is_a_note_not_a_failure(vault_model: ProtocolModel):
    """A ProtocolModel may legitimately be checked against a re-parse; rejecting it would
    fail a correct artifact for a mismatched input."""
    from engine.core.models.code import CodeModel

    vault_model.code_content_hash = "a" * 64
    notes = validate(canonicalize(vault_model), CodeModel(content_hash="b" * 64))
    assert any("different CodeModel" in note for note in notes)


def test_an_invariant_without_evidence_still_validates():
    """Nothing here demands a full understanding — a sparse model is a legitimate result."""
    model = ProtocolModel(
        invariants=[Invariant(id="inv:x", statement="s", targets=["src/V.sol:V"])]
    )
    assert validate(canonicalize(model)) == []
