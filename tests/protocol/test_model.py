"""`ProtocolModel` — schema, derived views, and round-trip serialization.

The hand-built `SimpleVault` in `conftest.py` is the worked example the schema was designed
against, so these tests double as a check that the schema can actually express a vault.
"""

from __future__ import annotations

import json
from pathlib import Path

from engine.core.artifacts import load_artifact, save_artifact
from engine.core.models.evidence import Confidence
from engine.core.models.protocol import (
    SCHEMA_VERSION,
    Invariant,
    InvariantStatus,
    OperationKind,
    ProtocolModel,
    Reconciliation,
    TrustLevel,
)
from engine.protocol import finalize
from tests.protocol.conftest import DEPOSIT, WITHDRAW


def test_an_empty_model_is_valid_and_versioned():
    """Stages fill this in incrementally, so the empty model has to be constructible."""
    model = ProtocolModel()
    assert model.schema_version == SCHEMA_VERSION
    assert model.counts["operations"] == 0
    assert model.coverage.classification_rate == 0.0


def test_the_schema_expresses_the_worked_vault_example(vault_model: ProtocolModel):
    counts = vault_model.counts
    assert counts["operations"] == 2
    assert counts["assets"] == 2
    assert counts["state"] == 3
    assert counts["invariants"] == 1

    deposit = vault_model.operation_for(DEPOSIT)
    assert deposit is not None
    assert deposit.kind is OperationKind.DEPOSIT
    assert vault_model.asset(deposit.outputs[0]) is not None
    assert vault_model.asset(deposit.outputs[0]).kind.value == "share"


def test_spec_7_6_field_names_are_available(vault_model: ProtocolModel):
    """SPEC §7.6 names `archetype`, `value_flows`, `trust_assumptions`, `external_deps`;
    the model stores richer records and exposes those names as views over them."""
    assert vault_model.archetype == ["vault"]
    assert vault_model.value_flows is vault_model.asset_flows
    assert vault_model.trust_assumptions == []
    assert vault_model.external_deps == []


def test_invariants_start_as_candidates_never_as_findings(vault_model: ProtocolModel):
    invariant = vault_model.invariants[0]
    assert invariant.status is InvariantStatus.CANDIDATE
    assert vault_model.candidate_invariants == [invariant]
    assert vault_model.verified_invariants == []
    assert invariant.is_actionable


def test_an_invariant_without_targets_is_not_actionable():
    """It cannot be checked, cited, or turned into a test — it is a sentence."""
    assert not Invariant(id="inv:x", statement="things are fine", targets=[]).is_actionable


def test_users_are_untrusted_by_default(vault_model: ProtocolModel):
    assert [a.trust for a in vault_model.untrusted_actors] == [TrustLevel.UNTRUSTED]


def test_the_confidence_histogram_shows_how_much_was_guessed(vault_model: ProtocolModel):
    histogram = vault_model.confidence_histogram()
    assert histogram[Confidence.INFERRED.value] > 0
    assert histogram[Confidence.DERIVED.value] > 0
    assert histogram[Confidence.VERIFIED.value] == 0
    assert sum(histogram.values()) == len(vault_model.claims())


def test_claims_enumerates_nested_capabilities(vault_model: ProtocolModel):
    function_ids = {
        getattr(claim, "function_id", None) for claim in vault_model.claims()
    }
    assert DEPOSIT in function_ids and WITHDRAW in function_ids


def test_evidence_for_returns_the_trail_behind_one_record(vault_model: ProtocolModel):
    invariant = vault_model.invariants[0]
    trail = vault_model.evidence_for(invariant.id)
    assert trail and trail[0].ref == WITHDRAW
    assert vault_model.evidence_for("inv:does-not-exist") == []


def test_documentation_conflicts_are_surfaced_separately():
    assert ProtocolModel().conflicts == []
    assert Reconciliation.CONFLICTS.value == "conflicts"


def test_round_trips_through_json_byte_identically(
    vault_model: ProtocolModel, tmp_path: Path
):
    """SPEC §7.1: the same input must produce a byte-identical file on every run."""
    finalized = finalize(vault_model)
    run_dir = tmp_path / "run"
    (run_dir / "artifacts").mkdir(parents=True)

    first = save_artifact(finalized, run_dir, "protocol")
    original = first.read_bytes()

    reloaded = load_artifact(ProtocolModel, first)
    assert reloaded == finalized

    save_artifact(reloaded, run_dir, "protocol")
    assert first.read_bytes() == original


def test_content_hash_covers_the_semantics_not_the_hash_field(vault_model: ProtocolModel):
    finalized = finalize(vault_model)
    assert finalized.content_hash
    assert finalized.with_content_hash().content_hash == finalized.content_hash

    changed = finalized.model_copy(deep=True)
    changed.invariants[0].statement = "something else entirely"
    assert changed.with_content_hash().content_hash != finalized.content_hash


def test_serialized_form_is_json_serializable_end_to_end(vault_model: ProtocolModel):
    payload = json.loads(finalize(vault_model).model_dump_json())
    assert payload["archetypes"][0]["archetype"] == "vault"
    assert payload["invariants"][0]["label"] == "INV-001"
