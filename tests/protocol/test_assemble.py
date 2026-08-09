"""Stage 17 — canonicalize, label, measure, validate, hash.

The property that matters: `finalize` is deterministic and pure. Two runs that discovered
the same facts in a different order must produce the same bytes, or the artifact cache
never hits and nobody notices.
"""

from __future__ import annotations

from engine.core.models.code import CodeModel, Contract, Function, StateVar
from engine.core.models.evidence import Confidence, source_evidence
from engine.core.models.protocol import Assumption, ProtocolModel
from engine.protocol import finalize, measure, new_model
from engine.protocol.order import canonical_order_violations, canonicalize
from tests.protocol.conftest import DEPOSIT, PATH, TOTAL_ASSETS, VAULT, WITHDRAW, simple_vault_model


def test_new_model_records_which_artifacts_it_describes():
    code = CodeModel(content_hash="c" * 64)
    model = new_model(code=code)
    assert model.code_content_hash == code.content_hash


def test_discovery_order_does_not_change_the_artifact():
    """The whole reason canonical ordering exists: same facts, different detector order,
    identical bytes."""
    forward = simple_vault_model()
    reversed_discovery = simple_vault_model()
    reversed_discovery.operations.reverse()
    reversed_discovery.state.reverse()
    reversed_discovery.assets.reverse()
    reversed_discovery.asset_flows.reverse()

    assert finalize(forward).content_hash == finalize(reversed_discovery).content_hash


def test_canonicalize_is_pure(vault_model: ProtocolModel):
    before = [operation.id for operation in vault_model.operations]
    canonicalize(vault_model)
    assert [operation.id for operation in vault_model.operations] == before


def test_canonicalize_leaves_nothing_out_of_order(vault_model: ProtocolModel):
    assert canonical_order_violations(canonicalize(vault_model)) == []


def test_archetypes_are_ranked_strongest_first():
    from engine.core.models.protocol import Archetype, ArchetypeClaim

    model = ProtocolModel(
        archetypes=[
            ArchetypeClaim(archetype=Archetype.STAKING, weight=0.3),
            ArchetypeClaim(archetype=Archetype.VAULT, weight=0.9),
        ]
    )
    assert canonicalize(model).archetype == ["vault", "staking"]


def test_core_contracts_ranking_is_not_alphabetized():
    """It is a ranking; sorting it would destroy the only information it carries."""
    model = ProtocolModel(core_contracts=["src/Z.sol:Z", "src/A.sol:A"])
    assert canonicalize(model).core_contracts == ["src/Z.sol:Z", "src/A.sol:A"]


def test_evidence_is_deduped_during_canonicalization():
    model = ProtocolModel(
        assumptions=[
            Assumption(
                id="assume:x",
                statement="s",
                evidence=[source_evidence("src/V.sol:V"), source_evidence("src/V.sol:V")],
            )
        ]
    )
    assert len(canonicalize(model).assumptions[0].evidence) == 1


def test_labels_follow_canonical_order_and_are_stable(vault_model: ProtocolModel):
    finalized = finalize(vault_model)
    assert finalized.invariants[0].label == "INV-001"
    assert finalize(finalized).invariants[0].label == "INV-001"


def test_finalize_appends_validation_notes_without_duplicating_them(
    vault_model: ProtocolModel,
):
    vault_model.assumptions = [
        Assumption(id="assume:x", statement="unsupported", confidence=Confidence.DERIVED)
    ]
    once = finalize(vault_model)
    twice = finalize(once)
    assert once.notes
    assert twice.notes == once.notes


def test_coverage_denominators_come_from_the_code_model(vault_model: ProtocolModel):
    """"We classified 1 contract" means nothing without "out of 3"."""
    code = CodeModel(
        contracts=[
            Contract(
                id=VAULT,
                name="SimpleVault",
                path=PATH,
                functions=[
                    Function(
                        id=DEPOSIT, name="deposit", contract_id=VAULT, visibility="external"
                    ),
                    Function(
                        id=WITHDRAW, name="withdraw", contract_id=VAULT, visibility="external"
                    ),
                ],
                state_vars=[
                    StateVar(
                        id=TOTAL_ASSETS, name="totalAssets", type="uint256", contract_id=VAULT
                    )
                ],
            ),
            Contract(id="src/Other.sol:Other", name="Other", path="src/Other.sol"),
        ]
    )
    coverage = measure(canonicalize(vault_model), code)

    assert coverage.contracts_total == 2
    assert coverage.contracts_classified == 1
    assert coverage.classification_rate == 0.5
    assert coverage.entrypoints_total == 2
    assert coverage.operations_modelled == 2
    assert coverage.operation_rate == 1.0


def test_coverage_separates_grounded_claims_from_guesses(vault_model: ProtocolModel):
    coverage = measure(canonicalize(vault_model))
    assert coverage.grounded_claims > 0
    assert coverage.ungrounded_claims > 0
    assert coverage.grounded_claims + coverage.ungrounded_claims == len(vault_model.claims())


def test_an_empty_model_finalizes_cleanly():
    """A protocol we understood poorly is a legitimate outcome, not a crash."""
    finalized = finalize(ProtocolModel())
    assert finalized.content_hash
    assert finalized.coverage.contracts_total == 0
