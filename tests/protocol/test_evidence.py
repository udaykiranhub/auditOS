"""Evidence and confidence — the mechanism that keeps interpretation honest.

The rules under test are the ones that stop a naming guess laundering itself into a
certainty by the time an agent reads it.
"""

from __future__ import annotations

from engine.core.models.evidence import (
    Claim,
    Confidence,
    Evidence,
    EvidenceKind,
    dedupe_evidence,
    doc_evidence,
    graph_evidence,
    heuristic_evidence,
    source_evidence,
)


def test_the_confidence_ladder_is_ordered_weakest_first():
    ladder = [
        Confidence.REFUTED,
        Confidence.PROPOSED,
        Confidence.INFERRED,
        Confidence.DERIVED,
        Confidence.STATED,
        Confidence.VERIFIED,
    ]
    assert [level.rank for level in ladder] == sorted(level.rank for level in ladder)


def test_only_derived_and_above_count_as_grounded():
    assert not Confidence.INFERRED.is_grounded
    assert not Confidence.PROPOSED.is_grounded
    assert Confidence.DERIVED.is_grounded
    assert Confidence.VERIFIED.is_grounded


def test_a_chain_is_as_strong_as_its_weakest_link():
    """A DERIVED operation over an INFERRED asset is an INFERRED fact — propagating the
    stronger value is how a guess becomes a certainty two stages later."""
    assert (
        Confidence.weakest(Confidence.DERIVED, Confidence.INFERRED) is Confidence.INFERRED
    )
    assert Confidence.weakest(Confidence.VERIFIED, Confidence.STATED) is Confidence.STATED
    assert Confidence.weakest() is Confidence.INFERRED


def test_a_claim_is_grounded_only_when_it_is_both_confident_and_cites_something():
    bare = Claim(confidence=Confidence.DERIVED)
    assert not bare.is_grounded

    cited = Claim(confidence=Confidence.DERIVED, evidence=[source_evidence("src/V.sol:V")])
    assert cited.is_grounded

    guessed = Claim(confidence=Confidence.INFERRED, evidence=[heuristic_evidence("h", "d")])
    assert not guessed.is_grounded


def test_evidence_dedupes_so_one_line_is_not_two_corroborations():
    """Two detectors hitting the same declaration is one piece of evidence, not two."""
    items = [
        source_evidence("src/V.sol:V.f()", "a", detector="d"),
        source_evidence("src/V.sol:V.f()", "b", detector="d"),
        source_evidence("src/V.sol:V.g()", detector="d"),
    ]
    assert len(dedupe_evidence(items)) == 2


def test_evidence_order_is_canonical():
    items = [
        graph_evidence("b", "writes", "c"),
        source_evidence("a"),
        doc_evidence("README.md", "shares are proportional"),
    ]
    deduped = dedupe_evidence(items)
    assert [item.key() for item in deduped] == sorted(item.key() for item in deduped)


def test_claim_sources_returns_only_solidity_ids():
    claim = Claim(
        evidence=[
            source_evidence("src/V.sol:V.f()"),
            graph_evidence("src/V.sol:V.f()", "writes", "src/V.sol:V#x"),
            doc_evidence("README.md", "text"),
        ]
    )
    assert claim.sources() == ["src/V.sol:V.f()"]


def test_with_evidence_is_pure_and_keeps_the_list_canonical():
    original = Claim(evidence=[source_evidence("b")])
    extended = original.with_evidence(source_evidence("a"))

    assert [item.ref for item in original.evidence] == ["b"]
    assert [item.ref for item in extended.evidence] == ["a", "b"]


def test_evidence_kinds_carry_the_detector_that_produced_them():
    """A wrong claim must be traceable to a line of Python, not to a judgement call."""
    item = heuristic_evidence("erc4626_interface", "4 of 6 members present")
    assert item.kind is EvidenceKind.HEURISTIC
    assert item.detector == "erc4626_interface"


def test_evidence_rejects_unknown_fields():
    """`extra="forbid"` everywhere: a typo'd field must fail loudly, not vanish."""
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Evidence(kind=EvidenceKind.SOURCE, reference="typo")  # type: ignore[call-arg]
