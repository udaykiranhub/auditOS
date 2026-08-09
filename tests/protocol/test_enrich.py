"""Phase H — the four gates an LLM answer must pass to enter the artifact.

No network anywhere in this file. A fake provider returns canned responses, which is the
only way to test the gates: the point of the design is that the *validation* is
deterministic even though the model is not.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest

from engine.core.models.evidence import Confidence, EvidenceKind
from engine.core.models.protocol import ContractRole, StateRole
from engine.protocol.enrich import NullProvider, enrich
from engine.protocol.enrich.context import build as build_context
from engine.protocol.enrich.provider import Completion, Message
from tests.protocol.conftest import build_from_sources
from tests.protocol.conftest_sources import VAULT_PROJECT


@dataclass
class FakeProvider:
    """Returns whatever the test hands it, and records what it was asked."""

    responses: list[str] = field(default_factory=list)
    prompts: list[str] = field(default_factory=list)
    name: str = "fake"

    @property
    def available(self) -> bool:
        return True

    def complete(self, system, messages: list[Message], *, max_tokens=1500) -> Completion:
        self.prompts.append(messages[-1].content)
        text = self.responses.pop(0) if self.responses else ""
        return Completion(text=text, model="fake-1", input_tokens=10, output_tokens=5)


def answer(value: str, evidence: list[str], **extra) -> str:
    return json.dumps(
        {"answer": "because the code says so", "value": value, "evidence": evidence, **extra}
    )


@pytest.fixture
def built(tmp_path):
    code, graph, repo = build_from_sources(tmp_path, VAULT_PROJECT, name="enrich")
    from engine.protocol.understand import understand

    return understand(code, graph, repo), code


# ── The default path: no provider ─────────────────────────────────────────────


def test_without_a_provider_the_model_is_unchanged(built):
    """"V1 produces a complete ProtocolModel with no API key" has to be true, not aspirational."""
    model, code = built
    result = enrich(model, code, NullProvider())

    assert not result.enrichment.applied
    assert result.enrichment.gaps_answered == 0
    assert result.invariants == model.invariants
    assert result.contracts == model.contracts


def test_a_provider_outage_degrades_rather_than_raising(built):
    """P6: the deterministic model is already complete, so an outage must not fail the run."""
    model, code = built

    @dataclass
    class Broken:
        name: str = "broken"

        @property
        def available(self) -> bool:
            return True

        def complete(self, system, messages, *, max_tokens=1500) -> Completion:
            return Completion(error="503 upstream unavailable")

    result = enrich(model, code, Broken())
    assert not result.enrichment.applied
    assert result.enrichment.gaps_rejected > 0


# ── Gate 1: parseable ─────────────────────────────────────────────────────────


def test_unparseable_json_is_rejected(built):
    model, code = built
    provider = FakeProvider(responses=["I think this is probably a vault, honestly."] * 10)

    result = enrich(model, code, provider)
    assert result.enrichment.gaps_answered == 0
    assert result.enrichment.gaps_rejected > 0


def test_fenced_json_is_accepted(built):
    """Models fence their JSON. Rejecting that would fail on style, not on substance."""
    payload = Completion(text="```json\n{\"value\": \"vault\"}\n```")
    assert payload.json() == {"value": "vault"}


# ── Gate 3: evidence must have been in the context ────────────────────────────


def test_an_answer_citing_code_it_was_never_shown_is_rejected(built):
    """The gate that catches confabulation: a model cannot cite a function it never saw."""
    model, code = built
    gap = next(g for g in model.gaps if g.field == "assets.is_fee_on_transfer")
    provider = FakeProvider(
        responses=[answer("yes", ["src/Invented.sol:Ghost.rug()"])] * 10
    )

    result = enrich(model, code, provider)
    assert result.enrichment.gaps_answered == 0
    assert any("validation" in note for note in result.enrichment.notes)


def test_an_answer_citing_nothing_is_rejected(built):
    model, code = built
    provider = FakeProvider(responses=[answer("vault", [])] * 10)

    result = enrich(model, code, provider)
    assert result.enrichment.gaps_answered == 0


def test_declining_to_answer_leaves_the_gap_open(built):
    """A model saying "unknown" is a correct outcome, not an answer. The gap is the more
    useful record."""
    model, code = built
    provider = FakeProvider(responses=[answer("unknown", ["src/SimpleVault.sol:SimpleVault"])] * 10)

    result = enrich(model, code, provider)
    assert result.enrichment.gaps_answered == 0
    assert len(result.gaps) == len(model.gaps)


# ── Gate 2: schema ────────────────────────────────────────────────────────────


def test_an_invented_enum_value_is_rejected_never_coerced(tmp_path):
    """Coercion would silently turn a confabulation into a fact."""
    from engine.core.models.protocol import ProtocolModel, SemanticGap
    from engine.protocol.enrich.apply import _validate

    gap = SemanticGap(id="gap:x", subject="role:a", question="?", field="contracts.role")
    assert _validate(
        {"answer": "a", "value": "hyperdimensional_vault", "evidence": ["x"]}, gap, {"x"}
    ) is None
    assert _validate({"answer": "a", "value": "vault", "evidence": ["x"]}, gap, {"x"}) is not None
    assert ProtocolModel is not None


# ── Gate 4: confidence is capped, never self-reported ─────────────────────────


def test_an_accepted_answer_lands_at_proposed(tmp_path):
    """Models are systematically overconfident and their self-reported confidence is
    uncorrelated with correctness (SPEC §7.7), so it is not read at all."""
    from engine.protocol.understand import understand

    sources = {
        "src/Mystery.sol": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Mystery {
    uint256 public glorp;
    function frobnicate(uint256 n) external { glorp = n; }
}
"""
    }
    code, graph, repo = build_from_sources(tmp_path, sources, name="mystery")
    model = understand(code, graph, repo)

    gap = next(g for g in model.gaps if g.field == "contracts.role")
    provider = FakeProvider(
        responses=[
            answer("registry", ["src/Mystery.sol:Mystery"], confidence="absolutely certain")
        ]
        + [answer("unknown", [])] * 10
    )

    result = enrich(model, code, provider)
    classification = result.contract("src/Mystery.sol:Mystery")

    assert classification.role is ContractRole.REGISTRY
    assert classification.confidence is Confidence.PROPOSED
    assert any(e.kind is EvidenceKind.MODEL for e in classification.evidence)
    assert gap.field == "contracts.role"


def test_enrichment_never_overwrites_a_deterministic_finding(built):
    """A model disagreeing with a DERIVED fact loses: the derivation is checkable and the
    opinion is not."""
    from engine.core.models.protocol import SemanticGap
    from engine.protocol.enrich.apply import _apply, _Answer

    model, _ = built
    model.gaps.append(
        SemanticGap(
            id="gap:override",
            subject="role:src/SimpleVault.sol:SimpleVault",
            question="?",
            field="contracts.role",
        )
    )
    applied = _apply(
        model,
        model.gaps[-1],
        _Answer(value="bridge", text="t", evidence=["src/SimpleVault.sol:SimpleVault"], reasoning=""),
    )
    assert not applied
    assert model.contract("src/SimpleVault.sol:SimpleVault").role is ContractRole.VAULT


# ── Context construction ──────────────────────────────────────────────────────


def test_the_context_contains_only_what_the_gap_named(built):
    model, code = built
    gap = next(g for g in model.gaps if g.context_ids)
    context = build_context(gap, model, code)

    assert context.excerpts
    assert context.known_ids <= set(gap.context_ids)
    assert len(context.render()) < 12_000


def test_the_context_lists_the_ids_an_answer_may_cite(built):
    model, code = built
    gap = next(g for g in model.gaps if g.context_ids)
    rendered = build_context(gap, model, code).render()

    assert "Allowed evidence ids" in rendered
    assert "# Question" in rendered


def test_the_context_carries_what_the_engine_already_knows(built):
    """So the model answers the open question rather than re-deriving — differently — what
    the deterministic pass established."""
    model, code = built
    gap = next(g for g in model.gaps if g.context_ids)
    context = build_context(gap, model, code)

    assert any("archetype" in fact for fact in context.facts)


def test_an_id_naming_nothing_is_omitted_not_faked(built):
    """A context containing "// not found" invites an answer grounded in nothing."""
    from engine.core.models.protocol import SemanticGap

    model, code = built
    gap = SemanticGap(
        id="gap:ghost", subject="x", question="?", context_ids=["src/Nope.sol:Nope"]
    )
    assert build_context(gap, model, code).excerpts == []


# ── Blocking gaps come first ──────────────────────────────────────────────────


def test_blocking_gaps_are_answered_first(built):
    model, code = built
    provider = FakeProvider(responses=[answer("unknown", [])] * 30)
    enrich(model, code, provider, max_gaps=1)

    blocking = [g for g in model.gaps if g.blocking]
    if blocking:
        assert blocking[0].question[:40] in provider.prompts[0]
