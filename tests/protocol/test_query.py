"""`ProtocolQuery` — the retrieval the Context Builder will be built on.

The property under test throughout: asking about one anchor returns a **connected** slice —
the operation, what it touches, what constrains it, what is unknown about it — without
returning the whole artifact. Writing these here means a stage that emits an operation
without linking its state fails in this package, rather than silently in an agent prompt.

This is not the Context Builder. No ranking, no budgeting, no compression is tested for,
because none is implemented.
"""

from __future__ import annotations

import pytest

from engine.core.models.protocol import SurfaceDomain
from engine.protocol import ProtocolQuery
from tests.protocol.conftest_sources import LENDING_PROJECT, VAULT_PROJECT


@pytest.fixture
def vault(understand_of):
    return understand_of(VAULT_PROJECT)


@pytest.fixture
def query(vault):
    return ProtocolQuery(vault)


@pytest.fixture
def lending_query(understand_of):
    return ProtocolQuery(understand_of(LENDING_PROJECT))


# ── Anchoring ─────────────────────────────────────────────────────────────────


def test_an_anchor_may_be_named_in_any_vocabulary(query, vault):
    """An agent holds a SolidityID, a report holds a name, a UI holds a ProtocolID.
    Forcing one on all of them just moves the translation somewhere less consistent."""
    deposit = vault.operation_by_name("deposit")

    assert query.resolve(deposit.function_id) == deposit.function_id
    assert query.resolve(deposit.id) == deposit.function_id
    assert query.resolve("deposit") == deposit.function_id
    assert query.resolve("SimpleVault") == "src/SimpleVault.sol:SimpleVault"


def test_an_unknown_anchor_returns_an_empty_slice_rather_than_guessing(query):
    result = query.around("src/Nope.sol:Nope.ghost()")
    assert result.is_empty
    assert result.anchor == "src/Nope.sol:Nope.ghost()"


# ── The worked retrieval from the brief ───────────────────────────────────────


def test_an_operation_anchor_returns_everything_needed_to_reason_about_it(
    lending_query,
):
    """`business_logic + LendingMarket.borrow()` must reach the contract, the function,
    its state, the collateral and debt records, the accounting, the related operations,
    the invariants, the surfaces and the open questions — and nothing else."""
    result = lending_query.around("borrow")

    assert result.contracts, "the enclosing contract"
    assert result.operations, "the operation itself"
    assert result.state, "the state it touches"
    assert result.surfaces, "where to look"
    assert result.evidence, "the trail behind all of it"

    names = {item.name for item in result.state}
    assert {"collateral", "debt"} & names


def test_the_slice_reaches_the_inverse_operation(query, vault):
    """Every accounting bug lives in the gap between an operation and its inverse; a
    retrieval returning one without the other hands an agent half a system."""
    result = query.around("deposit")
    reached = {operation.name for operation in result.operations}
    assert {"deposit", "withdraw"} <= reached


def test_the_slice_is_smaller_than_the_whole_model(lending_query):
    result = lending_query.around("borrow")
    assert result.counts["operations"] < len(lending_query.model.operations)
    assert result.counts["state"] < len(lending_query.model.state)


def test_the_slice_names_the_code_a_context_request_would_fetch(query):
    result = query.around("deposit")
    ids = result.solidity_ids

    assert ids == sorted(ids), "deterministic ordering"
    assert any(sid.endswith("deposit(uint256)") for sid in ids)
    assert all("src/" in sid for sid in ids)


def test_invariants_and_surfaces_join_on_the_slice(query):
    """Everything returned must attach to something else in the slice — including the
    related operations, since those are pulled in precisely to be reasoned about."""
    result = query.around("withdraw")
    within = set(result.solidity_ids)

    assert result.invariants and result.surfaces
    for invariant in result.invariants:
        assert set(invariant.targets) & within
    for surface in result.surfaces:
        assert set(surface.targets) & within


def test_open_questions_travel_with_the_slice(query):
    result = query.around("SimpleVault")
    assert result.gaps, "a contract holding an external token has an open question"


# ── Other anchor kinds ────────────────────────────────────────────────────────


def test_a_contract_anchor_returns_its_whole_surface(query, vault):
    result = query.around("src/SimpleVault.sol:SimpleVault")
    assert len(result.operations) == len(vault.operations)
    assert len(result.state) == len(vault.state)
    assert result.actors


def test_a_state_anchor_returns_everyone_who_touches_it(query, vault):
    total_assets = next(item for item in vault.state if item.name == "totalAssets")
    result = query.around(total_assets.state_var_id)

    assert [item.name for item in result.state] == ["totalAssets"]
    assert {o.name for o in result.operations} >= {"deposit", "withdraw"}
    assert result.transitions


# ── Domain filtering, and what it deliberately does not filter ────────────────


def test_a_domain_narrows_the_surfaces(query):
    everything = query.around("deposit")
    accounting = query.around("deposit", domains=[SurfaceDomain.ACCOUNTING])

    assert accounting.counts["surfaces"] <= everything.counts["surfaces"]
    assert all(
        SurfaceDomain.ACCOUNTING in surface.domains for surface in accounting.surfaces
    )


def test_a_domain_does_not_strip_the_structure_needed_to_answer(query):
    """An accounting-focused request still needs the guards and calls to reason about;
    filtering the whole slice by domain removes the context that makes it correct."""
    accounting = query.around("deposit", domains=[SurfaceDomain.ACCOUNTING])
    assert accounting.operations
    assert accounting.state
    assert accounting.contracts


# ── Orchestrator entry points ─────────────────────────────────────────────────


def test_domain_anchors_are_ranked_by_the_models_own_priority(query):
    """Given an agent whose capability is `accounting`, where should it start? The answer
    is the model's ranking, not the caller's guess."""
    anchors = query.anchors_for_domain(SurfaceDomain.ACCOUNTING)
    assert anchors
    assert len(anchors) == len(set(anchors))
    assert all(query.resolve(anchor) is not None for anchor in anchors)


def test_the_domain_census_shows_where_the_work_is(query):
    census = query.domains()
    assert census
    counts = list(census.values())
    assert counts == sorted(counts, reverse=True)


def test_no_agent_names_appear_anywhere_in_retrieval(query):
    """The model must not answer "which agent must run?" — that is the Orchestrator's call
    against its own registry."""
    result = query.around("deposit")
    for surface in result.surfaces:
        assert not hasattr(surface, "suggested_agents")
        assert all(isinstance(domain, SurfaceDomain) for domain in surface.domains)


# ── Determinism ───────────────────────────────────────────────────────────────


def test_retrieval_is_deterministic(query):
    first = query.around("deposit")
    second = query.around("deposit")
    assert first.solidity_ids == second.solidity_ids
    assert [i.id for i in first.invariants] == [i.id for i in second.invariants]
    assert [e.key() for e in first.evidence] == [e.key() for e in second.evidence]
