"""The deterministic detectors, run against real Solidity through the real pipeline.

Every test here goes reader → parser → graph → understand. A hand-built `CodeModel` would
let a detector pass on assumptions the parser does not satisfy, which is the failure mode
the whole artifact exists to prevent.
"""

from __future__ import annotations

import pytest

from engine.core.models.evidence import Confidence, EvidenceKind
from engine.core.models.protocol import (
    AssetKind,
    Compliance,
    Compliance as C,
    ContractRole,
    DependencyKind,
    FlowKind,
    InvariantStatus,
    OperationKind,
    Standard,
    StateRole,
    SurfaceKind,
    TransitionEffect,
    TrustLevel,
)
from tests.protocol.conftest_sources import (
    LENDING_PROJECT,
    TOKEN_PROJECT,
    VAULT_PROJECT,
)


@pytest.fixture
def vault(understand_of):
    return understand_of(VAULT_PROJECT)


@pytest.fixture
def lending(understand_of):
    return understand_of(LENDING_PROJECT)


@pytest.fixture
def tokens(understand_of):
    return understand_of(TOKEN_PROJECT)


# ── Stage 3: standards — "looks similar ≠ compliant" ──────────────────────────


def test_a_full_interface_match_is_compliant(tokens):
    claim = next(
        c
        for c in tokens.standards
        if c.standard is Standard.ERC20 and "GoodToken" in c.contract_id
    )
    assert claim.compliance is C.COMPLIANT
    assert claim.confidence is Confidence.DERIVED
    assert not claim.missing


def test_a_transfer_returning_nothing_is_divergent_not_compliant(tokens):
    """The USDT-style break: full interface, wrong semantics. The most security-relevant
    status the enum has."""
    claim = next(
        c
        for c in tokens.standards
        if c.standard is Standard.ERC20 and "SloppyToken" in c.contract_id
    )
    assert claim.compliance is C.DIVERGENT
    assert any("not (bool)" in d for d in claim.divergences)


def test_deposit_plus_withdraw_is_not_erc4626(vault):
    """SimpleVault has deposit and withdraw and is not ERC-4626. Claiming otherwise sends
    every agent hunting for inflation attacks the protocol never promised to prevent."""
    claims = [c for c in vault.standards if c.standard is Standard.ERC4626]
    assert all(c.compliance is not Compliance.COMPLIANT for c in claims)


def test_public_mappings_satisfy_an_interface(tokens):
    """`mapping(address => uint256) public balanceOf` compiles to `balanceOf(address)`.
    Missing that reports every Solmate-style token as non-compliant."""
    claim = next(
        c
        for c in tokens.standards
        if c.standard is Standard.ERC20 and "GoodToken" in c.contract_id
    )
    assert "balanceOf(address)" in claim.satisfied
    assert "allowance(address,address)" in claim.satisfied
    assert "totalSupply()" in claim.satisfied


# ── Stages 1–2: roles and archetype ───────────────────────────────────────────


def test_roles_and_archetype_are_derived_from_the_contracts(vault, lending, tokens):
    assert vault.contract_by_name("SimpleVault").role is ContractRole.VAULT
    assert lending.contract_by_name("LendingMarket").role is ContractRole.LENDING_MARKET
    assert vault.archetype == ["vault"]
    assert lending.archetype == ["lending"]
    assert tokens.archetype == ["token"]


def test_interfaces_are_not_classified_as_protocol_contracts(vault):
    """`IERC20` is a dependency's shape, not this protocol's. Classifying it would put a
    role record on every import in the repository."""
    assert all("IERC20" not in c.contract_id for c in vault.contracts)


def test_the_protocol_is_not_named_after_an_interface(vault):
    """File order is alphabetical, so "first contract" reliably picks IERC20."""
    assert vault.identity.name == "SimpleVault"


# ── Stage 4: actors ───────────────────────────────────────────────────────────


def test_an_unguarded_entrypoint_is_reachable_by_an_untrusted_user(vault):
    user = next(a for a in vault.actors if a.name == "user")
    assert user.trust is TrustLevel.UNTRUSTED
    assert any("deposit" in c.function_id for c in user.capabilities)


def test_onlyowner_produces_a_trusted_actor_with_that_capability(vault):
    owner = next(a for a in vault.actors if a.name == "owner")
    assert owner.trust is TrustLevel.TRUSTED
    assert any("setOwner" in fid for fid in owner.privileged_functions)


def test_liquidate_records_both_the_liquidator_and_anyone(lending):
    """`liquidate` is conventionally a liquidator's function and is still callable by any
    address. Replacing USER with LIQUIDATOR would hide exactly that."""
    names = {a.name for a in lending.actors}
    assert "liquidator" in names and "user" in names

    liquidate = lending.operation_by_name("liquidate")
    assert len(liquidate.actor_ids) >= 2


def test_constructors_are_not_operations(vault):
    """A constructor runs once at deployment, before any actor exists."""
    assert all(o.name != "constructor" for o in vault.operations)


# ── Stage 5: trust boundaries ─────────────────────────────────────────────────


def test_an_outbound_boundary_names_a_counterparty_that_exists(vault):
    outbound = [b for b in vault.trust_boundaries if b.outer == "actor:external-protocol"]
    assert outbound
    assert vault.actor("actor:external-protocol") is not None


def test_inbound_boundaries_record_the_checks_at_the_door(vault):
    owner_boundary = next(
        b for b in vault.trust_boundaries if b.outer.endswith(":owner")
    )
    assert "onlyOwner" in owner_boundary.checks


# ── Stage 6: assets ───────────────────────────────────────────────────────────


def test_a_token_typed_handle_is_a_derived_asset(vault):
    asset = next(a for a in vault.assets if a.symbol == "asset")
    assert asset.kind is AssetKind.ERC20
    assert asset.is_external
    assert asset.confidence is Confidence.DERIVED


def test_shares_are_protocol_issued_and_not_external(vault):
    share = next(a for a in vault.assets if a.kind is AssetKind.SHARE)
    assert share.is_protocol_issued
    assert not share.is_external


def test_an_index_is_not_an_asset(lending):
    """`borrowIndex` contains "borrow" and is an accrual multiplier, not debt. Treating it
    as an asset puts a phantom asset in every conservation invariant on the market."""
    assert all("index" not in a.symbol.lower() for a in lending.assets)


# ── Stage 7: flows ────────────────────────────────────────────────────────────


def test_transfer_from_flows_from_the_caller_into_the_protocol(vault):
    inbound = next(f for f in vault.asset_flows if f.kind is FlowKind.TRANSFER_FROM)
    assert inbound.source.endswith(":user")
    assert "SimpleVault" in inbound.target
    assert inbound.confidence is Confidence.DERIVED


def test_transfer_flows_out_of_the_protocol_to_the_caller(vault):
    outbound = next(f for f in vault.asset_flows if f.kind is FlowKind.TRANSFER)
    assert "SimpleVault" in outbound.source
    assert outbound.target.endswith(":user")


def test_the_amount_is_carried_verbatim(vault):
    """`Edge.text` is the callee expression only; the amount lives in the source."""
    assert all(f.amount_expr == "amount" for f in vault.asset_flows)


# ── Stage 8: operations ───────────────────────────────────────────────────────


def test_operations_are_named_in_protocol_terms(vault, lending):
    assert vault.operation_by_name("deposit").kind is OperationKind.DEPOSIT
    assert vault.operation_by_name("withdraw").kind is OperationKind.WITHDRAW
    assert lending.operation_by_name("borrow").kind is OperationKind.BORROW
    assert lending.operation_by_name("liquidate").kind is OperationKind.LIQUIDATE


def test_preconditions_are_extracted_verbatim(vault):
    withdraw = vault.operation_by_name("withdraw")
    assert any(
        "shares[msg.sender] >= amount" in precondition
        for precondition in withdraw.preconditions
    )


def test_modifiers_appear_as_preconditions(vault):
    assert "modifier onlyOwner" in vault.operation_by_name("setOwner").preconditions


def test_an_operation_records_the_state_it_writes(vault):
    deposit = vault.operation_by_name("deposit")
    written = {sid.rpartition("#")[2] for sid in deposit.writes}
    assert {"totalAssets", "totalShares", "shares"} <= written


# ── Stages 9–10: state and transitions ────────────────────────────────────────


def test_state_roles_are_read_from_names_within_what_the_type_allows(vault):
    by_name = {item.name: item for item in vault.state}
    assert by_name["totalAssets"].role is StateRole.ACCOUNTING_TOTAL
    assert by_name["totalShares"].role is StateRole.SHARE_SUPPLY
    assert by_name["shares"].role is StateRole.USER_BALANCE
    assert by_name["owner"].role is StateRole.ROLE_REGISTRY


def test_a_handle_is_never_an_accounting_record(lending):
    """`IERC20 collateralToken` contains "collateral" and is an address, not a balance.
    Reading it as one produced a solvency invariant about a token address."""
    item = next(i for i in lending.state if i.name == "collateralToken")
    assert item.role is StateRole.ADDRESS_REF


def test_transitions_carry_the_assignment_as_written(vault):
    deposit = vault.operation_by_name("deposit")
    transitions = vault.transitions_of(deposit.id)
    totals = next(
        t for t in transitions if t.state_id.endswith("#totalAssets")
    )
    assert totals.effect is TransitionEffect.INCREASE
    assert totals.delta_expr == "totalAssets += amount"


def test_withdraw_decreases_what_deposit_increased(vault):
    withdraw = vault.operation_by_name("withdraw")
    effects = {t.effect for t in vault.transitions_of(withdraw.id)}
    assert TransitionEffect.DECREASE in effects


def test_admin_controlled_state_is_flagged(vault):
    owner = next(item for item in vault.state if item.name == "owner")
    assert owner.is_admin_controlled


# ── Stage 11: dependencies ────────────────────────────────────────────────────


def test_a_dependency_is_named_by_its_declared_interface(vault):
    """`IERC20 public asset` names its interface nowhere in `asset.transferFrom(...)`, so a
    text-only match would report the dependency as "asset" and lose every failure mode."""
    names = {d.name for d in vault.dependencies}
    assert "IERC20" in names


def test_an_oracle_dependency_carries_concrete_failure_modes(lending):
    oracle = next(d for d in lending.dependencies if d.kind is DependencyKind.ORACLE)
    assert any("stale" in mode for mode in oracle.failure_modes)
    assert oracle.used_by


# ── Stage 12: accounting ──────────────────────────────────────────────────────


def test_a_ratio_is_recorded_only_when_the_code_contains_it(vault):
    ratio = next(r for r in vault.accounting.relations if r.kind.value == "ratio")
    assert ratio.expression == "shareAmount * totalAssets / totalShares"
    assert ratio.confidence is Confidence.DERIVED
    assert ratio.rounding == "unspecified"


def test_no_ratio_is_invented_when_the_code_has_none(lending):
    """A relationship invented from the archetype produces an invariant that is false for
    this protocol, and a confirmed false invariant is the worst output the system can make."""
    assert not [r for r in lending.accounting.relations if r.kind.value == "ratio"]


def test_quantities_carry_their_unit(vault):
    """Unit confusion between a share amount and an asset amount is a whole vulnerability
    class, and it is invisible unless someone writes the unit down."""
    quantities = {q.name: q for q in vault.accounting.quantities}
    assert quantities["totalShares"].unit == "share"
    assert quantities["totalAssets"].unit != quantities["totalShares"].unit


# ── Stage 13: economics ───────────────────────────────────────────────────────


def test_a_deposit_opens_the_conventional_vault_surfaces(vault):
    kinds = {s.kind for s in vault.economics.surfaces}
    assert SurfaceKind.FIRST_DEPOSITOR in kinds
    assert SurfaceKind.DONATION in kinds
    assert SurfaceKind.ROUNDING in kinds


def test_surfaces_ask_questions_rather_than_assert_bugs(vault):
    """A question survives being wrong; an assertion does not."""
    surface = next(s for s in vault.economics.surfaces if s.kind is SurfaceKind.DONATION)
    assert surface.questions
    assert all(q.endswith("?") for q in surface.questions)


def test_risk_surfaces_are_prioritised_and_carry_domains(vault):
    """Domains, not agents: which agent runs is the Orchestrator's decision (schema 1.1)."""
    surfaces = sorted(vault.risk_surfaces, key=lambda s: -s.priority)
    assert surfaces[0].priority > 0
    assert surfaces[0].domains


# ── Stage 14: documentation ───────────────────────────────────────────────────


def test_an_unenforced_documented_restriction_is_a_conflict(understand_of):
    model = understand_of(
        VAULT_PROJECT,
        readme="# SimpleVault\n\nOnly the owner can call deposit on this vault.\n",
    )
    conflict = next(
        (r for r in model.conflicts if "deposit" in r.statement.lower()), None
    )
    assert conflict is not None
    assert "no access-control modifier" in conflict.finding


def test_boilerplate_is_not_treated_as_a_rule(understand_of):
    model = understand_of(
        VAULT_PROJECT,
        readme="# SimpleVault\n\nYou must run `forge install` before the test suite.\n",
    )
    assert not model.documentation_rules


def test_a_documented_conflict_becomes_an_invariant(understand_of):
    model = understand_of(
        VAULT_PROJECT,
        readme="# SimpleVault\n\nOnly the owner can call deposit on this vault.\n",
    )
    assert any(i.source == "documentation" for i in model.invariants)


# ── Stage 15: invariants ──────────────────────────────────────────────────────


def test_every_invariant_is_a_candidate(vault, lending, tokens):
    for model in (vault, lending, tokens):
        assert all(
            i.status is InvariantStatus.CANDIDATE for i in model.invariants
        ), "nothing deterministic may promote past CANDIDATE"


def test_every_invariant_names_what_it_constrains(vault, lending, tokens):
    for model in (vault, lending, tokens):
        assert all(i.targets for i in model.invariants)
        assert all(i.evidence for i in model.invariants)


def test_a_vault_gets_a_solvency_and_a_supply_invariant(vault):
    kinds = {i.kind.value for i in vault.invariants}
    assert "solvency" in kinds
    assert "supply" in kinds


def test_a_lending_market_gets_invariants_too(lending):
    """Keying solvency only on WITHDRAW/REDEEM produced zero invariants for a lending
    protocol — the stage's most important output missing on one of its main archetypes."""
    assert lending.invariants
    assert "solvency" in {i.kind.value for i in lending.invariants}


def test_invariants_say_how_they_would_break(vault):
    solvency = next(i for i in vault.invariants if i.kind.value == "solvency")
    assert solvency.breaks_if


def test_assumptions_are_separate_from_invariants(lending):
    """An invariant is enforced by the code; an assumption is relied on by it."""
    oracle_assumption = next(
        a for a in lending.assumptions if "IPriceOracle" in a.statement
    )
    assert oracle_assumption.criticality == "high"
    assert not oracle_assumption.is_documented


# ── Stage 16: gaps ────────────────────────────────────────────────────────────


def test_external_token_behaviour_is_a_blocking_gap(vault):
    """`is_fee_on_transfer` defaults to False, and for an external token that default is an
    absence dressed as a finding."""
    gap = next(g for g in vault.gaps if "fee on transfer" in g.question)
    assert gap.blocking
    assert gap.context_ids
    assert gap.field == "assets.is_fee_on_transfer"


def test_gaps_carry_a_small_context(vault):
    assert all(len(g.context_ids) <= 6 for g in vault.gaps)


# ── Cross-cutting ─────────────────────────────────────────────────────────────


def test_the_model_validates_and_is_reproducible(vault, lending, tokens):
    for model in (vault, lending, tokens):
        assert model.content_hash
        assert model.with_content_hash().content_hash == model.content_hash


def test_every_claim_carries_evidence_or_admits_it_is_a_guess(vault):
    for claim in vault.claims():
        if claim.confidence.rank > Confidence.INFERRED.rank:
            assert claim.evidence, f"{claim} claims derivation with nothing behind it"


def test_evidence_points_at_real_code(vault):
    refs = {
        item.ref
        for claim in vault.claims()
        for item in claim.evidence
        if item.kind is EvidenceKind.SOURCE
    }
    assert refs
    assert all("src/" in ref for ref in refs if ref)


def test_coverage_reports_what_was_understood(vault):
    assert vault.coverage.contracts_total >= 1
    assert vault.coverage.classification_rate == 1.0
    assert vault.coverage.operation_rate > 0


def test_the_summary_always_states_its_limits(vault):
    assert vault.summary
    assert "SimpleVault" in vault.summary
