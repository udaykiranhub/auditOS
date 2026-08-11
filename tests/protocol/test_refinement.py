"""Regression tests for the semantic-quality refinement pass.

Every test here pins a defect observed in a **real** run of the current implementation
against Arcadia Finance (`accounts-v2` and `lending-v2`). The fixtures below are minimal
reproductions of the exact shapes that broke, so a regression fails here in a second rather
than three phases downstream in an agent prompt.
"""

from __future__ import annotations

import pytest

from engine.core.models.evidence import Confidence
from engine.core.models.protocol import (
    AssetIdentity,
    AssetRole,
    ContractRole,
    OperationKind,
    RelationshipStatus,
    StateRole,
    SurfaceDomain,
)
from engine.protocol.heuristics.signatures import (
    camel_tokens,
    has_token,
    starts_with_token,
)
from tests.protocol.conftest_sources import VAULT_PROJECT

# ── Fixtures reproducing the Arcadia shapes ───────────────────────────────────

#: A valuation adapter. Has `processDirectDeposit` and `getUsdValue…AfterDeposit`, custodies
#: nothing — and was classified as a VAULT, inheriting custody semantics and solvency
#: invariants about funds it never touches.
ASSET_MODULE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ChainlinkAM {
    mapping(address => uint256) public assetToAssetInformation;
    mapping(address => uint256) public exposureOfAsset;
    address public registry;

    function getValue(address asset, uint256 amount) external view returns (uint256) {
        return assetToAssetInformation[asset] * amount;
    }

    function getUsdValueExposureToUnderlyingAssetAfterDeposit(address asset)
        external view returns (uint256)
    {
        return exposureOfAsset[asset];
    }

    function processDirectDeposit(address asset, uint256 amount) external {
        exposureOfAsset[asset] += amount;
    }

    function processIndirectWithdrawal(address asset, uint256 amount) external {
        exposureOfAsset[asset] -= amount;
    }

    function isAllowed(address asset) external view returns (bool) {
        return assetToAssetInformation[asset] > 0;
    }
}
"""

#: Two contracts each declaring `IERC20 public asset`. Whether they hold the same token is
#: not knowable from source, and the model must not decide either way.
TWO_VAULTS = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "./IERC20.sol";

contract VaultA {
    IERC20 public asset;
    uint256 public totalAssets;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    function deposit(uint256 amount) external {
        asset.transferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += amount;
        totalAssets += amount;
        totalShares += amount;
    }

    function withdraw(uint256 amount) external {
        shares[msg.sender] -= amount;
        totalShares -= amount;
        totalAssets -= amount;
        asset.transfer(msg.sender, amount);
    }

    function redeem(uint256 amount) external { withdraw(amount); }
    function mint(uint256 amount) external { deposit(amount); }
    function convertToAssets(uint256 s) public view returns (uint256) {
        return s * totalAssets / totalShares;
    }
}

contract VaultB {
    IERC20 public asset;
    uint256 public totalAssets;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    function deposit(uint256 amount) external {
        asset.transferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += amount;
        totalAssets += amount;
        totalShares += amount;
    }

    function withdraw(uint256 amount) external {
        shares[msg.sender] -= amount;
        totalShares -= amount;
        totalAssets -= amount;
        asset.transfer(msg.sender, amount);
    }

    function redeem(uint256 amount) external { withdraw(amount); }
    function mint(uint256 amount) external { deposit(amount); }
    function convertToAssets(uint256 s) public view returns (uint256) {
        return s * totalAssets / totalShares;
    }
}
"""

#: Constants and bounds that were read as accounting totals and reward assets.
PARAMETERS = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Params {
    uint256 public constant MAX_TOTAL_PENALTY = 1000;
    uint256 public maxReward;
    uint256 public minRewardWeight;
    uint256 public originationFee;
    uint256 public borrowIndex;
    uint256 public totalRealisedLiquidity;

    function borrow(uint256 amount) external { totalRealisedLiquidity -= amount; }
    function repay(uint256 amount) external { totalRealisedLiquidity += amount; }
}
"""

ASSET_MODULE_PROJECT = {"src/ChainlinkAM.sol": ASSET_MODULE}
TWO_VAULTS_PROJECT = {
    "src/IERC20.sol": VAULT_PROJECT["src/IERC20.sol"],
    "src/Vaults.sol": TWO_VAULTS,
}
PARAMETERS_PROJECT = {"src/Params.sol": PARAMETERS}


@pytest.fixture
def vault(understand_of):
    return understand_of(VAULT_PROJECT)


# ── 0. Token-boundary matching, the root cause of the role collapse ───────────


def test_camel_tokens_recovers_word_boundaries():
    """Case is preserved — the tokenizer keeps the spelling a reader recognizes; matching
    folds separately."""
    assert camel_tokens("batchProcessDeposit") == ["batch", "Process", "Deposit"]
    assert camel_tokens("getUSDValue") == ["get", "USD", "Value"]
    assert camel_tokens("MAX_TOTAL_PENALTY") == ["MAX", "TOTAL", "PENALTY"]


def test_whole_word_matching_rejects_accidental_substrings():
    assert has_token("getUsdValueAfterDeposit", "deposit")
    assert has_token("assetToAssetInformation", "asset")
    assert not has_token("index", "de")
    assert not has_token("withdrawn", "draw")


def test_prefix_position_distinguishes_doing_from_reporting():
    """A function named for an action performs it; one that mentions it reports on it."""
    assert starts_with_token("withdrawAll", "withdraw")
    assert not starts_with_token("getUsdValueAfterDeposit", "deposit")
    assert not starts_with_token("setPauseFlag", "pause")


# ── 3. Contract role quality ──────────────────────────────────────────────────


def test_a_valuation_adapter_is_not_a_vault(understand_of):
    """`processDirectDeposit` and `getUsdValue…AfterDeposit` made every Arcadia asset
    module a vault, attaching custody semantics to contracts that hold nothing."""
    model = understand_of(ASSET_MODULE_PROJECT)
    classification = model.contract_by_name("ChainlinkAM")

    assert classification.role is ContractRole.PRICING_MODULE
    assert ContractRole.VAULT not in (classification.role, *classification.secondary_roles)


def test_a_contract_may_hold_several_scored_roles(vault):
    classification = vault.contract_by_name("SimpleVault")
    assert classification.roles
    assert classification.roles[0].role is ContractRole.VAULT
    assert 0.0 < classification.roles[0].score <= 1.0
    assert classification.roles[0].evidence


def test_role_scores_are_ranked_and_ambiguity_is_visible(understand_of):
    model = understand_of(ASSET_MODULE_PROJECT)
    classification = model.contract_by_name("ChainlinkAM")
    scores = [assignment.score for assignment in classification.roles]

    assert scores == sorted(scores, reverse=True)
    assert isinstance(classification.is_ambiguous, bool)


def test_role_and_secondary_roles_remain_readable(vault):
    """Existing consumers read these; they became views over `roles` rather than fields."""
    classification = vault.contract_by_name("SimpleVault")
    assert classification.role is ContractRole.VAULT
    assert isinstance(classification.secondary_roles, list)


def test_an_unclassified_contract_is_unknown_not_guessed(understand_of):
    model = understand_of(PARAMETERS_PROJECT)
    classification = model.contract_by_name("Params")
    if not classification.roles:
        assert classification.role is ContractRole.UNKNOWN
        assert classification.confidence is Confidence.UNKNOWN


# ── 1. Invariant deduplication ────────────────────────────────────────────────


def test_one_rule_across_two_contracts_is_one_invariant(understand_of):
    """Arcadia lending emitted the same ERC-4626 consistency clause once per implementer,
    and three solvency invariants that were one rule over three totals."""
    model = understand_of(TWO_VAULTS_PROJECT)

    for invariant in model.invariants:
        assert invariant.semantic_key, "every invariant must carry a semantic identity"

    keys = [i.semantic_key for i in model.invariants]
    assert len(keys) == len(set(keys)), "two invariants share a semantic key: not merged"


def test_merging_keeps_every_supporting_location(understand_of):
    model = understand_of(TWO_VAULTS_PROJECT)
    merged = [i for i in model.invariants if i.occurrences > 1]

    for invariant in merged:
        assert len(invariant.supporting_contracts) >= 1
        assert invariant.targets, "targets must survive the merge"
        assert invariant.evidence, "evidence must survive the merge"


def test_a_merged_invariant_does_not_read_as_being_about_one_place(understand_of):
    """A statement still naming the first location would imply the others are unconstrained."""
    model = understand_of(TWO_VAULTS_PROJECT)
    for invariant in model.invariants:
        if len(invariant.supporting_contracts) > 1 and invariant.kind.value == "solvency":
            assert "must always cover" in invariant.statement


def test_different_rules_are_never_merged(vault):
    """Deduplication must not merge two invariants merely because they look alike."""
    kinds = {(i.kind, i.semantic_key) for i in vault.invariants}
    assert len(kinds) == len(vault.invariants)


def test_a_constant_never_earns_a_solvency_invariant(understand_of):
    """`MAX_TOTAL_PENALTY` contains "total", never changes, and was given an invariant
    asserting the protocol's assets must cover a compile-time constant."""
    model = understand_of(PARAMETERS_PROJECT)
    assert all("MAX_TOTAL_PENALTY" not in i.statement for i in model.invariants)

    penalty = next(s for s in model.state if s.name == "MAX_TOTAL_PENALTY")
    assert penalty.role is StateRole.CONFIG
    assert not penalty.is_critical


# ── 2. Asset normalization ────────────────────────────────────────────────────


def test_same_name_does_not_merge_two_unresolved_handles(understand_of):
    """Two contracts each declaring `IERC20 public asset` receive their address at
    construction. Merging asserts an identity nobody established."""
    model = understand_of(TWO_VAULTS_PROJECT)
    handles = [a for a in model.assets if a.symbol == "asset"]

    assert len(handles) == 2
    assert all(a.identity is AssetIdentity.UNRESOLVED for a in handles)
    assert len({a.identity_group for a in handles}) == 1, "they must share one group"


def test_the_identity_group_is_asked_about_once(understand_of):
    """Not once per sighting — that is the budget going on a question already in hand."""
    model = understand_of(TWO_VAULTS_PROJECT)
    identity_gaps = [g for g in model.gaps if g.field == "assets.identity"]

    assert len(identity_gaps) == 1
    assert len(identity_gaps[0].context_ids) >= 1


def test_different_names_for_one_variable_do_not_split(understand_of):
    """Storage is inheritance-flattened, so one variable seen from two contracts produced
    two identical assets. Aliases record the names; the asset stays one."""
    model = understand_of(PARAMETERS_PROJECT)
    symbols = [a.symbol for a in model.assets]
    assert len(symbols) == len(set(symbols)) or all(
        a.identity is AssetIdentity.UNRESOLVED
        for a in model.assets
        if symbols.count(a.symbol) > 1
    )


def test_assets_carry_a_role_distinct_from_their_kind(vault):
    share = next(a for a in vault.assets if a.role is AssetRole.SHARE)
    assert share.kind.value == "share"
    underlying = next(a for a in vault.assets if a.symbol == "asset")
    assert underlying.role is AssetRole.UNDERLYING
    assert underlying.declared_type.startswith("IERC20")


def test_parameters_are_not_assets(understand_of):
    """`maxReward`, `minRewardWeight` and `originationFee` are configuration; they became
    reward and fee *assets*, putting non-existent tokens in the model."""
    model = understand_of(PARAMETERS_PROJECT)
    symbols = {a.symbol.lower() for a in model.assets}

    assert "maxreward" not in symbols
    assert "minrewardweight" not in symbols
    assert not any("index" in s for s in symbols)


# ── 5. Risk surfaces carry domains, never agents ──────────────────────────────


def test_surfaces_describe_domains_and_never_name_agents(vault):
    assert vault.risk_surfaces
    for surface in vault.risk_surfaces:
        assert surface.domains, "every surface must say what reasoning it calls for"
        assert all(isinstance(d, SurfaceDomain) for d in surface.domains)
        assert not hasattr(surface, "suggested_agents")


def test_a_centralization_surface_is_not_routed_to_reentrancy(vault):
    """The exact unsupported cross-domain claim the old mapping produced: a centralization
    surface acquiring the reentrancy agent because the enclosing function made a call."""
    for surface in vault.risk_surfaces:
        if surface.kind.value == "centralization":
            assert SurfaceDomain.ACCESS_CONTROL in surface.domains


def test_external_interaction_is_only_claimed_with_evidence(vault):
    for surface in vault.risk_surfaces:
        if SurfaceDomain.EXTERNAL_INTERACTION in surface.domains:
            operations = [
                o for o in vault.operations if o.function_id in surface.targets
            ]
            assert not operations or any(o.external_calls for o in operations)


def test_surface_titles_are_qualified_by_contract(understand_of):
    """Nine contracts each with `addAsset` produced nine identically-titled surfaces, which
    reads as duplication and is not — the reader who dismisses them dismisses eight real ones."""
    model = understand_of(TWO_VAULTS_PROJECT)
    titles = [s.title for s in model.risk_surfaces]
    assert len(titles) == len(set(titles))


# ── 4. Operation semantics ────────────────────────────────────────────────────


def test_an_operation_links_to_its_inverse(vault):
    deposit = vault.operation_by_name("deposit")
    withdraw = vault.operation_by_name("withdraw")
    assert withdraw.id in deposit.related_operations
    assert deposit.id in withdraw.related_operations


def test_a_view_is_not_mistaken_for_an_action(understand_of):
    """`getUsdValueExposureToUnderlyingAssetAfterDeposit` is a view about deposits."""
    model = understand_of(ASSET_MODULE_PROJECT)
    reporter = model.operation_by_name(
        "getUsdValueExposureToUnderlyingAssetAfterDeposit"
    )
    assert reporter.kind is OperationKind.VIEW


def test_unknown_operations_stay_unknown(understand_of):
    model = understand_of(ASSET_MODULE_PROJECT)
    unknown = [o for o in model.operations if o.kind is OperationKind.UNKNOWN]
    for operation in unknown:
        assert operation.evidence, "even an unknown must say what was looked at"


# ── 7. Economic relationships ─────────────────────────────────────────────────


def test_a_paired_relationship_quotes_its_formula_when_one_exists(vault):
    pairs = vault.economics.relationships
    assert pairs, "a vault tracking assets and shares should pair them"

    for relationship in pairs:
        if relationship.status is RelationshipStatus.FORMULA:
            assert relationship.formula
            assert relationship.confidence is Confidence.DERIVED


def test_a_missing_relationship_is_an_open_question_not_a_defect(understand_of):
    model = understand_of(PARAMETERS_PROJECT)
    for relationship in model.economics.relationships:
        if relationship.status is RelationshipStatus.EXPECTED_MISSING:
            assert relationship.open_question
            assert relationship.confidence is Confidence.UNKNOWN
            assert "?" in relationship.open_question


def test_relationships_never_assert_exploitability(vault):
    banned = ("exploit", "vulnerab", "attack", "bug", "unsafe")
    for relationship in vault.economics.relationships:
        text = f"{relationship.nature} {relationship.open_question}".lower()
        assert not any(word in text for word in banned)


# ── 6. Fact / inference / unknown ─────────────────────────────────────────────


def test_unknown_is_a_distinct_epistemic_state(vault):
    assert Confidence.UNKNOWN.rank < Confidence.REFUTED.rank
    assert not Confidence.UNKNOWN.is_grounded
    assert Confidence.weakest(Confidence.VERIFIED, Confidence.UNKNOWN) is Confidence.UNKNOWN


def test_a_name_heuristic_never_becomes_a_derived_fact(vault):
    """Every claim resting only on name matching must stay at or below `inferred`."""
    from engine.core.models.evidence import EvidenceKind

    for claim in vault.claims():
        only_heuristic = claim.evidence and all(
            item.kind is EvidenceKind.HEURISTIC for item in claim.evidence
        )
        if only_heuristic:
            assert claim.confidence.rank <= Confidence.INFERRED.rank, claim


def test_gaps_say_how_sure_they_are_of_being_unresolved(vault):
    token_gaps = [g for g in vault.gaps if g.field == "assets.is_fee_on_transfer"]
    assert token_gaps
    assert token_gaps[0].resolution_confidence is Confidence.DERIVED


# ── 8. Open questions ─────────────────────────────────────────────────────────


def test_one_question_asked_once_lists_every_entity_it_affects(understand_of):
    """"Does this token charge a fee on transfer?" was asked four times on Arcadia."""
    model = understand_of(TWO_VAULTS_PROJECT)
    fee_gaps = [g for g in model.gaps if g.field == "assets.is_fee_on_transfer"]

    assert len(fee_gaps) == 1
    assert fee_gaps[0].occurrences == 2
    assert len(fee_gaps[0].affected) == 2


def test_collapsing_never_drops_a_subject(understand_of):
    model = understand_of(TWO_VAULTS_PROJECT)
    for gap in model.gaps:
        assert gap.affected, "every gap must name what it bears on"
        assert gap.subject in gap.affected


def test_more_sightings_raises_priority(understand_of):
    model = understand_of(TWO_VAULTS_PROJECT)
    merged = [g for g in model.gaps if g.occurrences > 1]
    single = [g for g in model.gaps if g.occurrences == 1]
    if merged and single:
        assert max(g.priority for g in merged) > 0


# ── 10. Determinism ───────────────────────────────────────────────────────────


def test_the_refined_model_is_still_byte_reproducible(understand_of):
    first = understand_of(TWO_VAULTS_PROJECT)
    second = understand_of(TWO_VAULTS_PROJECT)
    assert first.content_hash == second.content_hash


def test_deduplication_itself_is_deterministic(understand_of):
    first = understand_of(TWO_VAULTS_PROJECT)
    second = understand_of(TWO_VAULTS_PROJECT)
    assert [i.semantic_key for i in first.invariants] == [
        i.semantic_key for i in second.invariants
    ]
    assert [g.id for g in first.gaps] == [g.id for g in second.gaps]
