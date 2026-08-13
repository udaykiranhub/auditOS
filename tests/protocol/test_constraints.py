"""Stage 12b — relations read out of the guards a protocol enforces on itself.

The contract below is the smallest thing that exercises the whole chain: a guard comparing
two state variables, a total moved in lockstep with a per-account mapping, and no shares or
oracle anywhere. It is deliberately the shape that the role-pair table missed — collateral
is called `deposits`, which infers as `user_balance`, not `collateral_record`.
"""

from __future__ import annotations

import pytest

from engine.core.models.evidence import Confidence
from engine.core.models.protocol import (
    InvariantKind,
    RelationKind,
    RelationshipStatus,
    SurfaceKind,
)

SIMPLE_LENDING = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract SimpleLending {
    IERC20 public asset;

    mapping(address => uint256) public deposits;
    mapping(address => uint256) public debt;

    uint256 public totalDeposits;
    uint256 public totalDebt;

    function deposit(uint256 amount) external {
        asset.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
        totalDeposits += amount;
    }

    function borrow(uint256 amount) external {
        require(deposits[msg.sender] >= amount * 2);
        debt[msg.sender] += amount;
        totalDebt += amount;
        asset.transfer(msg.sender, amount);
    }

    function repay(uint256 amount) external {
        asset.transferFrom(msg.sender, address(this), amount);
        debt[msg.sender] -= amount;
        totalDebt -= amount;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount);
        require(deposits[msg.sender] - amount >= debt[msg.sender] * 2);
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;
        asset.transfer(msg.sender, amount);
    }
}
"""

LENDING_PROJECT = {"src/SimpleLending.sol": SIMPLE_LENDING}


@pytest.fixture
def lending(understand_of):
    return understand_of(LENDING_PROJECT)


def quantity(model, name):
    found = next((q for q in model.accounting.quantities if q.name == name), None)
    assert found is not None, f"no quantity {name}"
    return found


def storage(model, name):
    """Constraints are keyed on storage, not on quantities.

    An `AccountingQuantity` exists only where the state pass inferred a role it recognises —
    3 of 49 variables on a real lending protocol — so a constraint keyed on quantities can
    say nothing about most of a codebase.
    """
    found = next((s for s in model.state if s.name == name), None)
    assert found is not None, f"no state item {name}"
    return found


# ── The relationship the protocol enforces on itself ──────────────────────────


def test_a_guard_comparing_two_state_variables_becomes_a_relationship(lending):
    """`require(deposits[…] - amount >= debt[…] * 2)` *is* the evidence.

    The role-pair table pairs `collateral_record ↕ debt_record` and misses this entirely,
    because this protocol calls its collateral `deposits`. Widening the table would assert
    the link from two names; reading the guard reads it from a line that reverts.
    """
    deposits, debt = storage(lending, "deposits"), storage(lending, "debt")
    found = next(
        (
            r
            for r in lending.economics.relationships
            if {r.left, r.right} == {deposits.id, debt.id}
        ),
        None,
    )

    assert found is not None, "deposits ↕ debt was not related"
    assert found.status is RelationshipStatus.FORMULA
    assert found.confidence is Confidence.DERIVED
    # Quoted, never paraphrased.
    assert "debt[msg.sender] * 2" in found.formula
    assert found.left == deposits.id, "the constrained side comes first"


def test_the_ratio_survives_into_the_nature(lending):
    """`2x` is the difference between "these are related" and a checkable property."""
    natures = [r.nature for r in lending.economics.relationships]
    assert any("2x" in nature for nature in natures), natures


def test_the_guard_relation_is_recorded_in_accounting(lending):
    bound = [r for r in lending.accounting.relations if r.kind is RelationKind.BOUND]
    assert bound
    assert all(r.confidence is Confidence.DERIVED for r in bound)
    assert all(r.state_ids for r in bound), "constraints are keyed on storage"


def test_the_recorded_rule_is_normalised_not_the_guard_as_written(lending):
    """`if (x > MAX) revert` establishes `x <= MAX` — the opposite of its own condition.

    The relation therefore carries the *rule*, and the guard as written stays on the
    evidence, which is where a quotation belongs. Recording the raw condition as the rule
    stated the reverse of what the code enforces.
    """
    bound = next(
        r
        for r in lending.accounting.relations
        if r.kind is RelationKind.BOUND and "deposits" in r.expression
    )
    assert bound.expression == "deposits >= debt * 2"
    assert any("debt[msg.sender] * 2" in e.detail for e in bound.evidence)


def test_the_collateral_invariant_is_produced(lending):
    """Their INV-001: `deposits[user] >= 2 × debt[user]`."""
    found = [
        i
        for i in lending.invariants
        if i.kind is InvariantKind.SOLVENCY and "deposits >= debt * 2" in i.statement
    ]
    assert found, [i.statement for i in lending.invariants]
    assert found[0].breaks_if


# ── Conservation: a total against its per-account mapping ─────────────────────


def test_total_is_related_to_the_sum_of_its_mapping(lending):
    sums = [r for r in lending.accounting.relations if r.kind is RelationKind.SUM]
    expressions = {r.expression for r in sums}
    assert "totalDeposits == sum(deposits[account])" in expressions
    assert "totalDebt == sum(debt[account])" in expressions


def test_conservation_invariants_read_in_the_right_direction(lending):
    """`totalDeposits == Σ deposits`, not the reverse.

    The invariant builder used to read operands off a model-ordered list, which produced
    "deposits must equal the sum of totalDeposits across all accounts" — the rule stated
    backwards, which is worse than not stating it.
    """
    conservation = [
        i for i in lending.invariants if i.kind is InvariantKind.CONSERVATION
    ]
    assert conservation
    for invariant in conservation:
        assert invariant.statement.startswith("total"), invariant.statement


def test_a_total_written_without_its_mapping_is_not_paired(understand_of):
    """One unmatched write disqualifies the pairing — the sum would not hold."""
    sources = {
        "src/Skewed.sol": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Skewed {
    mapping(address => uint256) public balances;
    uint256 public totalBalances;

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
        totalBalances += amount;
    }

    function skim(uint256 amount) external {
        totalBalances -= amount;
    }
}
"""
    }
    model = understand_of(sources)
    sums = [r for r in model.accounting.relations if r.kind is RelationKind.SUM]
    assert sums == [], "skim() moves the total alone, so the sum cannot hold"


# ── Bounded configuration: where most real invariants actually live ───────────


BOUNDED = {
    "src/Config.sol": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Config {
    uint256 public startPriceMultiplier;
    uint256 public auctionsInProgress;

    error BadValue();

    function setStartPriceMultiplier(uint256 startPriceMultiplier_) external {
        if (startPriceMultiplier_ < 10_000) revert BadValue();
        if (startPriceMultiplier_ > 30_000) revert BadValue();
        startPriceMultiplier = startPriceMultiplier_;
    }

    function addTranche() external {
        if (auctionsInProgress > 0) revert BadValue();
        auctionsInProgress = auctionsInProgress;
    }
}
"""
}


def test_an_if_revert_guard_is_negated(understand_of):
    """`if (x > MAX) revert` establishes `x <= MAX`, the opposite of its own condition.

    Reading the condition literally recorded the exact reverse of what the code enforces —
    the most dangerous single failure this pass can have, because the output looks fine.
    """
    model = understand_of(BOUNDED)
    expressions = {r.expression for r in model.accounting.relations}
    assert "startPriceMultiplier <= 30000" in expressions
    assert "startPriceMultiplier >= 10000" in expressions
    assert "startPriceMultiplier > 30000" not in expressions


def test_both_halves_of_a_range_become_one_invariant(understand_of):
    """The two halves are written as two guards; they are one rule."""
    model = understand_of(BOUNDED)
    found = [
        i
        for i in model.invariants
        if i.kind is InvariantKind.CONFIGURATION and "startPriceMultiplier" in i.statement
    ]
    assert len(found) == 1, [i.statement for i in found]
    assert "30000" in found[0].statement and "10000" in found[0].statement


def test_an_operation_precondition_is_not_a_standing_range(understand_of):
    """`if (auctionsInProgress > 0) revert` inside a setter is a precondition of *that
    operation*. It says nothing about what the variable may hold in general, and reporting
    "auctionsInProgress must remain at most 0" is simply false."""
    model = understand_of(BOUNDED)
    statements = [i.statement for i in model.invariants]
    assert not any("auctionsInProgress must remain" in s for s in statements), statements


# ── Not inventing what the source does not establish ──────────────────────────


def test_a_lending_market_without_shares_gets_no_share_surfaces(lending):
    """This contract has no shares and no exchange rate.

    Reporting "the first deposit sets the initial exchange rate" against it describes a
    different protocol. These are conventional hazards of the *vault* archetype, and firing
    them on operation name alone is the invented semantics the artifact exists to avoid.
    """
    kinds = {s.kind for s in lending.risk_surfaces}
    assert SurfaceKind.FIRST_DEPOSITOR not in kinds
    assert SurfaceKind.SHARE_PRICING not in kinds


def test_a_lending_market_without_an_oracle_gets_no_oracle_surface(lending):
    assert SurfaceKind.ORACLE_PRICING not in {s.kind for s in lending.risk_surfaces}


def test_the_gate_does_not_suppress_surfaces_a_vault_really_has(understand_of):
    """The asymmetry has to hold both ways, or the fix is just a regression."""
    sources = {
        "src/Vault.sol": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract Vault {
    IERC20 public asset;
    uint256 public totalAssets;
    uint256 public totalShares;
    mapping(address => uint256) public shareOf;

    function deposit(uint256 amount) external returns (uint256 shares) {
        shares = totalShares == 0 ? amount : amount * totalShares / totalAssets;
        asset.transferFrom(msg.sender, address(this), amount);
        totalAssets += amount;
        totalShares += shares;
        shareOf[msg.sender] += shares;
    }
}
"""
    }
    model = understand_of(sources)
    assert SurfaceKind.FIRST_DEPOSITOR in {s.kind for s in model.risk_surfaces}


def test_a_guard_over_one_quantity_produces_no_relation(lending):
    """`require(deposits[msg.sender] >= amount)` compares against a parameter.

    `amount` is not a quantity, so there is no second operand and nothing to relate. A pass
    that reached for one would be inventing.
    """
    deposits = quantity(lending, "deposits")
    self_relations = [
        r
        for r in lending.accounting.relations
        if r.quantity_ids.count(deposits.id) > 1
    ]
    assert self_relations == []


def test_no_relationship_claims_a_defect(lending):
    banned = ("vulnerable", "exploit", "insufficient", "unsafe", "attacker")
    for relationship in lending.economics.relationships:
        assert not any(word in relationship.nature.lower() for word in banned)


# ── Postconditions ────────────────────────────────────────────────────────────


def test_operations_state_what_is_true_afterwards(lending):
    """Preconditions without postconditions is half a contract per function."""
    borrow = lending.operation_by_name("borrow")
    assert borrow is not None
    assert borrow.preconditions
    assert borrow.postconditions
    assert any("debt" in line for line in borrow.postconditions)
    # Quoted from the assignment operator the transition stage read, not interpreted.
    assert any("+=" in line for line in borrow.postconditions)


def test_postconditions_record_the_asset_movement(lending):
    borrow = lending.operation_by_name("borrow")
    assert borrow is not None
    assert any("moves out" in line for line in borrow.postconditions)


# ── Risk surfaces carry their questions ───────────────────────────────────────


def test_risk_surfaces_carry_questions_as_a_list(lending):
    """A question survives being wrong; an assertion does not."""
    with_questions = [s for s in lending.risk_surfaces if s.questions]
    assert with_questions
    for surface in with_questions:
        assert all(q.strip().endswith("?") for q in surface.questions), surface.questions


def test_determinism(understand_of):
    first, second = understand_of(LENDING_PROJECT), understand_of(LENDING_PROJECT)
    assert first.content_hash == second.content_hash
