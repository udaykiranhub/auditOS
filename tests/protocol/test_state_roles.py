"""Multi-signal state role inference.

The old classifier matched one name against one table and left twelve of thirty-five
variables on a real lending protocol as `unknown` — not because the code was unclear, but
because a table keyed on names is silent about everything a protocol is mostly made of.

These tests pin the two things that fixed it: a vocabulary that can *name* a record store, an
index and a membership set; and signals that read the declared type, the direction of every
write and what constrains a variable, so a role no longer depends on someone having chosen a
conventional identifier.
"""

from __future__ import annotations

import pytest

from engine.core.models.evidence import Confidence
from engine.core.models.protocol import StateRole

LENDING = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address f, address t, uint256 a) external returns (bool);
}

contract Market {
    struct Position { uint256 supplied; uint256 borrowed; }
    struct Reserve { uint256 liquidity; uint16 ltvBps; }

    IERC20 public asset;
    string public name;

    uint256 public constant MAX_LTV_BPS = 8000;
    uint256 public stalenessThreshold;
    uint256 public nextLoanId;

    mapping(address => Position) internal _positions;
    mapping(address => Reserve) internal _reserves;
    mapping(address => bool) internal _allowed;
    mapping(address => address[]) internal _userAssets;
    mapping(address => uint256) public balanceOf;
    uint256 public totalLiquidity;

    error Denied();

    function setStaleness(uint256 threshold) external {
        if (threshold > 3600) revert Denied();
        stalenessThreshold = threshold;
    }

    function deposit(uint256 amount) external {
        asset.transferFrom(msg.sender, address(this), amount);
        balanceOf[msg.sender] += amount;
        totalLiquidity += amount;
    }

    function withdraw(uint256 amount) external {
        uint256 balance = balanceOf[msg.sender];
        if (balance < amount) revert Denied();
        balanceOf[msg.sender] = balance - amount;
        totalLiquidity -= amount;
        asset.transfer(msg.sender, amount);
    }

    function openLoan() external returns (uint256) {
        return nextLoanId++;
    }
}
"""


@pytest.fixture
def market(understand_with_ast):
    return understand_with_ast({"src/Market.sol": LENDING})


def role_of(model, name: str) -> StateRole:
    found = next((s for s in model.state if s.name == name), None)
    assert found is not None, f"no state item {name}"
    return found.role


# ── The kinds the vocabulary could not express ────────────────────────────────


def test_a_mapping_to_a_struct_is_a_record_store(market):
    assert role_of(market, "_reserves") is StateRole.RECORD_STORE


def test_a_per_account_struct_is_a_position(market):
    assert role_of(market, "_positions") in (StateRole.POSITION, StateRole.RECORD_STORE)


def test_a_mapping_to_bool_is_a_membership_set(market):
    assert role_of(market, "_allowed") is StateRole.MEMBERSHIP


def test_a_mapping_to_a_list_is_an_index(market):
    assert role_of(market, "_userAssets") is StateRole.INDEX_LIST


def test_text_is_metadata(market):
    """Never load-bearing for correctness, and saying so keeps it out of every accounting
    question rather than leaving it as an open one."""
    assert role_of(market, "name") is StateRole.METADATA


# ── Signals that do not read the name ─────────────────────────────────────────


def test_a_value_that_only_ever_rises_is_a_counter(market):
    """`nextLoanId++` is a `UnaryOperation`, not an assignment. A pass that looked only at
    assignments recorded no writer at all, so every id counter had no direction and no
    role."""
    assert role_of(market, "nextLoanId") is StateRole.COUNTER


def test_a_per_account_ledger_is_not_a_counter(market):
    """`balanceOf[from] = balance - amount` is a decrease written with `=`.

    Reading the direction off the operator alone saw only the `+=` and concluded the
    balance never falls — which made every solmate-style ERC20 balance a counter.
    """
    assert role_of(market, "balanceOf") is StateRole.USER_BALANCE


def test_a_variable_that_bounds_another_is_a_threshold(market):
    """Being compared *against* is what being a bound means."""
    assert role_of(market, "stalenessThreshold") is StateRole.THRESHOLD


def test_a_constant_is_a_parameter_whatever_it_is_called(market):
    """`MAX_LTV_BPS` cannot be an accounting total: it never changes."""
    assert role_of(market, "MAX_LTV_BPS") in (StateRole.THRESHOLD, StateRole.CONFIG)


def test_a_contract_handle_is_not_a_balance(market):
    assert role_of(market, "asset") is StateRole.ADDRESS_REF


# ── Honesty ───────────────────────────────────────────────────────────────────


def test_every_role_carries_the_evidence_that_produced_it(market):
    for item in market.state:
        if item.role is StateRole.UNKNOWN:
            continue
        assert item.evidence, item.name


def test_structural_agreement_reaches_derived(market):
    """A role several structural signals agree on is not the same claim as one read off a
    name, and the confidence has to say which."""
    graded = [s for s in market.state if s.role is not StateRole.UNKNOWN]
    assert graded
    assert any(s.confidence is Confidence.DERIVED for s in graded)


def test_the_protocol_is_mostly_understood(market):
    """The measure that mattered: how much of storage the model can name at all."""
    unknown = [s.name for s in market.state if s.role is StateRole.UNKNOWN]
    assert not unknown, unknown
