"""Stage 16 — contract profiles, function behaviour, permissions, cross-contract edges.

Every test runs reader → parser → graph → understand against real Solidity. The profile
layer is a projection of four earlier stages, so a hand-built `CodeModel` would let it pass
on structure the parser never produces — exactly the failure this layer exists to prevent.

What is asserted, and what deliberately is not: these tests pin *semantics* — that a guard
is recognised through its body and not only its name, that an ordered effect sequence puts
the external call where the source puts it, that a library call is not a trust boundary.
They do not pin counts or wording, which are free to improve.
"""

from __future__ import annotations

import pytest

from engine.core.models.protocol import (
    ContractRelationKind,
    EffectKind,
    PermissionMechanism,
)

# A deliberately awkward protocol. Each shape below is one thing the profile layer has to
# get right and has historically got wrong:
#
#   `onlyVault`      a guard whose name is not in any convention list; its body is the proof
#   `constructor`    base-contract invocations sit in the modifier slot and gate nothing
#   `Math.mulDiv`    a library call that looks identical to an external call
#   `amount.half()`  a `using … for` call, where even the receiver looks like an address
#   `withdraw`       a genuine external call with a state write after it
POOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library Math {
    function mulDiv(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        return (a * b) / c;
    }
    function half(uint256 a) internal pure returns (uint256) {
        return a / 2;
    }
}

interface IToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

abstract contract Owned {
    address public owner;
    constructor(address owner_) { owner = owner_; }
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
}

contract Pool is Owned {
    using Math for uint256;

    IToken public immutable token;
    address public vault;
    uint256 public totalDeposits;
    uint256 public totalShares;
    mapping(address => uint256) public shareOf;

    event Deposited(address indexed user, uint256 amount);

    error NotVault();

    modifier onlyVault() {
        if (msg.sender != vault) revert NotVault();
        _;
    }

    constructor(address token_, address owner_) Owned(owner_) {
        token = IToken(token_);
    }

    function setVault(address vault_) external onlyOwner {
        vault = vault_;
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "zero");
        uint256 shares = totalShares == 0 ? amount : Math.mulDiv(amount, totalShares, totalDeposits);
        token.transferFrom(msg.sender, address(this), amount);
        totalDeposits += amount;
        totalShares += shares;
        shareOf[msg.sender] += shares;
        emit Deposited(msg.sender, amount);
    }

    function withdraw(uint256 shares) external {
        uint256 amount = Math.mulDiv(shares, totalDeposits, totalShares);
        token.transfer(msg.sender, amount);
        shareOf[msg.sender] -= shares;
        totalShares -= shares;
        totalDeposits -= amount;
    }

    function sweep(uint256 amount) external onlyVault {
        totalDeposits -= amount.half();
    }
}
"""

VAULT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Pool} from "./Pool.sol";

contract Vault {
    Pool public immutable pool;

    constructor(address pool_) { pool = Pool(pool_); }

    function drain(uint256 amount) external {
        pool.sweep(amount);
    }

    function poolShares(address user) external view returns (uint256) {
        return pool.shareOf(user);
    }
}
"""

POOL_PROJECT = {"src/Pool.sol": POOL, "src/Vault.sol": VAULT}


@pytest.fixture
def pool(understand_of):
    return understand_of(POOL_PROJECT)


def profile(model, name):
    found = next((p for p in model.profiles if p.name == name), None)
    assert found is not None, f"no profile for {name}; got {[p.name for p in model.profiles]}"
    return found


def behavior(model, contract, function):
    found = next(
        (f for f in profile(model, contract).functions if f.name == function), None
    )
    assert found is not None, f"no behaviour for {contract}.{function}"
    return found


def permission(model, contract, function):
    found = next(
        (p for p in profile(model, contract).permissions if p.name == function), None
    )
    assert found is not None, f"no permission for {contract}.{function}"
    return found


# ── Every contract gets a profile ─────────────────────────────────────────────


def test_every_in_scope_contract_is_profiled(pool):
    """The point of the layer: no contract is left as a name in a summary."""
    profiled = {p.name for p in pool.profiles}
    assert {"Pool", "Vault", "Owned"} <= profiled
    assert pool.coverage.contracts_profiled == len(pool.profiles)


def test_profile_indexes_rather_than_copies(pool):
    """Every `ProtocolID` on a profile resolves in the global model.

    A profile that carried its own copies could drift from the model it describes; this is
    the assertion that it cannot.
    """
    known = {
        *(o.id for o in pool.operations),
        *(s.id for s in pool.state),
        *(a.id for a in pool.actors),
        *(a.id for a in pool.assets),
        *(i.id for i in pool.invariants),
        *(s.id for s in pool.risk_surfaces),
        *(b.id for b in pool.trust_boundaries),
        *(g.id for g in pool.gaps),
    }
    for candidate in pool.profiles:
        cited = {
            *candidate.operation_ids,
            *candidate.state_ids,
            *candidate.actor_ids,
            *candidate.asset_ids,
            *candidate.invariant_ids,
            *candidate.surface_ids,
            *candidate.boundary_ids,
            *candidate.gap_ids,
        }
        assert cited <= known, f"{candidate.name} cites unknown IDs: {sorted(cited - known)}"


def test_profile_is_deterministic(understand_of):
    first, second = understand_of(POOL_PROJECT), understand_of(POOL_PROJECT)
    assert [p.id for p in first.profiles] == [p.id for p in second.profiles]
    assert first.content_hash == second.content_hash


def test_purpose_is_assembled_from_evidenced_facts(pool):
    described = profile(pool, "Pool")
    assert described.purpose, "a classified contract with operations must state a purpose"
    assert described.responsibilities
    # Assembled from the model, not authored: every clause traces to a record that exists.
    assert "takes deposits" in described.responsibilities


def test_state_is_inheritance_flattened(pool):
    """`owner` is declared on `Owned`; a `Pool` profile without it hands an agent a
    contract whose access control has no storage behind it."""
    names = {s.split("#")[-1] for s in profile(pool, "Pool").state_ids}
    assert "owner" in names
    assert "totalDeposits" in names


# ── Guards: the body, not only the name ───────────────────────────────────────


def test_convention_named_guard_is_recognised(pool):
    assert behavior(pool, "Pool", "setVault").caller_requirements == ["onlyOwner"]
    assert behavior(pool, "Pool", "setVault").is_privileged


def test_protocol_specific_guard_is_recognised_through_its_body(pool):
    """`onlyVault` is in no convention list. Its body says `msg.sender != vault`.

    Reporting it as unguarded states "anyone may call this" about a function only the vault
    may call — the error that matters, in the direction that matters.
    """
    described = behavior(pool, "Pool", "sweep")
    assert described.caller_requirements == ["onlyVault"]
    assert described.is_privileged


def test_behaviour_and_permission_agree_on_privilege(pool):
    """The two views of one fact are derived from one source, so they cannot contradict.

    Before they shared a source, `sweep` was `is_privileged=False` in its behaviour record
    and `contract_only` in its permission record, with no way for a reader to settle it.
    """
    for described in profile(pool, "Pool").functions:
        if not described.is_entrypoint:
            continue
        record = next(
            (p for p in profile(pool, "Pool").permissions if p.function_id == described.function_id),
            None,
        )
        if record is None:
            continue
        assert described.is_privileged == record.is_privileged, described.name


def test_unguarded_function_is_not_reported_as_guarded(pool):
    described = behavior(pool, "Pool", "deposit")
    assert described.caller_requirements == []
    assert not described.is_privileged
    assert permission(pool, "Pool", "deposit").mechanism is PermissionMechanism.OPEN


def test_permission_mechanism_is_read_from_the_modifier_body(pool):
    """`onlyVault` compares against a state variable — a peer contract, not an admin."""
    assert permission(pool, "Pool", "sweep").mechanism is PermissionMechanism.CONTRACT_ONLY
    assert permission(pool, "Pool", "setVault").mechanism is PermissionMechanism.OWNER


# ── Constructors ──────────────────────────────────────────────────────────────


def test_base_constructor_is_not_a_guard(pool):
    """`constructor(…) Owned(owner_)` initialises a parent. It gates nothing.

    Listing `Owned` as a caller requirement says the constructor is access-controlled.
    """
    described = behavior(pool, "Pool", "constructor")
    assert "Owned" not in described.modifiers
    assert described.caller_requirements == []
    assert not described.is_privileged
    assert not any(line.startswith("modifier Owned") for line in described.preconditions)


def test_base_constructor_is_kept_in_the_effect_sequence(pool):
    """It is still a real call into parent code, and where immutables get set."""
    steps = behavior(pool, "Pool", "constructor").steps
    base = [s for s in steps if s.detail.startswith("base constructor")]
    assert base and all(s.kind is EffectKind.INTERNAL_CALL for s in base)


def test_constructor_has_no_permission_record(pool):
    """No actor exists at deployment, so "who may call it" is not a question about it."""
    assert all(p.name != "constructor" for p in profile(pool, "Pool").permissions)


# ── The effect sequence ───────────────────────────────────────────────────────


def test_steps_preserve_source_order(pool):
    described = behavior(pool, "Pool", "deposit")
    assert [s.order for s in described.steps] == sorted(s.order for s in described.steps)
    kinds = [s.kind for s in described.steps]
    assert EffectKind.TRANSFER in kinds
    # Modifiers and requires precede the body's effects.
    assert kinds.index(EffectKind.CHECK) < kinds.index(EffectKind.TRANSFER)


def test_write_after_external_call_is_flagged(pool):
    """`withdraw` transfers out, then decrements. A candidate to investigate, not a finding."""
    described = behavior(pool, "Pool", "withdraw")
    assert described.writes_after_external_call
    assert described.hands_over_control
    assert described.function_id in profile(pool, "Pool").cei_candidates


def test_library_call_is_not_a_trust_boundary(pool):
    """`Math.mulDiv(…)` runs in this frame. Typing it as a crossing marks every state
    write after an arithmetic helper as a reentrancy candidate."""
    described = behavior(pool, "Pool", "deposit")
    assert not any("mulDiv" in call for call in described.external_calls)
    library_steps = [s for s in described.steps if "mulDiv" in s.detail]
    assert library_steps and all(
        s.kind is EffectKind.INTERNAL_CALL for s in library_steps
    )


def test_using_for_call_is_not_a_trust_boundary(pool):
    """`amount.half()` binds through `using Math for uint256`; the receiver is a value."""
    described = behavior(pool, "Pool", "sweep")
    assert not any("half" in call for call in described.external_calls)


def test_genuine_external_call_is_still_reported(pool):
    """The asymmetry has to hold in both directions or the library fix would be a regression."""
    described = behavior(pool, "Pool", "withdraw")
    assert described.token_movements or described.external_calls
    assert any(
        s.kind in (EffectKind.EXTERNAL_CALL, EffectKind.TRANSFER) for s in described.steps
    )


def test_reads_and_writes_resolve_to_state_ids(pool):
    described = behavior(pool, "Pool", "deposit")
    state_ids = {s.id for s in pool.state}
    assert set(described.reads) <= state_ids
    assert set(described.writes) <= state_ids
    assert any(s.endswith("#totalDeposits") for s in described.writes)


def test_internal_functions_are_described_not_only_entrypoints(pool):
    """The accounting usually lives one call below the entrypoint."""
    assert any(not f.is_entrypoint for f in profile(pool, "Pool").functions)


# ── Cross-contract relationships ──────────────────────────────────────────────


def test_call_edge_is_recorded_with_its_call_site(pool):
    edge = next(
        (
            r
            for r in pool.contract_relationships
            if r.source.endswith(":Vault") and r.target.endswith(":Pool")
        ),
        None,
    )
    assert edge is not None, "Vault.drain calls Pool.sweep"
    assert edge.call_sites, "a relationship with no call site is an architectural assertion"


def test_inheritance_is_a_relationship(pool):
    kinds = {
        r.kind
        for r in pool.contract_relationships
        if r.source.endswith(":Pool") and r.target.endswith(":Owned")
    }
    assert ContractRelationKind.INHERITS in kinds


def test_consumed_by_answers_who_breaks_if_i_change_this(pool):
    assert any(s.endswith(":Vault") for s in profile(pool, "Pool").consumed_by)
    assert profile(pool, "Vault").consumed_by == []


def test_depends_on_is_directed(pool):
    assert any(d.endswith(":Pool") for d in profile(pool, "Vault").depends_on)


# ── Honesty ───────────────────────────────────────────────────────────────────


def test_unknowns_name_the_specific_blind_spot(pool):
    """"Coverage is partial" tells an agent nothing; a named variable tells it where to start."""
    for described in pool.profiles:
        for unknown in described.unknowns:
            assert unknown == unknown.strip() and len(unknown) > 20


def test_abstract_contract_declares_its_incompleteness(pool):
    assert any("abstract" in u for u in profile(pool, "Owned").unknowns)


def test_no_profile_claims_a_vulnerability(pool):
    """The artifact answers "what exists", never "this is exploitable"."""
    banned = ("vulnerable", "exploit", "attacker can", "is a bug")
    for described in pool.profiles:
        text = " ".join(
            [described.purpose, *described.responsibilities, *described.unknowns]
        ).lower()
        assert not any(word in text for word in banned)
