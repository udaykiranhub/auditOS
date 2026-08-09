"""`ProtocolID` — stable identity for semantic entities.

The property under test throughout: **the same protocol produces the same IDs on every run
and on every machine.** Everything in the artifact cross-references by these strings, so an
ID that drifts turns a diff into noise and a cached enrichment answer into a miss.
"""

from __future__ import annotations

import pytest

from engine.protocol.ids import (
    NAMESPACES,
    digest,
    invariant_label,
    is_protocol_id,
    make_actor_id,
    make_asset_id,
    make_flow_id,
    make_invariant_id,
    make_operation_id,
    make_role_id,
    make_state_id,
    namespace_of,
    slug,
)


def test_readable_ids_embed_their_natural_key():
    assert make_role_id("src/Vault.sol:Vault") == "role:src/Vault.sol:Vault"
    assert (
        make_operation_id("src/Vault.sol:Vault.deposit(uint256)")
        == "op:src/Vault.sol:Vault.deposit(uint256)"
    )
    assert (
        make_state_id("src/Vault.sol:Vault#totalAssets")
        == "state:src/Vault.sol:Vault#totalAssets"
    )
    assert make_actor_id("admin") == "actor:admin"


def test_every_minted_id_is_in_a_known_namespace():
    minted = [
        make_role_id("src/V.sol:V"),
        make_actor_id("keeper"),
        make_asset_id("USDC"),
        make_operation_id("src/V.sol:V.f()"),
        make_state_id("src/V.sol:V#x"),
        make_flow_id("actor:user", "role:src/V.sol:V", "asset:usdc"),
        make_invariant_id("x holds", ["src/V.sol:V"]),
    ]
    assert all(is_protocol_id(pid) for pid in minted)
    assert all(namespace_of(pid) in NAMESPACES for pid in minted)


def test_a_solidity_id_is_not_a_protocol_id():
    """The check that catches a SolidityID written where a ProtocolID belongs."""
    assert not is_protocol_id("src/Vault.sol:Vault")
    assert not is_protocol_id("src/Vault.sol:Vault.deposit(uint256)")


def test_ids_are_stable_across_calls():
    first = make_flow_id("actor:user", "role:src/V.sol:V", "asset:usdc", "op:src/V.sol:V.f()")
    second = make_flow_id("actor:user", "role:src/V.sol:V", "asset:usdc", "op:src/V.sol:V.f()")
    assert first == second


def test_distinct_tuples_cannot_collide_through_concatenation():
    """`("a","bc")` and `("ab","c")` must not digest alike — the classic naive-join bug,
    which here would silently merge two different asset flows into one."""
    assert digest("a", "bc") != digest("ab", "c")


def test_shares_of_two_vaults_are_two_assets():
    """Keying an asset on its symbol alone would merge them and make every conservation
    invariant meaningless."""
    assert make_asset_id("shares", ref="src/A.sol:A") != make_asset_id("shares", ref="src/B.sol:B")


def test_overloads_stay_distinct_operations():
    assert make_operation_id("src/V.sol:V.f(uint256)") != make_operation_id(
        "src/V.sol:V.f(address)"
    )


def test_two_admin_roles_do_not_collapse_into_one_actor():
    assert make_actor_id("admin", "pauser_role") != make_actor_id("admin", "minter_role")
    assert make_actor_id("admin") != make_actor_id("admin", "pauser_role")


def test_invariant_id_is_content_derived_and_label_is_ordinal():
    """The id must survive an invariant being added upstream; the label need not."""
    statement = "totalAssets >= totalShares"
    assert make_invariant_id(statement, ["a", "b"]) == make_invariant_id(statement, ["b", "a"])
    assert make_invariant_id(statement, ["a"]) != make_invariant_id(statement, ["a", "b"])
    assert invariant_label(1) == "INV-001"
    assert invariant_label(42) == "INV-042"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Chainlink Price Feed", "chainlink-price-feed"),
        ("  UPPER_case  ", "upper-case"),
        ("ERC-4626", "erc-4626"),
        ("", "unnamed"),
    ],
)
def test_slug_is_deterministic_and_never_empty(text: str, expected: str):
    assert slug(text) == expected
