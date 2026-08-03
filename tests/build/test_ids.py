"""`SolidityID` — the join key for the whole system (SPEC §7.2).

If two modules compute these differently, static corroboration and context selection break
silently, so the forms are pinned here.
"""

from __future__ import annotations

import pytest

from engine.core.models.ids import (
    canonical_type,
    make_contract_id,
    make_function_id,
    make_function_id_from_signature,
    make_modifier_id,
    make_state_var_id,
    normalize_path,
    split_contract_id,
)


def test_the_four_id_forms():
    assert make_contract_id("src/vault/Vault.sol", "Vault") == "src/vault/Vault.sol:Vault"
    assert (
        make_function_id("src/vault/Vault.sol", "Vault", "deposit", ["uint256", "address"])
        == "src/vault/Vault.sol:Vault.deposit(uint256,address)"
    )
    assert (
        make_state_var_id("src/vault/Vault.sol", "Vault", "totalAssets")
        == "src/vault/Vault.sol:Vault#totalAssets"
    )
    assert (
        make_modifier_id("src/vault/Vault.sol", "Vault", "onlyOwner")
        == "src/vault/Vault.sol:Vault.onlyOwner"
    )


def test_paths_are_posix_and_repo_relative():
    assert normalize_path("src\\vault\\Vault.sol") == "src/vault/Vault.sol"
    assert normalize_path("./src/Vault.sol") == "src/Vault.sol"


@pytest.mark.parametrize(
    ("written", "canonical"),
    [
        ("uint", "uint256"),
        ("int", "int256"),
        ("byte", "bytes1"),
        ("uint256", "uint256"),
        ("address", "address"),
        ("uint[]", "uint256[]"),
        ("uint[2][]", "uint256[2][]"),
        ("MyStruct", "MyStruct"),
    ],
)
def test_canonical_solc_type_names(written: str, canonical: str):
    assert canonical_type(written) == canonical


def test_signature_form_matches_the_explicit_form():
    """solc's methodIdentifiers keys are already canonical — the cheap path must agree."""
    assert make_function_id_from_signature(
        "src/Vault.sol", "Vault", "deposit(uint256)"
    ) == make_function_id("src/Vault.sol", "Vault", "deposit", ["uint256"])

    assert (
        make_function_id_from_signature("src/Vault.sol", "Vault", "poke()")
        == "src/Vault.sol:Vault.poke()"
    )


def test_overloads_are_disambiguated_by_full_signature():
    one = make_function_id("src/Vault.sol", "Vault", "deposit", ["uint256"])
    two = make_function_id("src/Vault.sol", "Vault", "deposit", ["uint256", "address"])
    assert one != two


def test_contract_id_round_trips():
    contract_id = make_contract_id("src/vault/Vault.sol", "Vault")
    assert split_contract_id(contract_id) == ("src/vault/Vault.sol", "Vault")


def test_split_rejects_a_non_id():
    with pytest.raises(ValueError):
        split_contract_id("Vault")
