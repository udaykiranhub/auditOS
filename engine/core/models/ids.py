"""`SolidityID` — the join key for the entire system (SPEC §7.2).

```
Contract : "src/vault/Vault.sol:Vault"
Function : "src/vault/Vault.sol:Vault.deposit(uint256,address)"
StateVar : "src/vault/Vault.sol:Vault#totalAssets"
Modifier : "src/vault/Vault.sol:Vault.onlyOwner"
```

This ID joins `CodeModel`, `GraphModel`, `BuildModel`, Slither output, `ContextBundle`
and `Finding`. If two modules compute it differently, static corroboration and context
selection break silently — so it is implemented **once**, here.

Rules: the path is repo-relative and POSIX; signatures use canonical solc type names
(`uint256`, not `uint`); overloads are disambiguated by the full signature; inherited
functions are addressed by their **defining** contract, never the inheriting one.

Note that solc already emits the contract form in `storageLayout[].contract`, so this is
the format the compiler agrees with, not one invented here.
"""

from __future__ import annotations

from pathlib import PurePosixPath

# solc's canonical spellings for the aliases Solidity accepts in source.
_TYPE_ALIASES = {
    "uint": "uint256",
    "int": "int256",
    "byte": "bytes1",
    "ufixed": "ufixed128x18",
    "fixed": "fixed128x18",
}


def normalize_path(path: str) -> str:
    """Repo-relative POSIX form. Every ID starts here."""
    return PurePosixPath(str(path).replace("\\", "/")).as_posix().lstrip("./")


def canonical_type(type_name: str) -> str:
    """Canonicalize one solc type name: `uint` → `uint256`, `uint[]` → `uint256[]`."""
    text = type_name.strip()
    # `address payable` and `address` share an ABI type, so solc computes the selector of
    # `pay(address payable)` over `pay(address)`. Keeping the qualifier here would mean the
    # tree-sitter ID and the compiler's `methodIdentifiers` key never join — silently, for
    # exactly those functions that move ETH.
    if text.startswith("address ") or text == "address payable":
        text = "address"
    suffix = ""
    while text.endswith("]"):
        start = text.rfind("[")
        if start == -1:
            break
        suffix = text[start:] + suffix
        text = text[:start].strip()
    return _TYPE_ALIASES.get(text, text) + suffix


def make_contract_id(path: str, contract: str) -> str:
    """`src/Vault.sol:Vault`"""
    return f"{normalize_path(path)}:{contract}"


def make_function_id(path: str, contract: str, name: str, param_types: list[str]) -> str:
    """`src/Vault.sol:Vault.deposit(uint256,address)`"""
    params = ",".join(canonical_type(t) for t in param_types)
    return f"{make_contract_id(path, contract)}.{name}({params})"


def make_function_id_from_signature(path: str, contract: str, signature: str) -> str:
    """Build a function ID from a canonical solc signature such as `deposit(uint256)`.

    solc's `evm.methodIdentifiers` keys are already canonical, which makes this the
    cheapest correct path from a compiler artifact to an ID.
    """
    name, _, rest = signature.partition("(")
    params = [part for part in rest.rstrip(")").split(",") if part]
    return make_function_id(path, contract, name, params)


def make_state_var_id(path: str, contract: str, variable: str) -> str:
    """`src/Vault.sol:Vault#totalAssets`"""
    return f"{make_contract_id(path, contract)}#{variable}"


def make_modifier_id(path: str, contract: str, modifier: str) -> str:
    """`src/Vault.sol:Vault.onlyOwner`"""
    return f"{make_contract_id(path, contract)}.{modifier}"


def split_contract_id(contract_id: str) -> tuple[str, str]:
    """Inverse of :func:`make_contract_id`. Round-trips for every valid ID."""
    path, _, contract = contract_id.rpartition(":")
    if not path:
        raise ValueError(f"Not a contract id: {contract_id!r}")
    return path, contract
