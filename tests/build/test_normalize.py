"""Compiler-output normalization (SPEC §10).

These run without a compiler: Foundry, Hardhat and direct solc all funnel into the same
normalizers, so the normalizers are where the shared behaviour is pinned.
"""

from __future__ import annotations

from engine.core.models.build import DiagnosticSeverity
from engine.ingest.build.base import (
    build_contract_artifact,
    line_index,
    normalize_diagnostics,
    normalize_storage_layout,
    offset_to_line_column,
)

SOURCE = "pragma solidity ^0.8.20;\ncontract A {\n    uint256 x;\n}\n"
#          0                    23 24        25          37 38  42
UINT_OFFSET = SOURCE.index("uint256")  # 42 — the indented declaration on line 3


def test_offsets_become_line_and_column():
    offsets = line_index({"A.sol": SOURCE})["A.sol"]

    assert offset_to_line_column(offsets, 0) == (1, 1)
    assert offset_to_line_column(offsets, 24) == (1, 25)  # the newline still belongs to line 1
    assert offset_to_line_column(offsets, 25) == (2, 1)  # first char of line 2
    assert offset_to_line_column(offsets, UINT_OFFSET) == (3, 5)  # after four spaces


def test_diagnostics_are_normalized_and_located():
    raw = [
        {
            "severity": "error",
            "type": "ParserError",
            "errorCode": "2314",
            "message": "Expected primary expression.",
            "sourceLocation": {"file": "A.sol", "start": UINT_OFFSET, "end": UINT_OFFSET + 7},
        }
    ]

    [diagnostic] = normalize_diagnostics(raw, line_index({"A.sol": SOURCE}))

    assert diagnostic.severity is DiagnosticSeverity.ERROR
    assert diagnostic.path == "A.sol"
    assert (diagnostic.line, diagnostic.column) == (3, 5)
    assert diagnostic.error_code == "2314"


def test_diagnostic_without_a_location_survives():
    [diagnostic] = normalize_diagnostics(
        [{"severity": "warning", "message": "SPDX missing", "sourceLocation": {"start": -1}}]
    )
    assert diagnostic.severity is DiagnosticSeverity.WARNING
    assert diagnostic.line is None


def test_severity_falls_back_to_the_type_field():
    """Older solc emits `type: ParserError` without a `severity`."""
    [diagnostic] = normalize_diagnostics([{"type": "TypeError", "message": "bad"}])
    assert diagnostic.severity is DiagnosticSeverity.ERROR


def test_diagnostics_are_sorted_deterministically():
    raw = [
        {"severity": "warning", "message": "b", "sourceLocation": {"file": "B.sol", "start": -1}},
        {"severity": "warning", "message": "a", "sourceLocation": {"file": "A.sol", "start": -1}},
    ]
    assert [d.path for d in normalize_diagnostics(raw)] == ["A.sol", "B.sol"]


def test_storage_layout_resolves_types_and_packing():
    layout = {
        "storage": [
            {"label": "a", "offset": 0, "slot": "1", "type": "t_uint128"},
            {"label": "b", "offset": 16, "slot": "1", "type": "t_uint128"},
            {"label": "m", "offset": 0, "slot": "0", "type": "t_mapping"},
        ],
        "types": {
            "t_uint128": {"label": "uint128", "numberOfBytes": "16", "encoding": "inplace"},
            "t_mapping": {
                "label": "mapping(address => uint256)",
                "numberOfBytes": "32",
                "encoding": "mapping",
            },
        },
    }

    slots = normalize_storage_layout(layout)

    assert [(s.label, s.slot, s.offset) for s in slots] == [("a", 1, 0), ("b", 1, 16), ("m", 0, 0)]
    assert slots[0].type_label == "uint128"
    assert slots[2].encoding == "mapping"


def test_missing_storage_layout_is_empty_not_an_error():
    assert normalize_storage_layout(None) == []


# ── Contract artifacts ────────────────────────────────────────────────────────

FOUNDRY_SHAPE = {
    "abi": [{"type": "function", "name": "deposit"}],
    "methodIdentifiers": {"deposit()": "d0e30db0"},
    "bytecode": {"object": "0x6080"},
    "deployedBytecode": {"object": "0x60"},
}

STANDARD_JSON_SHAPE = {
    "abi": [{"type": "function", "name": "deposit"}],
    "evm": {
        "methodIdentifiers": {"deposit()": "d0e30db0"},
        "bytecode": {"object": "6080"},
        "deployedBytecode": {"object": "60"},
    },
}


def test_both_artifact_shapes_produce_the_same_result():
    """Foundry hoists bytecode; standard-JSON nests it under `evm`."""
    foundry = build_contract_artifact("src/Vault.sol", "Vault", FOUNDRY_SHAPE, True)
    standard = build_contract_artifact("src/Vault.sol", "Vault", STANDARD_JSON_SHAPE, True)

    assert foundry.model_dump() == standard.model_dump()
    assert foundry.id == "src/Vault.sol:Vault"
    assert foundry.bytecode_size == 2
    assert foundry.deployed_bytecode_size == 1


def test_abi_is_omitted_for_out_of_scope_contracts():
    """A repo's dependency ABIs add megabytes; no agent reasons about OZ's interface."""
    artifact = build_contract_artifact("lib/oz/ERC20.sol", "ERC20", FOUNDRY_SHAPE, False)

    assert artifact.abi == []
    assert artifact.abi_omitted is True
    assert artifact.method_identifiers  # selectors are tiny and always kept


def test_eip_170_oversize_detection():
    artifact = build_contract_artifact(
        "src/Big.sol", "Big", {"deployedBytecode": {"object": "00" * 24_577}}, True
    )
    assert artifact.exceeds_size_limit

    small = build_contract_artifact("src/S.sol", "S", {"deployedBytecode": {"object": "00"}}, True)
    assert not small.exceeds_size_limit
