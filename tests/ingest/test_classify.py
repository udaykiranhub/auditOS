"""Scope classification (SPEC §9.3) — the highest-leverage heuristic in the system.

Tests 6-11 of the Phase 1 acceptance list, plus the false-positive cases that make the
difference between a useful audit and one that reports bugs in OpenZeppelin.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.core.models.repo import ScopeOverride
from engine.ingest.classify import (
    classify,
    count_loc,
    is_dependency_path,
    is_interface_only,
    is_mock_path,
    is_test_path,
    strip_comments_and_strings,
)
from engine.ingest.reader import read_repository
from tests.conftest import IERC20_SOL, VAULT_SOL, write


# ── Path signals ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "path",
    [
        "test/Vault.t.sol",
        "tests/Vault.sol",
        "src/Vault.t.sol",
        "script/Deploy.s.sol",
        "test/VaultTest.sol",
        "contracts/test/Helper.sol",
    ],
)
def test_test_paths(path: str):
    assert is_test_path(path)


@pytest.mark.parametrize("path", ["src/Vault.sol", "src/Testament.sol", "src/Protest.sol"])
def test_non_test_paths(path: str):
    assert not is_test_path(path)


@pytest.mark.parametrize(
    "path",
    [
        "test/mocks/MockOracle.sol",
        "src/mocks/Oracle.sol",
        "src/MockERC20.sol",
        "src/ERC20Mock.sol",
        "src/FakeOracle.sol",
        "src/VaultHarness.sol",
        "src/StubRouter.sol",
    ],
)
def test_mock_paths(path: str):
    assert is_mock_path(path)


@pytest.mark.parametrize("path", ["src/StubbornVault.sol", "src/Mockingbird.sol"])
def test_mock_lookalikes_are_not_mocks(path: str):
    """Token-aware matching: `Stubborn` is not `Stub`, `Mockingbird` is not `Mock`."""
    assert not is_mock_path(path)


@pytest.mark.parametrize(
    "path",
    [
        "lib/forge-std/src/Test.sol",
        "node_modules/@openzeppelin/contracts/token/ERC20.sol",
        "vendor/solmate/src/ERC20.sol",
        "external/chainlink/AggregatorV3.sol",
        "openzeppelin-contracts/contracts/token/ERC20.sol",
        "packages/app/node_modules/solady/src/Foo.sol",
    ],
)
def test_dependency_paths(path: str):
    assert is_dependency_path(path)


@pytest.mark.parametrize(
    "path",
    [
        "src/ERC20.sol",  # a *modified* library copy — in scope (SPEC §9.3 common mistake)
        "src/Vault.sol",
        "src/lib/Math.sol",  # the protocol's own helper library, not a dependency root
        "src/uniswap-integration/Router.sol",  # integrates with, is not, Uniswap
        "contracts/oracles/ChainlinkAdapter.sol",
    ],
)
def test_non_dependency_paths(path: str):
    assert not is_dependency_path(path)


def test_foundry_libs_config_overrides_the_default_dependency_roots():
    assert is_dependency_path("dependencies/oz/ERC20.sol", ("dependencies",))
    assert not is_dependency_path("lib/mine/Math.sol", ("dependencies",))


# ── Source signals ────────────────────────────────────────────────────────────

def test_interface_only_detection():
    assert is_interface_only(strip_comments_and_strings(IERC20_SOL))
    assert not is_interface_only(strip_comments_and_strings(VAULT_SOL))


def test_a_file_mixing_interface_and_contract_is_not_interface_only():
    source = "interface IFoo { function a() external; }\ncontract Foo is IFoo {}\n"
    assert not is_interface_only(strip_comments_and_strings(source))


def test_declarations_in_comments_and_strings_are_ignored():
    source = '''
// contract Ghost {}
/* contract AlsoGhost {} */
interface IReal {
    function note() external pure returns (string memory); // returns "contract Nope"
}
'''
    stripped = strip_comments_and_strings(source)
    assert is_interface_only(stripped)
    assert "Ghost" not in stripped


def test_loc_counts_code_not_comments_or_blanks():
    source = "// a comment\n\npragma solidity ^0.8.20;\n\ncontract A {}\n"
    assert count_loc(strip_comments_and_strings(source)) == 2


def test_strip_preserves_line_structure():
    source = "contract A {\n/* two\nlines */\n}\n"
    assert len(strip_comments_and_strings(source).splitlines()) == len(source.splitlines())


# ── The scope rule itself ─────────────────────────────────────────────────────

def test_in_scope_is_the_conjunction_of_three_negatives():
    flags = classify("src/Vault.sol", strip_comments_and_strings(VAULT_SOL))
    assert flags["in_scope"]

    for path in ("lib/oz/ERC20.sol", "test/Vault.t.sol", "src/MockOracle.sol"):
        assert not classify(path, "contract A {}")["in_scope"]


def test_interface_only_files_remain_in_scope():
    """Interfaces are in scope; the flag is metadata for the Context Builder, not a filter."""
    flags = classify("src/IERC20.sol", strip_comments_and_strings(IERC20_SOL))
    assert flags["is_interface_only"]
    assert flags["in_scope"]


def test_out_of_scope_files_are_kept_in_the_inventory(foundry_project: Path, run_root: Path):
    """Scope is metadata, not a filter — the Parser still needs these files."""
    model, _ = read_repository(foundry_project, run_root=run_root)

    paths = {f.path for f in model.files}
    assert "lib/openzeppelin-contracts/contracts/token/ERC20.sol" in paths
    assert "test/Vault.t.sol" in paths
    assert "test/mocks/MockOracle.sol" in paths

    assert model.counts["total"] == 8
    assert model.counts["in_scope"] == 3  # Vault.sol, IERC20.sol, ERC20.sol


def test_modified_library_in_src_stays_in_scope(foundry_project: Path, run_root: Path):
    model, _ = read_repository(foundry_project, run_root=run_root)
    src_erc20 = next(f for f in model.files if f.path == "src/ERC20.sol")

    assert not src_erc20.is_dependency
    assert src_erc20.in_scope

    vendored = next(
        f for f in model.files if f.path.startswith("lib/openzeppelin-contracts/")
    )
    assert vendored.is_dependency
    assert not vendored.in_scope


def test_every_file_records_why_it_was_scoped(foundry_project: Path, run_root: Path):
    model, _ = read_repository(foundry_project, run_root=run_root)
    assert all(f.scope_reason for f in model.files)
    assert next(f for f in model.files if f.path == "src/Vault.sol").scope_reason == "in scope"
    assert "dependency" in next(f for f in model.files if f.is_dependency).scope_reason


# ── The escape hatch ──────────────────────────────────────────────────────────

def test_scope_override_include_and_exclude(tmp_path: Path, run_root: Path):
    root = tmp_path / "override"
    write(root, "src/Vault.sol", VAULT_SOL)
    write(root, "src/mocks/MockOracle.sol", "contract MockOracle {}")

    model, _ = read_repository(
        root,
        run_root=run_root,
        scope_override=ScopeOverride(
            include=["src/mocks/*"],
            exclude=["src/Vault.sol"],
        ),
    )

    by_path = {f.path: f for f in model.files}
    assert not by_path["src/Vault.sol"].in_scope
    assert by_path["src/mocks/MockOracle.sol"].in_scope
    assert "scope_override" in by_path["src/Vault.sol"].scope_reason


def test_exclude_beats_include(tmp_path: Path, run_root: Path):
    root = tmp_path / "conflict"
    write(root, "src/Vault.sol", VAULT_SOL)

    model, _ = read_repository(
        root,
        run_root=run_root,
        scope_override=ScopeOverride(include=["src/*"], exclude=["src/Vault.sol"]),
    )
    assert not model.files[0].in_scope
