"""The build pipeline end to end (SPEC §10, §10.2).

The compiler-backed tests skip when the toolchain is absent, so the suite still runs on a
machine without Foundry or solc. The degradation tests do not skip — "must not die" is the
property that matters most, and it must hold everywhere.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from engine.core.models.build import BuildModel
from engine.core.models.repo import ProjectKind
from engine.ingest.build.hardhat import HardhatBuilder
from engine.core.models.build import Diagnostic, DiagnosticSeverity
from engine.ingest.build.pipeline import (
    build_and_save,
    build_repository,
    select_builders,
    summarize_failures,
)
from engine.ingest.build.solc import find_solc
from engine.ingest.reader import read_repository
from tests.conftest import write

has_forge = pytest.mark.skipif(shutil.which("forge") is None, reason="forge is not installed")
has_solc = pytest.mark.skipif(find_solc() is None, reason="no solc available")


@pytest.fixture
def raw_vault(tmp_path: Path) -> Path:
    root = tmp_path / "raw-vault"
    write(
        root,
        "Vault.sol",
        "pragma solidity ^0.8.20;\n"
        "contract Vault {\n"
        "    mapping(address => uint256) public balance;\n"
        "    uint128 a;\n"
        "    uint128 b;\n"
        "    function deposit() external payable { balance[msg.sender] += msg.value; }\n"
        "}\n",
    )
    return root


@pytest.fixture
def broken(tmp_path: Path) -> Path:
    root = tmp_path / "broken"
    write(root, "Broken.sol", "pragma solidity ^0.8.20;\ncontract Broken {\n  function d() external {\n")
    return root


# ── Builder selection ─────────────────────────────────────────────────────────

def test_foundry_projects_prefer_forge(foundry_project: Path, run_root: Path):
    repo, _ = read_repository(foundry_project, run_root=run_root)
    assert [b.name for b in select_builders(repo)] == ["foundry", "solc"]


def test_hardhat_defaults_to_solc_because_hardhat_executes_the_targets_javascript(
    hardhat_project: Path, run_root: Path
):
    """`npx hardhat compile` runs hardhat.config.js — code from the repo under audit.

    The Reader refuses to execute that same file (§9.1); the Build phase must not quietly
    do it instead.
    """
    repo, _ = read_repository(hardhat_project, run_root=run_root)
    assert [b.name for b in select_builders(repo)][0] == "solc"


def test_allow_hardhat_promotes_it(hardhat_project: Path, run_root: Path):
    repo, _ = read_repository(hardhat_project, run_root=run_root)
    assert [b.name for b in select_builders(repo, allow_hardhat=True)] == ["hardhat", "solc"]


def test_hardhat_builder_is_unavailable_without_explicit_permission(
    hardhat_project: Path, run_root: Path
):
    repo, _ = read_repository(hardhat_project, run_root=run_root)
    assert HardhatBuilder(allowed=False).available(repo) is False


def test_raw_projects_use_solc_only(raw_vault: Path, run_root: Path):
    repo, _ = read_repository(raw_vault, run_root=run_root)
    assert repo.kind is ProjectKind.RAW
    assert [b.name for b in select_builders(repo)] == ["solc"]


# ── Compilation ───────────────────────────────────────────────────────────────

@has_forge
def test_foundry_build(foundry_project: Path, run_root: Path):
    repo, run_dir = read_repository(foundry_project, run_root=run_root)
    build = build_repository(repo, run_dir)

    assert build.builder == "foundry"
    assert build.build_available
    assert build.status in {"success", "partial"}
    assert build.solc_version_resolved
    assert build.counts["contracts"] > 0
    assert build.counts["with_ast"] > 0


@has_solc
def test_solc_build_extracts_storage_layout_with_packing(raw_vault: Path, run_root: Path):
    """Storage slots and packing are the thing only a compiler knows (§10)."""
    repo, run_dir = read_repository(raw_vault, run_root=run_root)
    build = build_repository(repo, run_dir)

    assert build.builder == "solc"
    assert build.build_available

    [vault] = build.contracts
    slots = {slot.label: (slot.slot, slot.offset) for slot in vault.storage}
    assert slots["balance"] == (0, 0)
    assert slots["a"] == (1, 0)
    assert slots["b"] == (1, 16)  # packed into the same slot as `a`
    assert vault.method_identifiers["deposit()"] == "d0e30db0"


@has_solc
def test_ast_is_written_to_disk_not_embedded(raw_vault: Path, run_root: Path):
    """A mid-size contract's AST is megabytes; embedding it makes build.json unusable."""
    repo, run_dir = read_repository(raw_vault, run_root=run_root)
    build = build_repository(repo, run_dir)

    [source] = build.sources
    assert source.ast_path == "build/ast/Vault.sol.json"
    assert (run_dir / source.ast_path).is_file()
    assert source.ast_sha256 and source.ast_nodes

    ast = json.loads((run_dir / source.ast_path).read_text(encoding="utf-8"))
    assert ast["nodeType"] == "SourceUnit"
    assert "ast" not in build.model_dump()  # nothing AST-shaped leaked into the artifact


# ── Degradation (§10.2) — these never skip ────────────────────────────────────

@has_solc
def test_a_repository_that_does_not_compile_still_produces_a_buildmodel(
    broken: Path, run_root: Path
):
    repo, run_dir = read_repository(broken, run_root=run_root)
    build = build_repository(repo, run_dir)

    assert isinstance(build, BuildModel)
    assert build.status == "failed"
    assert build.build_available is False
    assert build.errors
    assert build.errors[0].path == "Broken.sol"
    assert build.errors[0].line
    assert any("BUILD_DEGRADED" in note for note in build.notes)


def test_no_available_builder_is_skipped_not_fatal(raw_vault: Path, run_root: Path, monkeypatch):
    """Missing toolchain must cost the storage layout, not the audit."""
    monkeypatch.setattr("engine.ingest.build.solc.find_solc", lambda *_, **__: None)

    repo, run_dir = read_repository(raw_vault, run_root=run_root)
    build = build_repository(repo, run_dir)

    assert build.status == "skipped"
    assert build.builder == "none"
    assert build.build_available is False
    assert any("BUILD_DEGRADED" in note for note in build.notes)


def test_a_crashing_builder_cannot_abort_the_pipeline(raw_vault: Path, run_root: Path, monkeypatch):
    def explode(self, repo, run_dir):
        raise RuntimeError("boom")

    monkeypatch.setattr("engine.ingest.build.solc.SolcBuilder.available", lambda self, repo: True)
    monkeypatch.setattr("engine.ingest.build.solc.SolcBuilder.build", explode)

    repo, run_dir = read_repository(raw_vault, run_root=run_root)
    build = build_repository(repo, run_dir)

    assert build.status == "skipped"
    assert any("crashed" in note for note in build.notes)


# ── Artifact rules (§7.1) ─────────────────────────────────────────────────────

@has_solc
def test_build_model_chains_to_its_repo_model(raw_vault: Path, run_root: Path):
    repo, run_dir = read_repository(raw_vault, run_root=run_root)
    build = build_repository(repo, run_dir)

    assert build.repo_content_hash == repo.content_hash
    assert build.content_hash


@has_solc
def test_build_is_deterministic_across_runs(raw_vault: Path, tmp_path: Path):
    first_repo, first_dir = read_repository(raw_vault, run_root=tmp_path / "a")
    second_repo, second_dir = read_repository(raw_vault, run_root=tmp_path / "b")

    first = build_repository(first_repo, first_dir)
    second = build_repository(second_repo, second_dir)

    assert first.content_hash == second.content_hash


# ── Reporting the failure (found the hard way on a real protocol) ─────────────

@has_solc
def test_a_failed_build_still_names_the_builder_that_ran(broken: Path, run_root: Path):
    """`builder: "none"` hid the fact that a compiler had run and produced the errors."""
    repo, run_dir = read_repository(broken, run_root=run_root)
    build = build_repository(repo, run_dir)

    assert build.builder == "solc"
    assert build.diagnostics


@has_solc
def test_every_attempt_is_recorded_in_notes(broken: Path, run_root: Path):
    """Silence in `notes` made a failed build impossible to diagnose from the artifact."""
    repo, run_dir = read_repository(broken, run_root=run_root)
    build = build_repository(repo, run_dir)

    assert any("attempted" in note for note in build.notes)


def test_unresolved_imports_collapse_into_one_actionable_note():
    """58 identical "Source not found" errors say one thing; the note says that thing."""
    diagnostics = [
        Diagnostic(
            severity=DiagnosticSeverity.ERROR,
            error_code="6275",
            message=f'Source "@uniswap/v4-core/src/{name}.sol" not found: File not found.',
        )
        for name in ("IPoolManager", "PoolKey", "Currency")
    ] + [
        Diagnostic(
            severity=DiagnosticSeverity.ERROR,
            error_code="6275",
            message='Source "@nomad-xyz/src/ExcessivelySafeCall.sol" not found: File not found.',
        )
    ]

    [note] = summarize_failures(diagnostics)

    assert "4 imports could not be resolved" in note
    assert "@uniswap (×3)" in note
    assert "@nomad-xyz (×1)" in note
    assert "remappings" in note


def test_a_solc_version_mismatch_is_explained():
    diagnostics = [
        Diagnostic(
            severity=DiagnosticSeverity.ERROR,
            error_code="5333",
            message="Source file requires different compiler version (current 0.8.28)",
        )
    ]
    [note] = summarize_failures(diagnostics)
    assert "solc-select install" in note


def test_a_clean_build_has_nothing_to_summarize():
    assert summarize_failures([]) == []


@has_solc
def test_artifact_is_saved_as_build_json(raw_vault: Path, run_root: Path):
    repo, run_dir = read_repository(raw_vault, run_root=run_root)
    build, artifact = build_and_save(repo, run_dir)

    assert artifact.name == "build.json"
    reloaded = BuildModel.model_validate_json(artifact.read_text(encoding="utf-8"))
    assert reloaded.content_hash == build.content_hash
