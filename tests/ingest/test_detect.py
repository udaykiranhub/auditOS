"""Project detection (SPEC §9.2) — tests 1-5 of the Phase 1 acceptance list."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.core.errors import FatalError, IngestCode
from engine.core.models.repo import ProjectKind
from engine.ingest.detect import detect_kind
from engine.ingest.reader import read_repository
from tests.conftest import FOUNDRY_TOML, HARDHAT_CONFIG_JS, VAULT_SOL, write


def test_detects_foundry(foundry_project: Path, run_root: Path):
    model, _ = read_repository(foundry_project, run_root=run_root)
    assert model.kind is ProjectKind.FOUNDRY


def test_detects_hardhat(hardhat_project: Path, run_root: Path):
    model, _ = read_repository(hardhat_project, run_root=run_root)
    assert model.kind is ProjectKind.HARDHAT


def test_detects_raw_solidity(raw_project: Path, run_root: Path):
    model, _ = read_repository(raw_project, run_root=run_root)
    assert model.kind is ProjectKind.RAW


def test_no_solidity_files_is_fatal(empty_project: Path, run_root: Path):
    with pytest.raises(FatalError) as excinfo:
        read_repository(empty_project, run_root=run_root)
    assert excinfo.value.code == IngestCode.NO_SOLIDITY_FILES


def test_foundry_wins_when_both_configs_present(tmp_path: Path, run_root: Path):
    root = tmp_path / "both"
    write(root, "foundry.toml", FOUNDRY_TOML)
    write(root, "hardhat.config.js", HARDHAT_CONFIG_JS)
    write(root, "src/Vault.sol", VAULT_SOL)

    model, _ = read_repository(root, run_root=run_root)

    assert model.kind is ProjectKind.FOUNDRY
    assert any("both foundry.toml and hardhat.config" in note for note in model.notes)


def test_hardhat_detected_from_package_json_alone(tmp_path: Path, run_root: Path):
    root = tmp_path / "pkg-only"
    write(root, "package.json", '{"devDependencies": {"hardhat": "^2.22.0"}}\n')
    write(root, "contracts/Vault.sol", VAULT_SOL)

    model, _ = read_repository(root, run_root=run_root)

    assert model.kind is ProjectKind.HARDHAT
    assert any("package.json" in note for note in model.notes)


def test_a_hardhat_dependency_inside_node_modules_does_not_decide_the_kind(tmp_path: Path):
    """A vendored hardhat.config must not make the *project* Hardhat."""
    root = tmp_path / "vendored"
    write(root, "foundry.toml", FOUNDRY_TOML)
    write(root, "node_modules/some-pkg/hardhat.config.js", HARDHAT_CONFIG_JS)
    write(root, "src/Vault.sol", VAULT_SOL)

    kind, markers, _ = detect_kind(root)

    assert kind is ProjectKind.FOUNDRY
    assert "hardhat.config" not in markers


def test_marker_found_below_root_is_noted(tmp_path: Path, run_root: Path):
    """Monorepo: packages/contracts/foundry.toml still detects, and says so."""
    root = tmp_path / "monorepo"
    write(root, "packages/contracts/foundry.toml", FOUNDRY_TOML)
    write(root, "packages/contracts/src/Vault.sol", VAULT_SOL)

    model, _ = read_repository(root, run_root=run_root)

    assert model.kind is ProjectKind.FOUNDRY
    assert any("below the repository root" in note for note in model.notes)
