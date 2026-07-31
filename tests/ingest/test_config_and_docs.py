"""Configuration extraction and documentation discovery (SPEC §9.1 steps 5-6).

Tests 16-18 of the Phase 1 acceptance list.
"""

from __future__ import annotations

from pathlib import Path

from engine.ingest.config import parse_remappings_text, solidity_version_from_pragmas
from engine.ingest.reader import read_repository
from tests.conftest import VAULT_SOL, write


# ── Foundry ───────────────────────────────────────────────────────────────────

def test_foundry_config_is_parsed(foundry_project: Path, run_root: Path):
    model, _ = read_repository(foundry_project, run_root=run_root)

    assert model.solidity_version == "0.8.28"
    assert model.solidity_version_source == "foundry.toml"
    assert model.config_raw["foundry.toml"]["profile"]["default"]["src"] == "src"


def test_remappings_txt_overrides_the_inline_list(foundry_project: Path, run_root: Path):
    model, _ = read_repository(foundry_project, run_root=run_root)

    assert model.remappings["forge-std/"] == "lib/forge-std/src/"  # from foundry.toml
    assert model.remappings["@openzeppelin/"] == "lib/openzeppelin-contracts/"  # from .txt


def test_remappings_text_parser_ignores_comments_and_blanks():
    text = "\n# a comment\n@oz/=lib/oz/\n\nsolmate/=lib/solmate/src/\n"
    assert parse_remappings_text(text) == {
        "@oz/": "lib/oz/",
        "solmate/": "lib/solmate/src/",
    }


def test_foundry_libs_become_the_dependency_roots(tmp_path: Path, run_root: Path):
    root = tmp_path / "custom-libs"
    write(root, "foundry.toml", '[profile.default]\nsrc = "src"\nlibs = ["dependencies"]\n')
    write(root, "src/Vault.sol", VAULT_SOL)
    write(root, "dependencies/oz/ERC20.sol", "contract ERC20 {}")
    write(root, "lib/mine/Math.sol", "library Math {}")

    model, _ = read_repository(root, run_root=run_root)
    by_path = {f.path: f for f in model.files}

    assert by_path["dependencies/oz/ERC20.sol"].is_dependency
    assert not by_path["lib/mine/Math.sol"].is_dependency  # not declared as a lib root
    assert any("dependency roots taken from foundry.toml" in n for n in model.notes)


# ── Hardhat ───────────────────────────────────────────────────────────────────

def test_hardhat_config_is_read_as_text_never_executed(hardhat_project: Path, run_root: Path):
    model, _ = read_repository(hardhat_project, run_root=run_root)

    assert model.solidity_version == "0.8.24"
    assert model.solidity_version_source == "hardhat.config"
    assert "module.exports" in model.config_raw["hardhat_config_text"]
    assert model.config_raw["hardhat_config_path"] == "hardhat.config.js"


def test_ambiguous_hardhat_version_is_left_unset_not_guessed(tmp_path: Path, run_root: Path):
    """If extraction is uncertain, store the raw config rather than guess (SPEC §9.1)."""
    root = tmp_path / "multi-solc"
    write(
        root,
        "hardhat.config.js",
        'module.exports = { solidity: { compilers: ['
        '{ version: "0.8.20" }, { version: "0.7.6" }] } };\n',
    )
    write(root, "contracts/Vault.sol", "pragma solidity ^0.8.20;\ncontract Vault {}\n")

    model, _ = read_repository(root, run_root=run_root)

    assert model.solidity_version == "^0.8.20"  # fell through to the pragma
    assert model.solidity_version_source == "pragma"
    assert any("declares 2 solc versions" in note for note in model.notes)
    assert "hardhat_config_text" in model.config_raw


# ── Pragma fallback ───────────────────────────────────────────────────────────

def test_raw_project_takes_its_version_from_pragmas(raw_project: Path, run_root: Path):
    model, _ = read_repository(raw_project, run_root=run_root)

    assert model.solidity_version == "^0.8.20"
    assert model.solidity_version_source == "pragma"


def test_pragma_fallback_picks_the_most_common_and_breaks_ties_deterministically():
    sources = [
        ("a.sol", "pragma solidity ^0.8.20;"),
        ("b.sol", "pragma solidity ^0.8.20;"),
        ("c.sol", "pragma solidity ^0.7.6;"),
    ]
    assert solidity_version_from_pragmas(sources) == "^0.8.20"

    tied = [("a.sol", "pragma solidity ^0.8.20;"), ("b.sol", "pragma solidity ^0.7.6;")]
    assert solidity_version_from_pragmas(tied) == "^0.7.6"  # alphabetical, therefore stable


# ── Docs ──────────────────────────────────────────────────────────────────────

def test_readme_and_docs_are_discovered(foundry_project: Path, run_root: Path):
    model, _ = read_repository(foundry_project, run_root=run_root)

    assert model.readme is not None
    assert "An ERC4626-ish vault" in model.readme
    assert "README.md" in model.docs
    assert "docs/architecture.md" in model.docs


def test_dependency_documentation_is_excluded(foundry_project: Path, run_root: Path):
    """Otherwise a Hardhat project contributes several hundred node_modules READMEs."""
    model, _ = read_repository(foundry_project, run_root=run_root)

    assert "lib/openzeppelin-contracts/README.md" not in model.docs
    assert all(not path.startswith("lib/") for path in model.docs)


def test_whitepaper_pdfs_are_recorded_but_not_parsed(tmp_path: Path, run_root: Path):
    root = tmp_path / "papered"
    write(root, "src/Vault.sol", VAULT_SOL)
    (root / "whitepaper.pdf").write_bytes(b"%PDF-1.7 binary garbage")

    model, _ = read_repository(root, run_root=run_root)

    assert "whitepaper.pdf" in model.docs
    assert model.readme is None


def test_docs_are_sorted(hardhat_project: Path, run_root: Path):
    write(hardhat_project, "docs/zeta.md", "z")
    write(hardhat_project, "docs/alpha.md", "a")
    write(hardhat_project, "README.md", "# R")

    model, _ = read_repository(hardhat_project, run_root=run_root)
    assert model.docs == sorted(model.docs)
