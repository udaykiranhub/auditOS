"""The Parsing Engine end to end (SPEC §12.3 acceptance criteria).

> - Golden-file test: contract/function counts match hand-labeled expectations.
> - Every `Function.id` round-trips through `make_id()` unchanged.
> - On a deliberately broken `.sol` file, the parser produces a partial `CodeModel` + a
>   `ParseError`, and does not raise.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.core.artifacts import load_artifact
from engine.core.errors import FatalError
from engine.core.models.code import CodeModel
from engine.core.models.ids import make_function_id, normalize_path
from engine.ingest.reader import read_repository
from engine.parse.pipeline import ParseCode, parse_and_save, parse_repository
from tests.conftest import write


def code_for(project: Path, run_root: Path) -> CodeModel:
    repo, _ = read_repository(project, run_root=run_root)
    return parse_repository(repo)


# ── Golden counts ─────────────────────────────────────────────────────────────

def test_counts_match_the_reference_project(foundry_project: Path, run_root: Path):
    code = code_for(foundry_project, run_root)
    counts = code.counts

    # 8 .sol files: Vault, IERC20, ERC20 (src) + Vault.t, MockOracle, Deploy (test/script)
    #               + forge-std Test, OZ ERC20 (lib)
    assert counts["sources"] == 8
    assert counts["contracts"] == 8
    assert counts["in_scope_contracts"] == 3
    assert counts["interfaces"] == 1
    assert counts["parse_errors"] == 0


def test_out_of_scope_code_is_parsed_not_skipped(foundry_project: Path, run_root: Path):
    """SPEC §9.3: parsed and graphed, never audited. The flag propagates; it does not filter."""
    code = code_for(foundry_project, run_root)
    paths = {c.path for c in code.contracts}

    assert "lib/openzeppelin-contracts/contracts/token/ERC20.sol" in paths
    assert "test/mocks/MockOracle.sol" in paths
    assert any(c.is_dependency for c in code.contracts)
    assert any(not c.in_scope for c in code.contracts)


def test_scope_and_dependency_flags_come_from_the_repo_model(
    foundry_project: Path, run_root: Path
):
    code = code_for(foundry_project, run_root)
    by_path = {c.path: c for c in code.contracts}

    assert by_path["src/Vault.sol"].in_scope
    assert not by_path["src/Vault.sol"].is_dependency
    assert by_path["lib/openzeppelin-contracts/contracts/token/ERC20.sol"].is_dependency


# ── Identity ──────────────────────────────────────────────────────────────────

def test_every_function_id_round_trips(foundry_project: Path, run_root: Path):
    """SPEC §12.3: the join key must be reproducible from its parts, or joins fail."""
    code = code_for(foundry_project, run_root)

    checked = 0
    for contract in code.contracts:
        for function in contract.functions:
            if function.kind.value in ("fallback", "receive"):
                continue
            rebuilt = make_function_id(
                contract.path, contract.name, function.name, [p.type for p in function.params]
            )
            assert rebuilt == function.id
            checked += 1
    assert checked > 0


def test_paths_are_repo_relative_posix(foundry_project: Path, run_root: Path):
    code = code_for(foundry_project, run_root)
    for contract in code.contracts:
        assert contract.path == normalize_path(contract.path)
        assert "\\" not in contract.path


# ── Error tolerance ───────────────────────────────────────────────────────────

def test_a_broken_file_yields_a_partial_model_and_a_parse_error(
    tmp_path: Path, run_root: Path
):
    """The whole reason tree-sitter is primary: broken code still has to be auditable."""
    project = tmp_path / "broken"
    write(project, "src/Good.sol", "pragma solidity ^0.8.20;\ncontract Good { function a() external {} }")
    write(
        project,
        "src/Broken.sol",
        "pragma solidity ^0.8.20;\ncontract Broken {\n  function withdraw() external {\n",
    )

    code = code_for(project, run_root)

    assert any(c.name == "Good" for c in code.contracts)
    assert any(c.name == "Broken" for c in code.contracts)  # partial, not dropped
    assert any(e.path == "src/Broken.sol" for e in code.parse_errors)
    assert any(s.has_syntax_error for s in code.sources)
    assert any("syntax errors" in note for note in code.notes)


def test_a_broken_file_still_yields_its_function_signature(tmp_path: Path, run_root: Path):
    project = tmp_path / "partial"
    write(
        project,
        "src/P.sol",
        "contract P {\n  function withdraw(uint256 amount) external {\n    uint x = ;\n  }\n}",
    )
    code = code_for(project, run_root)

    contract = next(c for c in code.contracts if c.name == "P")
    assert [f.name for f in contract.functions] == ["withdraw"]


def test_a_repository_with_no_contracts_is_fatal(tmp_path: Path, run_root: Path):
    project = tmp_path / "empty"
    write(project, "src/NotCode.sol", "pragma solidity ^0.8.20;\n// nothing here\n")

    repo, _ = read_repository(project, run_root=run_root)
    with pytest.raises(FatalError) as excinfo:
        parse_repository(repo)
    assert excinfo.value.code == ParseCode.NO_CONTRACTS


# ── Cross-file resolution ─────────────────────────────────────────────────────

def test_relative_imports_resolve(foundry_project: Path, run_root: Path):
    code = code_for(foundry_project, run_root)
    vault = next(s for s in code.sources if s.path == "src/Vault.sol")

    assert vault.imports[0].path == "./IERC20.sol"
    assert vault.imports[0].resolved_path == "src/IERC20.sol"


def test_remapped_imports_resolve(tmp_path: Path, run_root: Path):
    project = tmp_path / "remapped"
    write(project, "foundry.toml", '[profile.default]\nsrc = "src"\nlibs = ["lib"]\n')
    write(project, "remappings.txt", "@oz/=lib/oz/\n")
    write(project, "src/A.sol", 'import {ERC20} from "@oz/ERC20.sol";\ncontract A is ERC20 {}')
    write(project, "lib/oz/ERC20.sol", "contract ERC20 {}")

    code = code_for(project, run_root)
    source = next(s for s in code.sources if s.path == "src/A.sol")

    assert source.imports[0].resolved_path == "lib/oz/ERC20.sol"


def test_inheritance_resolves_to_a_solidity_id(tmp_path: Path, run_root: Path):
    project = tmp_path / "inherit"
    write(project, "src/Base.sol", "contract Base {}")
    write(project, "src/Child.sol", 'import "./Base.sol";\ncontract Child is Base {}')

    code = code_for(project, run_root)
    child = next(c for c in code.contracts if c.name == "Child")

    assert child.inherits == ["Base"]
    assert child.inherits_ids == ["src/Base.sol:Base"]


def test_an_unresolvable_parent_is_reported_not_dropped(tmp_path: Path, run_root: Path):
    project = tmp_path / "missing-parent"
    write(project, "src/C.sol", "contract C is Absent {}")

    code = code_for(project, run_root)
    contract = code.contracts[0]

    assert contract.inherits == ["Absent"]  # the fact survives
    assert contract.inherits_ids == []  # the resolution does not
    assert any("Absent" in e.message for e in code.parse_errors)


def test_a_duplicated_parent_name_prefers_the_imported_one(tmp_path: Path, run_root: Path):
    """Protocols routinely vendor two versions of the same library."""
    project = tmp_path / "two-versions"
    write(project, "foundry.toml", '[profile.default]\nsrc = "src"\nlibs = ["lib"]\n')
    write(project, "lib/oz-v3/ERC20.sol", "contract ERC20 {}")
    write(project, "lib/oz-v4/ERC20.sol", "contract ERC20 {}")
    write(project, "src/A.sol", 'import "../lib/oz-v4/ERC20.sol";\ncontract A is ERC20 {}')

    code = code_for(project, run_root)
    contract = next(c for c in code.contracts if c.name == "A")

    assert contract.inherits_ids == ["lib/oz-v4/ERC20.sol:ERC20"]


# ── Determinism and persistence ───────────────────────────────────────────────

def test_the_model_is_identical_across_runs(foundry_project: Path, run_root: Path):
    first = code_for(foundry_project, run_root)
    second = code_for(foundry_project, run_root)

    assert first.content_hash == second.content_hash
    assert first.model_dump() == second.model_dump()


def test_contracts_and_sources_are_sorted(foundry_project: Path, run_root: Path):
    code = code_for(foundry_project, run_root)

    assert [c.id for c in code.contracts] == sorted(c.id for c in code.contracts)
    assert [s.path for s in code.sources] == sorted(s.path for s in code.sources)


def test_the_artifact_round_trips(foundry_project: Path, run_root: Path):
    repo, run_dir = read_repository(foundry_project, run_root=run_root)
    code, artifact = parse_and_save(repo, run_dir)

    assert artifact.name == "code.json"
    reloaded = load_artifact(CodeModel, artifact)
    assert reloaded.content_hash == code.content_hash
    assert json.loads(artifact.read_text(encoding="utf-8"))["schema_version"]


def test_the_model_records_which_repo_it_describes(foundry_project: Path, run_root: Path):
    repo, _ = read_repository(foundry_project, run_root=run_root)
    code = parse_repository(repo)

    assert code.repo_content_hash == repo.content_hash
    assert not code.enriched  # no BuildModel was supplied
    assert any("no compiler enrichment" in note for note in code.notes)
