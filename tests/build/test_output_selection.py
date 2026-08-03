"""Scope-restricted compiler output (SPEC §10).

Dependencies must be *compiled* — they carry the types and base contracts in-scope code
resolves against — but nothing downstream reads their storage layout, ABI or AST. Asking
solc for output per file rather than under a `"*"` wildcard skips code generation for the
other ~97% of a real protocol, which is most of the compiler's work.
"""

from __future__ import annotations

from pathlib import Path

from engine.core.models.repo import ProjectKind, RepoModel, ScopeOverride, SourceFile
from engine.ingest.build.solc import output_selection, resolve_remappings


def _repo(**overrides) -> RepoModel:
    defaults = dict(
        root="/tmp/repo",
        origin="folder",
        kind=ProjectKind.RAW,
        files=[
            SourceFile(path="src/Vault.sol", sha256="a", loc=10, in_scope=True),
            SourceFile(
                path="lib/oz/ERC20.sol", sha256="b", loc=99, is_dependency=True, in_scope=False
            ),
            SourceFile(path="test/Vault.t.sol", sha256="c", loc=20, is_test=True, in_scope=False),
        ],
    )
    return RepoModel(**{**defaults, **overrides})


def test_output_is_requested_only_for_in_scope_files():
    selection = output_selection(_repo())

    assert set(selection) == {"src/Vault.sol"}
    assert "storageLayout" in selection["src/Vault.sol"]["*"]
    assert selection["src/Vault.sol"][""] == ["ast"]


def test_dependencies_and_tests_get_no_output_slot():
    selection = output_selection(_repo())

    assert "lib/oz/ERC20.sol" not in selection
    assert "test/Vault.t.sol" not in selection
    assert "*" not in selection  # a wildcard would re-enable codegen for everything


def test_a_scope_override_narrows_the_request(tmp_path: Path):
    repo = _repo(scope_override=ScopeOverride(exclude=["src/*"]))
    repo.files[0].in_scope = False

    # Nothing in scope is pathological, but a build with no requested output is useless —
    # fall back to the wildcard rather than compiling for nothing.
    assert output_selection(repo) == {
        "*": {"*": output_selection(_repo())["src/Vault.sol"]["*"], "": ["ast"]}
    }


def test_a_non_foundry_project_uses_its_configured_remappings_only():
    repo = _repo(remappings={"@oz/": "lib/oz/", "solmate/": "lib/solmate/src/"})

    remappings, notes = resolve_remappings(repo)

    assert remappings == ["@oz/=lib/oz/", "solmate/=lib/solmate/src/"]
    assert notes == []
