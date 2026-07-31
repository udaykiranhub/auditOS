"""Determinism and artifact persistence (SPEC §7.1, §9.4).

> Given the same input, `RepoModel` is byte-identical across runs (modulo `root`).

Test 15 of the Phase 1 acceptance list, plus the artifact rules that make the cache a
valid resume mechanism.
"""

from __future__ import annotations

import json
from pathlib import Path

from engine.core.artifacts import load_artifact
from engine.core.models.repo import SCHEMA_VERSION, RepoModel
from engine.ingest.reader import ingest, read_repository
from tests.conftest import VAULT_SOL, write


def test_repo_model_is_identical_across_runs(foundry_project: Path, run_root: Path):
    first, _ = read_repository(foundry_project, run_root=run_root)
    second, _ = read_repository(foundry_project, run_root=run_root)

    assert first.root != second.root  # different run directories
    assert first.model_dump(exclude={"root"}) == second.model_dump(exclude={"root"})
    assert first.content_hash == second.content_hash


def test_content_hash_excludes_the_run_path(foundry_project: Path, tmp_path: Path):
    """Two different run roots on two different disks must still agree on the hash."""
    a, _ = read_repository(foundry_project, run_root=tmp_path / "run-a")
    b, _ = read_repository(foundry_project, run_root=tmp_path / "run-b")

    assert a.root != b.root
    assert a.content_hash == b.content_hash
    assert "root" not in a.hash_payload()
    assert "content_hash" not in a.hash_payload()


def test_content_hash_changes_when_content_changes(foundry_project: Path, run_root: Path):
    before, _ = read_repository(foundry_project, run_root=run_root)

    write(foundry_project, "src/Vault.sol", VAULT_SOL + "\n// changed\n")
    after, _ = read_repository(foundry_project, run_root=run_root)

    assert before.content_hash != after.content_hash


def test_content_hash_changes_when_scope_changes(foundry_project: Path, run_root: Path):
    from engine.core.models.repo import ScopeOverride

    plain, _ = read_repository(foundry_project, run_root=run_root)
    overridden, _ = read_repository(
        foundry_project, run_root=run_root, scope_override=ScopeOverride(exclude=["src/*"])
    )
    assert plain.content_hash != overridden.content_hash


def test_files_are_sorted_by_path(foundry_project: Path, run_root: Path):
    model, _ = read_repository(foundry_project, run_root=run_root)
    paths = [f.path for f in model.files]

    assert paths == sorted(paths)
    assert all("\\" not in path for path in paths)  # POSIX separators, on every platform


def test_no_timestamps_or_absolute_paths_leak_into_the_hash(foundry_project: Path, run_root: Path):
    model, _ = read_repository(foundry_project, run_root=run_root)
    payload = json.dumps(model.hash_payload())

    assert str(run_root) not in payload
    assert str(foundry_project) not in payload


def test_artifact_round_trips(foundry_project: Path, run_root: Path):
    model, artifact_path = ingest(foundry_project, run_root=run_root)

    assert artifact_path.name == "repo.json"
    assert artifact_path.parent.name == "artifacts"

    reloaded = load_artifact(RepoModel, artifact_path)
    assert reloaded.model_dump() == model.model_dump()
    assert reloaded.schema_version == SCHEMA_VERSION


def test_artifact_json_is_stable_on_disk(foundry_project: Path, tmp_path: Path):
    _, first = ingest(foundry_project, run_root=tmp_path / "run-a")
    _, second = ingest(foundry_project, run_root=tmp_path / "run-b")

    a = json.loads(first.read_text(encoding="utf-8"))
    b = json.loads(second.read_text(encoding="utf-8"))
    a.pop("root"), b.pop("root")

    assert a == b
    # Serialization itself is canonical: same keys, same order.
    assert list(a) == list(b)
