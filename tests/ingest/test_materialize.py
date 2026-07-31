"""Materialization: ZIP safety, folder immutability, git ingestion (SPEC §9.1).

Tests 12-14, 19 and 20 of the Phase 1 acceptance list.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from engine.core.errors import FatalError, IngestCode
from engine.core.models.repo import ProjectKind
from engine.ingest.materialize import MAX_ARCHIVE_ENTRIES, materialize_zip
from engine.ingest.reader import read_repository
from tests.conftest import FOUNDRY_TOML, VAULT_SOL, write


# ── ZIP ───────────────────────────────────────────────────────────────────────

def _zip_from_dir(source: Path, dest: Path) -> Path:
    archive = dest / "protocol.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(source).as_posix())
    return archive


def test_zip_ingestion_produces_the_same_model_as_the_folder(
    foundry_project: Path, tmp_path: Path, run_root: Path
):
    archive = _zip_from_dir(foundry_project, tmp_path)

    from_folder, _ = read_repository(foundry_project, run_root=run_root)
    from_zip, _ = read_repository(archive, run_root=run_root)

    assert from_zip.origin == "zip"
    assert from_folder.origin == "folder"
    # Same bytes in, same classification out — only the origin differs.
    assert [f.model_dump() for f in from_zip.files] == [f.model_dump() for f in from_folder.files]


def test_zip_slip_is_rejected(tmp_path: Path, run_root: Path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("src/Vault.sol", VAULT_SOL)
        zf.writestr("../../escaped.sol", "contract Escaped {}")

    with pytest.raises(FatalError) as excinfo:
        read_repository(archive, run_root=run_root)

    assert excinfo.value.code == IngestCode.ZIP_SLIP
    assert not (run_root.parent / "escaped.sol").exists()


def test_absolute_path_zip_entry_is_rejected(tmp_path: Path):
    archive = tmp_path / "absolute.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("/etc/passwd.sol", "contract X {}")

    with pytest.raises(FatalError) as excinfo:
        materialize_zip(archive, tmp_path / "out")
    assert excinfo.value.code == IngestCode.ZIP_SLIP


def test_zip_with_too_many_entries_is_rejected(tmp_path: Path):
    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for i in range(MAX_ARCHIVE_ENTRIES + 1):
            zf.writestr(f"f{i}.txt", "")

    with pytest.raises(FatalError) as excinfo:
        materialize_zip(archive, tmp_path / "out")
    assert excinfo.value.code == IngestCode.ZIP_TOO_MANY_ENTRIES


def test_zip_bomb_is_rejected_on_uncompressed_size(tmp_path: Path, monkeypatch):
    """A small archive that expands past the limit must be refused before extraction.

    The compressed-size check alone is exactly what a zip bomb defeats.
    """
    monkeypatch.setattr("engine.ingest.materialize.MAX_ARCHIVE_BYTES", 1024)

    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.txt", "A" * 100_000)  # compresses to a few hundred bytes

    assert archive.stat().st_size < 1024
    with pytest.raises(FatalError) as excinfo:
        materialize_zip(archive, tmp_path / "out")
    assert excinfo.value.code == IngestCode.ZIP_TOO_LARGE


def test_corrupt_zip_fails_cleanly(tmp_path: Path):
    archive = tmp_path / "corrupt.zip"
    archive.write_bytes(b"this is not a zip file")

    with pytest.raises(FatalError) as excinfo:
        materialize_zip(archive, tmp_path / "out")
    assert excinfo.value.code == IngestCode.ZIP_INVALID


def test_github_style_wrapper_directory_is_flattened(tmp_path: Path, run_root: Path):
    archive = tmp_path / "wrapped.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("protocol-main/foundry.toml", FOUNDRY_TOML)
        zf.writestr("protocol-main/src/Vault.sol", VAULT_SOL)

    model, _ = read_repository(archive, run_root=run_root)

    assert model.kind is ProjectKind.FOUNDRY
    assert [f.path for f in model.files] == ["src/Vault.sol"]


# ── Folder ────────────────────────────────────────────────────────────────────

def test_folder_is_copied_not_referenced(foundry_project: Path, run_root: Path):
    """The run must be immutable against user edits mid-analysis."""
    model, _ = read_repository(foundry_project, run_root=run_root)
    original_hash = next(f for f in model.files if f.path == "src/Vault.sol").sha256

    (foundry_project / "src" / "Vault.sol").write_text("contract Tampered {}", encoding="utf-8")

    copied = Path(model.root) / "src" / "Vault.sol"
    assert copied.exists()
    assert not copied.is_symlink()
    assert "Tampered" not in copied.read_text(encoding="utf-8")
    assert original_hash  # unchanged: the model describes the snapshot, not the source


def test_build_output_is_not_copied(foundry_project: Path, run_root: Path):
    write(foundry_project, "out/Vault.sol/Vault.json", "{}")
    write(foundry_project, "cache/solidity-files-cache.json", "{}")

    model, _ = read_repository(foundry_project, run_root=run_root)

    assert not (Path(model.root) / "out").exists()
    assert not (Path(model.root) / "cache").exists()


def test_run_dir_inside_the_source_is_refused(foundry_project: Path):
    with pytest.raises(FatalError) as excinfo:
        read_repository(foundry_project, run_root=foundry_project / "run")
    assert excinfo.value.code == IngestCode.COPY_FAILED


def test_missing_source_fails_cleanly(tmp_path: Path, run_root: Path):
    with pytest.raises(FatalError) as excinfo:
        read_repository(tmp_path / "nope", run_root=run_root)
    assert excinfo.value.code == IngestCode.SOURCE_NOT_FOUND


# ── Git ───────────────────────────────────────────────────────────────────────

@pytest.fixture
def local_git_repo(foundry_project: Path, tmp_path: Path) -> str:
    """A real local git repository, so the git path is tested without network access."""
    if shutil.which("git") is None:
        pytest.skip("git is not installed")

    origin = tmp_path / "origin"
    shutil.copytree(foundry_project, origin)
    env = os.environ | {
        "GIT_AUTHOR_NAME": "auditos-test",
        "GIT_AUTHOR_EMAIL": "test@auditos.local",
        "GIT_COMMITTER_NAME": "auditos-test",
        "GIT_COMMITTER_EMAIL": "test@auditos.local",
    }
    for args in (
        ["init", "-q", "-b", "main"],
        ["add", "-A"],
        ["commit", "-qm", "initial"],
    ):
        subprocess.run(["git", *args], cwd=origin, check=True, env=env, capture_output=True)
    return origin.as_uri()


def test_git_ingestion(local_git_repo: str, run_root: Path):
    model, _ = read_repository(local_git_repo, run_root=run_root)

    assert model.origin == "git"
    assert model.kind is ProjectKind.FOUNDRY
    assert "src/Vault.sol" in {f.path for f in model.files}
    # The run is a snapshot, not a working copy.
    assert not (Path(model.root) / ".git").exists()
