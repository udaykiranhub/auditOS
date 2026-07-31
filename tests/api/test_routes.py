"""The Phase 1 API slice (`engine/api/routes.py`).

The multipart-limit test is a regression guard: Starlette caps uploads at 1000 files by
default, and a real protocol folder is well past that. The cap trips mid-stream, so the
browser sees a dropped connection rather than a status code — a failure mode that is
extremely hard to read from the client side.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from engine.api.routes import app
from tests.conftest import FOUNDRY_TOML, VAULT_SOL


@pytest.fixture
def client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.setenv("AUDITOS_RUN_DIR", str(tmp_path / "run"))
    return TestClient(app)


def test_health(client: TestClient):
    assert client.get("/audits/health").json()["stage"] == "repository-reader"


# ── Upload ────────────────────────────────────────────────────────────────────

def test_upload_zip(client: TestClient, foundry_project: Path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path in sorted(foundry_project.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(foundry_project).as_posix())
    buffer.seek(0)

    response = client.post(
        "/audits/upload",
        files=[("files", ("protocol.zip", buffer, "application/zip"))],
        data={"include": "", "exclude": ""},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["repo"]["origin"] == "zip"
    assert body["repo"]["kind"] == "FOUNDRY"
    assert body["counts"]["in_scope"] == 3


def test_upload_folder_preserves_relative_paths(client: TestClient):
    """The dropped folder's own name is stripped; everything below it is repo-relative."""
    response = client.post(
        "/audits/upload",
        files=[
            ("files", ("protocol/foundry.toml", FOUNDRY_TOML, "text/plain")),
            ("files", ("protocol/src/Vault.sol", VAULT_SOL, "text/plain")),
            ("files", ("protocol/test/Vault.t.sol", "contract T {}", "text/plain")),
        ],
        data={"include": "", "exclude": ""},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["repo"]["origin"] == "folder"
    assert [f["path"] for f in body["repo"]["files"]] == ["src/Vault.sol", "test/Vault.t.sol"]
    assert body["counts"]["in_scope"] == 1


def test_upload_accepts_more_than_starlettes_default_1000_files(client: TestClient):
    """A real protocol folder is thousands of files; the default cap must not apply."""
    files = [("files", ("protocol/foundry.toml", FOUNDRY_TOML, "text/plain"))]
    files += [
        ("files", (f"protocol/src/C{index}.sol", f"contract C{index} {{}}", "text/plain"))
        for index in range(1200)
    ]

    response = client.post("/audits/upload", files=files, data={"include": "", "exclude": ""})

    assert response.status_code == 200
    assert response.json()["counts"]["total"] == 1200


def test_upload_traversal_entry_is_dropped(client: TestClient):
    response = client.post(
        "/audits/upload",
        files=[
            ("files", ("protocol/src/Vault.sol", VAULT_SOL, "text/plain")),
            ("files", ("../../escaped.sol", "contract E {}", "text/plain")),
        ],
        data={"include": "", "exclude": ""},
    )

    assert response.status_code == 200
    assert [f["path"] for f in response.json()["repo"]["files"]] == ["src/Vault.sol"]


def test_upload_without_files_is_a_clean_400(client: TestClient):
    response = client.post("/audits/upload", data={"include": "", "exclude": ""})
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "UPLOAD_EMPTY"


# ── Remote ────────────────────────────────────────────────────────────────────

def test_remote_local_path(client: TestClient, foundry_project: Path):
    response = client.post("/audits/remote", json={"source": str(foundry_project)})

    assert response.status_code == 200
    body = response.json()
    assert body["repo"]["origin"] == "folder"
    assert body["counts"]["total"] == 8


def test_remote_scope_override(client: TestClient, foundry_project: Path):
    response = client.post(
        "/audits/remote",
        json={"source": str(foundry_project), "exclude": ["src/ERC20.sol"]},
    )
    assert response.json()["counts"]["in_scope"] == 2


def test_fatal_error_is_clean_json_not_a_traceback(client: TestClient, empty_project: Path):
    response = client.post("/audits/remote", json={"source": str(empty_project)})

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["code"] == "INGEST_NO_SOLIDITY_FILES"
    assert detail["hint"]


# ── Re-read ───────────────────────────────────────────────────────────────────

def test_get_repo_by_run_id(client: TestClient, foundry_project: Path):
    run_id = client.post("/audits/remote", json={"source": str(foundry_project)}).json()["run_id"]

    response = client.get(f"/audits/{run_id}/repo")

    assert response.status_code == 200
    assert response.json()["kind"] == "FOUNDRY"


def test_get_repo_unknown_run_id(client: TestClient):
    assert client.get("/audits/nope/repo").status_code == 404
