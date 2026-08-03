"""The Phase 1 API slice (`engine/api/routes.py`).

The multipart-limit test is a regression guard: Starlette caps uploads at 1000 files by
default, and a real protocol folder is well past that. The cap trips mid-stream, so the
browser sees a dropped connection rather than a status code — a failure mode that is
extremely hard to read from the client side.
"""

from __future__ import annotations

import io
import time
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
    assert "build" in client.get("/audits/health").json()["stages"]


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


# ── Build (SPEC §10) ──────────────────────────────────────────────────────────

def await_build(client: TestClient, run_id: str, timeout: float = 300.0) -> dict:
    """Start a build and poll it, the way the frontend does.

    The build runs on a worker thread and the request returns 202 immediately: compiling a
    real protocol takes minutes, which is longer than any sensible HTTP timeout.
    """
    started = client.post(f"/audits/{run_id}/build")
    assert started.status_code == 202
    assert started.json()["state"] == "running"

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = client.get(f"/audits/{run_id}/build/status").json()
        if status["state"] == "done":
            return status["model"]
        assert status["state"] != "error", status["error"]
        time.sleep(0.2)
    raise AssertionError(f"build did not finish within {timeout}s")


def test_build_a_run(client: TestClient, foundry_project: Path):
    run_id = client.post("/audits/remote", json={"source": str(foundry_project)}).json()["run_id"]

    body = await_build(client, run_id)

    assert body["repo_content_hash"]
    assert body["status"] in {"success", "partial", "failed", "skipped"}
    # Re-readable from disk afterwards.
    assert client.get(f"/audits/{run_id}/build").json()["content_hash"] == body["content_hash"]


def test_build_status_reports_elapsed_time(client: TestClient, foundry_project: Path):
    run_id = client.post("/audits/remote", json={"source": str(foundry_project)}).json()["run_id"]
    await_build(client, run_id)

    status = client.get(f"/audits/{run_id}/build/status").json()
    assert status["state"] == "done"
    assert status["elapsed_seconds"] >= 0


def test_polling_a_build_that_was_never_started_is_404(client: TestClient, foundry_project: Path):
    run_id = client.post("/audits/remote", json={"source": str(foundry_project)}).json()["run_id"]
    assert client.get(f"/audits/{run_id}/build/status").status_code == 404


def test_a_failed_build_is_a_200_not_an_error(client: TestClient, tmp_path: Path):
    """Losing the storage layout must not cost the audit — degraded, never fatal (§10.2)."""
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "Broken.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract B {\n  function f() external {\n", encoding="utf-8"
    )

    run_id = client.post("/audits/remote", json={"source": str(broken)}).json()["run_id"]
    body = await_build(client, run_id)

    assert body["build_available"] is False
    assert body["status"] in {"failed", "skipped"}


def test_build_of_an_unknown_run_is_404(client: TestClient):
    assert client.post("/audits/nope/build").status_code == 404


def test_build_before_it_has_run_is_404(client: TestClient, foundry_project: Path):
    run_id = client.post("/audits/remote", json={"source": str(foundry_project)}).json()["run_id"]
    assert client.get(f"/audits/{run_id}/build").status_code == 404


def test_ast_endpoint_refuses_traversal(client: TestClient, foundry_project: Path):
    run_id = client.post("/audits/remote", json={"source": str(foundry_project)}).json()["run_id"]
    client.post(f"/audits/{run_id}/build")

    assert client.get(f"/audits/{run_id}/ast", params={"path": "../artifacts/repo.json"}).status_code == 404
    assert client.get(f"/audits/{run_id}/ast", params={"path": "build/ast/nope.json"}).status_code == 404
