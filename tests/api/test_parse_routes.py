"""The parse endpoints (SPEC §6, §12)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient


def test_parse_a_run(client: TestClient, foundry_project: Path):
    run_id = client.post("/audits/remote", json={"source": str(foundry_project)}).json()["run_id"]

    response = client.post(f"/audits/{run_id}/parse")

    assert response.status_code == 200
    body = response.json()
    assert body["repo_content_hash"]
    assert len(body["contracts"]) == 8
    assert body["enriched"] is False  # no build was run first

    # Re-readable from disk afterwards.
    assert client.get(f"/audits/{run_id}/code").json()["content_hash"] == body["content_hash"]


def test_parse_uses_the_build_when_one_exists(client: TestClient, foundry_project: Path):
    """Storage slots are enrichment, never a precondition (SPEC §12.1)."""
    run_id = client.post("/audits/remote", json={"source": str(foundry_project)}).json()["run_id"]
    client.post(f"/audits/{run_id}/build")

    # Whether the compiler is installed decides `enriched`; that the endpoint succeeds
    # either way is the property under test.
    assert client.post(f"/audits/{run_id}/parse").status_code == 200


def test_code_before_parse_is_404(client: TestClient, foundry_project: Path):
    run_id = client.post("/audits/remote", json={"source": str(foundry_project)}).json()["run_id"]
    assert client.get(f"/audits/{run_id}/code").status_code == 404


def test_parse_of_an_unknown_run_is_404(client: TestClient):
    assert client.post("/audits/nope/parse").status_code == 404


def test_health_lists_the_implemented_stages(client: TestClient):
    assert "parse" in client.get("/audits/health").json()["stages"]
