"""The Protocol Understanding endpoints (SPEC §6, §7.6)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient


def _run(client: TestClient, project: Path) -> str:
    return client.post("/audits/remote", json={"source": str(project)}).json()["run_id"]


def test_protocol_requires_a_graph_first(client: TestClient, foundry_project: Path):
    """No implicit re-run of an upstream stage: silently redoing one hides which artifact
    you are looking at."""
    run_id = _run(client, foundry_project)

    response = client.post(f"/audits/{run_id}/protocol")

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "PROTOCOL_NEEDS_GRAPH"


def test_the_full_chain_produces_a_protocol_model(client: TestClient, foundry_project: Path):
    run_id = _run(client, foundry_project)
    client.post(f"/audits/{run_id}/parse")
    client.post(f"/audits/{run_id}/graph")

    response = client.post(f"/audits/{run_id}/protocol")

    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"]
    assert body["content_hash"]
    assert body["summary"]
    assert body["code_content_hash"]


def test_enrichment_is_off_by_default(client: TestClient, foundry_project: Path):
    """A default-on enrich would silently spend an API budget and make the artifact
    non-comparable to the run before it."""
    run_id = _run(client, foundry_project)
    client.post(f"/audits/{run_id}/parse")
    client.post(f"/audits/{run_id}/graph")

    body = client.post(f"/audits/{run_id}/protocol").json()

    assert body["enrichment"]["applied"] is False


def test_the_persisted_model_is_served_back(client: TestClient, foundry_project: Path):
    run_id = _run(client, foundry_project)
    client.post(f"/audits/{run_id}/parse")
    client.post(f"/audits/{run_id}/graph")
    created = client.post(f"/audits/{run_id}/protocol").json()

    fetched = client.get(f"/audits/{run_id}/protocol").json()

    assert fetched["content_hash"] == created["content_hash"]


def test_the_summary_view_never_disagrees_with_the_model(
    client: TestClient, foundry_project: Path
):
    """Everything in it is read off the stored artifact; nothing is recomputed, so this
    view cannot drift from the model it summarizes."""
    run_id = _run(client, foundry_project)
    client.post(f"/audits/{run_id}/parse")
    client.post(f"/audits/{run_id}/graph")
    model = client.post(f"/audits/{run_id}/protocol").json()

    summary = client.get(f"/audits/{run_id}/protocol/summary").json()

    assert summary["summary"] == model["summary"]
    assert summary["counts"]["invariants"] == len(model["invariants"])
    assert summary["archetype"] == [claim["archetype"] for claim in model["archetypes"]]
    assert summary["coverage"] == model["coverage"]


def test_the_summary_is_far_smaller_than_the_model(client: TestClient, foundry_project: Path):
    """A ProtocolModel for a real repository is megabytes; a progress screen wants a dozen
    numbers."""
    import json

    run_id = _run(client, foundry_project)
    client.post(f"/audits/{run_id}/parse")
    client.post(f"/audits/{run_id}/graph")
    model = client.post(f"/audits/{run_id}/protocol").json()

    summary = client.get(f"/audits/{run_id}/protocol/summary").json()

    assert len(json.dumps(summary)) < len(json.dumps(model))


def test_protocol_before_it_is_built_is_404(client: TestClient, foundry_project: Path):
    run_id = _run(client, foundry_project)
    assert client.get(f"/audits/{run_id}/protocol").status_code == 404


def test_protocol_of_an_unknown_run_is_404(client: TestClient):
    assert client.post("/audits/nope/protocol").status_code in (404, 409)


def test_health_lists_the_protocol_stage(client: TestClient):
    assert "protocol" in client.get("/audits/health").json()["stages"]
