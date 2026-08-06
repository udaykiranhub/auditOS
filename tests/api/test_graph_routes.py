"""The graph endpoints (SPEC §6, §13)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def graphed(client: TestClient, foundry_project: Path) -> str:
    run_id = client.post("/audits/remote", json={"source": str(foundry_project)}).json()["run_id"]
    client.post(f"/audits/{run_id}/parse")
    assert client.post(f"/audits/{run_id}/graph").status_code == 200
    return run_id


def test_build_the_graph(client: TestClient, graphed: str):
    body = client.get(f"/audits/{graphed}/graph").json()
    assert body["nodes"]
    assert body["edges"]
    assert body["code_content_hash"]
    assert set(body["views"]) >= {"call", "storage", "inheritance", "permission"}


def test_graph_before_parse_is_a_conflict_not_a_silent_reparse(
    client: TestClient, foundry_project: Path
):
    """Redoing an expensive stage implicitly hides which artifact you are looking at."""
    run_id = client.post("/audits/remote", json={"source": str(foundry_project)}).json()["run_id"]
    response = client.post(f"/audits/{run_id}/graph")
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "GRAPH_NEEDS_PARSE"


def test_graph_of_an_unknown_run_is_404(client: TestClient):
    assert client.get("/audits/nope/graph").status_code == 404


def test_the_graph_is_reproducible_across_requests(client: TestClient, graphed: str):
    first = client.post(f"/audits/{graphed}/graph").json()["content_hash"]
    second = client.post(f"/audits/{graphed}/graph").json()["content_hash"]
    assert first == second


@pytest.mark.parametrize(
    "query",
    [
        "entrypoints",
        "privileged_writes",
        "privileged_variables",
        "external_calls",
        "delegatecall_targets",
        "reentrancy_candidates",
        "centrality",
    ],
)
def test_targetless_queries_answer(client: TestClient, graphed: str, query: str):
    response = client.get(f"/audits/{graphed}/graph/query", params={"q": query})
    assert response.status_code == 200
    assert response.json()["query"] == query


def test_a_targeted_query_answers_about_that_node(client: TestClient, graphed: str):
    target = "src/Vault.sol:Vault.withdraw(uint256)"
    response = client.get(
        f"/audits/{graphed}/graph/query",
        params={"q": "external_call_paths", "target": target},
    )
    assert response.status_code == 200
    result = response.json()["result"]
    assert result
    assert result[0]["target"] == "@UNTRUSTED_EXTERNAL"


def test_reaching_entrypoints_is_reachable_over_http(client: TestClient, graphed: str):
    response = client.get(
        f"/audits/{graphed}/graph/query",
        params={"q": "reaching_entrypoints", "target": "src/Vault.sol:Vault.withdraw(uint256)"},
    )
    assert response.json()["result"] == ["src/Vault.sol:Vault.withdraw(uint256)"]


def test_an_unknown_query_names_the_known_ones(client: TestClient, graphed: str):
    response = client.get(f"/audits/{graphed}/graph/query", params={"q": "taint_paths"})
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["code"] == "GRAPH_UNKNOWN_QUERY"
    assert "reaching_entrypoints" in detail["hint"]


def test_an_unknown_view_is_a_clean_400(client: TestClient, graphed: str):
    response = client.get(
        f"/audits/{graphed}/graph/query", params={"q": "view", "target": "control_flow"}
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "GRAPH_BAD_TARGET"


def test_query_before_graph_is_404(client: TestClient, foundry_project: Path):
    run_id = client.post("/audits/remote", json={"source": str(foundry_project)}).json()["run_id"]
    assert client.get(f"/audits/{run_id}/graph/query", params={"q": "entrypoints"}).status_code == 404


def test_health_lists_the_graph_stage(client: TestClient):
    assert "graph" in client.get("/audits/health").json()["stages"]
