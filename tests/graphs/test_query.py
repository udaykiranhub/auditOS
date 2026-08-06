"""The query API (SPEC §13.5) — what the Context Builder will actually call."""

from __future__ import annotations

import pytest

from engine.core.models.graph import UNTRUSTED_EXTERNAL
from engine.graphs.views import VIEWS
from tests.graphs.conftest import BUMP, DEPOSIT, PRAGMA, PROTOCOL, TOTAL, VAULT_ID, WITHDRAW

CHAIN = {
    "src/Chain.sol": PRAGMA
    + """
contract Chain {
    uint256 public total;
    function entry(uint256 a) external { _one(a); }
    function alsoEntry(uint256 a) public { _one(a); }
    function _one(uint256 a) internal { _two(a); }
    function _two(uint256 a) internal { total += a; }
    function orphan() private { total = 0; }
}
"""
}
TWO = "src/Chain.sol:Chain._two(uint256)"


def test_reaching_entrypoints_finds_every_way_in(query_of):
    """SPEC: get this one right first — it cuts more context noise than any compression."""
    assert query_of(CHAIN).reaching_entrypoints(TWO) == [
        "src/Chain.sol:Chain.alsoEntry(uint256)",
        "src/Chain.sol:Chain.entry(uint256)",
    ]


def test_an_unreachable_function_has_no_entrypoints(query_of):
    """Empty means "no attacker path exists" — the signal to down-rank hard."""
    assert query_of(CHAIN).reaching_entrypoints("src/Chain.sol:Chain.orphan()") == []


def test_an_entrypoint_reaches_itself(query_of):
    entry = "src/Chain.sol:Chain.entry(uint256)"
    assert query_of(CHAIN).reaching_entrypoints(entry) == [entry]


def test_entrypoint_paths_are_concrete_and_shortest_first(query_of):
    paths = query_of(CHAIN).entrypoint_paths(TWO)
    assert paths
    assert all(path[-1] == TWO for path in paths)
    assert paths == sorted(paths, key=lambda p: (len(p), p))
    assert [len(path) for path in paths] == sorted(len(path) for path in paths)


def test_entrypoint_paths_terminate_on_a_recursive_call(query_of):
    """A cycle must bound the search, not hang it."""
    query = query_of(
        {
            "src/Loop.sol": PRAGMA
            + """
contract Loop {
    function entry() external { _a(); }
    function _a() internal { _b(); }
    function _b() internal { _a(); }
}
"""
        }
    )
    paths = query.entrypoint_paths("src/Loop.sol:Loop._b()")
    assert paths
    assert all(len(set(path)) == len(path) for path in paths)


def test_neighborhood_is_bounded_by_depth(query_of):
    query = query_of(CHAIN)
    near = query.neighborhood("src/Chain.sol:Chain._one(uint256)", depth=1)
    assert TWO in near
    assert "src/Chain.sol:Chain.entry(uint256)" in near
    assert "src/Chain.sol:Chain.orphan()" not in near


def test_neighborhood_never_returns_a_sentinel(query_of):
    """A sentinel is a marker, not a function; handing one to the Context Builder as a
    neighbour to slice would produce an empty code excerpt."""
    assert UNTRUSTED_EXTERNAL not in query_of(PROTOCOL).neighborhood(WITHDRAW, depth=3)


def test_callers_and_callees_are_inverses(query_of):
    query = query_of(PROTOCOL)
    assert BUMP in query.callees(DEPOSIT)
    assert DEPOSIT in query.callers(BUMP)


def test_external_call_paths_returns_only_edges_leaving_the_repo(query_of):
    edges = query_of(PROTOCOL).external_call_paths(WITHDRAW)
    assert edges
    assert all(edge.target.startswith("@") for edge in edges)


def test_program_slice_names_what_must_be_read(query_of):
    slice_ = query_of(PROTOCOL).program_slice(BUMP)
    assert DEPOSIT in slice_["functions"]
    assert TOTAL in slice_["state_vars"]
    assert DEPOSIT in slice_["entrypoints"]


def test_variable_dependencies_are_labelled_as_coupling_not_dataflow(query_of):
    """`total` and `balance` are written by the same functions, so they move together."""
    deps = query_of(PROTOCOL).variable_dependencies(TOTAL)
    assert f"{VAULT_ID}#balance" in deps
    assert TOTAL not in deps


def test_centrality_ranks_the_core_contract_first(query_of):
    ranked = list(query_of(PROTOCOL).contract_centrality())
    assert ranked[0] == VAULT_ID


def test_centrality_is_reproducible(query_of):
    query = query_of(PROTOCOL)
    assert query.centrality() == query.centrality()


def test_centrality_on_an_edgeless_graph_is_empty(query_of):
    query = query_of({"src/Lonely.sol": PRAGMA + "contract Lonely { uint256 public x; }\n"})
    assert query.centrality() == {}


@pytest.mark.parametrize("name", sorted(VIEWS))
def test_every_view_projects_only_its_own_edge_kinds(name, query_of):
    query = query_of(PROTOCOL)
    assert all(edge.kind in VIEWS[name] for edge in query.view(name))


def test_views_never_duplicate_the_edge_list(query_of, graph_of):
    """A view is a projection. Every edge it yields must be an edge of the one graph."""
    graph = graph_of(PROTOCOL)
    from engine.graphs.query import GraphQuery

    query = GraphQuery(graph)
    known = {edge.key() for edge in graph.edges}
    for name in VIEWS:
        assert all(edge.key() in known for edge in query.view(name))


def test_unknown_view_raises_rather_than_returning_nothing(query_of):
    with pytest.raises(KeyError, match="unknown view"):
        query_of(PROTOCOL).view("control_flow")


def test_view_summaries_in_the_artifact_match_the_projection(graph_of):
    from engine.graphs.query import GraphQuery

    graph = graph_of(PROTOCOL)
    query = GraphQuery(graph)
    for name, summary in graph.views.items():
        assert summary.edges == len(query.view(name))


def test_to_networkx_round_trips_every_node_and_edge(graph_of):
    """SPEC mandates NetworkX; this is the handoff to it."""
    graph = graph_of(PROTOCOL)
    from engine.graphs.query import GraphQuery

    digraph = GraphQuery(graph).to_networkx()
    assert digraph.number_of_nodes() == len(graph.nodes)
    assert digraph.number_of_edges() == len(graph.edges)
