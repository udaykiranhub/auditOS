"""Assembly, determinism, scope selection and validation of the finished artifact."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.core.artifacts import create_run_dir
from engine.core.errors import FatalError
from engine.core.models.graph import SENTINELS, Edge, EdgeKind, GraphModel, Node, NodeKind
from engine.graphs import build_and_save, build_graph
from engine.graphs.select import MAX_INTERFACE_FANOUT
from engine.graphs.validate import GraphCode, validate
from engine.ingest.reader import read_repository
from engine.parse.pipeline import parse_repository
from tests.graphs.conftest import IERC20, OWNABLE, PRAGMA, PROTOCOL, VAULT, VAULT_ID

# ── Determinism (SPEC §7.1, §9.4) ─────────────────────────────────────────────


def test_the_same_repository_produces_the_same_graph(tmp_path: Path):
    from tests.graphs.conftest import build_from_sources

    first = build_from_sources(tmp_path, PROTOCOL, name="one")
    second = build_from_sources(tmp_path, PROTOCOL, name="two")
    assert first.content_hash == second.content_hash


def test_the_serialized_artifact_is_byte_identical(tmp_path: Path):
    from tests.graphs.conftest import build_from_sources

    first = build_from_sources(tmp_path, PROTOCOL, name="one")
    second = build_from_sources(tmp_path, PROTOCOL, name="two")
    assert json.dumps(first.hash_payload(), sort_keys=True) == json.dumps(
        second.hash_payload(), sort_keys=True
    )


def test_content_hash_changes_when_the_code_changes(tmp_path: Path):
    from tests.graphs.conftest import build_from_sources

    first = build_from_sources(tmp_path, PROTOCOL, name="one")
    changed = dict(PROTOCOL)
    changed["src/Vault.sol"] = VAULT.replace("total -= amount;", "total -= amount * 2;")
    second = build_from_sources(tmp_path, changed, name="two")
    assert first.content_hash != second.content_hash


def test_nodes_and_edges_are_stored_in_canonical_order(graph_of):
    graph = graph_of(PROTOCOL)
    assert [node.id for node in graph.nodes] == sorted(node.id for node in graph.nodes)
    assert [edge.key() for edge in graph.edges] == sorted(edge.key() for edge in graph.edges)


# ── Persistence ───────────────────────────────────────────────────────────────


def test_build_and_save_writes_the_artifact(tmp_path: Path, run_root: Path):
    root = tmp_path / "protocol"
    for rel, text in PROTOCOL.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    repo, run_dir = read_repository(root, run_root=run_root)
    graph, artifact = build_and_save(parse_repository(repo), run_dir)

    assert artifact.name == "graph.json"
    reloaded = GraphModel.model_validate_json(artifact.read_text(encoding="utf-8"))
    assert reloaded.content_hash == graph.content_hash


def test_the_graph_records_the_code_it_was_built_from(tmp_path: Path, run_root: Path):
    """The artifact spine: a `GraphModel` states which `CodeModel` produced it."""
    root = tmp_path / "protocol"
    for rel, text in PROTOCOL.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    repo, _ = read_repository(root, run_root=run_root)
    code = parse_repository(repo)
    assert build_graph(code).code_content_hash == code.content_hash


# ── Scope selection ───────────────────────────────────────────────────────────


def test_dependencies_outside_the_closure_are_not_graphed(graph_of):
    """A vendored library nobody touches is noise; SPEC says filter before graphing."""
    graph = graph_of(
        {
            **PROTOCOL,
            "lib/unused/Huge.sol": PRAGMA + "contract Huge { uint256 public x; }\n",
        }
    )
    assert graph.node("lib/unused/Huge.sol:Huge") is None
    assert any("of" in note and "contracts" in note for note in graph.notes)


def test_a_dependency_parent_is_pulled_in(graph_of):
    graph = graph_of(
        {
            "src/Vault.sol": PRAGMA
            + 'import {Ownable} from "../lib/oz/Ownable.sol";\n'
            + "contract Vault is Ownable { uint256 public x; }\n",
            "lib/oz/Ownable.sol": OWNABLE,
        }
    )
    assert graph.node("lib/oz/Ownable.sol:Ownable") is not None


def test_a_type_referenced_by_a_state_var_is_pulled_in(graph_of):
    graph = graph_of(
        {
            "src/Vault.sol": PRAGMA
            + 'import {IERC20} from "../lib/oz/IERC20.sol";\n'
            + "contract Vault { IERC20 public token; }\n",
            "lib/oz/IERC20.sol": IERC20,
        }
    )
    assert graph.node("lib/oz/IERC20.sol:IERC20") is not None


def test_interface_fanout_is_capped_and_the_cap_is_reported(graph_of):
    sources = {
        "src/IThing.sol": PRAGMA + "interface IThing { function ping() external; }\n",
        "src/User.sol": PRAGMA
        + 'import {IThing} from "./IThing.sol";\n'
        + "contract User { IThing public thing; function go() external { thing.ping(); } }\n",
    }
    for index in range(MAX_INTERFACE_FANOUT + 5):
        sources[f"lib/impl/Impl{index:02d}.sol"] = (
            PRAGMA
            + 'import {IThing} from "../../src/IThing.sol";\n'
            + f"contract Impl{index:02d} is IThing {{ function ping() external {{}} }}\n"
        )

    graph = graph_of(sources)
    assert any(u.reason == "INTERFACE_FANOUT_CAPPED" for u in graph.unresolved)


def test_an_empty_scope_graphs_everything_rather_than_nothing(graph_of):
    """The Reader already warns; an empty graph would be a worse answer than a wide one."""
    graph = graph_of({"test/Only.t.sol": PRAGMA + "contract OnlyTest { uint256 public x; }\n"})
    assert graph.node("test/Only.t.sol:OnlyTest") is not None
    assert any("no contract is in scope" in note for note in graph.notes)


# ── Sentinels and structure ───────────────────────────────────────────────────


def test_both_sentinels_always_exist(graph_of):
    graph = graph_of(PROTOCOL)
    for sentinel in SENTINELS:
        node = graph.node(sentinel)
        assert node is not None
        assert node.kind is NodeKind.SENTINEL


def test_containment_links_file_to_contract_to_member(query_of):
    query = query_of(PROTOCOL)
    contains = [
        edge.target
        for edge in query.graph.edges
        if edge.kind is EdgeKind.CONTAINS and edge.source == VAULT_ID
    ]
    assert f"{VAULT_ID}#total" in contains
    assert f"{VAULT_ID}.deposit(uint256)" in contains


def test_import_cycles_are_reported_not_raised(graph_of):
    """Legal in Solidity. Reporting is the contract; raising would reject real protocols."""
    graph = graph_of(
        {
            "src/A.sol": PRAGMA + 'import "./B.sol";\ncontract A { uint256 public x; }\n',
            "src/B.sol": PRAGMA + 'import "./A.sol";\ncontract B { uint256 public y; }\n',
        }
    )
    assert graph.import_cycles == [["src/A.sol", "src/B.sol"]]


def test_free_functions_are_graphed(query_of):
    query = query_of(
        {
            "src/Free.sol": PRAGMA
            + """
function double(uint256 a) pure returns (uint256) { return a * 2; }
contract User {
    uint256 public x;
    function go(uint256 a) external { x = double(a); }
}
"""
        }
    )
    assert "src/Free.sol:double(uint256)" in query.callees("src/Free.sol:User.go(uint256)")


# ── Validator ─────────────────────────────────────────────────────────────────


def _minimal() -> GraphModel:
    return GraphModel(
        nodes=[
            Node(id="a:A", kind=NodeKind.CONTRACT, name="A"),
            Node(id="a:A.f()", kind=NodeKind.FUNCTION, name="f", contract_id="a:A"),
        ],
        edges=[Edge(source="a:A", target="a:A.f()", kind=EdgeKind.CONTAINS)],
    )


def test_a_dangling_edge_is_fatal():
    graph = _minimal()
    graph.edges.append(Edge(source="a:A", target="a:Missing", kind=EdgeKind.CALLS))
    with pytest.raises(FatalError) as exc:
        validate(graph)
    assert exc.value.code == GraphCode.DANGLING_EDGE


def test_a_duplicate_node_id_is_fatal():
    graph = _minimal()
    graph.nodes.append(Node(id="a:A", kind=NodeKind.CONTRACT, name="A"))
    with pytest.raises(FatalError) as exc:
        validate(graph)
    assert exc.value.code == GraphCode.DUPLICATE_NODE


def test_unsorted_nodes_are_fatal_because_the_artifact_must_reproduce():
    graph = _minimal()
    graph.nodes.reverse()
    with pytest.raises(FatalError) as exc:
        validate(graph)
    assert exc.value.code == GraphCode.UNSORTED


def test_an_uncalled_library_is_not_an_error(graph_of):
    """"No orphan nodes" would fail on every real repository. Orphans are legitimate."""
    graph = graph_of(
        {
            **PROTOCOL,
            "src/Unused.sol": PRAGMA
            + "library Unused { function noop() internal pure {} }\n",
        }
    )
    assert graph.node("src/Unused.sol:Unused") is not None


def test_an_empty_code_model_is_fatal(tmp_path: Path, run_root: Path):
    from engine.core.models.code import CodeModel

    with pytest.raises(FatalError) as exc:
        build_graph(CodeModel())
    assert exc.value.code == GraphCode.NO_CODE


def test_counts_cover_nodes_edges_and_candidates(graph_of):
    counts = graph_of(PROTOCOL).counts
    assert counts["nodes"] > 0
    assert counts["edges"] > 0
    assert counts["reentrancy_candidates"] >= 1


def test_a_run_dir_can_be_created_without_a_repo(run_root: Path):
    """Guards the artifact path convention the API depends on."""
    run_dir = create_run_dir(run_root)
    assert (run_dir / "artifacts").exists()
