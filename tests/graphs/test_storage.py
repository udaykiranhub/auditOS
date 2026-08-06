"""Storage read/write edges and the pre-computed reentrancy candidates (SPEC §13.3)."""

from __future__ import annotations

from engine.core.models.graph import UNTRUSTED_EXTERNAL, EdgeKind
from tests.graphs.conftest import BUMP, DEPOSIT, PRAGMA, PROTOCOL, TOTAL, VAULT_ID, WITHDRAW


def test_writes_are_recorded_against_the_state_var(query_of):
    assert TOTAL in query_of(PROTOCOL).state_writes(BUMP)


def test_reads_and_writes_are_distinguished(query_of):
    query = query_of(PROTOCOL)
    balance = f"{VAULT_ID}#balance"
    assert balance in query.state_writes(WITHDRAW)


def test_writers_of_finds_every_mutator(query_of):
    """The query that seeds the Invariant agent."""
    writers = query_of(PROTOCOL).writers_of(TOTAL)
    assert BUMP in writers
    assert WITHDRAW in writers


def test_a_shadowed_local_is_not_a_state_access(query_of):
    """Scope-awareness, tested at the graph level because that is where it is consumed."""
    query = query_of(
        {
            "src/Shadow.sol": PRAGMA
            + """
contract Shadow {
    uint256 public total;
    function f() external pure returns (uint256) {
        uint256 total = 5;
        total = total + 1;
        return total;
    }
}
"""
        }
    )
    assert query.state_writes("src/Shadow.sol:Shadow.f()") == []


def test_emit_produces_an_event_edge(query_of):
    assert query_of(PROTOCOL).emits(WITHDRAW) == [f"{VAULT_ID}#Withdrawn"]


def test_reentrancy_candidate_is_precomputed_with_a_concrete_path(graph_of):
    """SPEC §13.2 requires this to be computed here, not left for the model to find."""
    graph = graph_of(PROTOCOL)
    candidates = [c for c in graph.reentrancy_candidates if c.function == WITHDRAW]
    assert candidates

    candidate = candidates[0]
    assert candidate.entrypoint == WITHDRAW  # externally callable, so it is its own entry
    assert candidate.external_target == UNTRUSTED_EXTERNAL
    assert f"{VAULT_ID}#balance" in candidate.writes_after
    assert candidate.confidence == "high"
    assert candidate.external_line > 0


def test_a_low_level_call_outranks_a_typed_one(graph_of):
    """`.call` reaches arbitrary code; `token.transferFrom` may well reach a trusted peer."""
    graph = graph_of(PROTOCOL)
    by_function = {c.function: c for c in graph.reentrancy_candidates}
    assert by_function[WITHDRAW].confidence == "high"
    assert by_function[DEPOSIT].confidence == "medium"


def test_a_reentrancy_guard_is_recorded_but_does_not_suppress_the_candidate(graph_of):
    """The guard may not cover the path. Reporting it is the agent's input, not a filter."""
    graph = graph_of(PROTOCOL)
    guarded = [
        c for c in graph.reentrancy_candidates if c.function == f"{VAULT_ID}.safeWithdraw(uint256)"
    ]
    assert guarded
    assert guarded[0].guard == "nonReentrant"


def test_check_effects_interactions_order_produces_no_candidate(graph_of):
    """The write happens *before* the call, which is the correct pattern."""
    graph = graph_of(
        {
            "src/Good.sol": PRAGMA
            + """
contract Good {
    mapping(address => uint256) public balance;
    function withdraw(uint256 amount) external {
        balance[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
"""
        }
    )
    assert graph.reentrancy_candidates == []


def test_candidate_paths_reach_through_an_internal_helper(graph_of):
    """The write-after-call is in an internal function; the path must name the entrypoint."""
    graph = graph_of(
        {
            "src/Indirect.sol": PRAGMA
            + """
contract Indirect {
    uint256 public total;
    function pull(uint256 a) external { _inner(a); }
    function _inner(uint256 a) internal {
        (bool ok,) = msg.sender.call{value: a}("");
        require(ok);
        total -= a;
    }
}
"""
        }
    )
    candidates = graph.reentrancy_candidates
    assert candidates
    assert candidates[0].path == [
        "src/Indirect.sol:Indirect.pull(uint256)",
        "src/Indirect.sol:Indirect._inner(uint256)",
    ]


def test_assembly_is_recorded_as_a_known_blind_spot(graph_of):
    """`sstore` in Yul is a state write with no edge behind it. Say so rather than imply
    the graph is complete."""
    graph = graph_of(
        {
            "src/Asm.sol": PRAGMA
            + """
contract Asm {
    function poke(uint256 v) external {
        assembly { sstore(0, v) }
    }
}
"""
        }
    )
    assert any(u.reason == "UNRESOLVED_ASSEMBLY_ACCESS" for u in graph.unresolved)
    assert any("inline assembly" in note for note in graph.notes)


def test_privileged_writes_are_externally_reachable_only(query_of):
    query = query_of(PROTOCOL)
    writes = query.privileged_writes()
    assert f"{VAULT_ID}.setOracle(address)" in writes
    assert f"{VAULT_ID}.unreachable()" not in writes


def test_storage_edges_carry_body_order_for_cei_analysis(graph_of):
    graph = graph_of(PROTOCOL)
    writes = [
        edge
        for edge in graph.edges
        if edge.kind is EdgeKind.WRITES and edge.source == WITHDRAW
    ]
    assert writes
    assert all(edge.order > 0 for edge in writes)
