"""The call-resolution ladder and the two sentinels (SPEC §13.2)."""

from __future__ import annotations

from engine.core.models.graph import UNKNOWN_EXTERNAL, UNTRUSTED_EXTERNAL, EdgeKind
from tests.graphs.conftest import (
    BUMP,
    DEPOSIT,
    IERC20,
    PRAGMA,
    PROTOCOL,
    VAULT_ID,
    WITHDRAW,
)


def _edges(graph, kind: EdgeKind, source: str | None = None):
    return [
        edge
        for edge in graph.edges
        if edge.kind is kind and (source is None or edge.source == source)
    ]


def test_internal_call_resolves_within_the_contract(query_of):
    assert BUMP in query_of(PROTOCOL).callees(DEPOSIT)


def test_low_level_call_reaches_the_untrusted_sentinel(query_of):
    """SPEC §13.2: `.call` is where reentrancy and untrusted callbacks live."""
    assert UNTRUSTED_EXTERNAL in query_of(PROTOCOL).callees(WITHDRAW)


def test_delegatecall_is_its_own_edge_kind_and_is_reported_unresolved(graph_of):
    graph = graph_of(
        {
            "src/Proxy.sol": PRAGMA
            + """
contract Proxy {
    address public implementation;
    function forward(bytes calldata data) external {
        (bool ok,) = implementation.delegatecall(data);
        require(ok);
    }
}
"""
        }
    )
    edges = _edges(graph, EdgeKind.DELEGATECALLS)
    assert [edge.target for edge in edges] == [UNTRUSTED_EXTERNAL]
    # A delegatecall runs foreign code against our storage. It is never silently dropped.
    assert any(u.reason == "UNRESOLVED_DELEGATECALL" for u in graph.unresolved)


def test_staticcall_is_distinguished_from_call(graph_of):
    graph = graph_of(
        {
            "src/Reader.sol": PRAGMA
            + """
contract Reader {
    function peek(address t, bytes calldata d) external view {
        (bool ok,) = t.staticcall(d);
        require(ok);
    }
}
"""
        }
    )
    assert [e.target for e in _edges(graph, EdgeKind.STATICCALLS)] == [UNTRUSTED_EXTERNAL]


def test_typed_receiver_resolves_to_the_declared_interface(query_of):
    """`IERC20 token; token.transferFrom(...)` → the interface's function."""
    assert "src/IERC20.sol:IERC20.transferFrom(address,address,uint256)" in query_of(
        PROTOCOL
    ).callees(DEPOSIT)


def test_interface_with_no_implementer_also_reaches_the_unknown_sentinel(query_of):
    """An interface nobody implements in-repo is an external protocol: an oracle, a router."""
    assert UNKNOWN_EXTERNAL in query_of(PROTOCOL).callees(DEPOSIT)


def test_interface_call_fans_out_to_implementers(query_of):
    query = query_of(
        {
            "src/IVault.sol": PRAGMA + "interface IVault { function pull(uint256 a) external; }\n",
            "src/VaultA.sol": PRAGMA
            + 'import {IVault} from "./IVault.sol";\n'
            + "contract VaultA is IVault { function pull(uint256 a) external {} }\n",
            "src/VaultB.sol": PRAGMA
            + 'import {IVault} from "./IVault.sol";\n'
            + "contract VaultB is IVault { function pull(uint256 a) external {} }\n",
            "src/Router.sol": PRAGMA
            + 'import {IVault} from "./IVault.sol";\n'
            + """
contract Router {
    IVault public vault;
    function go(uint256 a) external { vault.pull(a); }
}
""",
        }
    )
    callees = query.callees("src/Router.sol:Router.go(uint256)")
    assert "src/VaultA.sol:VaultA.pull(uint256)" in callees
    assert "src/VaultB.sol:VaultB.pull(uint256)" in callees


def test_library_call_through_using_for(query_of):
    query = query_of(
        {
            "src/Math.sol": PRAGMA
            + "library Math { function add(uint256 a, uint256 b) internal pure returns (uint256) { return a + b; } }\n",
            "src/Calc.sol": PRAGMA
            + 'import {Math} from "./Math.sol";\n'
            + """
contract Calc {
    using Math for uint256;
    uint256 public total;
    function bump(uint256 a) external { total = Math.add(total, a); }
}
""",
        }
    )
    callees = query.callees("src/Calc.sol:Calc.bump(uint256)")
    assert "src/Math.sol:Math.add(uint256,uint256)" in callees


def test_untypeable_receiver_reaches_unknown_external(query_of):
    query = query_of(
        {
            "src/Loose.sol": PRAGMA
            + """
interface IThing { function ping() external; }
contract Loose {
    function go(address a) external { IThing(a).ping(); }
}
"""
        }
    )
    callees = query.callees("src/Loose.sol:Loose.go(address)")
    # The cast names the interface, so the declared signature resolves…
    assert "src/Loose.sol:IThing.ping()" in callees


def test_new_contract_is_a_creates_edge(graph_of):
    graph = graph_of(
        {
            "src/Factory.sol": PRAGMA
            + """
contract Child { uint256 public x; }
contract Factory {
    function spawn() external returns (Child) { return new Child(); }
}
"""
        }
    )
    edges = _edges(graph, EdgeKind.CREATES)
    assert [edge.target for edge in edges] == ["src/Factory.sol:Child"]


def test_builtins_produce_no_edge(query_of):
    """`require`, `keccak256` and friends are not calls into the protocol."""
    assert "require" not in " ".join(query_of(PROTOCOL).callees(WITHDRAW))


def test_overloads_are_disambiguated_by_arity(query_of):
    query = query_of(
        {
            "src/Over.sol": PRAGMA
            + """
contract Over {
    uint256 public x;
    function set(uint256 a) internal { x = a; }
    function set(uint256 a, uint256 b) internal { x = a + b; }
    function run() external { set(1, 2); }
}
"""
        }
    )
    callees = query.callees("src/Over.sol:Over.run()")
    assert "src/Over.sol:Over.set(uint256,uint256)" in callees
    assert "src/Over.sol:Over.set(uint256)" not in callees


def test_address_transfer_is_a_value_send_to_untrusted_code(graph_of):
    """`payable(x).transfer(v)` takes one argument and reaches an arbitrary `receive`.

    ERC-20 `transfer(to, amount)` takes two and does not. Confusing them either floods the
    untrusted sentinel with token calls or hides every ETH send — both wreck the analysis.
    """
    graph = graph_of(
        {
            "src/Payer.sol": PRAGMA
            + """
contract Payer {
    function pay(address payable to, uint256 v) external { to.transfer(v); }
}
"""
        }
    )
    calls = _edges(graph, EdgeKind.CALLS, "src/Payer.sol:Payer.pay(address,uint256)")
    assert [edge.target for edge in calls] == [UNTRUSTED_EXTERNAL]
    assert not _edges(graph, EdgeKind.TRANSFERS)


def test_modifier_produces_a_permission_edge(query_of):
    assert query_of(PROTOCOL).permissions(f"{VAULT_ID}.setOracle(address)") == [
        "src/Ownable.sol:Ownable.onlyOwner"
    ]


def test_every_edge_carries_its_source_location(graph_of):
    graph = graph_of(PROTOCOL)
    call_edges = [edge for edge in graph.edges if edge.kind is EdgeKind.CALLS]
    assert call_edges
    assert all(edge.line > 0 and edge.text for edge in call_edges)


def test_token_and_call_edges_coexist_for_one_call_site(graph_of):
    """`token.transferFrom(...)` is both a call edge and a token-flow edge."""
    graph = graph_of({**PROTOCOL, "src/IERC20.sol": IERC20})
    transfers = _edges(graph, EdgeKind.TRANSFERS_FROM, DEPOSIT)
    assert [edge.target for edge in transfers] == [f"{VAULT_ID}#token"]
    assert transfers[0].confidence == "high"
