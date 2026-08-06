"""C3 linearization and the inheritance graph (SPEC §13.1).

SPEC: *"Golden-test the call graph against a fixture with a deliberately nasty
diamond-inheritance case."* That fixture is `DIAMOND` below — the classic C3 case, in
Solidity's base ordering, where a naive depth-first walk resolves `who()` to the wrong
implementation and every override chain built on it is silently wrong.
"""

from __future__ import annotations

import pytest

from engine.core.models.code import Contract, ContractKind
from engine.graphs.inheritance import Linearizer, _merge
from tests.graphs.conftest import IERC20, OWNABLE, PRAGMA, PROTOCOL, VAULT_ID

DIAMOND = {
    "src/Diamond.sol": PRAGMA
    + """
contract A { function who() public virtual returns (string memory) { return "A"; } }
contract B is A { function who() public virtual override returns (string memory) { return "B"; } }
contract C is A { function who() public virtual override returns (string memory) { return "C"; } }
contract D is B, C {
    function who() public override(B, C) returns (string memory) { return super.who(); }
}
"""
}


def _fake(contract_id: str, parents: list[str]) -> Contract:
    path, _, name = contract_id.rpartition(":")
    return Contract(
        id=contract_id, name=name, path=path, kind=ContractKind.CONTRACT, inherits_ids=parents
    )


def test_c3_orders_a_diamond_the_way_solidity_does(graph_of):
    """`contract D is B, C` linearizes to D, C, B, A — bases reversed, then C3."""
    graph = graph_of(DIAMOND)
    assert graph.linearization["src/Diamond.sol:D"] == [
        "src/Diamond.sol:D",
        "src/Diamond.sol:C",
        "src/Diamond.sol:B",
        "src/Diamond.sol:A",
    ]


def test_super_resolves_through_the_mro_not_the_first_parent(query_of):
    """`super.who()` in D must reach C, not B — the whole reason C3 exists."""
    query = query_of(DIAMOND)
    callees = query.callees("src/Diamond.sol:D.who()")
    assert "src/Diamond.sol:C.who()" in callees
    assert "src/Diamond.sol:B.who()" not in callees


def test_override_chain_is_recorded_in_mro_order(graph_of):
    graph = graph_of(DIAMOND)
    assert graph.override_chains["src/Diamond.sol:D.who()"] == [
        "src/Diamond.sol:C.who()",
        "src/Diamond.sol:B.who()",
        "src/Diamond.sol:A.who()",
    ]


def test_linearization_always_starts_with_the_contract_itself(graph_of):
    graph = graph_of(PROTOCOL)
    for contract_id, mro in graph.linearization.items():
        assert mro[0] == contract_id


def test_inherited_members_resolve_through_the_flattened_scope(query_of):
    """`onlyOwner` is declared on Ownable and used on Vault."""
    query = query_of(PROTOCOL)
    assert query.permissions(f"{VAULT_ID}.setOracle(address)") == [
        "src/Ownable.sol:Ownable.onlyOwner"
    ]


def test_interface_inheritance_is_an_implements_edge(graph_of):
    graph = graph_of(
        {
            "src/IERC20.sol": IERC20,
            "src/Token.sol": PRAGMA
            + """
import {IERC20} from "./IERC20.sol";
contract Token is IERC20 {
    function transfer(address to, uint256 a) external returns (bool) { return true; }
    function transferFrom(address f, address t, uint256 a) external returns (bool) { return true; }
}
""",
        }
    )
    kinds = {
        (edge.source, edge.target): edge.kind.value
        for edge in graph.edges
        if edge.source == "src/Token.sol:Token"
    }
    assert kinds[("src/Token.sol:Token", "src/IERC20.sol:IERC20")] == "implements"


def test_inheritance_cycle_is_reported_not_hung(graph_of):
    """Illegal in Solidity, producible by a partial parse. Must terminate."""
    linearizer = Linearizer(
        {
            "a:A": _fake("a:A", ["b:B"]),
            "b:B": _fake("b:B", ["a:A"]),
        }
    )
    mro = linearizer.linearize("a:A")
    assert mro[0] == "a:A"
    assert any(u.reason == "AMBIGUOUS_LINEARIZATION" for u in linearizer.unresolved)


def test_unresolvable_linearization_degrades_instead_of_raising():
    """`_merge` returns None when no consistent order exists; the caller must cope."""
    assert _merge([["X", "Y"], ["Y", "X"], ["X", "Y"]]) is None


def test_missing_parent_is_recorded_as_unresolved(graph_of):
    graph = graph_of(
        {
            "src/Orphan.sol": PRAGMA
            + "contract Orphan is SomethingNotInThisRepo { uint256 public x; }\n"
        }
    )
    reasons = {u.reason for u in graph.unresolved}
    assert "UNRESOLVED_PARENT" in reasons


@pytest.mark.parametrize(
    ("sequences", "expected"),
    [
        ([["A"]], ["A"]),
        ([["B", "A"], ["C", "A"], ["B", "C"]], ["B", "C", "A"]),
        ([[], ["A"]], ["A"]),
    ],
)
def test_merge_cases(sequences, expected):
    assert _merge(sequences) == expected


def test_contracts_pulled_in_only_as_parents_are_still_graphed(graph_of):
    """A dependency parent must be in the graph or its members vanish from resolution."""
    graph = graph_of(
        {
            "src/Vault.sol": PRAGMA
            + 'import {Ownable} from "../lib/oz/Ownable.sol";\n'
            + "contract Vault is Ownable { function f() external onlyOwner {} }\n",
            "lib/oz/Ownable.sol": OWNABLE,
        }
    )
    assert graph.node("lib/oz/Ownable.sol:Ownable") is not None
