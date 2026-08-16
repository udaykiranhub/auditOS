"""Assembling the semantic graph from the solc AST.

Built against `SimpleLending` — the protocol the design discussion used, and deliberately
the shape that defeated the earlier passes: its collateral is called `deposits`, which
infers as `user_balance` rather than `collateral_record`, so no role-pair table pairs it
with `debt`. The guard does.

`solc` is not run here. The AST fragments are assembled to the shape real compiler output
has, so the suite stays runnable without a toolchain while still exercising the reader
against what it will actually meet.
"""

from __future__ import annotations

from typing import Any

import pytest

from engine.core.models.code import CodeModel, Contract, ContractKind, Function
from engine.core.models.semantic import EdgeKind, Fidelity, NodeKind
from engine.protocol.semantic import build as semantic
from engine.protocol.semantic.solc_ast import AstIndex, SourceAst

PATH = "src/SimpleLending.sol"

# Declaration ids, as solc would assign them.
DEPOSITS, DEBT, TOTAL_DEPOSITS = 101, 102, 103
BORROW, WITHDRAW, DEPOSIT = 201, 202, 203
AMOUNT = 301


def var(identifier: int, name: str, type_name: str = "uint256") -> dict[str, Any]:
    return {
        "nodeType": "VariableDeclaration",
        "id": identifier,
        "name": name,
        "stateVariable": True,
        "visibility": "public",
        "mutability": "mutable",
        "typeDescriptions": {"typeString": type_name},
        "src": "1:1:1",
    }


def ident(name: str, declaration: int) -> dict[str, Any]:
    return {
        "nodeType": "Identifier",
        "name": name,
        "referencedDeclaration": declaration,
        "src": "1:1:1",
        "typeDescriptions": {"typeString": "uint256"},
    }


def index_access(base: dict[str, Any]) -> dict[str, Any]:
    return {
        "nodeType": "IndexAccess",
        "baseExpression": base,
        "indexExpression": {
            "nodeType": "MemberAccess",
            "expression": {"nodeType": "Identifier", "name": "msg"},
            "memberName": "sender",
            "referencedDeclaration": -15,
        },
        "src": "1:1:1",
    }


def binary(left: dict[str, Any], operator: str, right: dict[str, Any]) -> dict[str, Any]:
    return {
        "nodeType": "BinaryOperation",
        "operator": operator,
        "leftExpression": left,
        "rightExpression": right,
        "commonType": {"typeString": "uint256"},
        "src": "1:1:1",
    }


def literal(value: str) -> dict[str, Any]:
    return {"nodeType": "Literal", "kind": "number", "value": value, "src": "1:1:1"}


def require(condition: dict[str, Any]) -> dict[str, Any]:
    return {
        "nodeType": "ExpressionStatement",
        "expression": {
            "nodeType": "FunctionCall",
            "expression": {"nodeType": "Identifier", "name": "require"},
            "arguments": [condition],
            "src": "1:1:1",
        },
        "src": "1:1:1",
    }


def assign(target: dict[str, Any], operator: str, value: dict[str, Any]) -> dict[str, Any]:
    return {
        "nodeType": "ExpressionStatement",
        "expression": {
            "nodeType": "Assignment",
            "operator": operator,
            "leftHandSide": target,
            "rightHandSide": value,
            "src": "1:1:1",
        },
        "src": "1:1:1",
    }


def function(
    identifier: int, name: str, *statements: dict[str, Any], visibility: str = "external"
) -> dict[str, Any]:
    return {
        "nodeType": "FunctionDefinition",
        "id": identifier,
        "name": name,
        "kind": "function",
        "visibility": visibility,
        "stateMutability": "nonpayable",
        "src": "1:1:1",
        "parameters": {
            "nodeType": "ParameterList",
            "parameters": [
                {
                    "nodeType": "VariableDeclaration",
                    "id": AMOUNT,
                    "name": "amount",
                    "stateVariable": False,
                    "typeDescriptions": {"typeString": "uint256"},
                    "src": "1:1:1",
                }
            ],
        },
        "body": {"nodeType": "Block", "statements": list(statements)},
    }


@pytest.fixture
def graph():
    """`SimpleLending`, as the AST and as `CodeModel` see it."""
    root = {
        "nodeType": "SourceUnit",
        "absolutePath": PATH,
        "nodes": [
            {
                "nodeType": "ContractDefinition",
                "id": 1,
                "name": "SimpleLending",
                "contractKind": "contract",
                "baseContracts": [],
                "src": "1:1:1",
                "nodes": [
                    var(DEPOSITS, "deposits", "mapping(address => uint256)"),
                    var(DEBT, "debt", "mapping(address => uint256)"),
                    var(TOTAL_DEPOSITS, "totalDeposits"),
                    function(
                        DEPOSIT,
                        "deposit",
                        assign(
                            index_access(ident("deposits", DEPOSITS)),
                            "+=",
                            ident("amount", AMOUNT),
                        ),
                        assign(
                            ident("totalDeposits", TOTAL_DEPOSITS),
                            "+=",
                            ident("amount", AMOUNT),
                        ),
                    ),
                    function(
                        BORROW,
                        "borrow",
                        require(
                            binary(
                                index_access(ident("deposits", DEPOSITS)),
                                ">=",
                                binary(ident("amount", AMOUNT), "*", literal("2")),
                            )
                        ),
                        assign(
                            index_access(ident("debt", DEBT)),
                            "+=",
                            ident("amount", AMOUNT),
                        ),
                    ),
                    function(
                        WITHDRAW,
                        "withdraw",
                        require(
                            binary(
                                index_access(ident("deposits", DEPOSITS)),
                                ">=",
                                binary(
                                    index_access(ident("debt", DEBT)), "*", literal("2")
                                ),
                            )
                        ),
                        assign(
                            index_access(ident("deposits", DEPOSITS)),
                            "-=",
                            ident("amount", AMOUNT),
                        ),
                    ),
                ],
            }
        ],
    }
    source = SourceAst(path=PATH, root=root)
    from engine.protocol.semantic.solc_ast import _declarations

    source.declarations = _declarations(root, PATH)

    code = CodeModel(
        contracts=[
            Contract(
                id=f"{PATH}:SimpleLending",
                name="SimpleLending",
                path=PATH,
                kind=ContractKind.CONTRACT,
                functions=[
                    Function(
                        id=f"{PATH}:SimpleLending.{name}(uint256)",
                        name=name,
                        contract_id=f"{PATH}:SimpleLending",
                        visibility="external",
                    )
                    for name in ("deposit", "borrow", "withdraw")
                ],
            )
        ]
    )
    return semantic.build(AstIndex([source]), code)


def node_named(graph, kind: NodeKind, name: str):
    found = next((n for n in graph.of_kind(kind) if n.name == name), None)
    assert found is not None, f"no {kind.value} named {name}"
    return found


# ── What exists ───────────────────────────────────────────────────────────────


def test_the_graph_reports_ast_fidelity(graph):
    """An absent edge means different things at different fidelities, so this is not
    decoration — it is what stops a thin graph reading as a complete one."""
    assert graph.fidelity is Fidelity.AST
    assert graph.notes == []


def test_contracts_functions_and_storage_all_become_nodes(graph):
    assert {n.name for n in graph.of_kind(NodeKind.CONTRACT)} == {"SimpleLending"}
    assert {n.name for n in graph.of_kind(NodeKind.FUNCTION)} >= {
        "deposit",
        "borrow",
        "withdraw",
    }
    assert {n.name for n in graph.of_kind(NodeKind.STATE_VAR)} == {
        "deposits",
        "debt",
        "totalDeposits",
    }


def test_nodes_join_back_to_the_other_artifacts(graph):
    """A node the parser also knows about carries its `SolidityID`, so the graph is
    addressable by the same key every other artifact uses."""
    assert node_named(graph, NodeKind.CONTRACT, "SimpleLending").solidity_id == (
        f"{PATH}:SimpleLending"
    )
    assert node_named(graph, NodeKind.STATE_VAR, "deposits").solidity_id == (
        f"{PATH}:SimpleLending#deposits"
    )


def test_a_contract_declares_its_functions(graph):
    contract = node_named(graph, NodeKind.CONTRACT, "SimpleLending")
    declared = {
        graph.node(e.target).name for e in graph.out_edges(contract.id, EdgeKind.DECLARES)
    }
    assert {"deposit", "borrow", "withdraw"} <= declared


# ── State changes, with their direction ───────────────────────────────────────


def test_a_write_carries_its_delta_not_just_the_fact_of_writing(graph):
    """"writes totalDeposits" says only that it changed. `totalDeposits += amount` says
    the total rises with the deposit, which is the part an agent can reason with."""
    deposit = node_named(graph, NodeKind.FUNCTION, "deposit")
    writes = graph.out_edges(deposit.id, EdgeKind.WRITES)
    deltas = {e.detail for e in writes}

    assert "totalDeposits += amount" in deltas
    assert all(e.operator in ("increase", "decrease", "set") for e in writes)
    assert any(e.operator == "increase" for e in writes)


def test_the_direction_of_a_decrement_is_recorded(graph):
    withdraw = node_named(graph, NodeKind.FUNCTION, "withdraw")
    decreases = [
        e for e in graph.out_edges(withdraw.id, EdgeKind.WRITES) if e.operator == "decrease"
    ]
    assert decreases, [e.detail for e in graph.out_edges(withdraw.id, EdgeKind.WRITES)]


def test_a_subscripted_write_lands_on_the_mapping(graph):
    """`deposits[msg.sender] += amount` is a write to `deposits`."""
    deposits = node_named(graph, NodeKind.STATE_VAR, "deposits")
    writers = {
        graph.node(e.source).name for e in graph.in_edges(deposits.id, EdgeKind.WRITES)
    }
    assert {"deposit", "withdraw"} <= writers


# ── The relationship, which is the point ──────────────────────────────────────


def test_a_guard_comparing_two_state_variables_becomes_a_constrains_edge(graph):
    """`require(deposits[…] >= debt[…] * 2)` is the protocol stating that deposits back
    debt. No naming convention participates — a role-pair table misses this entirely,
    because this protocol calls its collateral `deposits`."""
    deposits = node_named(graph, NodeKind.STATE_VAR, "deposits")
    debt = node_named(graph, NodeKind.STATE_VAR, "debt")

    edges = [
        e
        for e in graph.out_edges(deposits.id, EdgeKind.CONSTRAINS)
        if e.target == debt.id
    ]
    assert edges, "deposits was not related to debt"
    assert edges[0].operator == ">="
    assert "debt" in edges[0].detail


def test_the_constraint_records_where_it_is_enforced(graph):
    """A rule with no location is a sentence. The function is what an agent goes and
    checks."""
    deposits = node_named(graph, NodeKind.STATE_VAR, "deposits")
    debt = node_named(graph, NodeKind.STATE_VAR, "debt")
    edge = next(
        e for e in graph.out_edges(deposits.id, EdgeKind.CONSTRAINS) if e.target == debt.id
    )
    assert edge.function_id.endswith("withdraw(uint256)")
    assert edge.evidence


def test_a_guard_edge_links_the_function_to_what_it_checks(graph):
    borrow = node_named(graph, NodeKind.FUNCTION, "borrow")
    guarded = {
        graph.node(e.target).name for e in graph.out_edges(borrow.id, EdgeKind.GUARDS)
    }
    assert "deposits" in guarded


def test_a_guard_against_a_parameter_is_not_a_state_relation(graph):
    """`deposits >= amount * 2` in `borrow` constrains storage against a parameter. The
    parameter is not a quantity the protocol has a standing rule about, so no
    `constrains` edge is minted between two storage slots that were never compared."""
    deposits = node_named(graph, NodeKind.STATE_VAR, "deposits")
    targets = {graph.node(e.target).kind for e in graph.out_edges(deposits.id, EdgeKind.CONSTRAINS)}
    assert NodeKind.STATE_VAR in targets


# ── Dataflow ──────────────────────────────────────────────────────────────────


def test_a_write_records_where_its_value_came_from(graph):
    """One hop, which is what connects a stored value back to its origin."""
    edges = [e for e in graph.edges if e.kind is EdgeKind.DERIVES_FROM]
    assert edges
    assert all(e.detail for e in edges)


# ── Degrading honestly ────────────────────────────────────────────────────────


def test_without_an_ast_the_graph_is_empty_and_says_so():
    """A repository that does not compile still produces a model. What it must not do is
    let an empty graph read as "this protocol enforces nothing"."""
    result = semantic.build(AstIndex([]), CodeModel())
    assert result.fidelity is Fidelity.TEXT
    assert result.nodes == []
    assert result.notes and "not that" in result.notes[0]


def test_the_graph_is_deterministic(graph):
    ids = [n.id for n in graph.nodes]
    assert ids == sorted(ids)
    edges = [(e.source, e.kind.value, e.target, e.order) for e in graph.edges]
    assert edges == sorted(edges)


# ── Derived surfaces: patterns over this protocol, not a table ────────────────


def test_a_clean_protocol_yields_no_reentrancy_surface(graph):
    """`SimpleLending` writes before it calls out, so the pattern must not match.

    An empty result is the point. A table keyed on operation name fires on every `deposit`
    regardless of what the body does, which is why its output was identical for every
    protocol; a pattern match is allowed — required — to find nothing.
    """
    from engine.protocol.semantic import surfaces

    kinds = {s.kind.value for s in surfaces.derive(graph)}
    assert "reentrancy" not in kinds


def test_surfaces_are_empty_without_a_graph():
    from engine.core.models.semantic import SemanticGraph
    from engine.protocol.semantic import surfaces

    assert surfaces.derive(SemanticGraph()) == []


def test_a_derived_surface_names_the_node_it_matched_on(graph):
    """The whole difference from a table: it points somewhere specific."""
    from engine.protocol.semantic import surfaces

    for surface in surfaces.derive(graph):
        assert surface.targets, surface.title
        assert surface.questions, surface.title
        assert surface.evidence


# ── The mechanism view the UI renders ─────────────────────────────────────────


def test_the_mechanism_view_reports_conditions_and_deltas(graph):
    from engine.protocol.semantic import mechanism

    found = next(c for c in mechanism.contracts(graph) if c.name == "SimpleLending")
    withdraw = next(f for f in found.functions if f.name == "withdraw")

    assert any("debt" in condition for condition in withdraw.conditions)
    assert any(change.effect == "decrease" for change in withdraw.state_changes)
    assert found.relationships, "the deposits/debt relation should reach the UI"


def test_entrypoints_are_listed_before_internal_helpers(graph):
    """A reader starts at the surface; a helper is interesting once you know what reaches it."""
    from engine.protocol.semantic import mechanism

    found = next(c for c in mechanism.contracts(graph) if c.name == "SimpleLending")
    flags = [f.is_entrypoint for f in found.functions]
    assert flags == sorted(flags, reverse=True)
