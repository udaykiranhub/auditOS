"""Reading the solc AST — the tool the semantic layer had available and never opened.

These tests build AST fragments by hand rather than shelling out to `solc`. The shapes are
copied from real compiler output (Arcadia and a lending pool), so they exercise the reader
against what solc actually emits, while keeping the suite runnable without a toolchain.

What is pinned here is *meaning*, not counts: that `if (…) revert` is negated, that a
struct field resolves to the field and not to the temporary holding it, and that anything
computed rather than denoted is refused.
"""

from __future__ import annotations

from typing import Any

from engine.protocol.semantic import solc_ast
from engine.protocol.semantic.solc_ast import SourceAst


def identifier(name: str, declaration: int) -> dict[str, Any]:
    return {
        "nodeType": "Identifier",
        "name": name,
        "referencedDeclaration": declaration,
        "src": "100:5:1",
        "typeDescriptions": {"typeString": "uint256"},
    }


def member(base: dict[str, Any], name: str, declaration: int) -> dict[str, Any]:
    return {
        "nodeType": "MemberAccess",
        "expression": base,
        "memberName": name,
        "referencedDeclaration": declaration,
        "src": "100:5:1",
        "typeDescriptions": {"typeString": "uint256"},
    }


def literal(value: str) -> dict[str, Any]:
    return {"nodeType": "Literal", "kind": "number", "value": value, "src": "1:1:1"}


def binary(left: dict[str, Any], operator: str, right: dict[str, Any]) -> dict[str, Any]:
    return {
        "nodeType": "BinaryOperation",
        "operator": operator,
        "leftExpression": left,
        "rightExpression": right,
        "commonType": {"typeString": "uint256"},
        "src": "100:20:1",
    }


def if_revert(condition: dict[str, Any]) -> dict[str, Any]:
    return {
        "nodeType": "IfStatement",
        "condition": condition,
        "trueBody": {"nodeType": "RevertStatement", "src": "1:1:1"},
        "src": "1:1:1",
    }


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


def source(*statements: dict[str, Any], name: str = "Pool") -> SourceAst:
    root = {
        "nodeType": "SourceUnit",
        "absolutePath": "src/Pool.sol",
        "nodes": [
            {
                "nodeType": "ContractDefinition",
                "name": name,
                "id": 1,
                "src": "0:100:1",
                "nodes": [
                    {
                        "nodeType": "FunctionDefinition",
                        "name": "borrow",
                        "id": 10,
                        "kind": "function",
                        "src": "10:90:1",
                        "body": {"nodeType": "Block", "statements": list(statements)},
                    }
                ],
            }
        ],
    }
    return SourceAst(path="src/Pool.sol", root=root)


def only(statements: list[dict[str, Any]]) -> solc_ast.Comparison:
    found = solc_ast.comparisons(source(*statements))
    assert len(found) == 1, [c.source for c in found]
    return found[0]


# ── Negation: the failure that silently states the reverse ────────────────────


def test_require_asserts_its_condition():
    found = only([require(binary(identifier("a", 2), ">=", identifier("b", 3)))])
    assert found.operator == ">="
    assert found.left == (2,) and found.right == (3,)


def test_if_revert_asserts_the_negation():
    """`if (cutoffTime > 64800) revert` establishes `cutoffTime <= 64800`.

    Reading the condition literally records the exact opposite of what the code enforces,
    and the output looks entirely plausible while being backwards.
    """
    found = only([if_revert(binary(identifier("cutoffTime", 2), ">", literal("64800")))])
    assert found.operator == "<="
    assert found.literal == "64800"
    assert found.reverts_when_true


def test_an_if_that_does_more_than_revert_is_not_a_guard():
    """The other statement runs on some path, so the condition is not a standing rule."""
    node = {
        "nodeType": "IfStatement",
        "condition": binary(identifier("a", 2), ">", identifier("b", 3)),
        "trueBody": {
            "nodeType": "Block",
            "statements": [
                {"nodeType": "ExpressionStatement", "src": "1:1:1"},
                {"nodeType": "RevertStatement", "src": "1:1:1"},
            ],
        },
        "src": "1:1:1",
    }
    assert solc_ast.comparisons(source(node)) == []


# ── Resolution: what the AST buys over a regex ────────────────────────────────


def test_a_struct_field_resolves_to_the_field_not_the_temporary():
    """`account.totalDebtUsd > account.borrowLimitUsd` is the health check of every lending
    market, and the quantities are the *fields*.

    Walking the subtree blindly collects the base identifier too, which rendered the rule as
    `borrowLimitUsd + account >= totalDebtUsd + account` — the temporary struct reported as
    a quantity beside the field that carries the meaning.
    """
    account = identifier("account", 5)
    found = only(
        [
            if_revert(
                binary(
                    member(account, "totalDebtUsd", 20),
                    ">",
                    member(account, "borrowLimitUsd", 21),
                )
            )
        ]
    )
    # Negated to `<=`, then mirrored so the bounding side leads.
    assert found.left == (21,), "borrowLimitUsd constrains totalDebtUsd"
    assert found.right == (20,)
    assert 5 not in found.left + found.right, "the temporary is not a quantity"


def test_an_index_access_resolves_to_the_mapping():
    """`deposits[msg.sender]` is about `deposits`; the key is an accessor."""
    node = {
        "nodeType": "IndexAccess",
        "baseExpression": identifier("deposits", 7),
        "indexExpression": {
            "nodeType": "MemberAccess",
            "expression": {"nodeType": "Identifier", "name": "msg"},
            "memberName": "sender",
            "referencedDeclaration": -15,
        },
        "src": "1:1:1",
    }
    found = only([require(binary(node, ">=", identifier("amount", 8)))])
    assert found.left == (7,)


def test_a_call_result_is_not_denoted():
    """A computed value is not a quantity the protocol has a standing rule about, and its
    arguments are certainly not."""
    call = {
        "nodeType": "FunctionCall",
        "expression": identifier("balanceOf", 9),
        "arguments": [identifier("user", 11)],
        "src": "1:1:1",
    }
    found = solc_ast.comparisons(source(require(binary(call, ">=", literal("0")))))
    assert found == []


def test_a_factor_is_read_off_the_multiplication():
    """The `2` in `debt * 2` is the collateralisation ratio — the difference between
    "these are related" and a checkable property."""
    found = only(
        [
            require(
                binary(
                    identifier("deposits", 2),
                    ">=",
                    binary(identifier("debt", 3), "*", literal("2")),
                )
            )
        ]
    )
    assert found.factor == "2"
    assert found.right == (3,)


# ── Orientation and refusal ───────────────────────────────────────────────────


def test_a_literal_on_the_left_is_mirrored_onto_the_variable():
    """`0 < totalDebt` is a statement about `totalDebt`."""
    found = only([require(binary(literal("0"), "<", identifier("totalDebt", 4)))])
    assert found.left == (4,)
    assert found.operator == ">"


def test_an_upper_bound_keeps_the_variable_on_the_constrained_side():
    """Mirroring on the operator alone moved the variable onto the empty side of
    `cutoffTime <= 64800` and lost every upper bound in the protocol."""
    found = only([require(binary(identifier("cutoffTime", 2), "<=", literal("64800")))])
    assert found.left == (2,)
    assert found.operator == "<="
    assert found.literal == "64800"


def test_an_or_is_refused():
    """Either side may be the one that held, so neither is enforced on its own."""
    condition = {
        "nodeType": "BinaryOperation",
        "operator": "||",
        "leftExpression": binary(identifier("a", 2), ">", identifier("b", 3)),
        "rightExpression": binary(identifier("c", 4), ">", identifier("d", 5)),
        "src": "1:1:1",
    }
    assert solc_ast.comparisons(source(require(condition))) == []


def test_an_and_yields_both_halves():
    """Each side of an `&&` is independently enforced."""
    condition = {
        "nodeType": "BinaryOperation",
        "operator": "&&",
        "leftExpression": binary(identifier("a", 2), ">=", identifier("b", 3)),
        "rightExpression": binary(identifier("c", 4), ">=", identifier("d", 5)),
        "src": "1:1:1",
    }
    found = solc_ast.comparisons(source(require(condition)))
    assert len(found) == 2


def test_a_disequality_is_not_a_relation():
    """`msg.sender != owner` is authorization, which the permission pass owns."""
    found = solc_ast.comparisons(
        source(require(binary(identifier("a", 2), "!=", identifier("b", 3))))
    )
    assert found == []


def test_comparing_a_thing_to_itself_is_not_a_relation():
    found = solc_ast.comparisons(
        source(require(binary(identifier("a", 2), ">=", identifier("a", 2))))
    )
    assert found == []


# ── Degrading honestly ────────────────────────────────────────────────────────


def test_no_build_means_no_ast_rather_than_an_error():
    """A repository that does not compile still gets a model, at lower fidelity."""
    index = solc_ast.load(None, None)
    assert not index.available
    assert index.declarations == {}
