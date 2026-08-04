"""Layer 3: what a function does (SPEC §12.2, §13.2, §13.3).

The two things worth being pedantic about here:

* **Call classification.** `UNTRUSTED_EXTERNAL` is where reentrancy, oracle manipulation
  and untrusted callbacks live (SPEC §13.2). If ordinary ERC-20 calls land in that bucket,
  the sentinel stops meaning anything.
* **Shadowing.** SPEC §13.3: "shadowed locals must not be counted as state access — this is
  a real bug source, test it."
"""

from __future__ import annotations

import pytest

from engine.core.models.code import AccessKind, CallKind
from engine.parse.normalize import parse_file

REENTRANT = """
contract Vault {
    mapping(address => uint256) public balance;
    event Withdraw(address indexed who);

    function withdraw(uint256 amount) external {
        require(balance[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balance[msg.sender] -= amount;
        emit Withdraw(msg.sender);
    }

    function safeWithdraw(uint256 amount) external {
        balance[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
"""


def parse(source: str, path: str = "src/T.sol"):
    return parse_file(path, source.encode("utf-8"))


def function_named(source: str, name: str):
    _, contracts, _ = parse(source)
    for contract in contracts:
        for function in (*contract.functions, *contract.modifiers):
            if function.name == name:
                return function
    raise AssertionError(f"no function named {name}")


# ── Call classification ───────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("statement", "kind", "name"),
    [
        ("(bool k,) = a.call{value: 1}('');", CallKind.LOW_LEVEL, "call"),
        ("a.delegatecall(d);", CallKind.LOW_LEVEL, "delegatecall"),
        ("a.staticcall(d);", CallKind.LOW_LEVEL, "staticcall"),
        ("payable(a).transfer(1);", CallKind.LOW_LEVEL, "transfer"),
        ("a.send(1);", CallKind.LOW_LEVEL, "send"),
        ("token.transfer(a, 1);", CallKind.MEMBER, "transfer"),
        ("IERC20(a).transferFrom(a, b, 1);", CallKind.MEMBER, "transferFrom"),
        ("super.v();", CallKind.SUPER, "v"),
        ("this.g();", CallKind.THIS, "g"),
        ("helper(1);", CallKind.INTERNAL, "helper"),
        ("new Foo(1);", CallKind.NEW, "Foo"),
        ("require(x);", CallKind.BUILTIN, "require"),
        ("keccak256(d);", CallKind.BUILTIN, "keccak256"),
    ],
)
def test_call_kinds(statement: str, kind: CallKind, name: str):
    source = f"contract C {{ function f(address a, address b, bytes d, bool x) external {{ {statement} }} }}"
    call = next(c for c in function_named(source, "f").calls if c.name == name)
    assert call.kind is kind


def test_erc20_transfer_is_not_a_low_level_call():
    """Arity disambiguates: `token.transfer(to, amt)` is an ERC-20 call, not an ETH send.

    Misclassifying these points the whole protocol at `UNTRUSTED_EXTERNAL` and destroys
    the signal that makes reentrancy candidates worth computing.
    """
    source = """
    contract C {
        function f(address to, uint256 amt) external {
            token.transfer(to, amt);
            payable(to).transfer(amt);
        }
    }
    """
    calls = function_named(source, "f").calls
    erc20, native = calls[0], calls[1]

    assert erc20.kind is CallKind.MEMBER and not erc20.sends_value
    assert native.kind is CallKind.LOW_LEVEL and native.sends_value


def test_a_type_cast_is_not_a_call():
    """`IERC20(t)` is a cast; as a call edge it points at a function that does not exist."""
    source = """
    import {IERC20} from "./IERC20.sol";
    contract C { function f(address t) external { IERC20(t).transfer(t, 1); } }
    """
    calls = function_named(source, "f").calls
    assert not any(c.kind is CallKind.INTERNAL and c.name == "IERC20" for c in calls)


def test_delegatecall_and_value_and_try_are_flagged():
    source = """
    contract C {
        function f(address a, bytes d) external {
            a.delegatecall(d);
            (bool k,) = a.call{value: 5}("");
            try pool.swap(1) returns (uint z) {} catch {}
        }
    }
    """
    by_name = {c.name: c for c in function_named(source, "f").calls}

    assert by_name["delegatecall"].is_delegate
    assert by_name["call"].sends_value
    assert by_name["swap"].is_try


def test_calls_are_ordered_by_position():
    source = "contract C { function f(address a) external { first(); second(); third(); } }"
    calls = function_named(source, "f").calls
    assert [c.name for c in calls] == ["first", "second", "third"]
    assert [c.order for c in calls] == [1, 2, 3]


# ── Storage access ────────────────────────────────────────────────────────────

def test_reads_and_writes_are_separated():
    function = function_named(REENTRANT, "withdraw")
    assert function.writes == ["src/T.sol:Vault#balance"]
    assert function.reads == ["src/T.sol:Vault#balance"]


def test_compound_assignment_is_both_a_read_and_a_write():
    source = "contract C { uint256 total; function f() external { total += 1; } }"
    accesses = function_named(source, "f").accesses
    assert {a.kind for a in accesses} == {AccessKind.READ, AccessKind.WRITE}


def test_plain_assignment_is_a_write_only():
    source = "contract C { uint256 total; function f() external { total = 1; } }"
    accesses = [a for a in function_named(source, "f").accesses if a.name == "total"]
    assert {a.kind for a in accesses} == {AccessKind.WRITE}


def test_increment_is_a_write():
    source = "contract C { uint256 n; function f() external { n++; } }"
    assert function_named(source, "f").writes == ["src/T.sol:C#n"]


def test_a_shadowing_local_is_not_a_state_access():
    """SPEC §13.3 — a storage graph that counts locals looks right and is quietly wrong."""
    source = """
    contract C {
        address owner;
        function f() external {
            address owner = msg.sender;
            owner = address(0);
        }
    }
    """
    assert function_named(source, "f").accesses == []


def test_a_parameter_shadowing_a_state_variable_is_not_a_state_access():
    source = """
    contract C {
        uint256 amount;
        function f(uint256 amount) external { amount = 1; }
    }
    """
    assert function_named(source, "f").accesses == []


def test_state_access_outside_the_shadowing_block_still_counts():
    source = """
    contract C {
        uint256 total;
        function f() external {
            { uint256 total = 1; total = 2; }
            total = 3;
        }
    }
    """
    writes = function_named(source, "f").writes
    assert writes == ["src/T.sol:C#total"]


def test_an_inherited_state_variable_is_recorded_unresolved():
    """The declaring contract is unknown until the Graph Engine linearizes inheritance.

    Recording the candidate is what makes that resolution possible; dropping it would lose
    the storage edge permanently.
    """
    source = "contract C is Base { function f() external { inheritedVar = 1; } }"
    access = function_named(source, "f").accesses[0]

    assert access.name == "inheritedVar"
    assert access.state_var_id == ""


# ── Ordering: the reentrancy candidate ────────────────────────────────────────

def test_a_write_after_an_external_call_is_a_candidate():
    assert function_named(REENTRANT, "withdraw").writes_after_external_call


def test_checks_effects_interactions_is_not_a_candidate():
    assert not function_named(REENTRANT, "safeWithdraw").writes_after_external_call


# ── Emits, reverts and body flags ─────────────────────────────────────────────

def test_emits_and_reverts_are_collected():
    source = """
    contract C {
        function f(bool ok) external {
            emit Deposit(msg.sender, 1);
            if (!ok) revert Unauthorized(msg.sender);
        }
    }
    """
    function = function_named(source, "f")
    assert function.emits == ["Deposit"]
    assert function.reverts == ["Unauthorized"]


def test_assembly_loops_and_unchecked_are_flagged():
    source = """
    contract C {
        function f() external {
            for (uint i; i < 3; ++i) { unchecked { ++i; } }
            assembly { let s := sload(0) }
        }
    }
    """
    function = function_named(source, "f")
    assert function.has_loop and function.has_unchecked and function.has_assembly


def test_a_body_less_function_analyses_cleanly():
    function = function_named("interface I { function f() external; }", "f")
    assert function.calls == [] and function.accesses == []


def test_entrypoints_are_identified():
    source = """
    contract C {
        function pub() public {}
        function ext() external {}
        function int_() internal {}
        function priv() private {}
        receive() external payable {}
    }
    """
    _, contracts, _ = parse(source)
    entrypoints = {f.name for f in contracts[0].entrypoints}
    assert entrypoints == {"pub", "ext", "receive"}
