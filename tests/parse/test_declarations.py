"""Layer 1 & 2: symbols and relationships (SPEC §12.2).

Coverage is organized by *language feature* rather than by protocol. Vendoring Aave,
Compound and MakerDAO would add gigabytes to the repository and still only exercise the
features those protocols happen to use; a fixture per construct exercises them all and
fails with a readable diff.
"""

from __future__ import annotations

import pytest

from engine.core.models.code import ContractKind, FunctionKind
from engine.parse.normalize import parse_file


def parse(source: str, path: str = "src/T.sol"):
    return parse_file(path, source.encode("utf-8"))


# ── Contracts ─────────────────────────────────────────────────────────────────

def test_contract_interface_library_and_abstract_are_distinguished():
    _, contracts, _ = parse(
        """
        contract C {}
        interface I {}
        library L {}
        abstract contract A { function f() public virtual; }
        """
    )
    kinds = {c.name: c.kind for c in contracts}

    assert kinds == {
        "C": ContractKind.CONTRACT,
        "I": ContractKind.INTERFACE,
        "L": ContractKind.LIBRARY,
        "A": ContractKind.ABSTRACT,
    }


def test_ids_follow_the_spec_format():
    _, contracts, _ = parse(
        "contract Vault { uint256 x; function deposit(uint a, address b) external {} "
        "modifier m() { _; } }",
        path="src/vault/Vault.sol",
    )
    contract = contracts[0]

    assert contract.id == "src/vault/Vault.sol:Vault"
    # `uint` is canonicalized to `uint256` — the compiler's spelling, per SPEC §7.2.
    assert contract.functions[0].id == "src/vault/Vault.sol:Vault.deposit(uint256,address)"
    assert contract.state_vars[0].id == "src/vault/Vault.sol:Vault#x"
    assert contract.modifiers[0].id == "src/vault/Vault.sol:Vault.m"


def test_inheritance_with_constructor_arguments():
    _, contracts, _ = parse("contract C is Base(1), IFoo, Ownable {}")
    assert contracts[0].inherits == ["Base", "IFoo", "Ownable"]


def test_natspec_is_captured_but_ordinary_comments_are_not():
    _, contracts, _ = parse(
        """
        /// @notice A vault.
        contract A {}
        // just a note
        contract B {}
        """
    )
    by_name = {c.name: c for c in contracts}

    assert "@notice A vault." in (by_name["A"].natspec or "")
    assert by_name["B"].natspec is None


# ── Functions ─────────────────────────────────────────────────────────────────

def test_every_callable_kind_is_recognized():
    _, contracts, _ = parse(
        """
        contract C {
            constructor(uint x) {}
            receive() external payable {}
            fallback() external {}
            function f() public {}
            modifier m() { _; }
        }
        """
    )
    contract = contracts[0]
    kinds = {f.kind for f in contract.functions}

    assert kinds == {
        FunctionKind.CONSTRUCTOR,
        FunctionKind.RECEIVE,
        FunctionKind.FALLBACK,
        FunctionKind.FUNCTION,
    }
    assert contract.modifiers[0].kind is FunctionKind.MODIFIER


@pytest.mark.parametrize(
    ("declaration", "visibility", "mutability"),
    [
        ("function f() external view {}", "external", "view"),
        ("function f() public pure {}", "public", "pure"),
        ("function f() external payable {}", "external", "payable"),
        ("function f() internal {}", "internal", "nonpayable"),
        ("function f() private {}", "private", "nonpayable"),
        ("function f() {}", "internal", "nonpayable"),
    ],
)
def test_visibility_and_mutability(declaration: str, visibility: str, mutability: str):
    _, contracts, _ = parse(f"contract C {{ {declaration} }}")
    function = contracts[0].functions[0]

    assert function.visibility == visibility
    assert function.mutability == mutability


def test_virtual_override_and_unimplemented():
    _, contracts, _ = parse(
        """
        contract C {
            function a() public virtual {}
            function b() public override(X, Y) {}
            function c() external;
        }
        """
    )
    by_name = {f.name: f for f in contracts[0].functions}

    assert by_name["a"].is_virtual
    assert by_name["b"].is_override
    assert not by_name["c"].is_implemented  # an interface method has no body


def test_params_returns_and_modifiers():
    _, contracts, _ = parse(
        "contract C { function f(uint256 a, address to) external onlyOwner nonReentrant "
        "returns (uint256 shares, bool ok) {} }"
    )
    function = contracts[0].functions[0]

    assert [(p.type, p.name) for p in function.params] == [("uint256", "a"), ("address", "to")]
    assert [(p.type, p.name) for p in function.returns] == [("uint256", "shares"), ("bool", "ok")]
    assert function.modifiers == ["onlyOwner", "nonReentrant"]


def test_overloads_are_distinct_ids():
    _, contracts, _ = parse(
        "contract C { function f(uint256 a) external {} function f(address a) external {} }"
    )
    ids = {f.id for f in contracts[0].functions}
    assert len(ids) == 2


def test_data_location_is_recorded():
    _, contracts, _ = parse("contract C { function f(bytes calldata d, uint[] memory a) external {} }")
    locations = [p.location for p in contracts[0].functions[0].params]
    assert locations == ["calldata", "memory"]


def test_raw_source_and_spans_are_stored():
    """SPEC §7.4: the Context Builder slices at function granularity, hundreds of times."""
    source = "contract C {\n    function f() external {\n        uint x = 1;\n    }\n}"
    _, contracts, _ = parse(source)
    function = contracts[0].functions[0]

    assert function.raw.startswith("function f()")
    assert "uint x = 1;" in function.raw
    assert function.line_start == 2
    assert function.line_end == 4
    assert function.body_hash


def test_identical_bodies_share_a_body_hash():
    _, contracts, _ = parse(
        "contract A { function f() public { return; } }"
        "contract B { function f() public { return; } }"
    )
    assert contracts[0].functions[0].body_hash == contracts[1].functions[0].body_hash


# ── State variables ───────────────────────────────────────────────────────────

def test_state_variable_qualifiers():
    _, contracts, _ = parse(
        """
        contract C {
            uint256 public constant CAP = 100;
            uint256 internal immutable start;
            mapping(address => uint256) private balance;
            uint128 transient locked;
            address owner;
        }
        """
    )
    by_name = {v.name: v for v in contracts[0].state_vars}

    assert by_name["CAP"].is_constant and by_name["CAP"].visibility == "public"
    assert by_name["start"].is_immutable
    assert by_name["balance"].type == "mapping(address => uint256)"
    assert by_name["balance"].visibility == "private"
    assert by_name["locked"].is_transient
    assert by_name["owner"].visibility == "internal"  # Solidity's default
    assert all(v.slot is None for v in contracts[0].state_vars)  # solc's job, not ours


# ── Other members ─────────────────────────────────────────────────────────────

def test_events_errors_structs_enums_and_using_for():
    _, contracts, _ = parse(
        """
        contract C {
            using SafeERC20 for IERC20;
            using Math for *;
            event Deposit(address indexed who, uint256 amount);
            error Unauthorized(address who);
            struct Position { uint128 size; uint128 entry; }
            enum State { Open, Closed }
        }
        """
    )
    contract = contracts[0]

    event = contract.events[0]
    assert event.name == "Deposit"
    assert [p.indexed for p in event.params] == [True, False]

    assert contract.errors[0].name == "Unauthorized"
    assert [f.name for f in contract.structs[0].fields] == ["size", "entry"]
    assert contract.enums[0].values == ["Open", "Closed"]
    assert [(u.library, u.target_type) for u in contract.using_for] == [
        ("SafeERC20", "IERC20"),
        ("Math", "*"),
    ]


# ── File level ────────────────────────────────────────────────────────────────

def test_file_level_declarations():
    unit, _, _ = parse(
        """
        pragma solidity ^0.8.20;
        import {IERC20 as IT} from "./IERC20.sol";
        import "./Other.sol";
        type Price is uint128;
        error TopLevel();
        struct Shared { uint a; }
        function freeFn(uint a) pure returns (uint) { return a; }
        contract C {}
        """
    )

    assert unit.pragma == "pragma solidity ^0.8.20"
    assert [i.path for i in unit.imports] == ["./IERC20.sol", "./Other.sol"]
    assert unit.imports[0].symbols == ["IERC20 as IT"]
    assert unit.user_defined_types == ["Price"]
    assert unit.errors[0].name == "TopLevel"
    assert unit.structs[0].name == "Shared"

    free = unit.free_functions[0]
    assert free.name == "freeFn"
    assert free.kind is FunctionKind.FREE
    assert free.contract_id is None
    assert free.id == "src/T.sol:freeFn(uint256)"
