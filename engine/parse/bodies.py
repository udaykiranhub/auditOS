"""Layer 3: what a function *does* (SPEC §12.2, §13.2, §13.3).

For each body: the calls it makes, the state it reads and writes, the events it emits, the
errors it reverts with — **and the order those happen in**, because SPEC §13.2's reentrancy
candidates are exactly "a state write ordered after an external call".

This stops well short of expression modeling. A call site is recorded as a reference —
callee, receiver, kind, line, order — not as a parsed expression; the agent reads `raw`
for meaning. SPEC §12.2 names full expression-level AST modeling *the single biggest scope
trap in the project*, and the line is drawn here deliberately.

**Shadowing is handled properly.** SPEC §13.3: "scope-aware: shadowed locals must not be
counted as state access — this is a real bug source, test it". A local named `owner` inside
`withdraw()` is not the state variable `owner`, and counting it as one produces a storage
graph that looks right and is quietly wrong.
"""

from __future__ import annotations

from tree_sitter import Node

from engine.core.models.code import (
    AccessKind,
    CallKind,
    CallSite,
    Contract,
    Function,
    StateAccess,
)
from engine.parse.treesitter import line_of, text_of

# `x.call{value: v}(…)` and friends — the edges SPEC §13.2 says to flag prominently.
LOW_LEVEL_CALLS = {"call", "delegatecall", "staticcall", "callcode"}
DELEGATE_CALLS = {"delegatecall", "callcode"}

# `transfer` and `send` are ambiguous, and getting them wrong is expensive.
#
#   payable(to).transfer(amount)   → native ETH send, low-level, 1 argument
#   token.transfer(to, amount)     → an ordinary ERC-20 call,     2 arguments
#
# Tree-sitter has no types, so arity is the disambiguator. Treating every ERC-20
# `transfer` as low-level would point the whole protocol at the `UNTRUSTED_EXTERNAL`
# sentinel and destroy the signal that makes reentrancy candidates worth computing.
VALUE_SENDING_CALLS = {"transfer", "send"}

# Language builtins: never a user call edge, never a state variable.
BUILTINS = {
    "require", "assert", "revert", "keccak256", "sha256", "sha3", "ripemd160", "ecrecover",
    "addmod", "mulmod", "selfdestruct", "suicide", "blockhash", "gasleft", "type", "new",
    "abi", "msg", "block", "tx", "now", "this", "super", "payable", "address", "bool",
    "string", "bytes", "byte", "wei", "gwei", "ether", "seconds", "minutes", "hours",
    "days", "weeks", "unchecked", "emit", "delete", "return", "_",
}

#: Value types `new` can allocate in memory rather than deploy. `uintN`/`bytesN` are
#: matched by prefix below, since spelling out all 32 widths of each buys nothing.
ELEMENTARY_TYPES = {"address", "bool", "string", "bytes", "int", "uint", "fixed", "ufixed"}

_ASSIGNMENTS = ("assignment_expression", "augmented_assignment_expression")
_LOOPS = ("for_statement", "while_statement", "do_while_statement")
_NESTED_DEFINITIONS = ("function_definition", "modifier_definition", "constructor_definition")


def _in_order(node: Node) -> list[Node]:
    """Every named descendant in source order — `order` must reflect execution sequence."""
    found: list[Node] = []

    def visit(current: Node) -> None:
        for child in current.children:
            if child.is_named:
                found.append(child)
            visit(child)

    visit(node)
    return found


def _base_identifier(node: Node, source: bytes) -> Node | None:
    """The variable an lvalue ultimately targets: `balance[msg.sender].x` → `balance`."""
    current: Node | None = node
    while current is not None:
        if current.type == "identifier":
            return current
        if current.type == "member_expression":
            current = current.child_by_field_name("object")
            continue
        if current.type == "array_access":
            current = current.child_by_field_name("base") or (
                current.named_children[0] if current.named_children else None
            )
            continue
        if current.type == "update_expression":  # `n++` / `--n`
            current = current.child_by_field_name("argument")
            continue
        if current.type == "expression" and current.named_children:
            current = current.named_children[0]
            continue
        return None
    return None


class _Scope:
    """Local declarations with the block they belong to, so shadowing is positional."""

    def __init__(self) -> None:
        self.locals: list[tuple[str, int, int]] = []  # (name, valid_from, block_end)

    def declare(self, name: str, declared_at: int, block_end: int) -> None:
        if name:
            self.locals.append((name, declared_at, block_end))

    def shadows(self, name: str, position: int) -> bool:
        return any(
            local == name and declared_at <= position <= block_end
            for local, declared_at, block_end in self.locals
        )


def _enclosing_block_end(node: Node) -> int:
    current = node.parent
    while current is not None:
        if current.type in ("function_body", "block_statement", "for_statement"):
            return current.end_byte
        current = current.parent
    return node.end_byte


def _collect_locals(body: Node, source: bytes, function: Function) -> _Scope:
    """Parameters, named returns and every local declaration in the body."""
    scope = _Scope()

    for param in (*function.params, *function.returns):
        scope.declare(param.name, body.start_byte, body.end_byte)

    for node in _in_order(body):
        if node.type == "variable_declaration":
            name_node = node.child_by_field_name("name")
            name = text_of(name_node, source) if name_node else ""
            scope.declare(name, node.start_byte, _enclosing_block_end(node))
        elif node.type == "yul_variable_declaration":
            for child in node.named_children:
                if child.type == "yul_identifier":
                    scope.declare(text_of(child, source), node.start_byte, body.end_byte)
                    break

    return scope


def _unwrap(node: Node) -> tuple[Node, bool]:
    """Strip `expression` wrappers and call options. Returns `(node, sends_value)`.

    `addr.call{value: v}(data)` parses as a `struct_expression` wrapping the real callee —
    the `{value: …}` block reuses struct-literal syntax. Without unwrapping it, the most
    security-relevant call in Solidity is classified as an ordinary member access.
    """
    current = node
    sends_value = False

    while True:
        if current.type == "expression" and current.named_children:
            current = current.named_children[0]
        elif current.type == "struct_expression":
            sends_value = sends_value or "value" in _option_keys(current)
            inner = current.child_by_field_name("type")
            if inner is None:
                return current, sends_value
            current = inner
        else:
            return current, sends_value


def _option_keys(struct_expression: Node) -> set[str]:
    """The `{value: …, gas: …}` keys on a call."""
    return {
        field.named_children[0].type and _identifier_text(field)
        for field in struct_expression.named_children
        if field.type == "struct_field_assignment"
    }


def _identifier_text(field: Node) -> str:
    for child in field.named_children:
        if child.type == "identifier":
            return child.text.decode("utf-8", errors="replace") if child.text else ""
    return ""


_OPERATOR_CHARS = "!~+-*/%<>=&|^?:,"


def _is_elementary(name: str) -> bool:
    """`bytes32`, `uint128`, `address` — anything `new` allocates instead of deploying."""
    base = name.rstrip("0123456789")
    return base in ELEMENTARY_TYPES and (base == name or name[len(base) :].isdigit())


def _receiver_head(receiver: str) -> str:
    """The operand a member call actually attaches to.

    The grammar binds surrounding operators *inside* the member expression, so
    `require(!factory.isPool(x))` gives an object node spanning `!factory`, and
    `18 - ERC20(token).decimals()` gives one spanning `18 - ERC20(token)`. Neither operator
    is part of the receiver, and leaving it there means the receiver never matches the
    variable it names — so its declared type is never found, and an ordinary typed call is
    recorded as a call to an unknown address. Scanning for the last top-level operator
    recovers the operand; bracket depth keeps `IERC20(a - b)` intact.
    """
    depth = 0
    cut = 0
    for index, char in enumerate(receiver):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif depth == 0 and char in _OPERATOR_CHARS:
            cut = index + 1
    return receiver[cut:].strip()


def _classify_call(
    callee: Node,
    source: bytes,
    argument_count: int,
    type_names: set[str],
) -> tuple[CallKind, str, str | None, bool]:
    """`(kind, name, receiver, sends_value)` for a call's callee expression."""
    node, sends_value = _unwrap(callee)

    if node.type == "identifier":
        name = text_of(node, source)
        if name in BUILTINS or name in type_names:
            # `IERC20(token)` is a cast, not a call. Left as an internal call it becomes a
            # phantom edge to a function that does not exist.
            return CallKind.BUILTIN, name, None, sends_value
        return CallKind.INTERNAL, name, None, sends_value

    if node.type == "new_expression":
        target = node.child_by_field_name("name")
        name = text_of(target, source) if target else ""
        # `new bytes32[](n)` allocates memory; only `new C(...)` deploys a contract. Both
        # are `new_expression`, and conflating them puts an array allocation on the call
        # graph as a contract creation — which then reads as an external interaction.
        if name.endswith("]") or _is_elementary(name):
            return CallKind.BUILTIN, name, None, sends_value
        return CallKind.NEW, name, None, sends_value

    if node.type == "member_expression":
        # The grammar names these, so read the fields rather than guessing by position:
        # `IERC20(t).transfer` has an `expression` object, not an identifier.
        object_node = node.child_by_field_name("object")
        property_node = node.child_by_field_name("property")
        receiver = _receiver_head(text_of(object_node, source) if object_node else "")
        member = text_of(property_node, source) if property_node else ""
        head = receiver.split(".")[0].split("(")[0].strip()

        if member in LOW_LEVEL_CALLS:
            return CallKind.LOW_LEVEL, member, receiver, sends_value
        if member in VALUE_SENDING_CALLS and argument_count == 1:
            return CallKind.LOW_LEVEL, member, receiver, True
        if head == "super":
            return CallKind.SUPER, member, "super", sends_value
        if head == "this":
            return CallKind.THIS, member, "this", sends_value
        if head in ("abi", "msg", "block", "tx", "type"):
            return CallKind.BUILTIN, member, head, sends_value
        return CallKind.MEMBER, member, receiver, sends_value

    text = text_of(node, source)
    return CallKind.MEMBER, text.split("(")[0].strip(), None, sends_value


def _inside_try(node: Node) -> bool:
    """`try pool.swap(…)` — a call whose revert is handled, which changes its risk."""
    current = node.parent
    while current is not None:
        if current.type == "try_statement":
            return True
        if current.type in ("function_body", "block_statement"):
            return False
        current = current.parent
    return False


def analyze_body(
    node: Node,
    source: bytes,
    function: Function,
    contract: Contract | None,
    type_names: set[str] | None = None,
) -> None:
    """Fill in a function's behaviour, in place.

    `contract` supplies the state variables whose IDs can be resolved here. An access to a
    variable declared in a *parent* contract cannot be resolved yet — inheritance is the
    Graph Engine's job (SPEC §13.1) — so it is recorded with an empty `state_var_id` for
    that phase to complete. Recording the candidate is what makes the resolution possible;
    dropping it would lose the edge permanently.
    """
    body = node.child_by_field_name("body")
    if body is None:
        return

    type_names = type_names or set()
    scope = _collect_locals(body, source, function)
    own_state_vars = {v.name: v.id for v in contract.state_vars} if contract else {}
    declared_names = _declared_names(contract)

    order = 0
    written: set[int] = set()

    for current in _in_order(body):
        if current.type in _NESTED_DEFINITIONS:
            continue

        if current.type == "call_expression":
            callee = current.child_by_field_name("function") or (
                current.named_children[0] if current.named_children else None
            )
            if callee is not None:
                arguments = len([c for c in current.named_children if c.type == "call_argument"])
                kind, name, receiver, sends_value = _classify_call(
                    callee, source, arguments, type_names
                )
                order += 1
                function.calls.append(
                    CallSite(
                        kind=kind,
                        name=name,
                        receiver=receiver,
                        # Collapsed to one line: a callee expression can wrap across four
                        # lines of source, and this text is quoted as evidence in findings.
                        text=" ".join(text_of(callee, source).split())[:200],
                        line=line_of(current),
                        order=order,
                        arg_count=arguments,
                        sends_value=sends_value,
                        is_delegate=name in DELEGATE_CALLS,
                        is_static=name == "staticcall",
                        is_try=_inside_try(current),
                    )
                )

        elif current.type in _ASSIGNMENTS:
            target = current.named_children[0] if current.named_children else None
            base = _base_identifier(target, source) if target else None
            if base is not None:
                order += 1
                written.add(base.start_byte)
                _record_access(
                    function, base, source, scope, own_state_vars, declared_names,
                    AccessKind.WRITE, order,
                )
                # `a += b` reads `a` before writing it; a plain `=` does not.
                if current.type == "augmented_assignment_expression":
                    _record_access(
                        function, base, source, scope, own_state_vars, declared_names,
                        AccessKind.READ, order,
                    )

        elif current.type == "update_expression":  # ++x / x--
            base = _base_identifier(current, source)
            if base is not None:
                order += 1
                written.add(base.start_byte)
                _record_access(
                    function, base, source, scope, own_state_vars, declared_names,
                    AccessKind.WRITE, order,
                )

        elif current.type == "emit_statement":
            name = _leading_identifier(current, source)
            if name:
                function.emits.append(name)

        elif current.type == "revert_statement":
            name = _leading_identifier(current, source)
            if name and name not in ("revert",):
                function.reverts.append(name)

        elif current.type == "assembly_statement":
            function.has_assembly = True

        elif current.type in _LOOPS:
            function.has_loop = True

        elif current.type == "unchecked":
            function.has_unchecked = True

    _record_reads(function, body, source, scope, own_state_vars, declared_names, written)

    function.emits = sorted(set(function.emits))
    function.reverts = sorted(set(function.reverts))


def _declared_names(contract: Contract | None) -> set[str]:
    """Names that are definitely *not* state variables: functions, events, types…"""
    if contract is None:
        return set()
    names = {f.name for f in contract.functions} | {m.name for m in contract.modifiers}
    names |= {e.name for e in contract.events} | {e.name for e in contract.errors}
    names |= {s.name for s in contract.structs} | {e.name for e in contract.enums}
    names.add(contract.name)
    return names


def _leading_identifier(node: Node, source: bytes) -> str:
    for child in _in_order(node):
        if child.type == "identifier":
            return text_of(child, source)
    return ""


def _record_access(
    function: Function,
    identifier: Node,
    source: bytes,
    scope: _Scope,
    own_state_vars: dict[str, str],
    declared_names: set[str],
    kind: AccessKind,
    order: int,
) -> None:
    name = text_of(identifier, source)
    if not name or name in BUILTINS or name in declared_names:
        return
    if scope.shadows(name, identifier.start_byte):
        return  # a local of the same name — not the state variable (SPEC §13.3)

    function.accesses.append(
        StateAccess(
            name=name,
            state_var_id=own_state_vars.get(name, ""),
            kind=kind,
            line=line_of(identifier),
            order=order,
        )
    )


def _record_reads(
    function: Function,
    body: Node,
    source: bytes,
    scope: _Scope,
    own_state_vars: dict[str, str],
    declared_names: set[str],
    written: set[int],
) -> None:
    """Reads of *known* state variables.

    Deliberately narrower than the write rule: an assignment target that is not a local is
    almost certainly state, but a bare identifier being read could be a constant, an
    imported symbol, an enum member or a type. Only names this contract actually declares
    as state are recorded, so the storage graph stays precise. Inherited reads are resolved
    by the Graph Engine, which knows the inheritance chain.
    """
    if not own_state_vars:
        return

    for node in _in_order(body):
        if node.type != "identifier" or node.start_byte in written:
            continue
        name = text_of(node, source)
        if name not in own_state_vars or name in declared_names:
            continue
        if scope.shadows(name, node.start_byte):
            continue
        if node.parent is not None and node.parent.type == "member_expression":
            # `x.balance` — only the base counts, and the base is the first child.
            if node.parent.named_children and node.parent.named_children[0] is not node:
                continue

        function.accesses.append(
            StateAccess(
                name=name,
                state_var_id=own_state_vars[name],
                kind=AccessKind.READ,
                line=line_of(node),
                order=0,  # reads outside an assignment carry no ordering requirement
            )
        )
