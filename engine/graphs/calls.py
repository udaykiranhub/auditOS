"""Call graph (SPEC §13.2) — the resolution ladder, and the two sentinels.

| Edge kind | How resolved | Confidence |
|---|---|---|
| internal / `this.f()` | name resolution within the **linearized** scope | high |
| `super.f()` | the next implementation in the MRO after the current contract | high |
| library call (`using L for T`) | the `using for` directives | medium |
| typed interface | receiver's declared type → interface → implementers | medium (fan-out) |
| external to an unknown address | → `UNKNOWN_EXTERNAL` | low |
| low-level `call`/`delegatecall`/`staticcall` | → `UNTRUSTED_EXTERNAL` | **flagged** |

Resolution runs against the flattened (MRO) member set, never the contract's own members —
SPEC calls building on the unlinearized contract the mistake that produces "a graph that
looks fine and is quietly wrong".

Nothing here guesses at a call it cannot see. A `delegatecall` to a computed address is
recorded as `UNRESOLVED_DELEGATECALL` rather than dropped, because "we could not follow
this" is information the agents need and an absent edge is not.
"""

from __future__ import annotations

from engine.core.models.code import (
    CallKind,
    CallSite,
    CodeModel,
    Contract,
    ContractKind,
    Function,
)
from engine.core.models.graph import (
    UNKNOWN_EXTERNAL,
    UNTRUSTED_EXTERNAL,
    Confidence,
    Edge,
    EdgeKind,
    Unresolved,
)
from engine.graphs.inheritance import Flattened
from engine.graphs.select import MAX_INTERFACE_FANOUT

#: Solidity built-ins that read as member calls but never leave the contract.
_NON_CALL_MEMBERS = frozenset(
    {
        "push",
        "pop",
        "length",
        "encode",
        "encodePacked",
        "encodeWithSelector",
        "encodeWithSignature",
        "encodeCall",
        "decode",
        "concat",
        "selector",
        "wrap",
        "unwrap",
        "min",
        "max",
    }
)

#: `x.transfer(y)` / `x.send(y)` on an `address payable` — one argument, sends ETH, and
#: reaches an arbitrary contract's `receive`. Two arguments means ERC-20 `transfer`, which
#: `tokens.py` classifies instead.
_ADDRESS_VALUE_SENDS = frozenset({"transfer", "send"})


class CallResolver:
    """Resolves every call site in the selected contracts into typed edges."""

    def __init__(
        self,
        code: CodeModel,
        included: set[str],
        linearization: dict[str, list[str]],
        flattened: dict[str, Flattened],
    ):
        self.code = code
        self.included = included
        self.linearization = linearization
        self.flattened = flattened

        self.contracts = {c.id: c for c in code.contracts if c.id in included}
        self._by_name: dict[str, list[Contract]] = {}
        for contract in self.contracts.values():
            self._by_name.setdefault(contract.name, []).append(contract)

        self._implementers = _implementers_of(code, included)
        self._free_functions: dict[str, list[Function]] = {}
        for source in code.sources:
            for function in source.free_functions:
                self._free_functions.setdefault(function.name, []).append(function)

        self.edges: list[Edge] = []
        self.unresolved: list[Unresolved] = []

    # ── Entry point ───────────────────────────────────────────────────────────

    def resolve_all(self) -> tuple[list[Edge], list[Unresolved]]:
        for contract_id in sorted(self.contracts):
            contract = self.contracts[contract_id]
            flat = self.flattened.get(contract_id)
            if flat is None:
                continue
            for function in (*contract.functions, *contract.modifiers):
                self._resolve_function(contract, function, flat)
        return self.edges, self.unresolved

    # ── One function ──────────────────────────────────────────────────────────

    def _resolve_function(
        self, contract: Contract, function: Function, flat: Flattened
    ) -> None:
        types = self._type_environment(contract, function)

        # Modifiers run before the body and are where access control lives — the permission
        # graph is built entirely from these edges.
        for name in function.modifiers:
            modifier = flat.modifiers.get(name)
            if modifier is not None:
                self._edge(
                    function.id, modifier.id, EdgeKind.MODIFIED_BY,
                    line=function.line_start, via=name,
                )
            else:
                # Almost always a base-constructor invocation (`Ownable(msg.sender)`), not a
                # missing modifier, so this is not reported as unresolved.
                target = self._contract_by_name(name)
                if target is not None:
                    self._edge(
                        function.id, target.id, EdgeKind.CALLS,
                        confidence="medium", line=function.line_start, via="constructor",
                    )

        for call in function.calls:
            self._resolve_call(contract, function, flat, types, call)

    def _resolve_call(
        self,
        contract: Contract,
        function: Function,
        flat: Flattened,
        types: dict[str, str],
        call: CallSite,
    ) -> None:
        match call.kind:
            case CallKind.LOW_LEVEL:
                self._low_level(function, call)
            case CallKind.INTERNAL:
                self._internal(function, flat, call)
            case CallKind.THIS:
                self._internal(function, flat, call, via="this")
            case CallKind.SUPER:
                self._super(contract, function, call)
            case CallKind.MEMBER:
                self._member(contract, function, flat, types, call)
            case CallKind.NEW:
                self._new(function, call)
            case CallKind.BUILTIN:
                pass  # require/keccak256/… — no edge, by design

        if call.sends_value:
            target = self._value_target(function, flat, types, call)
            self._edge(
                function.id, target, EdgeKind.SENDS_VALUE,
                confidence="high", call=call,
            )

    # ── Ladder rungs ──────────────────────────────────────────────────────────

    def _low_level(self, function: Function, call: CallSite) -> None:
        """SPEC §13.2: flag prominently. This is where the bugs are."""
        kind = (
            EdgeKind.DELEGATECALLS
            if call.is_delegate
            else EdgeKind.STATICCALLS
            if call.is_static
            else EdgeKind.CALLS
        )
        self._edge(
            function.id, UNTRUSTED_EXTERNAL, kind, confidence="high", call=call,
        )
        if call.is_delegate:
            # A delegatecall runs foreign code against *our* storage. Never silently ignore.
            self.unresolved.append(
                Unresolved(
                    reason="UNRESOLVED_DELEGATECALL",
                    function=function.id,
                    detail=f"delegatecall target is a runtime value: {call.text}",
                    line=call.line,
                )
            )

    def _internal(
        self, function: Function, flat: Flattened, call: CallSite, via: str | None = None
    ) -> None:
        target = flat.resolve(call.name, call.arg_count)
        if target is not None:
            self._edge(function.id, target.id, EdgeKind.CALLS, call=call, via=via)
            return

        free = self._free_functions.get(call.name)
        if free:
            self._edge(
                function.id, free[0].id, EdgeKind.CALLS,
                confidence="medium" if len(free) > 1 else "high", call=call, via="free",
            )
            return

        # A struct constructor, an enum, a user-defined type, or a member of a parent we
        # never resolved. Recorded, not invented.
        self.unresolved.append(
            Unresolved(
                reason="UNRESOLVED_INTERNAL_CALL",
                function=function.id,
                detail=f"no definition of `{call.name}` in the linearized scope",
                line=call.line,
            )
        )

    def _super(self, contract: Contract, function: Function, call: CallSite) -> None:
        """`super.f()` — the next implementation *after* this contract in the MRO."""
        mro = self.linearization.get(contract.id, [contract.id])
        for ancestor_id in mro[1:]:
            ancestor = self.contracts.get(ancestor_id)
            if ancestor is None:
                continue
            for candidate in ancestor.functions:
                if candidate.name != call.name:
                    continue
                if call.arg_count >= 0 and len(candidate.params) != call.arg_count:
                    continue
                self._edge(function.id, candidate.id, EdgeKind.CALLS, call=call, via="super")
                return

        self.unresolved.append(
            Unresolved(
                reason="UNRESOLVED_INTERNAL_CALL",
                function=function.id,
                detail=f"super.{call.name} has no implementation in the MRO of {contract.name}",
                line=call.line,
            )
        )

    def _member(
        self,
        contract: Contract,
        function: Function,
        flat: Flattened,
        types: dict[str, str],
        call: CallSite,
    ) -> None:
        """`x.f(...)` — a library call, a typed external call, or an unknown address."""
        receiver = call.receiver or ""

        if call.name in _NON_CALL_MEMBERS and receiver not in self._by_name:
            return

        # `x.transfer(v)` / `x.send(v)` on an address is an ETH send to arbitrary code, which
        # belongs at the untrusted sentinel — not a call to a function named `transfer`.
        if call.name in _ADDRESS_VALUE_SENDS and call.arg_count == 1:
            self._edge(
                function.id, UNTRUSTED_EXTERNAL, EdgeKind.CALLS,
                confidence="high", call=call, via=receiver or None,
            )
            return

        # 1. `using L for T` — the library is named directly or attached to the receiver.
        library = self._library_for(contract, receiver, call, types)
        if library is not None:
            self._edge(
                function.id, library.id, EdgeKind.CALLS,
                confidence="medium", call=call, via=f"library {library.name}",
            )
            self._resolve_into(library, call, function, confidence="medium")
            return

        # 2. `SomeLibrary.f()` / `SomeContract.f()` written literally.
        named = self._contract_by_name(receiver)
        if named is not None and named.kind is ContractKind.LIBRARY:
            self._resolve_into(named, call, function, confidence="high")
            return

        # 3. Typed receiver: `IVault vault; vault.f()`.
        declared = types.get(receiver)
        target_contract = self._contract_by_name(declared) if declared else None
        if target_contract is None and receiver:
            # `IVault(addr).f()` — the parser records the cast expression as the receiver.
            target_contract = self._contract_by_name(_cast_type(receiver))

        if target_contract is not None:
            self._external_typed(function, target_contract, call)
            return

        # 4. An address we cannot type.
        self._edge(
            function.id, UNKNOWN_EXTERNAL, EdgeKind.CALLS,
            confidence="low", call=call, via=receiver or None,
        )
        self.unresolved.append(
            Unresolved(
                reason="UNRESOLVED_EXTERNAL_CALL",
                function=function.id,
                detail=f"receiver `{receiver}` has no known type: {call.text}",
                line=call.line,
            )
        )

    def _external_typed(
        self, function: Function, target: Contract, call: CallSite
    ) -> None:
        """Interface → every implementing contract in the repo (SPEC §13.2 fan-out)."""
        kind = self._external_kind(target, call)

        if target.kind is not ContractKind.INTERFACE:
            self._resolve_into(target, call, function, confidence="medium", kind=kind)
            return

        implementers = sorted(self._implementers.get(target.id, []))[:MAX_INTERFACE_FANOUT]
        if not implementers:
            # A declared interface with no implementation in-repo is an external protocol —
            # an oracle, a router, a bridge. That is exactly what the sentinel is for.
            self._edge(
                function.id, UNKNOWN_EXTERNAL, kind,
                confidence="low", call=call, via=target.name,
            )
            self._resolve_into(target, call, function, confidence="medium", kind=kind)
            return

        for implementer_id in implementers:
            implementer = self.contracts.get(implementer_id)
            if implementer is not None:
                self._resolve_into(
                    implementer, call, function, confidence="medium",
                    via=target.name, kind=self._external_kind(implementer, call),
                )

    def _external_kind(self, target: Contract, call: CallSite) -> EdgeKind:
        """An external `view`/`pure` call compiles to STATICCALL — record it as one.

        The distinction is load-bearing downstream: a staticcall cannot write, so nothing
        it reaches can reenter and mutate state. Recording `require(factory.isPool(x))` as
        an ordinary external call gives it the shape of a reentrancy candidate and none of
        the substance, and those false candidates crowd out the real ones.
        """
        flat = self.flattened.get(target.id)
        callee = flat.resolve(call.name, call.arg_count) if flat else None
        if callee is not None and callee.mutability in ("view", "pure"):
            return EdgeKind.STATICCALLS
        return EdgeKind.CALLS

    def _resolve_into(
        self,
        target: Contract,
        call: CallSite,
        function: Function,
        confidence: Confidence,
        via: str | None = None,
        kind: EdgeKind = EdgeKind.CALLS,
    ) -> None:
        """Edge into a named function of `target`, resolved through its own MRO."""
        flat = self.flattened.get(target.id)
        callee = flat.resolve(call.name, call.arg_count) if flat else None
        if callee is None:
            self._edge(
                function.id, target.id, kind,
                confidence="low", call=call, via=via or target.name,
            )
            return
        self._edge(
            function.id, callee.id, kind, confidence=confidence, call=call, via=via,
        )

    def _new(self, function: Function, call: CallSite) -> None:
        target = self._contract_by_name(call.name)
        self._edge(
            function.id,
            target.id if target else UNKNOWN_EXTERNAL,
            EdgeKind.CREATES,
            confidence="high" if target else "low",
            call=call,
            via=call.name,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _value_target(
        self, function: Function, flat: Flattened, types: dict[str, str], call: CallSite
    ) -> str:
        """Where the ETH goes. Low-level and untyped sends reach untrusted code."""
        if call.kind is CallKind.LOW_LEVEL:
            return UNTRUSTED_EXTERNAL
        if call.kind is CallKind.INTERNAL:
            target = flat.resolve(call.name, call.arg_count)
            return target.id if target else UNKNOWN_EXTERNAL
        declared = types.get(call.receiver or "")
        contract = self._contract_by_name(declared) if declared else None
        return contract.id if contract else UNTRUSTED_EXTERNAL

    def _type_environment(self, contract: Contract, function: Function) -> dict[str, str]:
        """`name → declared type` for everything visible inside this function body.

        Locals are not in `CodeModel` — SPEC §12.2 rules out expression-level modelling —
        so a `IVault v = IVault(a);` local resolves through the cast in the receiver text
        instead. State variables and parameters cover the large majority of real receivers.
        """
        types: dict[str, str] = {}
        for contract_id in self.linearization.get(contract.id, [contract.id]):
            ancestor = self.contracts.get(contract_id)
            if ancestor is None:
                continue
            for state_var in ancestor.state_vars:
                types.setdefault(state_var.name, _base_type(state_var.type))
        # Parameters shadow state variables — that is the whole point of the ordering here.
        for param in (*function.params, *function.returns):
            if param.name:
                types[param.name] = _base_type(param.type)
        return types

    def _library_for(
        self,
        contract: Contract,
        receiver: str,
        call: CallSite,
        types: dict[str, str],
    ) -> Contract | None:
        """Resolve a call that `using L for T` attached to a value.

        The receiver of an attached call is rarely the library's name — it is the *value*:
        `_balances[sender].sub(amount)` under `using SafeMath for uint256`. Matching only
        `SafeMath.sub(…)` leaves every one of those looking like an external member call,
        which floods the untrusted boundary with arithmetic and manufactures reentrancy
        candidates out of SafeMath. So three rungs, most certain first.
        """
        attached: list[Contract] = []
        for contract_id in self.linearization.get(contract.id, [contract.id]):
            ancestor = self.contracts.get(contract_id)
            if ancestor is None:
                continue
            for directive in ancestor.using_for:
                library = self._contract_by_name(directive.library)
                if library is None:
                    continue
                # a. `L.f(…)` — written literally.
                if directive.library == receiver:
                    return library
                # b. The receiver's declared type is what the directive attaches to.
                declared = types.get(receiver)
                if declared and directive.target_type in (declared, "*"):
                    if self._declares(library, call):
                        return library
                attached.append(library)

        # c. The receiver is an expression we cannot type (`_balances[sender]`,
        #    `a.b.c`). If exactly one attached library declares this name, it is that one;
        #    more than one and guessing would be worse than the fallback below.
        matching = [lib for lib in attached if self._declares(lib, call)]
        unique = {lib.id: lib for lib in matching}
        if len(unique) == 1:
            return next(iter(unique.values()))
        return None

    def _declares(self, library: Contract, call: CallSite) -> bool:
        flat = self.flattened.get(library.id)
        return flat is not None and flat.resolve(call.name, call.arg_count) is not None

    def _contract_by_name(self, name: str | None) -> Contract | None:
        if not name:
            return None
        candidates = self._by_name.get(name)
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        # Ambiguous across files: prefer in-scope, then the lowest ID, so the choice is
        # deterministic rather than dependent on parse order.
        return sorted(candidates, key=lambda c: (not c.in_scope, c.id))[0]

    def _edge(
        self,
        source: str,
        target: str,
        kind: EdgeKind,
        confidence: Confidence = "high",
        call: CallSite | None = None,
        line: int = 0,
        via: str | None = None,
    ) -> None:
        self.edges.append(
            Edge(
                source=source,
                target=target,
                kind=kind,
                confidence=confidence,
                line=call.line if call else line,
                order=call.order if call else -1,
                via=via,
                text=call.text if call else "",
            )
        )


def _implementers_of(code: CodeModel, included: set[str]) -> dict[str, list[str]]:
    """interface_id → contracts that inherit it, transitively."""
    direct: dict[str, list[str]] = {}
    for contract in code.contracts:
        if contract.id not in included:
            continue
        for parent_id in contract.inherits_ids:
            direct.setdefault(parent_id, []).append(contract.id)

    transitive: dict[str, list[str]] = {}
    for parent_id in direct:
        seen: set[str] = set()
        frontier = list(direct[parent_id])
        while frontier:
            child = frontier.pop()
            if child in seen:
                continue
            seen.add(child)
            frontier.extend(direct.get(child, []))
        transitive[parent_id] = sorted(seen)
    return transitive


def _base_type(type_name: str) -> str:
    text = type_name.strip()
    if text.startswith("mapping"):
        text = text.rpartition("=>")[2].strip().rstrip(")").strip()
    while text.endswith("]"):
        text = text[: text.rfind("[")].strip()
    return text.removeprefix("contract ").removeprefix("struct ").strip()


def _cast_type(receiver: str) -> str:
    """`IVault(addr)` → `IVault`; anything else unchanged."""
    head, sep, _ = receiver.partition("(")
    return head.strip() if sep else receiver
