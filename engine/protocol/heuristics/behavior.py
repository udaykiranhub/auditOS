"""Stage 16a — what one function body *does*, in order.

```
withdraw(uint256 shares)
 -3  CHECK           modifier nonReentrant
 -1  CHECK           modifier whenNotPaused
  0  CHECK           require(shares > 0)
  2  READ            totalShares
  4  CALCULATE       mulDiv(shares, totalAssets, totalShares)
  6  WRITE           totalShares
  8  TRANSFER        asset.transfer(msg.sender, amount)      ← control leaves
 11  WRITE           lastWithdrawAt                          ← after the call
```

**The sequence is the product.** Every other stage of this model records *what* a function
touches; nothing until here records *when*. Reentrancy is a WRITE after an EXTERNAL_CALL. A
stale read is a READ before a CHECK that never comes. Check-effects-interactions is a claim
about ordering and cannot be evaluated from an unordered set of facts, however complete.

**Nothing here is invented.** `CodeModel` stamps an `order` on every call site and every
state access precisely so this projection exists without a control-flow graph — which SPEC
§12.2 rules out and which cannot be reconstructed from a reference list. So a step exists
only where the parser recorded a position, the `detail` is the source text, and a call whose
target could not be resolved is typed `EXTERNAL_CALL` rather than guessed into something
more specific. Modifiers are the one exception to "order comes from the parser", and they
are not a guess either: Solidity runs them before the body, so they occupy the negative
positions by language semantics.

Two things this deliberately does not do. It does not branch — `if`/`else` are invisible
here, so a step sequence is the *textual* order, not an execution trace, and a reader must
not read it as one. And it does not judge: `writes_after_external_call` is a list of
candidates, not a finding, because the guard that makes it safe is frequently present.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from engine.core.models.code import (
    AccessKind,
    CallKind,
    CallSite,
    Contract,
    ContractKind,
    Function,
    FunctionKind,
)
from engine.core.models.evidence import (
    Confidence,
    Evidence,
    graph_evidence,
    source_evidence,
)
from engine.core.models.graph import SENTINELS
from engine.core.models.protocol import (
    EffectKind,
    FunctionBehavior,
    FunctionStep,
    Operation,
    OperationKind,
    StateItem,
)
from engine.protocol.heuristics.operations import preconditions
from engine.protocol.heuristics.signatures import (
    ProtocolIndex,
    privileged_names,
    signature_of,
)
from engine.protocol.ids import make_behavior_id

DETECTOR = "function_behavior"

#: Builtins that abort the transaction. Everything else builtin is arithmetic or encoding.
CHECK_BUILTINS = frozenset({"require", "assert", "revert"})

#: Member calls that are array operations, not calls to another address. `push` and `pop` do
#: not exist on `address`, so a receiver carrying them is storage or memory by construction.
ARRAY_OPERATIONS = frozenset({"push", "pop"})

#: Past this the sequence stops being a description and becomes a transcript. Truncation is
#: recorded on the record rather than applied silently — a reader who does not know the list
#: is a prefix will conclude "nothing happens after the external call" from its absence.
MAX_STEPS = 80

#: Cap on quoted external-call expressions. The steps carry the full picture; this list is
#: the at-a-glance summary and stops being one at length.
MAX_EXTERNAL = 12

#: Which non-entrypoint functions are worth describing. An internal helper that touches no
#: state and calls nothing is a formatting utility; one that writes storage is usually where
#: the accounting actually lives, and an agent handed only entrypoints never sees it.
_INTERNAL_KINDS = (FunctionKind.FUNCTION, FunctionKind.MODIFIER)

#: A guard clause mentioning `msg.sender`. The starting point for authorization extraction —
#: not the conclusion, because most such clauses are not authorization at all.
SENDER_CHECK = re.compile(r"(?:require\s*\(|if\s*\()(?P<cond>[^;{}]*\bmsg\.sender\b[^;{}]*)")

#: `a == msg.sender`, `msg.sender != b`. Equality against the caller is what authorization
#: looks like; a relational comparison against the caller's *balance* is not, and conflating
#: the two reports `realisedLiquidityOf[msg.sender] < assets` as an access-control check.
_SENDER_EQUALITY = re.compile(
    r"([\w.\[\]()]+)\s*(==|!=)\s*msg\.sender|msg\.sender\s*(?:==|!=)\s*([\w.\[\]()]+)"
)

#: `isTranche[msg.sender]` — an allowlist membership test.
_SENDER_MEMBERSHIP = re.compile(r"(\w+)\s*\[\s*msg\.sender\s*\]")

#: Role checks, which authorize without ever naming an address.
_ROLE_CALL = re.compile(
    r"\b(hasRole|_checkRole|checkRole|isAuthorized|canCall|requiresAuth|onlyRole)\b"
)

#: Any ordering comparison. Its presence alongside a membership test means the condition is
#: about *how much* the caller has, not *whether* the caller is allowed.
_RELATIONAL = re.compile(r"[<>]=?")

#: OperationKind → the clause that opens a function's purpose. Fixed phrasing, because a
#: generated sentence that varies between runs makes two artifacts diff as though the code
#: changed.
KIND_PHRASE: dict[OperationKind, str] = {
    OperationKind.DEPOSIT: "Accepts a deposit",
    OperationKind.WITHDRAW: "Processes a withdrawal",
    OperationKind.MINT: "Mints",
    OperationKind.BURN: "Burns",
    OperationKind.REDEEM: "Redeems a claim",
    OperationKind.BORROW: "Opens or increases a borrow",
    OperationKind.REPAY: "Repays debt",
    OperationKind.LIQUIDATE: "Liquidates a position",
    OperationKind.SWAP: "Swaps one asset for another",
    OperationKind.ADD_LIQUIDITY: "Adds liquidity",
    OperationKind.REMOVE_LIQUIDITY: "Removes liquidity",
    OperationKind.STAKE: "Stakes",
    OperationKind.UNSTAKE: "Unstakes",
    OperationKind.CLAIM: "Claims a payout",
    OperationKind.HARVEST: "Harvests yield",
    OperationKind.REBALANCE: "Rebalances",
    OperationKind.FLASH_LOAN: "Issues a flash loan",
    OperationKind.BRIDGE_SEND: "Sends across a bridge",
    OperationKind.BRIDGE_RECEIVE: "Receives from a bridge",
    OperationKind.PROPOSE: "Creates a governance proposal",
    OperationKind.VOTE: "Casts a vote",
    OperationKind.EXECUTE: "Executes a queued action",
    OperationKind.TRANSFER: "Transfers a balance",
    OperationKind.APPROVE: "Grants an allowance",
    OperationKind.INITIALIZE: "Initializes the contract",
    OperationKind.UPGRADE: "Changes the implementation",
    OperationKind.PAUSE: "Changes the paused state",
    OperationKind.CONFIGURE: "Changes configuration",
    OperationKind.ADMIN: "Performs an administrative action",
}


def describe(
    index: ProtocolIndex,
    contract: Contract,
    state: list[StateItem],
    operations: list[Operation],
) -> list[FunctionBehavior]:
    """Every function of one contract worth describing, in `SolidityID` order.

    Entrypoints always; internal functions and modifiers when they touch state or leave the
    frame. `state` and `operations` are the *whole model's* lists — a function may read
    storage declared in a parent, and the state item for it is filed under the parent.
    """
    state_by_var = {item.state_var_id: item.id for item in state}
    operation_by_function = {o.function_id: o for o in operations}

    described: list[FunctionBehavior] = []
    for function in (*contract.functions, *contract.modifiers):
        if not _worth_describing(function):
            continue
        described.append(
            _describe_one(
                index,
                contract,
                function,
                state_by_var,
                operation_by_function.get(function.id),
            )
        )
    return sorted(described, key=lambda b: b.id)


def _worth_describing(function: Function) -> bool:
    if not function.is_implemented:
        return False
    if function.kind not in (*_INTERNAL_KINDS, FunctionKind.CONSTRUCTOR,
                            FunctionKind.FALLBACK, FunctionKind.RECEIVE):
        return False
    if function.is_entrypoint or function.kind is FunctionKind.MODIFIER:
        return True
    # A constructor is not an operation — no actor exists yet — but it is where immutable
    # dependencies and initial authority are set, which is a question agents ask constantly.
    if function.kind is FunctionKind.CONSTRUCTOR:
        return True
    return bool(function.accesses) or any(
        call.kind is not CallKind.BUILTIN for call in function.calls
    )


def _describe_one(
    index: ProtocolIndex,
    contract: Contract,
    function: Function,
    state_by_var: dict[str, str],
    operation: Operation | None,
) -> FunctionBehavior:
    steps, truncated = _steps(index, contract, function, state_by_var)
    # A constructor's base-contract invocations sit in the modifier slot syntactically and
    # are not modifiers. Filtering them here keeps `modifiers`, `caller_requirements` and
    # `preconditions` from reporting `Creditor` as a guard on the constructor.
    applied = [
        name
        for name in function.modifiers
        if not _is_base_constructor(contract, function, name)
    ]
    guards = _guards(index, contract, applied)

    external = [
        step.detail or step.target
        for step in steps
        if step.kind in (EffectKind.EXTERNAL_CALL, EffectKind.CREATE)
    ]
    internal = sorted(
        {step.target for step in steps if step.kind is EffectKind.INTERNAL_CALL and step.target}
    )

    reads = sorted({state_by_var[v] for v in function.reads if v in state_by_var})
    writes = sorted({state_by_var[v] for v in function.writes if v in state_by_var})

    return FunctionBehavior(
        id=make_behavior_id(function.id),
        function_id=function.id,
        contract_id=contract.id,
        name=function.name,
        signature=signature_of(function),
        visibility=function.visibility,
        mutability=function.mutability,
        operation_id=operation.id if operation is not None else None,
        purpose=_purpose(function, operation, guards, writes, external, state_by_var),
        documented_purpose=natspec_lede(function.natspec),
        inputs=[_declaration(param.type, param.name) for param in function.params],
        outputs=[_declaration(param.type, param.name) for param in function.returns],
        modifiers=applied,
        caller_requirements=guards,
        preconditions=[
            line
            for line in preconditions(function)
            if line not in _base_constructor_preconditions(contract, function)
        ],
        reads=reads,
        writes=writes,
        internal_calls=internal,
        external_calls=_dedupe(external)[:MAX_EXTERNAL],
        token_movements=_token_movements(index, function),
        emits=sorted(set(function.emits)),
        reverts=sorted(set(function.reverts)),
        steps=steps,
        steps_truncated=truncated,
        writes_after_external_call=_writes_after_external(steps, state_by_var),
        is_entrypoint=function.is_entrypoint and function.kind is not FunctionKind.MODIFIER,
        is_view=index.is_view(function),
        is_payable=function.mutability == "payable",
        is_privileged=bool(guards),
        has_assembly=function.has_assembly,
        has_loop=function.has_loop,
        has_unchecked=function.has_unchecked,
        # Structural throughout: every field above is a projection of what the parser and
        # the graph recorded. `purpose` is the one interpretation, and it is assembled from
        # those same facts rather than from the function's name alone.
        confidence=Confidence.DERIVED,
        evidence=_evidence(contract, function, steps),
    )


# ── The effect sequence ───────────────────────────────────────────────────────


def _is_base_constructor(contract: Contract, function: Function, modifier: str) -> bool:
    """`constructor(…) ERC4626(asset) Owned(msg.sender)` — a base call in the modifier slot.

    The parser records these as modifiers because that is where the grammar puts them. They
    initialise parents; they gate nothing, and reporting `Owned` as a caller requirement
    states that the constructor is access-controlled when it is not.
    """
    if function.kind is not FunctionKind.CONSTRUCTOR:
        return False
    return _bare_name(modifier).lower() in {name.lower() for name in contract.inherits}


def _base_constructor_preconditions(contract: Contract, function: Function) -> set[str]:
    """The `modifier X` lines `preconditions()` emits for base-constructor invocations."""
    return {
        f"modifier {modifier}"
        for modifier in function.modifiers
        if _is_base_constructor(contract, function, modifier)
    }


def _guards(index: ProtocolIndex, contract: Contract, applied: list[str]) -> list[str]:
    """Modifiers that actually stand between an arbitrary caller and this body.

    Two sources, because a name-only test is wrong in the direction that matters. `index
    .guards()` recognises the conventional vocabulary — `onlyOwner`, `onlyRole`. It does not
    recognise `onlyTranche` or `onlyLiquidator`, whose bodies read `if (msg.sender !=
    LIQUIDATOR) revert` and which gate their functions exactly as hard.

    Reading the modifier body is what closes that gap, and it is the same source the
    permission pass uses. Before this, one artifact could report `auctionRepay` as
    unprivileged in its behaviour record and `contract_only` in its permission record — a
    contradiction an agent has no way to resolve.
    """
    table = index.modifier_table.get(contract.id, {})
    found = set(privileged_names(applied))
    for name in applied:
        definition = table.get(_bare_name(name))
        if definition is not None and authorization_checks(definition):
            found.add(name)
    return sorted(found)


def _steps(
    index: ProtocolIndex,
    contract: Contract,
    function: Function,
    state_by_var: dict[str, str],
) -> tuple[list[FunctionStep], int]:
    """Modifiers, then the body's calls and state accesses merged on their recorded order.

    Two independent order axes do *not* need reconciling: `CodeModel` numbers calls and
    accesses from one counter as it walks the body, so the two interleave correctly. The
    merge sorts on that counter and breaks ties on the step kind so a read and a write at
    the same position order reproducibly.
    """
    resolved = index.call_targets_by_order.get(function.id, {})
    token_orders = index.token_targets_by_order.get(function.id, {})

    steps: list[FunctionStep] = []

    # Modifiers execute before the body. Negative positions, in declared order, so the
    # sequence reads correctly without pretending the parser recorded a position for them.
    #
    # A constructor's base-contract invocations occupy the same syntactic slot — `constructor
    # (…) ERC4626(…) Owned(msg.sender)` — and the parser records them as modifiers because
    # that is where the grammar puts them. They are not guards, and typing them `CHECK` would
    # tell a reader that `ERC4626` validates something.
    for offset, modifier in enumerate(function.modifiers):
        is_base_constructor = _is_base_constructor(contract, function, modifier)
        steps.append(
            FunctionStep(
                order=-len(function.modifiers) + offset,
                kind=EffectKind.INTERNAL_CALL if is_base_constructor else EffectKind.CHECK,
                detail=(
                    f"base constructor {modifier}"
                    if is_base_constructor
                    else f"modifier {modifier}"
                ),
                line=function.line_start,
            )
        )

    for access in function.accesses:
        steps.append(
            FunctionStep(
                order=access.order,
                kind=EffectKind.READ if access.kind is AccessKind.READ else EffectKind.WRITE,
                detail=access.name,
                target=state_by_var.get(access.state_var_id, access.state_var_id),
                line=access.line,
            )
        )

    for call in function.calls:
        kind, target = _step_kind(index, contract, call, resolved, token_orders)
        steps.append(
            FunctionStep(
                order=call.order,
                kind=kind,
                detail=_call_text(call),
                target=target,
                line=call.line,
            )
        )

    steps.sort(key=lambda step: (step.order, step.kind.value, step.detail))
    if len(steps) <= MAX_STEPS:
        return steps, 0
    return steps[:MAX_STEPS], len(steps) - MAX_STEPS


def _step_kind(
    index: ProtocolIndex,
    contract: Contract,
    call: CallSite,
    resolved: dict[int, str],
    token_orders: dict[int, str],
) -> tuple[EffectKind, str]:
    """Type one call site. Unresolved always falls *outward*, never inward.

    An `EXTERNAL_CALL` that was really internal costs an agent one wasted question. An
    internal label on a call that really left the frame hides the reentrancy precondition
    entirely, so the asymmetry is deliberate.
    """
    if call.order in token_orders:
        return EffectKind.TRANSFER, token_orders[call.order]

    if call.kind is CallKind.BUILTIN:
        if call.name in CHECK_BUILTINS:
            return EffectKind.CHECK, ""
        return EffectKind.CALCULATE, ""

    # `tranches.push(x)` parses as a member call and is not one: `push`/`pop` exist only on
    # arrays and `bytes`, so the receiver is storage or memory, never an address. Typing them
    # as external calls put a phantom trust-boundary crossing in the middle of half the
    # admin functions in the repository — and every state write after one then read as a
    # check-effects-interactions candidate.
    if call.kind is CallKind.MEMBER and call.name in ARRAY_OPERATIONS:
        return EffectKind.WRITE, ""

    if call.kind is CallKind.NEW:
        return EffectKind.CREATE, resolved.get(call.order, "")

    if call.kind is CallKind.LOW_LEVEL:
        return EffectKind.EXTERNAL_CALL, resolved.get(call.order, "")

    if call.kind in (CallKind.INTERNAL, CallKind.SUPER):
        return EffectKind.INTERNAL_CALL, resolved.get(call.order, "")

    # `this.f()` really is an external call: a fresh frame, `msg.sender` becomes the
    # contract, and modifiers re-run. Treating it as internal is a classic mis-read.
    if call.kind is CallKind.THIS:
        return EffectKind.EXTERNAL_CALL, resolved.get(call.order, "")

    target = resolved.get(call.order, "")
    if target and target not in SENTINELS:
        owner = _owner_of(index, target)
        if owner is not None:
            if _stays_in_frame(index, contract, owner):
                return EffectKind.INTERNAL_CALL, target
            return EffectKind.EXTERNAL_CALL, target
        # The graph resolved the receiver but not the overload, so `target` names a contract
        # rather than a function. Fall through to the structural test rather than outward.

    # Two shapes are library calls on their face — `SafeCastLib.mulDiv(x)` and, through
    # `using FixedPointMathLib for uint256`, `amount.mulDivUp(a, b)`. Neither transfers
    # control, and typing them as crossings marks every state write after an arithmetic
    # helper as a CEI candidate. The evidence is structural — a `library` declaration, a
    # `using` directive — not a naming convention, which is what lets it overrule the
    # otherwise-deliberate habit of falling outward when unsure.
    if _is_library_call(index, contract, call, target):
        return EffectKind.INTERNAL_CALL, target
    return EffectKind.EXTERNAL_CALL, target


def _is_library_call(
    index: ProtocolIndex, contract: Contract, call: CallSite, target: str
) -> bool:
    if call.is_delegate:
        # A `delegatecall` to a library still transfers control into code this contract does
        # not own, executing against its own storage. Never in-frame.
        return False
    resolved_owner = index.contracts.get(target)
    if resolved_owner is not None and resolved_owner.kind is ContractKind.LIBRARY:
        return True
    if call.receiver and call.receiver in index.libraries_by_name:
        return True
    return call.name in index.bound_library_members(contract.id)


def _stays_in_frame(index: ProtocolIndex, contract: Contract, owner: Contract) -> bool:
    """A library call and an inherited call run in this contract's own frame.

    Libraries are the reason this matters: `using SafeERC20 for IERC20` puts `safeTransfer`
    on a member expression that looks identical to an external call, and typing every one of
    them as a trust-boundary crossing would bury the real crossings in noise.
    """
    if owner.kind is ContractKind.LIBRARY:
        return True
    return owner.id == contract.id or owner.id in index.query.inheritance(contract.id)


def _owner_of(index: ProtocolIndex, function_id: str) -> Contract | None:
    function = index.functions.get(function_id)
    if function is None or function.contract_id is None:
        return None
    return index.contracts.get(function.contract_id)


#: The step kinds that mean control left this frame — the only ones a write can come "after"
#: in the sense that matters.
_LEAVES_FRAME = frozenset(
    {EffectKind.EXTERNAL_CALL, EffectKind.TRANSFER, EffectKind.CREATE}
)


def _writes_after_external(
    steps: list[FunctionStep], state_by_var: dict[str, str]
) -> list[str]:
    """State written at a position after control first left the frame.

    Positional, not path-sensitive: the write may be on a branch the call cannot reach, and
    a reentrancy guard may make the whole question moot. That is exactly why this is a list
    of candidates on a descriptive record rather than a finding — SPEC §13.3 draws the same
    line for the graph's own reentrancy candidates.
    """
    first = next((step.order for step in steps if step.kind in _LEAVES_FRAME), None)
    if first is None:
        return []
    return sorted(
        {
            step.target
            for step in steps
            if step.kind is EffectKind.WRITE and step.order > first and step.target
        }
    )


# ── Description ───────────────────────────────────────────────────────────────


def _purpose(
    function: Function,
    operation: Operation | None,
    guards: list[str],
    writes: list[str],
    external: list[str],
    state_by_var: dict[str, str],
) -> str:
    """One sentence, assembled from what was observed — never from the name alone.

    A name-only sentence ("deposit deposits") restates the identifier and adds nothing an
    agent did not have. What is worth saying is what the body *touches*, so the clause about
    the operation kind is only ever the opening, and it is dropped entirely when the kind
    could not be established.
    """
    clauses: list[str] = []

    if function.kind is FunctionKind.CONSTRUCTOR:
        clauses.append("Deployment-time initialization")
    elif function.kind is FunctionKind.MODIFIER:
        clauses.append("Guard applied to other functions")
    elif operation is not None and operation.kind in KIND_PHRASE:
        clauses.append(KIND_PHRASE[operation.kind])
    elif function.mutability in ("view", "pure"):
        clauses.append("Reports derived or stored values")

    if guards:
        clauses.append(f"restricted by {', '.join(guards[:3])}")
    if writes:
        clauses.append(f"writes {_names(writes, state_by_var)}")
    elif function.mutability not in ("view", "pure") and not clauses:
        clauses.append("changes no storage of its own")
    if external:
        clauses.append(f"calls out to {_dedupe(external)[0]}")

    if not clauses:
        return ""
    sentence = "; ".join(clauses)
    return sentence[0].upper() + sentence[1:] + "."


def _names(state_ids: list[str], state_by_var: dict[str, str]) -> str:
    """`state:src/V.sol:V#totalAssets` → `totalAssets`, at most three, then a count."""
    by_id = {value: key for key, value in state_by_var.items()}
    names = [by_id.get(sid, sid).rpartition("#")[2] or sid for sid in state_ids]
    if len(names) <= 3:
        return ", ".join(names)
    return f"{', '.join(names[:3])} and {len(names) - 3} more"


def natspec_lede(natspec: str | None) -> str:
    """The author's own one-line description, verbatim.

    `@notice` first — it is the sentence written for users of the function — then `@dev`,
    then the first prose line. Quoted rather than paraphrased: a paraphrase in a field that
    reads like documentation is an unattributed interpretation, and reconciling docs against
    code (§14) is impossible once the docs have been rewritten by us.
    """
    if not natspec:
        return ""
    lines = [
        line.strip().lstrip("/*").lstrip("*").strip()
        for line in natspec.splitlines()
    ]
    for tag in ("@notice", "@dev"):
        for line in lines:
            if line.startswith(tag):
                text = line[len(tag) :].strip()
                if text:
                    return text[:300]
    for line in lines:
        if line and not line.startswith("@") and not line.startswith("/"):
            return line[:300]
    return ""


def _token_movements(index: ProtocolIndex, function: Function) -> list[str]:
    """`transfers → asset`, from the Graph Engine's signature-typed edges.

    Signature-derived, so this is a fact about what the code calls rather than a reading of
    what it means: `transfer(address,uint256)` is an ERC-20 transfer whatever the variable
    holding the token is called.
    """
    movements = {
        f"{kind.value} via {receiver}"
        for kind, receiver, _, _ in index.token_edges_by_function.get(function.id, [])
    }
    return sorted(movements)


def _declaration(type_name: str, name: str) -> str:
    return f"{type_name} {name}".strip()


def _bare_name(modifier: str) -> str:
    """`Owned(msg.sender)` → `Owned`."""
    return modifier.partition("(")[0].strip()


def _call_text(call: CallSite) -> str:
    text = " ".join(call.text.split())[:120]
    if call.is_delegate:
        return f"{text} (delegatecall)"
    if call.is_static:
        return f"{text} (staticcall)"
    if call.sends_value:
        return f"{text} (sends value)"
    return text


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _evidence(
    contract: Contract, function: Function, steps: list[FunctionStep]
) -> list[Evidence]:
    evidence: list[Evidence] = [
        source_evidence(
            function.id,
            f"{function.visibility} {function.mutability} {function.kind.value}",
            path=contract.path,
            line=function.line_start,
            line_end=function.line_end,
            detector=DETECTOR,
        )
    ]
    leaving = next((step for step in steps if step.kind in _LEAVES_FRAME), None)
    if leaving is not None:
        evidence.append(
            graph_evidence(
                function.id,
                "external call",
                leaving.target or "@UNKNOWN_EXTERNAL",
                detail=leaving.detail,
                detector=DETECTOR,
            )
        )
    return evidence


class AuthCheck(NamedTuple):
    """One authorization test read out of a body, with what it compares the caller against.

    `counterparty` is the *other side* of the comparison as written — `owner`, `LIQUIDATOR`,
    `isTranche` — and is what lets the permission stage decide the mechanism from evidence
    instead of from a modifier's name. Empty when the check is a role call, which authorizes
    without naming an address.
    """

    text: str
    counterparty: str
    via_role: bool


def authorization_checks(function: Function) -> list[AuthCheck]:
    """Inline authorization written against `msg.sender`, verbatim and deduped.

    A protocol that writes `require(msg.sender == factory)` instead of declaring
    `onlyFactory` is just as gated, and a permission model built only from modifier names
    reports it as open — the difference between "anyone may call this" and "only the factory
    may", stated backwards.

    The filtering is the substance. Three shapes count as authorization:

    ```
    accountOwner != msg.sender          equality against the caller
    isTranche[msg.sender]               allowlist membership
    hasRole(ADMIN, msg.sender)          role check
    ```

    and one shape emphatically does not:

    ```
    realisedLiquidityOf[msg.sender] < assets      a balance, not a permission
    ```

    That last one is a membership expression too, which is why presence of `msg.sender` and
    a mapping lookup cannot be the test — an ordering comparison means the condition is about
    *how much* the caller has, not *whether* the caller is allowed.
    """
    found: list[AuthCheck] = []
    for match in SENDER_CHECK.finditer(function.raw):
        condition = match.group("cond")
        text = " ".join(match.group(0).split())[:200]

        if _ROLE_CALL.search(condition):
            found.append(AuthCheck(text, "", True))
            continue

        equality = _SENDER_EQUALITY.search(condition)
        if equality is not None:
            found.append(AuthCheck(text, equality.group(1) or equality.group(3) or "", False))
            continue

        membership = _SENDER_MEMBERSHIP.search(condition)
        if membership is not None and not _RELATIONAL.search(condition):
            found.append(AuthCheck(text, membership.group(1), False))

    seen: set[str] = set()
    unique: list[AuthCheck] = []
    for check in found:
        if check.text not in seen:
            seen.add(check.text)
            unique.append(check)
    return unique[:6]


__all__ = [
    "ARRAY_OPERATIONS",
    "CHECK_BUILTINS",
    "KIND_PHRASE",
    "MAX_STEPS",
    "AuthCheck",
    "authorization_checks",
    "describe",
    "natspec_lede",
]
