"""Stages 9 and 10 — what storage *means*, and how each operation moves it.

```
totalAssets   ACCOUNTING_TOTAL   written by deposit, withdraw
              deposit  →  INCREASE  `totalAssets += amount`
              withdraw →  DECREASE  `totalAssets -= amount`
```

**Readers and writers come from the storage graph**, so they are complete for everything the
graph can see and honestly empty for what it cannot. A variable mutated only inside inline
assembly shows no writers, which is why `Coverage.unmodelled` names assembly explicitly
rather than letting the empty list read as "nothing writes this".

Transitions are **symbolic**. `delta_expr` holds the assignment as written; concrete
before/after values belong to an executed trace (Phase I), and a fabricated one is the most
convincing way there is to mislead an agent. `after_external_call` is carried through from
the body ordering, which is what makes check-effects reasoning possible at this level.
"""

from __future__ import annotations

import re

from engine.core.models.code import AccessKind, FunctionKind, StateVar
from engine.core.models.evidence import (
    Confidence,
    Evidence,
    graph_evidence,
    heuristic_evidence,
    source_evidence,
)
from engine.core.models.protocol import (
    Asset,
    ContractClassification,
    Operation,
    StateItem,
    StateRole,
    StateTransition,
    TransitionEffect,
)
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_state_id, make_transition_id

DETECTOR = "state_model"

#: Name fragment → the role the variable plays. Ordered; the first match wins, so specific
#: fragments precede general ones (`totalsupply` before `total`, `borrowindex` before `index`).
ROLE_BY_NAME: tuple[tuple[str, StateRole], ...] = (
    ("reentrancy", StateRole.LOCK),
    ("locked", StateRole.LOCK),
    ("status", StateRole.LOCK),
    ("paused", StateRole.FLAG),
    ("initialized", StateRole.FLAG),
    ("nonce", StateRole.NONCE),
    ("totalsupply", StateRole.SHARE_SUPPLY),
    ("totalshares", StateRole.SHARE_SUPPLY),
    ("totalassets", StateRole.ACCOUNTING_TOTAL),
    ("totalborrow", StateRole.ACCOUNTING_TOTAL),
    ("totaldebt", StateRole.ACCOUNTING_TOTAL),
    ("total", StateRole.ACCOUNTING_TOTAL),
    ("balanceof", StateRole.USER_BALANCE),
    ("balance", StateRole.USER_BALANCE),
    ("shares", StateRole.USER_BALANCE),
    ("staked", StateRole.USER_BALANCE),
    ("deposits", StateRole.USER_BALANCE),
    ("borrows", StateRole.DEBT_RECORD),
    ("debt", StateRole.DEBT_RECORD),
    ("collateral", StateRole.COLLATERAL_RECORD),
    ("exchangerate", StateRole.EXCHANGE_RATE),
    ("pricepershare", StateRole.EXCHANGE_RATE),
    ("index", StateRole.ACCUMULATOR),
    ("pertokenstored", StateRole.ACCUMULATOR),
    ("cumulative", StateRole.ACCUMULATOR),
    ("accumulated", StateRole.ACCUMULATOR),
    ("price", StateRole.PRICE),
    ("rate", StateRole.RATE_PARAM),
    ("fee", StateRole.RATE_PARAM),
    ("bps", StateRole.RATE_PARAM),
    ("role", StateRole.ROLE_REGISTRY),
    ("owner", StateRole.ROLE_REGISTRY),
    ("admin", StateRole.ROLE_REGISTRY),
    ("authority", StateRole.ROLE_REGISTRY),
    ("timestamp", StateRole.TIMESTAMP),
    ("deadline", StateRole.TIMESTAMP),
    ("lastupdate", StateRole.TIMESTAMP),
    ("periodfinish", StateRole.TIMESTAMP),
    ("allowance", StateRole.CONFIG),
    ("cached", StateRole.CACHE),
)

#: Roles whose corruption breaks solvency or authorization. Drives ranking, not severity.
CRITICAL_ROLES = frozenset(
    {
        StateRole.ACCOUNTING_TOTAL,
        StateRole.SHARE_SUPPLY,
        StateRole.USER_BALANCE,
        StateRole.DEBT_RECORD,
        StateRole.COLLATERAL_RECORD,
        StateRole.EXCHANGE_RATE,
        StateRole.ROLE_REGISTRY,
        StateRole.ACCUMULATOR,
    }
)

#: `totalAssets += amount` / `shares[msg.sender] -= amount` / `owner = newOwner`.
_ASSIGN = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]*\])*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)"
    r"\s*(\+=|-=|=)\s*([^;]+);"
)
_DELETE = re.compile(r"\bdelete\s+([A-Za-z_][A-Za-z0-9_]*)")


def detect(
    index: ProtocolIndex,
    classifications: list[ContractClassification],
    assets: list[Asset],
) -> list[StateItem]:
    """One item per state variable on a classified contract, with its meaning and users."""
    asset_by_var = {
        state_var_id: asset.id for asset in assets for state_var_id in asset.state_var_ids
    }
    admin_writers = _admin_only_writers(index)

    items: list[StateItem] = []
    for classification in classifications:
        contract = index.contracts.get(classification.contract_id)
        if contract is None:
            continue
        for variable in contract.state_vars:
            items.append(
                _build(index, variable, classification, asset_by_var, admin_writers)
            )
    return items


def _build(
    index: ProtocolIndex,
    variable: StateVar,
    classification: ContractClassification,
    asset_by_var: dict[str, str],
    admin_writers: set[str],
) -> StateItem:
    role = _role_of(variable)
    writers = index.query.writers_of(variable.id)
    readers = index.query.readers_of(variable.id)

    evidence: list[Evidence] = [
        source_evidence(
            variable.id,
            f"{variable.type} {variable.name}",
            line=variable.line,
            detector=DETECTOR,
        )
    ]
    evidence.extend(
        graph_evidence(writer, "writes", variable.id, detector=DETECTOR)
        for writer in writers[:3]
    )
    if role is not StateRole.UNKNOWN:
        evidence.append(
            heuristic_evidence(DETECTOR, f"name suggests {role.value}", ref=variable.id)
        )

    return StateItem(
        id=make_state_id(variable.id),
        state_var_id=variable.id,
        contract_id=classification.contract_id,
        name=variable.name,
        type=variable.type,
        role=role,
        meaning=_meaning(variable, role),
        readers=readers,
        writers=writers,
        asset_id=asset_by_var.get(variable.id),
        is_constant=variable.is_constant,
        is_immutable=variable.is_immutable,
        # Only writable from a guarded path — a lever, and therefore a risk surface.
        is_admin_controlled=bool(writers) and all(w in admin_writers for w in writers),
        is_critical=role in CRITICAL_ROLES,
        slot=variable.slot,
        # Readers/writers are graph facts; only `role` is a name guess, and its evidence
        # says so explicitly.
        confidence=Confidence.DERIVED,
        evidence=evidence,
    )


#: Accounting roles a variable can only hold if it actually stores a number. A handle is
#: not a balance however it is named.
_NUMERIC_ONLY = frozenset(
    {
        StateRole.ACCOUNTING_TOTAL,
        StateRole.USER_BALANCE,
        StateRole.SHARE_SUPPLY,
        StateRole.DEBT_RECORD,
        StateRole.COLLATERAL_RECORD,
        StateRole.EXCHANGE_RATE,
        StateRole.ACCUMULATOR,
        StateRole.PRICE,
        StateRole.RATE_PARAM,
    }
)


def classify_role(variable: StateVar) -> StateRole:
    """What this variable means. Shared with the asset stage, so the two cannot disagree.

    Two rules, both learned from real output:

    **Mutability beats naming.** A `constant` or `immutable` is a *parameter*, whatever it
    is called. `MAX_TOTAL_PENALTY` contains "total" and never changes, so it cannot be an
    accounting total — but it was read as one, and earned a solvency invariant asserting
    that the protocol's assets must cover a compile-time constant.

    **The type constrains what a name may mean.** `IERC20 public collateralToken` contains
    "collateral" and is a handle, not a balance; reading it as a collateral record produced
    a solvency invariant about a token address.
    """
    # First, and before any name matching: a value that cannot change is not a balance.
    if variable.is_constant or variable.is_immutable:
        return StateRole.CONFIG

    lowered = variable.name.lower().replace("_", "")
    numeric = _is_numeric(variable.type)

    for fragment, role in ROLE_BY_NAME:
        if fragment not in lowered:
            continue
        if role in _NUMERIC_ONLY and not numeric:
            continue
        return role

    if _is_address(variable.type):
        return StateRole.ADDRESS_REF
    if variable.type.startswith("bool"):
        return StateRole.FLAG
    return StateRole.UNKNOWN


#: Retained name. `classify_role` is the public one, because `assets.py` needs it too.
_role_of = classify_role


def _is_numeric(type_name: str) -> bool:
    """Does this hold a number — directly, or as the value type of a mapping?"""
    lowered = type_name.strip().lower()
    if lowered.startswith("mapping"):
        value = lowered[lowered.rfind("=>") + 2 :].strip().rstrip(")").strip()
        return value.startswith(("uint", "int"))
    return lowered.startswith(("uint", "int"))


def _is_address(type_name: str) -> bool:
    """A contract-typed variable (`IERC20 asset`) is an address reference too.

    solc gives it the same ABI type, and it is a handle either way. Detected by the leading
    capital: every Solidity elementary type is lowercase (`uint256`, `bool`, `bytes32`), so
    a capitalized type name is user-defined — a contract, interface, struct or enum.
    """
    text = type_name.strip()
    return text.startswith("address") or (bool(text) and text[0].isupper())


def _meaning(variable: StateVar, role: StateRole) -> str:
    if role is StateRole.UNKNOWN:
        return ""
    article = "per-account " if variable.type.startswith("mapping") else ""
    return f"{article}{role.value.replace('_', ' ')}"


def _admin_only_writers(index: ProtocolIndex) -> set[str]:
    """Functions that only a privileged actor can call, directly or transitively.

    Transitive matters: an internal `_setFee` is only as protected as the entrypoints that
    reach it, and checking the internal function's own modifiers would report it as
    unguarded when every caller is `onlyOwner`.
    """
    guarded: set[str] = set()
    for function_id, function in index.functions.items():
        # A constructor runs once, at deployment, and only the deployer can run it. Counting
        # it as an unguarded writer marks every variable a constructor initialises as
        # publicly writable — which is every `owner` in existence.
        if function.kind is FunctionKind.CONSTRUCTOR or index.guards(function):
            guarded.add(function_id)
            continue
        entrypoints = index.query.reaching_entrypoints(function_id)
        if not entrypoints:
            continue
        callers = [index.functions.get(e) for e in entrypoints]
        if all(caller is not None and index.guards(caller) for caller in callers):
            guarded.add(function_id)
    return guarded


# ── Stage 10: transitions ─────────────────────────────────────────────────────


def transitions(
    index: ProtocolIndex, operations: list[Operation], state: list[StateItem]
) -> list[StateTransition]:
    """`before → operation → after`, one per (operation, state item) write."""
    by_id = {item.id: item for item in state}
    by_var = {item.state_var_id: item for item in state}

    found: dict[str, StateTransition] = {}
    for operation in operations:
        function = index.functions.get(operation.function_id)
        if function is None:
            continue
        first_external = _first_external_order(index, function.id)
        assignments = _assignments(function.raw)

        for access in function.accesses:
            if access.kind is not AccessKind.WRITE:
                continue
            item = by_var.get(access.state_var_id)
            if item is None or item.id not in by_id:
                continue

            operator, expression = assignments.get(access.name, ("", ""))
            transition = StateTransition(
                id=make_transition_id(operation.id, item.id),
                operation_id=operation.id,
                state_id=item.id,
                effect=_effect(operator, function.raw, access.name),
                delta_expr=_delta(access.name, operator, expression),
                order=access.order,
                after_external_call=first_external >= 0 and access.order > first_external,
                confidence=Confidence.DERIVED if operator else Confidence.INFERRED,
                evidence=[
                    graph_evidence(
                        function.id, "writes", access.state_var_id, detector=DETECTOR
                    ),
                    source_evidence(
                        function.id,
                        f"writes {access.name} at line {access.line}",
                        line=access.line,
                        detector=DETECTOR,
                    ),
                ],
            )
            # One variable written twice in a body is one transition: the id is keyed on
            # (operation, state), and the first write carries the earliest order.
            found.setdefault(transition.id, transition)
    return list(found.values())


def _assignments(body: str) -> dict[str, tuple[str, str]]:
    """variable name → (operator, right-hand side), read straight from the source text."""
    found: dict[str, tuple[str, str]] = {}
    for match in _ASSIGN.finditer(body):
        target = match.group(1).strip()
        name = target.split("[")[0].split(".")[0].strip()
        found.setdefault(name, (match.group(2), " ".join(match.group(3).split())[:160]))
    for match in _DELETE.finditer(body):
        found.setdefault(match.group(1), ("delete", ""))
    return found


def _effect(operator: str, body: str, name: str) -> TransitionEffect:
    if operator == "+=":
        return TransitionEffect.INCREASE
    if operator == "-=":
        return TransitionEffect.DECREASE
    if operator == "delete":
        return TransitionEffect.DELETE
    if operator == "=":
        return TransitionEffect.SET
    if f"{name}++" in body:
        return TransitionEffect.INCREASE
    if f"{name}--" in body:
        return TransitionEffect.DECREASE
    return TransitionEffect.UNKNOWN


def _delta(name: str, operator: str, expression: str) -> str:
    """The assignment as written. Never normalized — a rewritten expression is uncheckable."""
    if not operator:
        return ""
    if operator == "delete":
        return f"delete {name}"
    return f"{name} {operator} {expression}"


def _first_external_order(index: ProtocolIndex, function_id: str) -> int:
    """Body position of the earliest call that hands control away, or -1.

    From the *resolved* graph, so a `using SafeMath for uint256` call — which the compiler
    inlines — does not make every subsequent write look like a CEI violation.
    """
    from engine.graphs.storage import external_call_edges

    orders = [
        edge.order for edge in external_call_edges(index.query, function_id) if edge.order >= 0
    ]
    return min(orders) if orders else -1


__all__ = [
    "CRITICAL_ROLES",
    "ROLE_BY_NAME",
    "classify_role",
    "detect",
    "transitions",
]
