"""Token-flow edges — the deterministic half of a "semantic" layer.

**Why this is narrower than it might be.** It is tempting to emit `deposit() —MINTS→ shares`
and `liquidate() —SEIZES→ collateral`. That is protocol *interpretation*: it needs to know
this is a vault, that `shares` is the receipt token, and that the accounting is what the
name suggests. The same names mean different things in different protocols, and a wrong
semantic edge is worse than a missing one because everything above it inherits the mistake
silently. SPEC puts that reasoning in Protocol Understanding, with an `LLM` synthesis pass
and heuristics that can see the whole system at once.

What *is* deterministic is signature matching. `transfer(address,uint256)` is the ERC-20
transfer selector; a call to it moves tokens whatever the protocol thinks it is doing. So
this module matches names against arity, marks a signature match `high` and a
convention-only name match `medium`, and leaves the interpretation to the phase that owns it.
"""

from __future__ import annotations

from engine.core.models.code import CallKind, CallSite, Contract
from engine.core.models.graph import (
    UNKNOWN_EXTERNAL,
    Confidence,
    Edge,
    EdgeKind,
)

#: `name → (edge kind, expected argument counts)`. Arity is what separates ERC-20
#: `transfer(address,uint256)` from `address.transfer(uint256)`, which sends ETH to
#: arbitrary code and is handled in `calls.py` instead.
_SIGNATURES: dict[str, tuple[EdgeKind, frozenset[int]]] = {
    "transfer": (EdgeKind.TRANSFERS, frozenset({2})),
    "safeTransfer": (EdgeKind.TRANSFERS, frozenset({2, 3})),
    "transferFrom": (EdgeKind.TRANSFERS_FROM, frozenset({3})),
    "safeTransferFrom": (EdgeKind.TRANSFERS_FROM, frozenset({3, 4})),
    "approve": (EdgeKind.APPROVES, frozenset({2})),
    "safeApprove": (EdgeKind.APPROVES, frozenset({2, 3})),
    "safeIncreaseAllowance": (EdgeKind.APPROVES, frozenset({2, 3})),
    "permit": (EdgeKind.APPROVES, frozenset({6, 7})),
}

#: Convention, not signature: `_mint`/`_burn` are OpenZeppelin's internal hooks and are
#: named that way nearly everywhere, but nothing enforces it. Hence `medium`.
_CONVENTIONS: dict[str, EdgeKind] = {
    "mint": EdgeKind.MINTS,
    "_mint": EdgeKind.MINTS,
    "safeMint": EdgeKind.MINTS,
    "burn": EdgeKind.BURNS,
    "_burn": EdgeKind.BURNS,
    "burnFrom": EdgeKind.BURNS,
}


def token_edges(contracts: dict[str, Contract], known: set[str]) -> list[Edge]:
    """Edges from a function to whatever it moves tokens *through*.

    The target is the receiver's node when we can name it (`token.transfer(…)` → the token
    contract if it is in the graph) and `UNKNOWN_EXTERNAL` otherwise, so a token flow to an
    external asset still appears rather than vanishing.
    """
    edges: list[Edge] = []

    for contract_id in sorted(contracts):
        contract = contracts[contract_id]
        receivers = {var.name: var.id for var in contract.state_vars}

        for function in contract.functions:
            for call in function.calls:
                classified = _classify(call)
                if classified is None:
                    continue
                kind, confidence = classified

                target = receivers.get(call.receiver or "")
                if target is None or target not in known:
                    target = UNKNOWN_EXTERNAL

                edges.append(
                    Edge(
                        source=function.id,
                        target=target,
                        kind=kind,
                        confidence=confidence,
                        line=call.line,
                        order=call.order,
                        via=call.receiver,
                        text=call.text,
                    )
                )
    return edges


def _classify(call: CallSite) -> tuple[EdgeKind, Confidence] | None:
    signature = _SIGNATURES.get(call.name)
    if signature is not None:
        kind, arities = signature
        if call.arg_count < 0 or call.arg_count in arities:
            return kind, "high"
        return None  # right name, wrong shape — not this selector

    convention = _CONVENTIONS.get(call.name)
    if convention is None:
        return None
    # An internal `_mint` is a call into our own accounting; a member `token.mint(…)` is a
    # call out. Both move supply, so both are recorded.
    if call.kind in (CallKind.INTERNAL, CallKind.MEMBER, CallKind.THIS, CallKind.SUPER):
        return convention, "medium"
    return None
