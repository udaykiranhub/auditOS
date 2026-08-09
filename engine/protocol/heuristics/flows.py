"""Stage 7 — who sends what to whom.

```
asset.transferFrom(msg.sender, address(this), amount)   →  USER  ──asset──>  VAULT
asset.transfer(msg.sender, amount)                      →  VAULT ──asset──>  USER
_mint(msg.sender, shares)                               →  VAULT ──shares──> USER
```

Built entirely on the Graph Engine's **signature-derived** token edges (`graphs/tokens.py`),
which are a fact about what the code calls. This stage adds the one thing a signature cannot
give: *direction*, read off the call's argument text.

The direction rule is small and worth stating, because getting it backwards inverts every
flow in the artifact:

| call | source | target |
|---|---|---|
| `transferFrom(from, to, x)` | `from` | `to` |
| `transfer(to, x)` | the contract making the call | `to` |
| `mint(to, x)` | the issuing contract (value created) | `to` |
| `burn(from, x)` | `from` | the issuing contract (value destroyed) |

Where an argument is not a recognizable actor (`msg.sender`, `address(this)`, a parameter
name), the endpoint falls back to the operation's actor or the contract itself, and the
flow's confidence drops to `INFERRED`. A flow with a fabricated endpoint would be worse
than no flow at all — it is the input to every conservation invariant downstream.
"""

from __future__ import annotations

from engine.core.models.evidence import Confidence, Evidence, graph_evidence, source_evidence
from engine.core.models.graph import EdgeKind
from engine.core.models.protocol import (
    Asset,
    AssetFlow,
    AssetKind,
    ContractClassification,
    FlowKind,
    Operation,
)
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_flow_id

DETECTOR = "asset_flow"

_KIND_MAP: dict[EdgeKind, FlowKind] = {
    EdgeKind.TRANSFERS: FlowKind.TRANSFER,
    EdgeKind.TRANSFERS_FROM: FlowKind.TRANSFER_FROM,
    EdgeKind.MINTS: FlowKind.MINT,
    EdgeKind.BURNS: FlowKind.BURN,
    EdgeKind.SENDS_VALUE: FlowKind.NATIVE_SEND,
}

_SELF = ("address(this)", "this")
_CALLER = ("msg.sender", "_msgSender()", "msgSender()")


def detect(
    index: ProtocolIndex,
    operations: list[Operation],
    assets: list[Asset],
    classifications: list[ContractClassification],
) -> list[AssetFlow]:
    """One flow per token-moving call site inside a modelled operation."""
    role_of = {c.contract_id: c.id for c in classifications}
    by_symbol = _asset_lookup(assets)

    flows: dict[str, AssetFlow] = {}
    for operation in operations:
        function = index.functions.get(operation.function_id)
        if function is None:
            continue
        contract_role = role_of.get(operation.contract_id or "")
        if contract_role is None:
            continue
        actor = operation.actor_ids[0] if operation.actor_ids else contract_role

        for kind, receiver, text, line in index.token_edges_by_function.get(function.id, []):
            flow_kind = _KIND_MAP.get(kind)
            if flow_kind is None:
                continue
            asset = _asset_for(receiver, text, by_symbol, assets, flow_kind)
            if asset is None:
                continue

            # `Edge.text` is the *callee* expression (`asset.transferFrom`) — CodeModel
            # records call sites as references, not parsed expressions (SPEC §12.2). The
            # arguments, which carry the direction and the amount, only exist in the source.
            arguments = call_arguments(function.raw, function.line_start, text, line)
            source, target, confident = _endpoints(
                flow_kind, arguments, actor, contract_role
            )
            amount = arguments[-1] if arguments else ""
            flow = AssetFlow(
                id=make_flow_id(source, target, asset.id, operation.id),
                source=source,
                target=target,
                asset_id=asset.id,
                operation_id=operation.id,
                kind=flow_kind,
                amount_expr=amount,
                conditions=list(operation.preconditions[:4]),
                call_site=function.id,
                line=line,
                confidence=Confidence.DERIVED if confident else Confidence.INFERRED,
                evidence=_evidence(function.id, kind, receiver, text, line),
            )
            flows.setdefault(flow.id, flow)
    return list(flows.values())


def _endpoints(
    kind: FlowKind, args: list[str], actor: str, contract_role: str
) -> tuple[str, str, bool]:
    """(source, target, endpoints_were_readable).

    The boolean is what keeps confidence honest: when an argument is a local variable we
    cannot resolve, the direction is a convention rather than an observation.
    """
    if kind is FlowKind.TRANSFER_FROM and len(args) >= 2:
        source, source_ok = _endpoint(args[0], actor, contract_role)
        target, target_ok = _endpoint(args[1], actor, contract_role)
        return source, target, source_ok and target_ok

    if kind in (FlowKind.TRANSFER, FlowKind.NATIVE_SEND) and args:
        target, ok = _endpoint(args[0], actor, contract_role)
        return contract_role, target, ok

    if kind is FlowKind.MINT and args:
        target, ok = _endpoint(args[0], actor, contract_role)
        # Minting creates value: it has no sender, so the issuer is the source.
        return contract_role, target, ok

    if kind is FlowKind.BURN and args:
        source, ok = _endpoint(args[0], actor, contract_role)
        return source, contract_role, ok

    # Unparseable arguments: record the flow between the actor and the contract, flagged
    # as inferred. Dropping it entirely would lose a real token movement.
    if kind in (FlowKind.TRANSFER, FlowKind.MINT):
        return contract_role, actor, False
    return actor, contract_role, False


def _endpoint(argument: str, actor: str, contract_role: str) -> tuple[str, bool]:
    text = argument.strip()
    if any(token in text for token in _SELF):
        return contract_role, True
    if any(token in text for token in _CALLER):
        return actor, True
    # `to`, `recipient`, `receiver` — a parameter naming an arbitrary address. The actor is
    # the best available stand-in, and the caller is told it is a stand-in.
    return actor, False


def call_arguments(body: str, body_start_line: int, callee: str, line: int) -> list[str]:
    """The arguments of `callee(...)` at `line`, read out of the function's own source.

    `CodeModel` records a call site as a *reference* — callee, receiver, line, order — and
    deliberately not as a parsed expression (SPEC §12.2 names expression-level AST modelling
    the biggest scope trap in the project). The direction of a transfer lives entirely in
    the arguments, so this stage goes back to the text it already cites as evidence.

    Anchored on the recorded line rather than searching the whole body, because a function
    that calls `transfer` three times must not attribute all three to the first one's
    arguments.
    """
    lines = body.splitlines()
    offset = line - body_start_line
    if not lines:
        return []

    # Search from the recorded line outward: tree-sitter's line for a multi-line call is the
    # start of the expression, but a formatter may have moved the callee onto its own line.
    for candidate in _nearby(offset, len(lines)):
        text = "\n".join(lines[candidate : candidate + 6])
        start = text.find(callee)
        if start == -1:
            continue
        opening = text.find("(", start + len(callee) - 1)
        if opening == -1:
            continue
        return split_arguments(_balanced(text, opening))
    return []


def _nearby(offset: int, total: int) -> list[int]:
    """The recorded line first, then a small window around it."""
    candidates = [offset, *(offset + delta for delta in (-1, 1, -2, 2))]
    return [c for c in candidates if 0 <= c < total]


def _balanced(text: str, opening: int) -> str:
    """The contents of the parenthesis group starting at `opening`, nesting respected."""
    depth = 0
    for position in range(opening, len(text)):
        if text[position] == "(":
            depth += 1
        elif text[position] == ")":
            depth -= 1
            if depth == 0:
                return text[opening + 1 : position]
    return ""


def split_arguments(inner: str) -> list[str]:
    """Split an argument list on top-level commas only.

    `transferFrom(msg.sender, address(this), amount)` must yield three arguments — a naive
    split on "," would make `address(this)` and any `abi.encode(a, b)` fall apart, and the
    resulting mis-indexed endpoints would invert the flow.
    """
    args: list[str] = []
    depth = 0
    current: list[str] = []
    for char in inner:
        if char == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        current.append(char)
    if current:
        args.append("".join(current).strip())
    return [" ".join(arg.split()) for arg in args if arg.strip()]


def _asset_lookup(assets: list[Asset]) -> dict[str, Asset]:
    lookup: dict[str, Asset] = {}
    for asset in assets:
        lookup.setdefault(asset.symbol.lower(), asset)
        for state_var_id in asset.state_var_ids:
            lookup.setdefault(state_var_id.rpartition("#")[2].lower(), asset)
    return lookup


def _asset_for(
    receiver: str,
    text: str,
    by_symbol: dict[str, Asset],
    assets: list[Asset],
    kind: FlowKind,
) -> Asset | None:
    """Which asset moved.

    The receiver of the call is the token handle: in `asset.transfer(...)` the asset is
    `asset`. For a bare `_mint(to, x)` there is no receiver — the contract mints its own
    token, so the protocol-issued share asset is the answer.
    """
    candidate = by_symbol.get(receiver.lower())
    if candidate is not None:
        return candidate

    if kind in (FlowKind.MINT, FlowKind.BURN):
        issued = [a for a in assets if a.is_protocol_issued and a.kind is AssetKind.SHARE]
        if len(issued) == 1:
            return issued[0]
        return None

    if kind is FlowKind.NATIVE_SEND:
        return next((a for a in assets if a.kind is AssetKind.NATIVE), None)

    # A transfer on a handle we never modelled as an asset. Better to omit the flow than to
    # attribute the movement to an arbitrary token.
    return None


def _evidence(
    function_id: str, kind: EdgeKind, receiver: str, text: str, line: int
) -> list[Evidence]:
    return [
        graph_evidence(function_id, kind.value, receiver, text, detector=DETECTOR),
        source_evidence(function_id, text, line=line, detector=DETECTOR),
    ]


__all__ = ["detect"]
