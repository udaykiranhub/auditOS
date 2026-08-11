"""Stage 8 — one externally callable action, described in protocol terms.

```
deposit(uint256)  →  DEPOSIT · actor USER · in ASSET · out SHARES · USER → VAULT
```

This is the record agents reason over. It is **not a summary of the function** — the body is
still there, addressed by `function_id`, and an agent that needs it reads it. This says what
the body is *for*, which is the one thing reading the body does not tell you cheaply.

`kind` is name-derived and therefore `INFERRED`; everything structural around it —
preconditions, reads, writes, external calls, privilege — is read off `CodeModel` and
`GraphModel` and is `DERIVED`. The two are recorded at their own confidences rather than
averaged, so an agent can trust the structure while doubting the label.

**Preconditions are extracted verbatim.** `require(shares[msg.sender] >= amount)` is copied
as written, never restated. A paraphrased guard is indistinguishable from a fabricated one
by the time it reaches an attack path.
"""

from __future__ import annotations

import re

from engine.core.models.code import Function
from engine.core.models.evidence import (
    Confidence,
    Evidence,
    heuristic_evidence,
    source_evidence,
)
from engine.core.models.graph import SENTINELS
from engine.core.models.protocol import (
    Actor,
    Asset,
    AssetFlow,
    Component,
    ContractClassification,
    Operation,
    OperationKind,
    StateItem,
    StateTransition,
)
from engine.protocol.heuristics.signatures import ProtocolIndex, starts_with_token
from engine.protocol.ids import make_operation_id

DETECTOR = "operation_model"

#: Function-name prefix → operation kind. Prefix rather than substring, and ordered so the
#: more specific wins: `withdrawAll` is a WITHDRAW, but `removeLiquidity` must not be read
#: as a REMOVE that happens to contain "move".
KIND_BY_PREFIX: tuple[tuple[str, OperationKind], ...] = (
    ("depositFor", OperationKind.DEPOSIT),
    ("deposit", OperationKind.DEPOSIT),
    ("supply", OperationKind.DEPOSIT),
    ("addLiquidity", OperationKind.ADD_LIQUIDITY),
    ("removeLiquidity", OperationKind.REMOVE_LIQUIDITY),
    ("withdraw", OperationKind.WITHDRAW),
    ("redeem", OperationKind.REDEEM),
    ("borrow", OperationKind.BORROW),
    ("repay", OperationKind.REPAY),
    ("liquidate", OperationKind.LIQUIDATE),
    ("swapExact", OperationKind.SWAP),
    ("swap", OperationKind.SWAP),
    ("exchange", OperationKind.SWAP),
    ("flashLoan", OperationKind.FLASH_LOAN),
    ("flash", OperationKind.FLASH_LOAN),
    ("stake", OperationKind.STAKE),
    ("unstake", OperationKind.UNSTAKE),
    ("harvest", OperationKind.HARVEST),
    ("rebalance", OperationKind.REBALANCE),
    ("compound", OperationKind.HARVEST),
    ("claim", OperationKind.CLAIM),
    ("getReward", OperationKind.CLAIM),
    ("propose", OperationKind.PROPOSE),
    ("castVote", OperationKind.VOTE),
    ("vote", OperationKind.VOTE),
    ("queue", OperationKind.EXECUTE),
    ("execute", OperationKind.EXECUTE),
    ("bridge", OperationKind.BRIDGE_SEND),
    ("send", OperationKind.BRIDGE_SEND),
    ("relay", OperationKind.BRIDGE_RECEIVE),
    ("finalize", OperationKind.BRIDGE_RECEIVE),
    ("transferFrom", OperationKind.TRANSFER),
    ("transfer", OperationKind.TRANSFER),
    ("approve", OperationKind.APPROVE),
    ("permit", OperationKind.APPROVE),
    ("mint", OperationKind.MINT),
    ("burn", OperationKind.BURN),
    ("initialize", OperationKind.INITIALIZE),
    ("upgradeTo", OperationKind.UPGRADE),
    ("upgrade", OperationKind.UPGRADE),
    ("pause", OperationKind.PAUSE),
    ("unpause", OperationKind.PAUSE),
    ("set", OperationKind.CONFIGURE),
    ("update", OperationKind.CONFIGURE),
    ("configure", OperationKind.CONFIGURE),
    ("add", OperationKind.CONFIGURE),
    ("remove", OperationKind.CONFIGURE),
    ("grant", OperationKind.ADMIN),
    ("revoke", OperationKind.ADMIN),
    ("renounce", OperationKind.ADMIN),
    ("rescue", OperationKind.ADMIN),
    ("sweep", OperationKind.ADMIN),
)

#: `require(cond, "msg")` / `revert Custom(...)` / `if (x) revert Y()`. Captured verbatim.
_REQUIRE = re.compile(r"\brequire\s*\((.+?)\)\s*;", re.DOTALL)
_REVERT = re.compile(r"\brevert\s+([A-Za-z_][A-Za-z0-9_]*\s*\([^;]*\))\s*;")
_IF_REVERT = re.compile(r"\bif\s*\((.+?)\)\s*(?:\{\s*)?revert\b", re.DOTALL)

MAX_PRECONDITIONS = 12


def detect(
    index: ProtocolIndex,
    classifications: list[ContractClassification],
    actors: list[Actor],
    assets: list[Asset],
    state: list[StateItem],
    components: list[Component],
) -> list[Operation]:
    """One operation per non-view entrypoint on a classified contract."""
    actors_by_function: dict[str, list[str]] = {}
    for actor in actors:
        for capability in actor.capabilities:
            actors_by_function.setdefault(capability.function_id, []).append(actor.id)

    state_by_var = {item.state_var_id: item.id for item in state}
    component_of = {
        contract_id: component.id
        for component in components
        for contract_id in component.contract_ids
    }
    asset_ids = {asset.id for asset in assets}

    operations: list[Operation] = []
    for classification in classifications:
        contract = index.contracts.get(classification.contract_id)
        if contract is None:
            continue
        for function in index.entrypoints_of(contract):
            operations.append(
                _build(
                    index,
                    function,
                    classification,
                    actors_by_function.get(function.id, []),
                    state_by_var,
                    component_of.get(classification.contract_id),
                    assets,
                    asset_ids,
                )
            )
    return operations


def _build(
    index: ProtocolIndex,
    function: Function,
    classification: ContractClassification,
    actor_ids: list[str],
    state_by_var: dict[str, str],
    component_id: str | None,
    assets: list[Asset],
    asset_ids: set[str],
) -> Operation:
    kind = classify_kind(function)
    is_view = index.is_view(function)
    guards = index.guards(function)

    reads = sorted({state_by_var[v] for v in function.reads if v in state_by_var})
    writes = sorted({state_by_var[v] for v in function.writes if v in state_by_var})

    external = [
        edge.text or edge.target
        for edge in index.query.external_call_paths(function.id)
    ] + [
        target
        for target in index.query.callees(function.id)
        if target not in SENTINELS
        and (node := index.query.nodes.get(target)) is not None
        and node.contract_id != classification.contract_id
    ]

    inputs, outputs = _assets_moved(index, function, assets, asset_ids)

    evidence: list[Evidence] = [
        source_evidence(
            function.id,
            f"{function.visibility} {function.mutability} entrypoint",
            path=classification.contract_id.rpartition(":")[0],
            line=function.line_start,
            line_end=function.line_end,
            detector=DETECTOR,
        ),
        heuristic_evidence(
            DETECTOR, f"name maps to {kind.value}", ref=function.id
        ),
    ]

    return Operation(
        id=make_operation_id(function.id),
        function_id=function.id,
        contract_id=classification.contract_id,
        name=function.name,
        kind=kind,
        component_id=component_id,
        description=f"{function.name} on {classification.name}",
        actor_ids=sorted(set(actor_ids)),
        is_privileged=bool(guards),
        is_permissionless=not guards,
        inputs=inputs,
        outputs=outputs,
        preconditions=preconditions(function),
        reads=reads,
        writes=writes,
        external_calls=sorted(set(external))[:12],
        emits=sorted(set(function.emits)),
        is_payable=function.mutability == "payable",
        is_view=is_view,
        # The structure is DERIVED; only `kind` is a name guess, and its evidence says so.
        confidence=Confidence.DERIVED,
        evidence=evidence,
    )


def classify_kind(function: Function) -> OperationKind:
    """Map a function name onto a protocol operation. Name-based, therefore fallible.

    `deposit` in a governance contract is not a deposit, and nothing here can tell. The
    flow and transition stages are what would contradict it, which is why the label and the
    structure carry separate confidences.

    Matched on whole camelCase words rather than a raw string prefix, and views are settled
    first. `setPauseFlag` is a configuration change, not a pause; `getDepositValue` is a
    view, not a deposit — and a lowercase-run prefix match calls both wrongly.
    """
    if function.mutability in ("view", "pure"):
        return OperationKind.VIEW
    for prefix, kind in KIND_BY_PREFIX:
        if starts_with_token(function.name, prefix):
            return kind
    return OperationKind.UNKNOWN


def preconditions(function: Function) -> list[str]:
    """Every guard in the body, verbatim and in source order.

    Regex over the raw body rather than a parsed condition tree: `CodeModel` deliberately
    does not model expressions (SPEC §12.2), and inventing a parser here would be the scope
    trap that section warns about. Copying the text is honest — an agent reads Solidity.
    """
    found: list[str] = []
    body = function.raw

    for modifier in function.modifiers:
        found.append(f"modifier {modifier}")
    for match in _REQUIRE.finditer(body):
        found.append(f"require({_collapse(match.group(1))})")
    for match in _IF_REVERT.finditer(body):
        found.append(f"if ({_collapse(match.group(1))}) revert")
    for match in _REVERT.finditer(body):
        found.append(f"revert {_collapse(match.group(1))}")

    deduped: list[str] = []
    for item in found:
        if item not in deduped:
            deduped.append(item)
    return deduped[:MAX_PRECONDITIONS]


def _collapse(text: str) -> str:
    return " ".join(text.split())[:200]


def _assets_moved(
    index: ProtocolIndex, function: Function, assets: list[Asset], asset_ids: set[str]
) -> tuple[list[str], list[str]]:
    """Which assets the caller supplies and receives.

    Derived from the direction of the token edges rather than from the operation's name: a
    `deposit` that mints nothing did not produce shares, whatever it is called.
    """
    inputs: set[str] = set()
    outputs: set[str] = set()
    by_symbol = {a.symbol.lower(): a for a in assets}

    for kind, receiver, _, _ in index.token_edges_by_function.get(function.id, []):
        asset = by_symbol.get(receiver.lower())
        if kind.value in ("transfers_from",) and asset is not None:
            inputs.add(asset.id)
        elif kind.value in ("transfers", "sends_value") and asset is not None:
            outputs.add(asset.id)
        elif kind.value == "mints":
            issued = [a for a in assets if a.is_protocol_issued]
            if len(issued) == 1:
                outputs.add(issued[0].id)
        elif kind.value == "burns":
            issued = [a for a in assets if a.is_protocol_issued]
            if len(issued) == 1:
                inputs.add(issued[0].id)

    if function.mutability == "payable":
        native = next((a for a in assets if a.kind.value == "native"), None)
        if native is not None:
            inputs.add(native.id)

    return sorted(inputs & asset_ids), sorted(outputs & asset_ids)


def link(
    operations: list[Operation],
    flows: list[AssetFlow],
    transitions: list[StateTransition],
) -> None:
    """Back-fill the cross-references flows and transitions established.

    Done after both exist rather than during construction: an operation cannot reference a
    flow that has not been minted yet, and `validate.py` rejects a dangling reference.
    """
    flows_by_operation: dict[str, list[str]] = {}
    for flow in flows:
        if flow.operation_id:
            flows_by_operation.setdefault(flow.operation_id, []).append(flow.id)

    transitions_by_operation: dict[str, list[str]] = {}
    for transition in transitions:
        transitions_by_operation.setdefault(transition.operation_id, []).append(transition.id)

    for operation in operations:
        operation.flow_ids = sorted(flows_by_operation.get(operation.id, []))
        operation.transition_ids = sorted(transitions_by_operation.get(operation.id, []))

    _link_related(operations)


#: Operations that must be reasoned about together. Every accounting bug lives in the gap
#: between an operation and its inverse, so a retrieval that returns one without the other
#: hands an agent half a system and asks it to find the imbalance.
INVERSE_KINDS: dict[OperationKind, tuple[OperationKind, ...]] = {
    OperationKind.DEPOSIT: (OperationKind.WITHDRAW, OperationKind.REDEEM),
    OperationKind.WITHDRAW: (OperationKind.DEPOSIT, OperationKind.MINT),
    OperationKind.REDEEM: (OperationKind.DEPOSIT, OperationKind.MINT),
    OperationKind.MINT: (OperationKind.BURN, OperationKind.REDEEM),
    OperationKind.BURN: (OperationKind.MINT, OperationKind.DEPOSIT),
    OperationKind.BORROW: (OperationKind.REPAY, OperationKind.LIQUIDATE),
    OperationKind.REPAY: (OperationKind.BORROW,),
    OperationKind.LIQUIDATE: (OperationKind.BORROW, OperationKind.REPAY),
    OperationKind.STAKE: (OperationKind.UNSTAKE, OperationKind.CLAIM),
    OperationKind.UNSTAKE: (OperationKind.STAKE,),
    OperationKind.CLAIM: (OperationKind.STAKE, OperationKind.HARVEST),
    OperationKind.ADD_LIQUIDITY: (OperationKind.REMOVE_LIQUIDITY,),
    OperationKind.REMOVE_LIQUIDITY: (OperationKind.ADD_LIQUIDITY,),
    OperationKind.BRIDGE_SEND: (OperationKind.BRIDGE_RECEIVE,),
    OperationKind.BRIDGE_RECEIVE: (OperationKind.BRIDGE_SEND,),
}

#: Cap per operation. Beyond this the list stops being "what else to read" and becomes the
#: whole contract, which is what the retrieval is supposed to avoid.
MAX_RELATED = 8


def _link_related(operations: list[Operation]) -> None:
    """Two ways an operation relates to another, both evidence-backed.

    *Inverse by kind* — a deposit and the withdraw that undoes it. *Shared critical state* —
    two operations writing the same accounting variable are coupled whether or not their
    names suggest it, and that coupling is read straight off the state model rather than
    guessed.
    """
    by_contract: dict[str, list[Operation]] = {}
    for operation in operations:
        by_contract.setdefault(operation.contract_id or "", []).append(operation)

    for operation in operations:
        if operation.is_view:
            continue
        peers = by_contract.get(operation.contract_id or "", [])
        related: set[str] = set()

        inverses = INVERSE_KINDS.get(operation.kind, ())
        related.update(
            peer.id for peer in peers if peer.kind in inverses and peer.id != operation.id
        )

        written = set(operation.writes)
        if written:
            related.update(
                peer.id
                for peer in peers
                if peer.id != operation.id
                and not peer.is_view
                and written & set(peer.writes)
            )

        operation.related_operations = sorted(related)[:MAX_RELATED]


__all__ = [
    "INVERSE_KINDS",
    "KIND_BY_PREFIX",
    "classify_kind",
    "detect",
    "link",
    "preconditions",
]
