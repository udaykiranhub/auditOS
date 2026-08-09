"""Stage 11 — what outside this repository the protocol's correctness rests on.

```
IPriceFeed.latestRoundData()  →  ORACLE   (stale price, reverting call)
IUniswapV2Router.swap(...)    →  DEX      (slippage, sandwich, reverting call)
IERC20.transfer(...)          →  TOKEN    (missing return value, fee on transfer)
```

Sourced from **interfaces the protocol calls through**, not from imports: an imported
interface that nothing calls is dead weight, and listing it as a dependency would make the
Context Builder pull in code no attacker can reach.

`failure_modes` is the field agents actually use. It is not a prediction that any of these
will happen — it is the list of ways this *category* of dependency has failed, attached to
the call sites where it would be felt. That converts "there is an oracle here" into "here is
what to check about this oracle", which is the difference between a map and a checklist.

`is_trusted` records how the protocol *treats* the dependency, which is an observation about
the code, not an endorsement. A dependency trusted in code that should not be is the finding.
"""

from __future__ import annotations

from engine.core.models.code import Contract
from engine.core.models.evidence import (
    Confidence,
    Evidence,
    graph_evidence,
    source_evidence,
)
from engine.core.models.graph import UNKNOWN_EXTERNAL, UNTRUSTED_EXTERNAL
from engine.core.models.protocol import ContractClassification, Dependency, DependencyKind
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_dependency_id

DETECTOR = "dependency_model"

#: Interface / receiver name fragment → what kind of thing it is, and how it fails.
#: Failure modes are per-*category* and deliberately concrete: "oracle risk" tells an agent
#: nothing, "the price may be stale — is `updatedAt` checked?" tells it where to look.
SIGNATURES: tuple[tuple[tuple[str, ...], DependencyKind, tuple[str, ...]], ...] = (
    (
        ("aggregator", "pricefeed", "chainlink", "oracle", "priceoracle", "pyth", "twap"),
        DependencyKind.ORACLE,
        (
            "price may be stale — is updatedAt / roundId validated?",
            "price may be zero or negative on a failed round",
            "the feed can be paused or deprecated by its operator",
            "a spot price read from an AMM is manipulable within one transaction",
        ),
    ),
    (
        ("router", "uniswap", "sushi", "curve", "balancer", "swap", "pair", "pool"),
        DependencyKind.DEX,
        (
            "swap output is manipulable — is a minimum-out enforced?",
            "reserves can be moved within the same block (sandwich / flash loan)",
            "the pool may hold insufficient liquidity and revert",
        ),
    ),
    (
        ("bridge", "messenger", "portal", "endpoint", "mailbox", "layerzero", "ccip"),
        DependencyKind.BRIDGE,
        (
            "message delivery is not atomic — is replay prevented by nonce?",
            "the remote sender must be authenticated, not just the local caller",
            "delivery may be delayed indefinitely or censored",
        ),
    ),
    (
        ("ierc20", "erc20", "token", "weth", "steth", "usdc", "usdt"),
        DependencyKind.TOKEN,
        (
            "transfer may return no value (USDT-style) — is SafeERC20 used?",
            "the token may charge a fee on transfer, so received != sent",
            "the token may rebase, so a stored balance goes stale",
            "the token may be pausable or blocklist an address",
        ),
    ),
    (
        ("registry", "addressprovider", "resolver", "factory"),
        DependencyKind.REGISTRY,
        ("the registry owner can repoint an address this protocol trusts",),
    ),
    (
        ("aave", "compound", "morpho", "ctoken", "atoken", "lending"),
        DependencyKind.LENDING_PROTOCOL,
        (
            "the market may be paused or frozen, blocking withdrawal",
            "utilisation may prevent a withdrawal from being serviced",
        ),
    ),
    (
        ("staking", "gauge", "lido", "rocket", "eigen"),
        DependencyKind.STAKING_PROTOCOL,
        ("withdrawal may be queued or delayed", "the exchange rate may move adversely"),
    ),
    (
        ("keeper", "gelato", "chainlinkautomation", "automation"),
        DependencyKind.KEEPER_NETWORK,
        ("the keeper may never call, or may call at an adversarially chosen time",),
    ),
)


def detect(
    index: ProtocolIndex, classifications: list[ContractClassification]
) -> list[Dependency]:
    """One dependency per external interface the audited code actually calls."""
    audited = {c.contract_id for c in classifications}
    interfaces = {c.name.lower(): c for c in index.interfaces}

    drafts: dict[str, _Draft] = {}
    for contract in index.audited:
        if contract.id not in audited:
            continue
        for function in contract.functions:
            _collect(index, contract, function.id, interfaces, audited, drafts)

    return [draft.build() for draft in drafts.values()]


class _Draft:
    def __init__(self, dependency_id: str, name: str, kind: DependencyKind):
        self.id = dependency_id
        self.name = name
        self.kind = kind
        self.interface_id: str | None = None
        self.used_by: set[str] = set()
        self.call_sites: set[str] = set()
        self.evidence: list[Evidence] = []
        self.untrusted = False

    def build(self) -> Dependency:
        _, failure_modes = _classify(self.name)
        return Dependency(
            id=self.id,
            name=self.name,
            kind=self.kind,
            interface_id=self.interface_id,
            description=f"external {self.kind.value} reached from {len(self.used_by)} functions",
            used_by=sorted(self.used_by),
            call_sites=sorted(self.call_sites)[:12],
            # The protocol calls it without validating who it is — that is what the code
            # does, stated as an observation. Whether that is safe is the agent's call.
            is_trusted=not self.untrusted,
            failure_modes=list(failure_modes),
            confidence=Confidence.DERIVED,
            evidence=self.evidence[:6],
        )


def _collect(
    index: ProtocolIndex,
    contract: Contract,
    function_id: str,
    interfaces: dict[str, Contract],
    audited: set[str],
    drafts: dict[str, _Draft],
) -> None:
    function = index.functions.get(function_id)
    if function is None:
        return

    for call in function.calls:
        receiver = (call.receiver or "").strip()
        if not receiver:
            continue
        interface = _interface_for(index, contract, receiver, call.text, interfaces)
        name = interface.name if interface is not None else receiver
        if interface is None and not _looks_external(index, receiver, contract, audited):
            continue

        kind, _ = _classify(name)
        dependency_id = make_dependency_id(
            name, ref=interface.id if interface is not None else ""
        )
        draft = drafts.setdefault(dependency_id, _Draft(dependency_id, name, kind))
        if interface is not None:
            draft.interface_id = interface.id
        draft.used_by.add(function_id)
        draft.call_sites.add(f"{call.text}:{call.line}")
        if len(draft.evidence) < 6:
            draft.evidence.append(
                source_evidence(
                    function_id, call.text, path=contract.path, line=call.line,
                    detector=DETECTOR,
                )
            )

    # A low-level call reaches genuinely arbitrary code — the strongest untrusted signal
    # available, and it must not be folded into a named dependency.
    for edge in index.query.external_call_paths(function_id):
        if edge.target != UNTRUSTED_EXTERNAL:
            continue
        dependency_id = make_dependency_id("arbitrary-external-call")
        draft = drafts.setdefault(
            dependency_id,
            _Draft(dependency_id, "arbitrary external call", DependencyKind.UNKNOWN),
        )
        draft.untrusted = True
        draft.used_by.add(function_id)
        draft.call_sites.add(f"{edge.text}:{edge.line}")
        if len(draft.evidence) < 6:
            draft.evidence.append(
                graph_evidence(
                    function_id, "calls", UNKNOWN_EXTERNAL, edge.text, detector=DETECTOR
                )
            )


def _interface_for(
    index: ProtocolIndex,
    contract: Contract,
    receiver: str,
    text: str,
    interfaces: dict[str, Contract],
) -> Contract | None:
    """Which interface is this call going through?

    Three sources, strongest first. The **declared type** is the one that matters in
    practice: `IERC20 public asset; … asset.transferFrom(…)` names its interface nowhere in
    the call text, so a text-only match reports the dependency as "asset" — the variable —
    rather than as the ERC-20 it is, and every failure mode keyed on the interface is lost.
    """
    variable = index.state_vars(contract.id).get(receiver)
    if variable is not None:
        declared = variable.type.strip().rstrip("[]").split()[0].lower()
        if declared in interfaces:
            return interfaces[declared]

    for name, interface in interfaces.items():
        if name == receiver.lower():
            return interface
    # `IPriceFeed(feed).latestAnswer()` — the cast names the interface inline.
    for name, interface in interfaces.items():
        if f"{name}(" in text.lower():
            return interface
    return None


def _looks_external(
    index: ProtocolIndex, receiver: str, contract: Contract, audited: set[str]
) -> bool:
    """Is this receiver a handle on something outside the audited code?

    Excludes locals and library handles: a call on a `using L for uint256` value is inlined
    by the compiler and is not a dependency in any meaningful sense.
    """
    lowered = receiver.lower()
    if lowered in ("this", "super", "msg", "block", "tx", "abi", "type", "address"):
        return False
    storage = index.state_vars(contract.id)
    variable = storage.get(receiver)
    if variable is None:
        return False
    # A handle typed as a contract we audit is an internal reference, not a dependency.
    return not any(variable.type.strip("[]") in cid for cid in audited)


def _classify(name: str) -> tuple[DependencyKind, tuple[str, ...]]:
    lowered = name.lower().replace("_", "")
    for fragments, kind, failure_modes in SIGNATURES:
        if any(fragment in lowered for fragment in fragments):
            return kind, failure_modes
    return DependencyKind.UNKNOWN, (
        "the callee's behaviour is not modelled here — it may revert, reenter, or return "
        "an unexpected value",
    )


def unresolved_note(index: ProtocolIndex) -> str | None:
    """One honest sentence about calls we could not attribute to any dependency."""
    unknown = sum(
        1 for item in index.graph.unresolved if item.reason == "UNRESOLVED_EXTERNAL_CALL"
    )
    if not unknown:
        return None
    return (
        f"{unknown} external calls have a receiver that could not be typed; the "
        "dependencies they reach are not in this list"
    )


__all__ = ["SIGNATURES", "detect", "unresolved_note"]
