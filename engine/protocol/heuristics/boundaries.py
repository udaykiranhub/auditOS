"""Stage 5 — trust boundaries: where control or value crosses between trust domains.

```
USER ──deposit()──> VAULT          an untrusted caller enters the protocol
VAULT ──.call{value}──> USER       the protocol hands control to untrusted code
```

Every exploit is something crossing one of these in a way it was not meant to. Modelling
them explicitly lets an agent ask *"what crosses here, and what is checked?"* instead of
reading every function hoping to notice.

Two kinds are emitted, and the second is the one that matters most:

* **Inbound** — an actor calls into a contract. `checks` lists the guards at the door.
* **Outbound with `hands_over_control`** — the contract calls out to code it does not
  control, which can call back in. That flag is the reentrancy precondition, and it is set
  from the Graph Engine's resolved external-call edges rather than from a name, so a
  SafeMath call that merely *looks* external does not raise it.
"""

from __future__ import annotations

from engine.core.models.evidence import (
    Confidence,
    graph_evidence,
    heuristic_evidence,
    source_evidence,
)
from engine.core.models.graph import UNKNOWN_EXTERNAL, UNTRUSTED_EXTERNAL
from engine.core.models.protocol import (
    Actor,
    ActorKind,
    ContractClassification,
    TrustBoundary,
    TrustLevel,
)
from engine.graphs.storage import external_call_edges
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_boundary_id

DETECTOR = "trust_boundary"

#: The far side of every outbound boundary. A single actor rather than one per callee: we
#: do not know who is out there, and inventing a distinct actor per unresolved target would
#: dress that ignorance up as knowledge.
EXTERNAL_ACTOR_ID = "actor:external-protocol"

#: Cap on functions listed per boundary. A protocol with 200 user entrypoints produces one
#: boundary record either way; enumerating all 200 crossings buries the shape in a list.
MAX_CROSSINGS = 25


def detect(
    index: ProtocolIndex,
    classifications: list[ContractClassification],
    actors: list[Actor],
) -> list[TrustBoundary]:
    """Inbound boundaries from the actor model, outbound from the resolved call graph."""
    by_contract = {c.contract_id: c for c in classifications}
    return [
        *_inbound(index, by_contract, actors),
        *_outbound(index, by_contract),
    ]


def _inbound(
    index: ProtocolIndex,
    by_contract: dict[str, ContractClassification],
    actors: list[Actor],
) -> list[TrustBoundary]:
    """actor → contract, one per (actor, contract) pair they can reach."""
    grouped: dict[tuple[str, str], list[str]] = {}
    for actor in actors:
        for capability in actor.capabilities:
            function = index.functions.get(capability.function_id)
            if function is None or not function.contract_id:
                continue
            grouped.setdefault((actor.id, function.contract_id), []).append(function.id)

    boundaries: list[TrustBoundary] = []
    for (actor_id, contract_id), function_ids in grouped.items():
        classification = by_contract.get(contract_id)
        if classification is None:
            continue
        actor = next(a for a in actors if a.id == actor_id)
        checks = sorted(
            {
                guard
                for fid in function_ids
                if (function := index.functions.get(fid)) is not None
                for guard in index.guards(function)
            }
        )
        boundaries.append(
            TrustBoundary(
                id=make_boundary_id(actor_id, classification.id),
                inner=classification.id,
                outer=actor_id,
                inner_trust=TrustLevel.TRUSTED,
                outer_trust=actor.trust,
                description=(
                    f"{actor.name} calls into {classification.name} "
                    f"({len(function_ids)} entrypoints)"
                ),
                crosses=sorted(function_ids)[:MAX_CROSSINGS],
                checks=checks,
                confidence=Confidence.DERIVED,
                evidence=[
                    source_evidence(
                        fid, "entrypoint crossing into the protocol", detector=DETECTOR
                    )
                    for fid in sorted(function_ids)[:3]
                ],
            )
        )
    return boundaries


def _outbound(
    index: ProtocolIndex, by_contract: dict[str, ContractClassification]
) -> list[TrustBoundary]:
    """contract → external code. `hands_over_control` marks the reentrancy precondition.

    Uses the Graph Engine's `external_call_edges`, which resolves `using L for T` library
    calls and drops external `view` calls (which compile to STATICCALL and cannot reenter).
    Reading raw call kinds instead would raise the flag on every SafeMath operation.
    """
    grouped: dict[str, list[tuple[str, str, str, int]]] = {}
    for contract in index.audited:
        if contract.id not in by_contract:
            continue
        for function in contract.functions:
            for edge in external_call_edges(index.query, function.id):
                grouped.setdefault(contract.id, []).append(
                    (function.id, edge.target, edge.text, edge.line)
                )

    boundaries: list[TrustBoundary] = []
    for contract_id, calls in grouped.items():
        classification = by_contract[contract_id]
        untrusted = [c for c in calls if c[1] == UNTRUSTED_EXTERNAL]
        unknown = [c for c in calls if c[1] == UNKNOWN_EXTERNAL]
        boundaries.append(
            TrustBoundary(
                id=make_boundary_id(classification.id, EXTERNAL_ACTOR_ID),
                inner=classification.id,
                outer=EXTERNAL_ACTOR_ID,
                inner_trust=TrustLevel.TRUSTED,
                outer_trust=TrustLevel.UNTRUSTED,
                description=(
                    f"{classification.name} calls out to code it does not control "
                    f"({len(untrusted)} low-level, {len(unknown)} typed-but-external)"
                ),
                crosses=sorted({c[0] for c in calls})[:MAX_CROSSINGS],
                # Only a low-level call reaches genuinely arbitrary code. A typed call to a
                # peer may be trusted; same shape, different prior, and the agent needs to
                # know which it is looking at.
                hands_over_control=bool(untrusted),
                confidence=Confidence.DERIVED,
                evidence=[
                    graph_evidence(source, "calls", target, text, detector=DETECTOR)
                    for source, target, text, _ in sorted(calls)[:4]
                ],
            )
        )
    return boundaries


def extra_actors(boundaries: list[TrustBoundary]) -> list[Actor]:
    """The counterparty on the far side of every outbound boundary.

    Declared explicitly rather than left implicit, because `validate.py` requires every
    boundary endpoint to resolve — and an outbound boundary pointing at nothing would be a
    dangling reference rather than an honest statement that we do not know who is there.
    Emitted only when an outbound boundary actually exists, so a protocol that never calls
    out does not carry a phantom actor.
    """
    if not any(b.outer == EXTERNAL_ACTOR_ID for b in boundaries):
        return []
    return [
        Actor(
            id=EXTERNAL_ACTOR_ID,
            kind=ActorKind.EXTERNAL_PROTOCOL,
            name="external-protocol",
            trust=TrustLevel.UNTRUSTED,
            description="code outside this repository, reached by an external call",
            confidence=Confidence.DERIVED,
            evidence=[
                heuristic_evidence(DETECTOR, "the target of every outbound trust boundary")
            ],
        )
    ]


__all__ = ["EXTERNAL_ACTOR_ID", "MAX_CROSSINGS", "detect", "extra_actors"]
