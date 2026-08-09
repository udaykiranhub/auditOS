"""Stage 4 — who can act on this protocol, and with what authority.

```
external function, no guard    →  USER      (untrusted)
external function, onlyOwner   →  ADMIN     (trusted)
onlyRole(KEEPER_ROLE)          →  KEEPER    (semi-trusted)
```

Actors are derived from the **permission graph**, not from a list of conventional names.
Every externally reachable function is examined, its guards read off the modifiers the
Graph Engine already resolved, and the caller who could pass those guards is the actor.

**The trust level is the field that changes the report.** A privileged function reachable by
an `UNTRUSTED` actor is an access-control finding; the same function reachable only by a
`FULLY_TRUSTED` governor is a centralization note. Same code, different severity, and the
difference is decided here rather than guessed six times by six agents.

Two admin roles never collapse into one actor. `onlyRole(PAUSER_ROLE)` and
`onlyRole(MINTER_ROLE)` gate different capabilities, and merging them answers "who can call
this?" wrongly — which is the only question the Access Control agent asks.
"""

from __future__ import annotations

import re

from engine.core.models.code import Function
from engine.core.models.evidence import Confidence, heuristic_evidence, source_evidence
from engine.core.models.protocol import (
    Actor,
    ActorKind,
    Capability,
    ContractClassification,
    TrustLevel,
)
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_actor_id

DETECTOR = "actor_model"

#: Modifier-name fragment → (actor kind, trust level). Order matters: the first match wins,
#: so more specific fragments must precede more general ones (`onlyowner` before `only`).
GUARD_ACTORS: tuple[tuple[str, ActorKind, TrustLevel], ...] = (
    ("timelock", ActorKind.TIMELOCK, TrustLevel.FULLY_TRUSTED),
    ("governance", ActorKind.GOVERNOR, TrustLevel.FULLY_TRUSTED),
    ("governor", ActorKind.GOVERNOR, TrustLevel.FULLY_TRUSTED),
    ("guardian", ActorKind.GUARDIAN, TrustLevel.TRUSTED),
    ("pauser", ActorKind.PAUSER, TrustLevel.TRUSTED),
    ("minter", ActorKind.MINTER, TrustLevel.TRUSTED),
    ("strategist", ActorKind.STRATEGIST, TrustLevel.TRUSTED),
    ("keeper", ActorKind.KEEPER, TrustLevel.SEMI_TRUSTED),
    ("operator", ActorKind.KEEPER, TrustLevel.SEMI_TRUSTED),
    ("relayer", ActorKind.RELAYER, TrustLevel.SEMI_TRUSTED),
    ("liquidator", ActorKind.LIQUIDATOR, TrustLevel.SEMI_TRUSTED),
    ("treasury", ActorKind.TREASURY, TrustLevel.TRUSTED),
    ("factory", ActorKind.PROTOCOL, TrustLevel.TRUSTED),
    ("self", ActorKind.PROTOCOL, TrustLevel.TRUSTED),
    ("owner", ActorKind.OWNER, TrustLevel.TRUSTED),
    ("admin", ActorKind.ADMIN, TrustLevel.TRUSTED),
    ("manager", ActorKind.ADMIN, TrustLevel.TRUSTED),
    ("authorized", ActorKind.ADMIN, TrustLevel.TRUSTED),
    ("auth", ActorKind.ADMIN, TrustLevel.TRUSTED),
)

#: `onlyRole(KEEPER_ROLE)` — the argument names the actor, so it must be extracted rather
#: than folded into a single "role-gated" bucket.
_ROLE_ARG = re.compile(r"only[Rr]ole\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)")

#: Permissionless functions whose name says they are meant to be called by an incentivized
#: third party rather than by the depositor. Only ever a *secondary* actor: the function is
#: still callable by anyone, and USER is recorded alongside.
INCENTIVIZED = {
    "liquidate": (ActorKind.LIQUIDATOR, TrustLevel.SEMI_TRUSTED),
    "liquidationcall": (ActorKind.LIQUIDATOR, TrustLevel.SEMI_TRUSTED),
    "harvest": (ActorKind.KEEPER, TrustLevel.SEMI_TRUSTED),
    "rebalance": (ActorKind.KEEPER, TrustLevel.SEMI_TRUSTED),
    "poke": (ActorKind.KEEPER, TrustLevel.SEMI_TRUSTED),
    "update": (ActorKind.KEEPER, TrustLevel.SEMI_TRUSTED),
    "accrue": (ActorKind.KEEPER, TrustLevel.SEMI_TRUSTED),
    "settle": (ActorKind.KEEPER, TrustLevel.SEMI_TRUSTED),
}


def detect(index: ProtocolIndex, classifications: list[ContractClassification]) -> list[Actor]:
    """One actor per distinct authority, with the capabilities that authority unlocks."""
    known = {c.contract_id for c in classifications}
    drafts: dict[str, _Draft] = {}

    for contract in index.audited:
        if contract.id not in known:
            continue
        for function in index.entrypoints_of(contract):
            if index.is_view(function):
                continue  # a view changes nothing; it is not a capability
            for actor_id, kind, trust, role_name in _actors_of(index, function):
                draft = drafts.setdefault(actor_id, _Draft(actor_id, kind, trust))
                draft.trust = _strongest(draft.trust, trust)
                if role_name:
                    draft.roles.add(role_name)
                draft.contracts.add(contract.id)
                draft.capabilities.append(
                    Capability(
                        function_id=function.id,
                        description=f"{function.name} on {contract.name}",
                        gated_by=index.guards(function),
                        is_privileged=index.is_privileged(function),
                        confidence=Confidence.DERIVED,
                        evidence=[
                            source_evidence(
                                function.id,
                                "external entrypoint"
                                + (
                                    f" gated by {', '.join(index.guards(function))}"
                                    if index.guards(function)
                                    else ", unguarded"
                                ),
                                path=contract.path,
                                line=function.line_start,
                                detector=DETECTOR,
                            )
                        ],
                    )
                )

    return [draft.build() for draft in drafts.values()]


class _Draft:
    """Accumulator for one actor while the permission graph is walked."""

    def __init__(self, actor_id: str, kind: ActorKind, trust: TrustLevel):
        self.id = actor_id
        self.kind = kind
        self.trust = trust
        self.roles: set[str] = set()
        self.contracts: set[str] = set()
        self.capabilities: list[Capability] = []

    def build(self) -> Actor:
        privileged = sum(1 for c in self.capabilities if c.is_privileged)
        return Actor(
            id=self.id,
            kind=self.kind,
            name=self.id.removeprefix("actor:"),
            trust=self.trust,
            description=(
                f"{len(self.capabilities)} callable functions, {privileged} privileged"
            ),
            roles=sorted(self.roles),
            capabilities=self.capabilities,
            controlled_contracts=sorted(self.contracts),
            # DERIVED: the guards are read off resolved modifiers, not guessed. Which
            # *human* holds the key is unknowable from source and is not claimed.
            confidence=Confidence.DERIVED,
            evidence=[
                heuristic_evidence(
                    DETECTOR,
                    f"{len(self.capabilities)} entrypoints reachable by this authority",
                    ref=sorted(self.contracts)[0] if self.contracts else "",
                )
            ],
        )


def _actors_of(
    index: ProtocolIndex, function: Function
) -> list[tuple[str, ActorKind, TrustLevel, str]]:
    """Every actor who can reach this function. Usually one; occasionally two."""
    guards = index.guards(function)
    found: list[tuple[str, ActorKind, TrustLevel, str]] = []

    for guard in guards:
        role = _role_argument(function, guard)
        kind, trust = _classify_guard(guard, role)
        actor_id = make_actor_id(kind.value, role or "")
        found.append((actor_id, kind, trust, role or ""))

    if guards:
        return found

    # Unguarded: anyone can call it. That is the default and the most important case.
    found.append((make_actor_id(ActorKind.USER.value), ActorKind.USER, TrustLevel.UNTRUSTED, ""))

    incentive = _incentivized(function)
    if incentive is not None:
        kind, trust = incentive
        # Recorded *alongside* USER, never instead of it: `liquidate` being conventionally
        # a liquidator's function does not stop an arbitrary address calling it, and
        # replacing USER here would hide exactly that.
        found.append((make_actor_id(kind.value), kind, trust, ""))
    return found


def _classify_guard(guard: str, role: str) -> tuple[ActorKind, TrustLevel]:
    haystack = f"{guard} {role}".lower().replace("_", "")
    for fragment, kind, trust in GUARD_ACTORS:
        if fragment in haystack:
            return kind, trust
    # A guard we do not recognize still restricts the caller — treating it as USER would
    # report a guarded function as permissionless, the more dangerous of the two errors.
    return ActorKind.ADMIN, TrustLevel.TRUSTED


def _role_argument(function: Function, guard: str) -> str:
    """Extract `KEEPER_ROLE` from `onlyRole(KEEPER_ROLE)`.

    `Function.modifiers` records the name as written, which for `onlyRole` includes the
    argument; when it does not, the raw body is the fallback.
    """
    match = _ROLE_ARG.search(guard) or _ROLE_ARG.search(function.raw[:400])
    if match:
        return match.group(1)
    return ""


def _incentivized(function: Function) -> tuple[ActorKind, TrustLevel] | None:
    name = function.name.lower().replace("_", "")
    for fragment, mapped in INCENTIVIZED.items():
        if name.startswith(fragment):
            return mapped
    return None


def _strongest(left: TrustLevel, right: TrustLevel) -> TrustLevel:
    """When one authority gates several functions at different levels, keep the highest.

    The opposite of `Confidence.weakest`: trust describes *what the protocol assumes*, and
    if any path assumes governance-level trust then that assumption is being made.
    """
    order = [
        TrustLevel.UNTRUSTED,
        TrustLevel.SEMI_TRUSTED,
        TrustLevel.TRUSTED,
        TrustLevel.FULLY_TRUSTED,
    ]
    return max(left, right, key=order.index)


__all__ = ["GUARD_ACTORS", "INCENTIVIZED", "detect"]
