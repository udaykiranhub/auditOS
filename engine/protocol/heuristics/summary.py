"""The 200–400 word "what is this" (SPEC §7.6).

Assembled from the model rather than written about it, and that constraint is the point:
every sentence below is generated from a field that already carries its own evidence and
confidence. Nothing here can assert something the artifact does not already contain, so the
summary cannot drift away from the model it summarizes.

It reads like prose and is not prose — it is a rendering. When Phase H enrichment runs it
may replace this text with a written summary, and `Enrichment.applied` is what tells a
reader which one they are looking at.
"""

from __future__ import annotations

from engine.core.models.protocol import (
    Archetype,
    ContractRole,
    InvariantStatus,
    ProtocolModel,
    TrustLevel,
)


def write(model: ProtocolModel) -> str:
    """Render the model as a paragraph. Deterministic; no interpretation added."""
    parts = [
        _what(model),
        _structure(model),
        _actors(model),
        _value(model),
        _dependencies(model),
        _invariants(model),
        _limits(model),
    ]
    return " ".join(part for part in parts if part)


def _what(model: ProtocolModel) -> str:
    name = model.identity.name or "This protocol"
    archetypes = [
        claim.archetype.value.replace("_", " ")
        for claim in model.archetypes
        if claim.archetype is not Archetype.UNKNOWN
    ]
    if not archetypes:
        return (
            f"{name} could not be matched to a known protocol archetype; the contracts "
            "below were analysed structurally without an assumed shape."
        )
    if len(archetypes) == 1:
        return f"{name} is a {archetypes[0]} protocol."
    return (
        f"{name} combines {', '.join(archetypes[:-1])} and {archetypes[-1]} behaviour in "
        "one system."
    )


def _structure(model: ProtocolModel) -> str:
    classified = [c for c in model.contracts if c.role is not ContractRole.UNKNOWN]
    if not classified:
        return f"It contains {len(model.contracts)} in-scope contracts, none of which "\
               "matched a recognised role."
    roles: dict[str, int] = {}
    for classification in classified:
        roles[classification.role.value.replace("_", " ")] = (
            roles.get(classification.role.value.replace("_", " "), 0) + 1
        )
    described = ", ".join(
        f"{count} {role}" if count > 1 else f"a {role}"
        for role, count in sorted(roles.items(), key=lambda item: (-item[1], item[0]))[:5]
    )
    core = model.core_contracts[0].rpartition(":")[2] if model.core_contracts else ""
    lead = f" The most central contract is {core}." if core else ""
    return (
        f"Across {len(model.contracts)} in-scope contracts it defines {described}."
        f"{lead}"
    )


def _actors(model: ProtocolModel) -> str:
    if not model.actors:
        return ""
    untrusted = [a for a in model.actors if a.trust is TrustLevel.UNTRUSTED]
    privileged = [
        a
        for a in model.actors
        if a.trust in (TrustLevel.TRUSTED, TrustLevel.FULLY_TRUSTED)
        and a.privileged_functions
    ]
    sentence = (
        f"{len(model.operations)} externally callable operations are modelled, "
        f"{len(model.privileged)} of them behind an access-control modifier."
    )
    if privileged:
        names = ", ".join(sorted(a.name for a in privileged)[:4])
        sentence += f" Privileged authority is held by {names}."
    if untrusted:
        sentence += (
            " The remaining surface is reachable by any address."
            if len(model.privileged) < len(model.operations)
            else ""
        )
    return sentence


def _value(model: ProtocolModel) -> str:
    if not model.assets:
        return ""
    issued = [a for a in model.assets if a.is_protocol_issued]
    external = [a for a in model.assets if a.is_external]
    parts = []
    if external:
        parts.append(
            f"holds {', '.join(sorted(a.symbol for a in external)[:5])}"
        )
    if issued:
        parts.append(f"issues {', '.join(sorted(a.symbol for a in issued)[:5])}")
    if not parts:
        return ""
    flows = f" {len(model.asset_flows)} asset movements were traced." if model.asset_flows else ""
    return f"It {' and '.join(parts)}.{flows}"


def _dependencies(model: ProtocolModel) -> str:
    if not model.dependencies:
        return "No external protocol dependencies were detected."
    names = ", ".join(sorted({d.name for d in model.dependencies})[:5])
    return (
        f"Correctness depends on {len(model.dependencies)} external systems ({names}), "
        "whose failure modes are recorded against the call sites that use them."
    )


def _invariants(model: ProtocolModel) -> str:
    if not model.invariants:
        return ""
    candidates = sum(1 for i in model.invariants if i.status is InvariantStatus.CANDIDATE)
    conflicts = len(model.conflicts)
    sentence = (
        f"{len(model.invariants)} candidate invariants were derived from the accounting "
        f"and permission structure ({candidates} unverified)."
    )
    if conflicts:
        sentence += (
            f" {conflicts} documented statements appear to conflict with the "
            "implementation and should be read first."
        )
    return sentence


def _limits(model: ProtocolModel) -> str:
    """Always last, and never omitted. A summary that states only what was understood
    reads as completeness, which is the one impression this artifact must not give."""
    bits: list[str] = []
    if model.coverage.unmodelled:
        bits.append(model.coverage.unmodelled[0])
    blocking = sum(1 for gap in model.gaps if gap.blocking)
    if blocking:
        bits.append(
            f"{blocking} questions materially affect the analysis and remain unanswered "
            "by the deterministic pass"
        )
    if not bits:
        return ""
    return "Coverage limits: " + "; ".join(bits) + "."


__all__ = ["write"]
