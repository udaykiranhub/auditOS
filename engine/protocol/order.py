"""Canonical ordering for `ProtocolModel` (SPEC §7.1: byte-identical artifacts).

Seventeen stages run in a fixed order but each appends in *discovery* order — the order a
dict happened to iterate, or a detector happened to fire. That is stable within a process
and not stable across them, which is enough to make `content_hash` differ between two runs
over identical input. Caching and resume both key on that hash, so an unsorted artifact
does not fail loudly; it just quietly never caches.

So every list has exactly one canonical order, defined here and only here, and
`engine.protocol.validate` checks the artifact is in it before the file is written.

Sorting is by `ProtocolID` wherever one exists, because those IDs are content-derived: the
order then depends on the protocol's content rather than on how the model was built.
"""

from __future__ import annotations

from engine.core.models.evidence import dedupe_evidence
from engine.core.models.protocol import (
    Accounting,
    ArchetypeClaim,
    Capability,
    ProtocolModel,
)


def _archetype_key(claim: ArchetypeClaim) -> tuple[float, str]:
    """Strongest first — this list is read as a ranking, so its order is meaning, not
    bookkeeping. Ties broken by name so equal weights still sort deterministically."""
    return (-claim.weight, claim.archetype.value)


def _capability_key(capability: Capability) -> tuple[str, str]:
    return (capability.function_id, capability.description)


#: Cross-reference lists on a `ContractProfile`. Every one is a set of IDs with no inherent
#: order, so every one sorts. `responsibilities` and `unknowns` are prose in a chosen order
#: and are deliberately absent from this list.
_PROFILE_ID_LISTS = (
    "entrypoints",
    "operation_ids",
    "state_ids",
    "actor_ids",
    "asset_ids",
    "dependency_ids",
    "flow_ids",
    "quantity_ids",
    "relationship_ids",
    "invariant_ids",
    "surface_ids",
    "boundary_ids",
    "standard_ids",
    "gap_ids",
    "depends_on",
    "consumed_by",
    "edge_ids",
)


def canonicalize(model: ProtocolModel) -> ProtocolModel:
    """Return an equivalent model in canonical order, with evidence deduped.

    Pure: the input is untouched, matching the append-only artifact rule (SPEC §7.1 rule 4).
    """
    actors = [
        actor.model_copy(
            update={
                "capabilities": [
                    capability.model_copy(
                        update={"evidence": dedupe_evidence(capability.evidence)}
                    )
                    for capability in sorted(actor.capabilities, key=_capability_key)
                ],
                "roles": sorted(set(actor.roles)),
                "controlled_contracts": sorted(set(actor.controlled_contracts)),
            }
        )
        for actor in model.actors
    ]

    accounting = Accounting(
        quantities=sorted(model.accounting.quantities, key=lambda q: q.id),
        relations=sorted(model.accounting.relations, key=lambda r: r.id),
        unit_conflicts=sorted(set(model.accounting.unit_conflicts)),
    )

    economics = model.economics.model_copy(
        update={
            "fee_sources": sorted(set(model.economics.fee_sources)),
            "reward_sources": sorted(set(model.economics.reward_sources)),
            "incentives": sorted(set(model.economics.incentives)),
            "value_capture": sorted(set(model.economics.value_capture)),
            "relationships": sorted(model.economics.relationships, key=lambda r: r.id),
            "surfaces": sorted(model.economics.surfaces, key=lambda s: s.id),
        }
    )

    # A classification's role list is a *ranking* — strongest first — so it is ordered by
    # score, not by name. Sorting it alphabetically would destroy the only thing it says.
    contracts = [
        classification.model_copy(
            update={
                "roles": sorted(
                    classification.roles, key=lambda a: (-a.score, a.role.value)
                )
            }
        )
        for classification in model.contracts
    ]

    # A profile's own lists are already ID-sorted at construction; re-sorting here is what
    # makes that a guarantee rather than a convention, and `steps` is deliberately *not*
    # touched — its order is the execution sequence and sorting it would destroy the only
    # thing it says.
    profiles = [
        profile.model_copy(
            update={
                "functions": sorted(profile.functions, key=lambda f: f.id),
                "permissions": sorted(profile.permissions, key=lambda p: p.id),
                **{
                    field: sorted(set(getattr(profile, field)))
                    for field in _PROFILE_ID_LISTS
                },
            }
        )
        for profile in model.profiles
    ]

    ordered = model.model_copy(
        update={
            "archetypes": sorted(model.archetypes, key=_archetype_key),
            "profiles": sorted(profiles, key=lambda p: p.id),
            "contract_relationships": sorted(
                model.contract_relationships, key=lambda r: r.id
            ),
            "components": sorted(model.components, key=lambda c: c.id),
            "contracts": sorted(contracts, key=lambda c: c.id),
            "standards": sorted(model.standards, key=lambda s: s.id),
            "actors": sorted(actors, key=lambda a: a.id),
            "trust_boundaries": sorted(model.trust_boundaries, key=lambda b: b.id),
            "assets": sorted(model.assets, key=lambda a: a.id),
            "asset_flows": sorted(model.asset_flows, key=lambda f: f.id),
            "operations": sorted(model.operations, key=lambda o: o.id),
            "entrypoints": sorted(set(model.entrypoints)),
            "privileged": sorted(set(model.privileged)),
            "state": sorted(model.state, key=lambda s: s.id),
            "state_transitions": sorted(model.state_transitions, key=lambda t: t.id),
            "dependencies": sorted(model.dependencies, key=lambda d: d.id),
            "accounting": accounting,
            "economics": economics,
            "documentation_rules": sorted(model.documentation_rules, key=lambda r: r.id),
            "assumptions": sorted(model.assumptions, key=lambda a: a.id),
            "invariants": sorted(model.invariants, key=lambda i: i.id),
            "risk_surfaces": sorted(model.risk_surfaces, key=lambda s: s.id),
            "gaps": sorted(model.gaps, key=lambda g: g.id),
            # `core_contracts` is a *ranking* (most central first) and is left alone —
            # sorting it alphabetically would destroy the only information it carries.
        }
    )

    for claim in ordered.claims():
        claim.evidence = dedupe_evidence(claim.evidence)
    return ordered


def _relationship_ids(model: ProtocolModel) -> list[str]:
    return [relationship.id for relationship in model.economics.relationships]


def canonical_order_violations(model: ProtocolModel) -> list[str]:
    """Names of the lists that are not in canonical order. Empty means reproducible.

    Compared by ID sequence rather than by record: every ID-keyed list sorts by its ID, so
    "are the IDs ascending?" is the same question and does not require the records
    themselves to be comparable.
    """
    by_id: dict[str, list[str]] = {
        "components": [c.id for c in model.components],
        "contracts": [c.id for c in model.contracts],
        "standards": [s.id for s in model.standards],
        "actors": [a.id for a in model.actors],
        "trust_boundaries": [b.id for b in model.trust_boundaries],
        "assets": [a.id for a in model.assets],
        "asset_flows": [f.id for f in model.asset_flows],
        "operations": [o.id for o in model.operations],
        "state": [s.id for s in model.state],
        "state_transitions": [t.id for t in model.state_transitions],
        "dependencies": [d.id for d in model.dependencies],
        "accounting.quantities": [q.id for q in model.accounting.quantities],
        "accounting.relations": [r.id for r in model.accounting.relations],
        "economics.relationships": _relationship_ids(model),
        "economics.surfaces": [s.id for s in model.economics.surfaces],
        "documentation_rules": [r.id for r in model.documentation_rules],
        "assumptions": [a.id for a in model.assumptions],
        "invariants": [i.id for i in model.invariants],
        "risk_surfaces": [s.id for s in model.risk_surfaces],
        "profiles": [p.id for p in model.profiles],
        "contract_relationships": [r.id for r in model.contract_relationships],
        "gaps": [g.id for g in model.gaps],
    }
    for profile in model.profiles:
        by_id[f"{profile.id}.functions"] = [f.id for f in profile.functions]
        by_id[f"{profile.id}.permissions"] = [p.id for p in profile.permissions]
    violations = [name for name, ids in by_id.items() if ids != sorted(ids)]

    # Archetypes rank by weight rather than by ID — the order is the meaning.
    keys = [_archetype_key(claim) for claim in model.archetypes]
    if keys != sorted(keys):
        violations.append("archetypes")
    return sorted(violations)


__all__ = ["canonical_order_violations", "canonicalize"]
