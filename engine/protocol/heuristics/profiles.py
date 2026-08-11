"""Stage 16c — one profile per contract: the level an agent is actually pointed at.

```
LendingPool
├── role            lending_market (0.71) · secondary: token (0.44)
├── purpose         Classified as a lending market. Exposes 9 entry points …
├── entry points    borrow · repay · liquidate · depositInLendingPool · …
├── state           totalRealisedLiquidity (accounting_total) · realisedDebt (debt_record)
│                   interestWeight (unresolved)
├── functions       ordered effect sequences, one per body worth describing
├── permissions     borrow: open · setInterestRate: owner · syncInterests: contract_only
├── depends on      IChainlinkOracle · Account · SafeERC20
├── consumed by     Factory · LiquidationEngine
└── unknowns        the semantic role of 3 state variables could not be established
```

**An index, not a copy.** Everything with a `ProtocolID` here points into the global lists;
only `functions` and `permissions` are per-contract records, because they are per-contract
facts with nowhere else to live. A profile therefore cannot disagree with the model it
describes — there is nothing in it to drift.

**`purpose` is assembled, never authored.** It is a fixed template filled from the role
assignment, the standards claims, the state roles, the operation kinds and the dependency
records — every one of which is a `Claim` with its own evidence and confidence. So the
sentence is as good as its inputs and no better, it is byte-identical across runs, and there
is no path by which a plausible-sounding description of a protocol we did not understand can
appear here.

**`unknowns` is load-bearing.** A profile that lists nine things it knows and stays silent
about the tenth reads as complete. Naming what could not be established is what lets a
downstream agent start where this pass stopped, instead of re-deriving all of it to find out.
"""

from __future__ import annotations

from engine.core.models.code import Contract, ContractKind, Function, FunctionKind
from engine.core.models.evidence import (
    Confidence,
    Evidence,
    heuristic_evidence,
    source_evidence,
)
from engine.core.models.graph import SENTINELS
from engine.core.models.protocol import (
    Asset,
    Compliance,
    ContractClassification,
    ContractProfile,
    ContractRelationship,
    ContractRole,
    Dependency,
    FunctionBehavior,
    Operation,
    OperationKind,
    Permission,
    PermissionMechanism,
    ProtocolModel,
    StateItem,
    StateRole,
)
from engine.protocol.heuristics import behavior as behavior_stage
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_permission_id, make_profile_id

DETECTOR = "contract_profile"

#: Modifier name → the mechanism it conventionally implements. Name-based, so a match here
#: alone produces an `INFERRED` permission; a `msg.sender` check found in the modifier's own
#: body upgrades it to `DERIVED`, because then the mechanism was *observed*.
MECHANISM_BY_MODIFIER: tuple[tuple[str, PermissionMechanism], ...] = (
    ("onlyowner", PermissionMechanism.OWNER),
    ("onlygovernance", PermissionMechanism.GOVERNANCE),
    ("onlygovernor", PermissionMechanism.GOVERNANCE),
    ("onlytimelock", PermissionMechanism.GOVERNANCE),
    ("onlyguardian", PermissionMechanism.GUARDIAN),
    ("onlyself", PermissionMechanism.SELF_ONLY),
    ("onlyproxy", PermissionMechanism.SELF_ONLY),
    ("onlyfactory", PermissionMechanism.CONTRACT_ONLY),
    ("onlyrole", PermissionMechanism.ROLE),
    ("onlyadmin", PermissionMechanism.ROLE),
    ("onlyauthorized", PermissionMechanism.ROLE),
    ("onlykeeper", PermissionMechanism.ROLE),
    ("onlyoperator", PermissionMechanism.ROLE),
    ("onlymanager", PermissionMechanism.ROLE),
    ("onlyminter", PermissionMechanism.ROLE),
    ("onlypauser", PermissionMechanism.ROLE),
    ("onlystrategist", PermissionMechanism.ROLE),
    ("requiresauth", PermissionMechanism.ROLE),
    ("restricted", PermissionMechanism.ROLE),
    ("auth", PermissionMechanism.ROLE),
)

#: Operation kinds grouped into the responsibility they evidence. Used only to *phrase* a
#: responsibility that the operations already establish — never to invent one.
RESPONSIBILITY_BY_KIND: dict[OperationKind, str] = {
    OperationKind.DEPOSIT: "takes deposits",
    OperationKind.WITHDRAW: "pays out withdrawals",
    OperationKind.REDEEM: "redeems claims",
    OperationKind.MINT: "mints",
    OperationKind.BURN: "burns",
    OperationKind.BORROW: "issues borrows",
    OperationKind.REPAY: "accepts repayments",
    OperationKind.LIQUIDATE: "liquidates positions",
    OperationKind.SWAP: "swaps assets",
    OperationKind.ADD_LIQUIDITY: "accepts liquidity",
    OperationKind.REMOVE_LIQUIDITY: "returns liquidity",
    OperationKind.STAKE: "accepts stake",
    OperationKind.UNSTAKE: "returns stake",
    OperationKind.CLAIM: "pays out claims",
    OperationKind.HARVEST: "harvests yield",
    OperationKind.REBALANCE: "rebalances holdings",
    OperationKind.FLASH_LOAN: "issues flash loans",
    OperationKind.BRIDGE_SEND: "sends across a bridge",
    OperationKind.BRIDGE_RECEIVE: "receives from a bridge",
    OperationKind.PROPOSE: "accepts governance proposals",
    OperationKind.VOTE: "records votes",
    OperationKind.EXECUTE: "executes queued actions",
    OperationKind.UPGRADE: "changes its own implementation",
    OperationKind.PAUSE: "can be paused",
    OperationKind.CONFIGURE: "exposes configuration",
    OperationKind.ADMIN: "exposes administrative actions",
    OperationKind.INITIALIZE: "is initialized after deployment",
    OperationKind.TRANSFER: "moves balances between holders",
    OperationKind.APPROVE: "grants allowances",
}

#: State roles worth naming in a purpose sentence. Config and flags are true and dull; a
#: purpose padded with them stops being readable, which is the only thing it is for.
_NOTABLE_STATE = (
    StateRole.ACCOUNTING_TOTAL,
    StateRole.USER_BALANCE,
    StateRole.DEBT_RECORD,
    StateRole.COLLATERAL_RECORD,
    StateRole.SHARE_SUPPLY,
    StateRole.EXCHANGE_RATE,
    StateRole.ACCUMULATOR,
    StateRole.PRICE,
)

MAX_NAMED = 4


def detect(
    index: ProtocolIndex,
    model: ProtocolModel,
    relationships: list[ContractRelationship],
) -> list[ContractProfile]:
    """One profile per classified contract, in canonical `ProtocolID` order.

    Runs late on purpose — after gaps — because a profile indexes the whole model including
    the questions it left open, and a stage cannot index something that has not been emitted.
    """
    modifiers = index.modifier_table
    by_source: dict[str, list[ContractRelationship]] = {}
    by_target: dict[str, list[ContractRelationship]] = {}
    for relationship in relationships:
        by_source.setdefault(relationship.source, []).append(relationship)
        by_target.setdefault(relationship.target, []).append(relationship)

    actors_by_function: dict[str, list[str]] = {}
    for actor in model.actors:
        for capability in actor.capabilities:
            actors_by_function.setdefault(capability.function_id, []).append(actor.id)

    profiles = [
        _build(
            index,
            model,
            classification.contract_id,
            modifiers,
            actors_by_function,
            by_source.get(classification.contract_id, []),
            by_target.get(classification.contract_id, []),
        )
        for classification in model.contracts
        if classification.contract_id in index.contracts
    ]
    return sorted((p for p in profiles if p is not None), key=lambda p: p.id)


def _build(
    index: ProtocolIndex,
    model: ProtocolModel,
    contract_id: str,
    modifiers: dict[str, dict[str, Function]],
    actors_by_function: dict[str, list[str]],
    outgoing: list[ContractRelationship],
    incoming: list[ContractRelationship],
) -> ContractProfile:
    contract = index.contracts[contract_id]
    classification = model.contract(contract_id)
    # Inheritance-flattened, like everything else this package asks about a contract.
    # Storage is inherited: `Tranche`'s share accounting lives in the `ERC4626` it extends,
    # and a profile listing only locally-declared variables hands an agent a vault with no
    # `totalSupply` in it. Two profiles both listing an inherited variable is correct —
    # each deployment has its own copy.
    chain = set(index.query.inheritance(contract_id))
    state = sorted(
        (item for item in model.state if item.contract_id in chain), key=lambda s: s.id
    )
    operations = model.operations_of(contract_id)
    behaviors = behavior_stage.describe(index, contract, model.state, model.operations)

    own_functions = {f.id for f in (*contract.functions, *contract.modifiers)}
    state_var_ids = [item.state_var_id for item in state]
    function_ids = sorted({o.function_id for o in operations})

    standards = model.standards_of(contract_id)
    implemented = [
        claim.standard.value
        for claim in standards
        if claim.compliance in (Compliance.COMPLIANT, Compliance.PARTIAL)
    ]

    assets = _assets_for(model, contract_id, state, operations)
    quantities = [
        q for q in model.accounting.quantities if q.state_id in {item.id for item in state}
    ]
    dependencies = [
        dependency
        for dependency in model.dependencies
        if own_functions & set(dependency.used_by)
    ]
    role_id = classification.id if classification is not None else ""

    purpose, responsibilities = _describe(
        index, model, contract, classification, state, operations, dependencies, implemented
    )

    return ContractProfile(
        id=make_profile_id(contract_id),
        contract_id=contract_id,
        name=contract.name,
        path=contract.path,
        kind=contract.kind.value,
        classification_id=role_id,
        component_id=classification.component_id if classification is not None else None,
        inherits=list(contract.inherits),
        implements=sorted(set(implemented)),
        libraries=sorted({d.library for d in contract.using_for}),
        purpose=purpose,
        documented_purpose=behavior_stage.natspec_lede(contract.natspec),
        responsibilities=responsibilities,
        centrality=round(index.centrality_of(contract_id), 6),
        functions=behaviors,
        permissions=_permissions(
            index, contract, behaviors, modifiers, actors_by_function, state
        ),
        entrypoints=function_ids,
        operation_ids=sorted(o.id for o in operations),
        state_ids=sorted(item.id for item in state),
        actor_ids=sorted(
            {
                actor.id
                for actor in model.actors
                if contract_id in actor.controlled_contracts
                or own_functions & {c.function_id for c in actor.capabilities}
            }
        ),
        asset_ids=sorted(asset.id for asset in assets),
        dependency_ids=sorted(dependency.id for dependency in dependencies),
        flow_ids=sorted(
            {
                flow.id
                for flow in model.asset_flows
                if flow.call_site in own_functions
                or (role_id and role_id in (flow.source, flow.target))
            }
        ),
        quantity_ids=sorted(q.id for q in quantities),
        relationship_ids=sorted(
            {
                relationship.id
                for relationship in model.economics.relationships
                if {relationship.left, relationship.right}
                & ({q.id for q in quantities} | {a.id for a in assets})
            }
        ),
        invariant_ids=sorted(
            {
                invariant.id
                for invariant in model.invariants
                if set(invariant.targets) & ({contract_id, *function_ids, *state_var_ids})
                or contract_id in invariant.supporting_contracts
            }
        ),
        surface_ids=sorted(
            {
                surface.id
                for surface in model.risk_surfaces
                if surface.contract_id == contract_id
                or set(surface.targets) & ({contract_id, *function_ids})
            }
        ),
        boundary_ids=sorted(
            {
                boundary.id
                for boundary in model.trust_boundaries
                if role_id in (boundary.inner, boundary.outer)
                or own_functions & set(boundary.crosses)
            }
        ),
        standard_ids=sorted(claim.id for claim in standards),
        gap_ids=sorted(
            gap.id
            for gap in model.gaps_touching(
                contract_id,
                *([role_id] if role_id else []),
                *(o.id for o in operations),
                *(item.id for item in state),
                *(asset.id for asset in assets),
            )
        ),
        depends_on=sorted({r.target for r in outgoing}),
        consumed_by=sorted({r.source for r in incoming}),
        edge_ids=sorted({r.id for r in (*outgoing, *incoming)}),
        unknowns=_unknowns(model, contract, classification, state, operations, behaviors),
        confidence=Confidence.DERIVED,
        evidence=[
            source_evidence(
                contract_id,
                f"{contract.kind.value} {contract.name}",
                path=contract.path,
                line=contract.line_start,
                line_end=contract.line_end,
                detector=DETECTOR,
            )
        ],
    )


# ── Purpose and responsibilities ──────────────────────────────────────────────


def _describe(
    index: ProtocolIndex,
    model: ProtocolModel,
    contract: Contract,
    classification: ContractClassification | None,
    state: list[StateItem],
    operations: list[Operation],
    dependencies: list[Dependency],
    implemented: list[str],
) -> tuple[str, list[str]]:
    """Assemble the purpose sentence and the responsibility list from evidenced facts.

    Every clause below is present only when the record it draws on exists. A contract whose
    role is `UNKNOWN`, whose state roles are all `UNKNOWN` and which exposes no classified
    operation produces an **empty purpose** — which is the correct output, and is why
    `unknowns` says so explicitly rather than leaving a blank field to be read as an
    oversight.
    """
    clauses: list[str] = []
    responsibilities: list[str] = []

    role = classification.role if classification is not None else ContractRole.UNKNOWN
    if classification is not None and role is not ContractRole.UNKNOWN:
        top = classification.roles[0]
        clause = f"Classified as a {role.value.replace('_', ' ')}"
        if classification.is_ambiguous:
            clause += f" (near-tie with {classification.roles[1].role.value})"
        if top.rationale:
            clause += f" — {top.rationale}"
        clauses.append(clause)

    if implemented:
        clauses.append(f"implements {', '.join(sorted(set(implemented))[:MAX_NAMED])}")

    kinds = _kind_counts(operations)
    if kinds:
        named = ", ".join(f"{kind} ({count})" for kind, count in kinds[:MAX_NAMED])
        clauses.append(f"exposes {len(operations)} entry points: {named}")
        for kind, _ in kinds:
            phrase = RESPONSIBILITY_BY_KIND.get(OperationKind(kind))
            if phrase and phrase not in responsibilities:
                responsibilities.append(phrase)

    notable = [item for item in state if item.role in _NOTABLE_STATE]
    if notable:
        clauses.append(
            "owns "
            + ", ".join(
                f"{item.name} ({item.role.value})" for item in notable[:MAX_NAMED]
            )
        )
        for item in notable[:MAX_NAMED]:
            responsibilities.append(f"maintains {item.name} ({item.role.value})")

    privileged = [o for o in operations if o.is_privileged]
    if privileged:
        responsibilities.append(
            f"gates {len(privileged)} privileged entry points behind access control"
        )

    if dependencies:
        names = ", ".join(sorted({d.name for d in dependencies})[:MAX_NAMED])
        clauses.append(f"depends on {names}")
        responsibilities.append(f"relies on external code: {names}")

    if classification is not None and classification.holds_funds:
        clauses.append("can custody value")
    if classification is not None and classification.is_upgradeable:
        clauses.append("is upgradeable")

    if not clauses:
        return "", sorted(set(responsibilities))

    sentence = ". ".join(
        [clauses[0], *(clause[0].upper() + clause[1:] for clause in clauses[1:])]
    )
    return sentence + ".", _ordered_unique(responsibilities)


def _kind_counts(operations: list[Operation]) -> list[tuple[str, int]]:
    """Operation kinds present, most common first. `UNKNOWN` and `VIEW` are excluded — a
    purpose built around "12 unknown entry points" describes our failure, not the contract."""
    counts: dict[str, int] = {}
    for operation in operations:
        if operation.kind in (OperationKind.UNKNOWN, OperationKind.VIEW):
            continue
        counts[operation.kind.value] = counts.get(operation.kind.value, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


# ── Permissions ───────────────────────────────────────────────────────────────


def _permissions(
    index: ProtocolIndex,
    contract: Contract,
    behaviors: list[FunctionBehavior],
    modifiers: dict[str, dict[str, Function]],
    actors_by_function: dict[str, list[str]],
    state: list[StateItem],
) -> list[Permission]:
    """One record per externally reachable function: who may call it, and how that is enforced.

    Two sources, and the second is what makes this more than a modifier-name lookup. A
    protocol that writes `require(msg.sender == factory)` inline is exactly as gated as one
    that declares `onlyFactory`, and a permission model built from names alone reports the
    first as open — stating "anyone may call this" about a function only the factory can.
    """
    available = modifiers.get(contract.id, {})
    state_names = set(index.state_vars(contract.id))
    records: list[Permission] = []

    for described in behaviors:
        if not described.is_entrypoint or _is_constructor(index, described.function_id):
            continue
        function = index.functions.get(described.function_id)
        if function is None:
            continue

        # Checks written inline, plus the checks inside every modifier applied to it. The
        # second source is the one that matters: `onlyLiquidator` says nothing on its own,
        # and its body says `LIQUIDATOR != msg.sender`.
        checks = list(behavior_stage.authorization_checks(function))
        for name in function.modifiers:
            definition = available.get(_bare(name))
            if definition is not None:
                checks.extend(behavior_stage.authorization_checks(definition))

        mechanism, grounded = _mechanism(function.modifiers, checks, state_names)
        records.append(
            Permission(
                id=make_permission_id(function.id),
                function_id=function.id,
                contract_id=contract.id,
                name=function.name,
                mechanism=mechanism,
                actor_ids=sorted(set(actors_by_function.get(function.id, []))),
                modifiers=list(function.modifiers),
                checks=_ordered_unique([check.text for check in checks])[:6],
                affected_state=list(described.writes),
                is_privileged=mechanism is not PermissionMechanism.OPEN,
                # `DERIVED` only when an authorization check was actually read out of a
                # body. A mechanism inferred from a modifier's *name* is exactly as strong
                # as the naming convention behind it, and no stronger.
                confidence=Confidence.DERIVED if grounded else Confidence.INFERRED,
                evidence=_permission_evidence(contract, function, grounded, checks),
            )
        )
    return sorted(records, key=lambda p: p.id)


def _mechanism(
    applied: list[str],
    checks: list[behavior_stage.AuthCheck],
    state_names: set[str],
) -> tuple[PermissionMechanism, bool]:
    """Decide the mechanism, and whether a body was read to decide it.

    **Evidence outranks naming.** An observed check names the thing the caller is compared
    against, and that identifier decides the mechanism: `owner` is an owner gate, a state
    variable is a named-peer gate, a local variable is a gate whose meaning this pass cannot
    establish. A modifier's *name* only gets consulted when no body could be read.

    Two failure modes this ordering exists to avoid. Arcadia's `borrow` compares against the
    local `accountOwner`; a naive substring search for "owner" reports it as owner-gated,
    which is the difference between a centralization note and a per-position permission. And
    an unrecognised modifier must never produce `OPEN` — a guard we failed to name is still a
    guard, and calling it no guard at all inverts what the record means.
    """
    for check in checks:
        if check.via_role:
            return PermissionMechanism.ROLE, True
        base = _identifier(check.counterparty)
        if base in ("owner", "_owner", "getowner", "owner()"):
            return PermissionMechanism.OWNER, True
        if base in ("this", "address(this)"):
            return PermissionMechanism.SELF_ONLY, True
        if base and base in {name.lower() for name in state_names}:
            return PermissionMechanism.CONTRACT_ONLY, True

    if checks:
        # A check exists and its counterparty is neither the owner nor storage — a local, a
        # parameter, a call result. Real authorization whose mechanism this pass cannot name,
        # which is what `UNKNOWN_GUARD` is for. The verbatim check travels on the record.
        return PermissionMechanism.UNKNOWN_GUARD, True

    for modifier in applied:
        normalized = _normalized(modifier)
        for prefix, mechanism in MECHANISM_BY_MODIFIER:
            if normalized.startswith(prefix):
                return mechanism, False

    # Modifiers with no `msg.sender` check anywhere in them — `nonReentrant`,
    # `whenNotPaused`. Real constraints, but not authorization, so this stays `OPEN`.
    return PermissionMechanism.OPEN, False


def _identifier(expression: str) -> str:
    """`IAccount(account).owner()` → `owner`; `isTranche` → `istranche`.

    The trailing member is what identifies the counterparty: a check against
    `IAccount(account).owner()` is about *an* owner, and its distinguishing token is the
    accessor, not the cast in front of it.
    """
    text = expression.strip().lower().rstrip("()")
    if "." in text:
        text = text.rpartition(".")[2]
    return text.strip("()")


def _is_constructor(index: ProtocolIndex, function_id: str) -> bool:
    """Constructors run once, before any actor exists.

    A permission record on one would assert that somebody may or may not call it, and
    nobody can — it is not part of the live authorization surface at all.
    """
    function = index.functions.get(function_id)
    return function is not None and function.kind is FunctionKind.CONSTRUCTOR


def _permission_evidence(
    contract: Contract,
    function: Function,
    grounded: bool,
    checks: list[behavior_stage.AuthCheck],
) -> list[Evidence]:
    evidence: list[Evidence] = [
        source_evidence(
            function.id,
            f"{function.visibility} {function.name}"
            + (f" {' '.join(function.modifiers)}" if function.modifiers else ""),
            path=contract.path,
            line=function.line_start,
            detector=DETECTOR,
        )
    ]
    for check in checks[:2]:
        evidence.append(
            source_evidence(function.id, check.text, path=contract.path, detector=DETECTOR)
        )
    if not grounded and function.modifiers:
        evidence.append(
            heuristic_evidence(
                DETECTOR,
                f"mechanism read from modifier name {function.modifiers[0]}",
                ref=function.id,
            )
        )
    return evidence



# ── Honesty ───────────────────────────────────────────────────────────────────


def _unknowns(
    model: ProtocolModel,
    contract: Contract,
    classification: ContractClassification | None,
    state: list[StateItem],
    operations: list[Operation],
    behaviors: list[FunctionBehavior],
) -> list[str]:
    """What this pass could not establish about *this* contract, in plain language.

    Deliberately specific. "Coverage is partial" tells a downstream agent nothing; "the
    semantic role of `interestWeight`, `totalInterestWeight` could not be established" tells
    it exactly which variable its own reasoning has to start from.
    """
    unknowns: list[str] = []

    if classification is None or classification.role is ContractRole.UNKNOWN:
        unknowns.append(
            "no role could be established from its interface, storage or naming; every "
            "role-dependent inference below is therefore absent rather than negative"
        )

    unresolved = [item.name for item in state if item.role is StateRole.UNKNOWN]
    if unresolved:
        unknowns.append(
            f"the semantic role of {len(unresolved)} state variables could not be "
            f"established ({', '.join(sorted(unresolved)[:MAX_NAMED])}"
            + (f", +{len(unresolved) - MAX_NAMED} more" if len(unresolved) > MAX_NAMED else "")
            + ")"
        )

    unclassified = [
        o.name for o in operations if o.kind is OperationKind.UNKNOWN and not o.is_view
    ]
    if unclassified:
        unknowns.append(
            f"{len(unclassified)} state-changing entry points could not be mapped to a "
            f"protocol operation ({', '.join(sorted(unclassified)[:MAX_NAMED])})"
        )

    assembly = [b.name for b in behaviors if b.has_assembly]
    if assembly:
        unknowns.append(
            f"{len(assembly)} functions use inline assembly "
            f"({', '.join(sorted(assembly)[:MAX_NAMED])}); storage and calls made in Yul "
            "are invisible to every stage of this model"
        )

    opaque = sorted(
        {
            call
            for described in behaviors
            for call in described.external_calls
            if any(sentinel in call for sentinel in SENTINELS)
        }
    )
    if opaque:
        unknowns.append(
            f"{len(opaque)} external calls resolve to code outside this repository; the "
            "callee's behaviour, including whether it re-enters, is not modelled"
        )

    if contract.kind is ContractKind.ABSTRACT:
        unknowns.append(
            "abstract: some behaviour is supplied by implementers that may live outside "
            "this repository"
        )

    if operations and not any(
        set(i.targets) & {o.function_id for o in operations} for i in model.invariants
    ):
        unknowns.append(
            "no invariant candidate constrains any of its entry points; nothing derived "
            "here can be checked against a property"
        )

    return unknowns


# ── Small helpers ─────────────────────────────────────────────────────────────


def _assets_for(
    model: ProtocolModel,
    contract_id: str,
    state: list[StateItem],
    operations: list[Operation],
) -> list[Asset]:
    wanted = {item.asset_id for item in state if item.asset_id}
    wanted |= {aid for o in operations for aid in (*o.inputs, *o.outputs)}
    return sorted(
        (
            asset
            for asset in model.assets
            if asset.id in wanted or asset.contract_id == contract_id
        ),
        key=lambda a: a.id,
    )


def _bare(modifier: str) -> str:
    """`onlyRole(ADMIN)` → `onlyRole`."""
    return modifier.partition("(")[0].strip()


def _normalized(name: str) -> str:
    return _bare(name).lower().replace("_", "")


def _ordered_unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


__all__ = ["MECHANISM_BY_MODIFIER", "RESPONSIBILITY_BY_KIND", "detect"]
