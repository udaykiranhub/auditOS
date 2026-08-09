"""Stage 2 — what each contract *is*, and stage 1 — what the protocol as a whole is.

```
SimpleVault  →  VAULT  →  archetype VAULT (weight 0.9)
```

Roles come first and the archetype is derived from them, not the other way round. A protocol
is what its contracts do; classifying the repository first and then forcing contracts to fit
that label is how a lending market's staking module gets mislabelled and its bug missed.

**Scoring, not first-match.** Each role is a set of weighted signals — required members,
supporting members, storage names, standards already detected. A contract gets the
highest-scoring role plus every other role that cleared the bar, because a `Vault` that is
also an `ERC20` (its share token) is genuinely both, and dropping the second role loses the
share-accounting half of every finding.

Everything here is `INFERRED` unless a standard carried it. Names are evidence of intent and
nothing more: a contract called `Vault` that lends is a lending market, and the operation
and flow stages downstream are what would catch that.
"""

from __future__ import annotations

from dataclasses import dataclass

from engine.core.models.code import Contract
from engine.core.models.evidence import Confidence, Evidence, heuristic_evidence
from engine.core.models.protocol import (
    Archetype,
    ArchetypeClaim,
    Compliance,
    Component,
    ContractClassification,
    ContractRole,
    Standard,
    StandardClaim,
)
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_component_id, make_role_id

DETECTOR = "contract_role"

#: A role must clear this to be recorded at all. Below it the signals are coincidental —
#: one matching function name in a 40-function contract means nothing.
ROLE_THRESHOLD = 2.0

#: A secondary role must clear this. Higher than the primary bar: a weak second role adds
#: noise to every downstream stage that iterates roles.
SECONDARY_THRESHOLD = 3.0


@dataclass(frozen=True)
class RoleRule:
    """Weighted signals for one role. Weights are relative, not calibrated probabilities."""

    role: ContractRole
    functions: tuple[str, ...] = ()
    """Function *name* fragments (not signatures) — matched against the flattened surface."""
    storage: tuple[str, ...] = ()
    names: tuple[str, ...] = ()
    """Contract-name fragments. Weakest signal, weighted lowest."""
    standards: tuple[Standard, ...] = ()
    requires: tuple[str, ...] = ()
    """Function-name fragments that MUST all be present. A vault without any deposit-shaped
    function is not a vault however many `total*` variables it has."""

    function_weight: float = 1.0
    storage_weight: float = 1.0
    name_weight: float = 0.75
    standard_weight: float = 3.0


RULES: tuple[RoleRule, ...] = (
    RoleRule(
        ContractRole.VAULT,
        functions=("deposit", "withdraw", "redeem", "mint", "previewdeposit", "converttoshares"),
        storage=("totalassets", "totalshares", "shares", "asset", "totalsupply"),
        names=("vault", "pool4626", "erc4626"),
        standards=(Standard.ERC4626,),
        requires=("deposit", "withdraw", "redeem"),
    ),
    RoleRule(
        ContractRole.LENDING_MARKET,
        functions=("borrow", "repay", "supply", "redeemunderlying", "accrueinterest"),
        storage=("totalborrows", "borrowindex", "reserves", "collateral", "debt"),
        names=("lend", "ctoken", "atoken", "market", "comptroller", "pool"),
        requires=("borrow", "repay"),
    ),
    RoleRule(
        ContractRole.LIQUIDATION_ENGINE,
        functions=("liquidate", "liquidationcall", "seize", "healthfactor", "iscollateralized"),
        storage=("liquidationthreshold", "closefactor", "liquidationbonus", "healthfactor"),
        names=("liquidat",),
        requires=("liquidat",),
    ),
    RoleRule(
        ContractRole.POOL,
        functions=("swap", "getreserves", "addliquidity", "removeliquidity", "mint", "burn"),
        storage=("reserve0", "reserve1", "kLast", "liquidity", "sqrtprice"),
        names=("pair", "pool", "amm", "curve"),
        requires=("swap",),
    ),
    RoleRule(
        ContractRole.ROUTER,
        functions=("swapexacttokensfor", "swaptokensforexact", "quote", "getamountsout",
                   "addliquidity", "multicall"),
        names=("router", "aggregator", "zap"),
        requires=("swap",),
    ),
    RoleRule(
        ContractRole.ORACLE,
        functions=("latestanswer", "latestrounddata", "getprice", "price", "consult", "peek"),
        storage=("pricefeed", "aggregator", "twap", "observations"),
        names=("oracle", "pricefeed", "aggregator"),
        requires=("price", "answer", "peek", "consult"),
    ),
    RoleRule(
        ContractRole.STAKING,
        functions=("stake", "unstake", "withdraw", "getreward", "earned", "exit"),
        storage=("rewardpertokenstored", "rewardrate", "periodfinish", "staked"),
        names=("staking", "stake", "gauge"),
        requires=("stake",),
    ),
    RoleRule(
        ContractRole.REWARD_DISTRIBUTOR,
        functions=("claim", "getreward", "notifyrewardamount", "distribute", "accrue"),
        storage=("rewards", "merkleroot", "claimed", "rewardpertoken"),
        names=("reward", "distributor", "merkle", "airdrop"),
        requires=("claim", "distribute", "getreward"),
    ),
    RoleRule(
        ContractRole.GOVERNANCE,
        functions=("propose", "castvote", "execute", "queue", "state", "quorum"),
        storage=("proposals", "votes", "quorum", "votingdelay", "votingperiod"),
        names=("governor", "governance", "voting"),
        requires=("propose", "castvote"),
    ),
    RoleRule(
        ContractRole.TIMELOCK,
        functions=("schedule", "queuetransaction", "executetransaction", "cancel", "delay"),
        storage=("delay", "queuedtransactions", "mindelay", "timestamps"),
        names=("timelock",),
        requires=("delay", "schedule", "queue"),
    ),
    RoleRule(
        ContractRole.BRIDGE,
        functions=("bridge", "deposit", "finalizewithdrawal", "relaymessage", "provehash",
                   "sendmessage", "receivemessage"),
        storage=("nonce", "processed", "messages", "remotechain", "domain"),
        names=("bridge", "portal", "messenger", "crosschain", "l1", "l2"),
        requires=("bridge", "relay", "message"),
    ),
    RoleRule(
        ContractRole.TOKEN,
        functions=("transfer", "approve", "balanceof", "totalsupply"),
        storage=("balanceof", "allowance", "totalsupply"),
        names=("token", "erc20", "coin"),
        standards=(Standard.ERC20,),
        requires=("transfer",),
    ),
    RoleRule(
        ContractRole.FACTORY,
        functions=("create", "deploy", "createpair", "clone", "getpair"),
        storage=("allpairs", "deployed", "implementation", "getpair"),
        names=("factory", "deployer", "creator"),
        requires=("create", "deploy", "clone"),
    ),
    RoleRule(
        ContractRole.REGISTRY,
        functions=("register", "set", "get", "add", "remove", "islisted"),
        storage=("registry", "whitelist", "allowlist", "registered"),
        names=("registry", "whitelist", "addressprovider", "resolver"),
        requires=("register", "islisted"),
    ),
    RoleRule(
        ContractRole.STRATEGY,
        functions=("harvest", "invest", "divest", "rebalance", "report", "tend"),
        storage=("want", "strategist", "vault", "lastharvest"),
        names=("strategy", "strat", "adapter"),
        requires=("harvest", "invest", "rebalance"),
    ),
    RoleRule(
        ContractRole.ESCROW,
        functions=("lock", "unlock", "release", "claim", "vest"),
        storage=("locked", "unlocktime", "vesting", "cliff"),
        names=("escrow", "vesting", "lock", "timelockedtoken"),
        requires=("lock", "vest", "release"),
    ),
    RoleRule(
        ContractRole.ACCESS_CONTROL,
        functions=("hasrole", "grantrole", "revokerole", "transferownership"),
        storage=("roles", "owner", "admin"),
        names=("access", "auth", "roles", "acl"),
        standards=(Standard.ACCESS_CONTROL,),
        requires=("role", "owner"),
    ),
)


def classify(index: ProtocolIndex, standards: list[StandardClaim]) -> list[ContractClassification]:
    """One classification per audited contract, roles scored rather than first-matched."""
    by_contract: dict[str, list[StandardClaim]] = {}
    for claim in standards:
        by_contract.setdefault(claim.contract_id, []).append(claim)

    classifications: list[ContractClassification] = []
    for contract in index.audited:
        scores = _score(index, contract, by_contract.get(contract.id, []))
        ranked = sorted(scores.items(), key=lambda item: (-item[1][0], item[0].value))

        primary, secondary = _pick(ranked)
        top_evidence = scores.get(primary, (0.0, []))[1]

        classifications.append(
            ContractClassification(
                id=make_role_id(contract.id),
                contract_id=contract.id,
                name=contract.name,
                role=primary,
                secondary_roles=secondary,
                is_upgradeable=_is_upgradeable(index, contract, by_contract.get(contract.id, [])),
                is_pausable=any(
                    c.standard is Standard.PAUSABLE for c in by_contract.get(contract.id, [])
                ),
                is_entry_contract=bool(index.entrypoints_of(contract)),
                holds_funds=_holds_funds(index, contract),
                centrality=index.centrality_of(contract.id),
                confidence=Confidence.INFERRED,
                evidence=top_evidence
                or [heuristic_evidence(DETECTOR, "no role signals matched", ref=contract.id)],
            )
        )
    return classifications


def _score(
    index: ProtocolIndex, contract: Contract, standards: list[StandardClaim]
) -> dict[ContractRole, tuple[float, list[Evidence]]]:
    surface = {name.lower() for name in index.exposed(contract.id)}
    storage = {name.lower() for name in index.state_vars(contract.id)}
    contract_name = contract.name.lower()
    compliant = {
        claim.standard
        for claim in standards
        if claim.compliance in (Compliance.COMPLIANT, Compliance.PARTIAL, Compliance.DIVERGENT)
    }

    scores: dict[ContractRole, tuple[float, list[Evidence]]] = {}
    for rule in RULES:
        if rule.requires and not any(
            _any_contains(surface, needle) for needle in rule.requires
        ):
            continue  # the defining behaviour is absent; nothing else can compensate

        total = 0.0
        evidence: list[Evidence] = []

        hits = [needle for needle in rule.functions if _any_contains(surface, needle)]
        if hits:
            total += rule.function_weight * len(hits)
            evidence.append(
                heuristic_evidence(
                    DETECTOR, f"exposes {', '.join(hits[:5])}", ref=contract.id
                )
            )

        storage_hits = [needle for needle in rule.storage if _any_contains(storage, needle)]
        if storage_hits:
            total += rule.storage_weight * len(storage_hits)
            evidence.append(
                heuristic_evidence(
                    DETECTOR, f"stores {', '.join(storage_hits[:5])}", ref=contract.id
                )
            )

        name_hits = [needle for needle in rule.names if needle in contract_name]
        if name_hits:
            total += rule.name_weight * len(name_hits)
            evidence.append(
                heuristic_evidence(DETECTOR, f"named for {name_hits[0]}", ref=contract.id)
            )

        standard_hits = [s for s in rule.standards if s in compliant]
        if standard_hits:
            total += rule.standard_weight * len(standard_hits)
            evidence.append(
                heuristic_evidence(
                    DETECTOR,
                    f"implements {', '.join(s.value for s in standard_hits)}",
                    ref=contract.id,
                )
            )

        if total > 0:
            scores[rule.role] = (total, evidence)
    return scores


def _pick(
    ranked: list[tuple[ContractRole, tuple[float, list[Evidence]]]],
) -> tuple[ContractRole, list[ContractRole]]:
    if not ranked or ranked[0][1][0] < ROLE_THRESHOLD:
        return ContractRole.UNKNOWN, []
    primary = ranked[0][0]
    secondary = [
        role for role, (score, _) in ranked[1:] if score >= SECONDARY_THRESHOLD
    ]
    return primary, secondary


def _is_upgradeable(
    index: ProtocolIndex, contract: Contract, standards: list[StandardClaim]
) -> bool:
    """Upgradeable if it *is* a proxy or is written to sit behind one.

    An `initialize()` with no constructor is the tell for an implementation contract: its
    constructor cannot run behind a proxy, so state is set in an initializer instead.
    """
    proxy_standards = {
        Standard.ERC1967,
        Standard.UUPS,
        Standard.TRANSPARENT_PROXY,
        Standard.BEACON_PROXY,
        Standard.DIAMOND,
    }
    if any(claim.standard in proxy_standards for claim in standards):
        return True
    if index.inherits_name(contract.id, "upgradeable", "initializable"):
        return True
    return any(name.startswith("initialize(") for name in index.exposed(contract.id))


def _holds_funds(index: ProtocolIndex, contract: Contract) -> bool:
    """Can this contract custody value?

    Three independent tells, any one sufficient: it accepts ETH, it pulls tokens to itself,
    or it holds per-account balances. Kept broad on purpose — a false positive costs a
    slightly wider risk surface, a false negative loses every asset-flow finding on it.
    """
    functions = [*contract.functions, *contract.modifiers]
    if any(f.mutability == "payable" for f in functions):
        return True
    if any(f.kind.value == "receive" for f in functions):
        return True
    for function in functions:
        for kind, _, text, _ in index.token_edges_by_function.get(function.id, []):
            if kind.value in ("transfers_from", "mints"):
                return True
            if "address(this)" in text:
                return True
    storage = index.state_vars(contract.id)
    return any(
        variable.type.startswith("mapping(address")
        and ("uint" in variable.type or "balance" in name.lower())
        for name, variable in storage.items()
    )


def _any_contains(haystack: set[str], needle: str) -> bool:
    return any(needle in item for item in haystack)


# ── Stage 1: protocol archetype, derived from the roles ───────────────────────

#: Which contract roles imply which protocol archetype, and how strongly. Derived from
#: roles rather than scanned independently: a protocol is what its contracts do.
ROLE_TO_ARCHETYPE: dict[ContractRole, tuple[Archetype, float]] = {
    ContractRole.VAULT: (Archetype.VAULT, 1.0),
    ContractRole.LENDING_MARKET: (Archetype.LENDING, 1.0),
    ContractRole.LIQUIDATION_ENGINE: (Archetype.LENDING, 0.6),
    ContractRole.POOL: (Archetype.AMM, 1.0),
    ContractRole.ROUTER: (Archetype.AMM, 0.5),
    ContractRole.STAKING: (Archetype.STAKING, 1.0),
    ContractRole.REWARD_DISTRIBUTOR: (Archetype.STAKING, 0.4),
    ContractRole.GOVERNANCE: (Archetype.GOVERNANCE, 1.0),
    ContractRole.TIMELOCK: (Archetype.GOVERNANCE, 0.4),
    ContractRole.BRIDGE: (Archetype.BRIDGE, 1.0),
    ContractRole.TOKEN: (Archetype.TOKEN, 0.5),
    ContractRole.ORACLE: (Archetype.ORACLE, 0.6),
    ContractRole.STRATEGY: (Archetype.YIELD_AGGREGATOR, 0.8),
    ContractRole.ESCROW: (Archetype.ESCROW, 0.7),
    ContractRole.REGISTRY: (Archetype.REGISTRY, 0.3),
}

#: Archetypes below this share of the total signal are dropped: every protocol has *some*
#: token contract, and listing TOKEN alongside LENDING on Aave would be actively misleading.
ARCHETYPE_FLOOR = 0.15


def archetypes(classifications: list[ContractClassification]) -> list[ArchetypeClaim]:
    """Stage 1, computed from stage 2. Multi-valued: a lending market with its own staking
    module is both, and forcing one label loses the half that gets exploited."""
    weights: dict[Archetype, float] = {}
    contributors: dict[Archetype, list[str]] = {}

    for classification in classifications:
        for role in (classification.role, *classification.secondary_roles):
            mapped = ROLE_TO_ARCHETYPE.get(role)
            if mapped is None:
                continue
            archetype, weight = mapped
            # Centrality-weighted: a peripheral helper with a staking-shaped interface
            # should not outvote the core market.
            scaled = weight * (1.0 + classification.centrality * 10)
            weights[archetype] = weights.get(archetype, 0.0) + scaled
            contributors.setdefault(archetype, []).append(classification.contract_id)

    if not weights:
        return [
            ArchetypeClaim(
                archetype=Archetype.UNKNOWN,
                weight=0.0,
                confidence=Confidence.INFERRED,
                rationale="no contract matched a known role",
                evidence=[heuristic_evidence(DETECTOR, "no role signals in the repository")],
            )
        ]

    total = sum(weights.values())
    claims = [
        ArchetypeClaim(
            archetype=archetype,
            weight=round(weight / total, 4),
            rationale=f"{len(contributors[archetype])} contracts classified into this archetype",
            confidence=Confidence.INFERRED,
            evidence=[
                heuristic_evidence(
                    DETECTOR,
                    f"from {', '.join(sorted(contributors[archetype])[:3])}",
                    ref=sorted(contributors[archetype])[0],
                )
            ],
        )
        for archetype, weight in weights.items()
        if weight / total >= ARCHETYPE_FLOOR
    ]
    return claims or [
        ArchetypeClaim(archetype=Archetype.UNKNOWN, weight=0.0, confidence=Confidence.INFERRED)
    ]


def components(
    index: ProtocolIndex, classifications: list[ContractClassification]
) -> list[Component]:
    """Stage 1's second half — named subsystems, one per distinct role cluster.

    Coarser than a contract and finer than the protocol: the unit a human auditor reasons
    in, and the unit the Context Builder slices on when a request is scoped to a feature.
    """
    clusters: dict[ContractRole, list[ContractClassification]] = {}
    for classification in classifications:
        if classification.role is not ContractRole.UNKNOWN:
            clusters.setdefault(classification.role, []).append(classification)

    result: list[Component] = []
    for role, members in sorted(clusters.items(), key=lambda item: item[0].value):
        contract_ids = sorted(m.contract_id for m in members)
        archetype = ROLE_TO_ARCHETYPE.get(role, (Archetype.UNKNOWN, 0.0))[0]
        result.append(
            Component(
                id=make_component_id(role.value),
                name=role.value.replace("_", " "),
                archetype=archetype,
                purpose=f"the {role.value.replace('_', ' ')} subsystem",
                contract_ids=contract_ids,
                entrypoints=sorted(
                    function.id
                    for cid in contract_ids
                    if (contract := index.contracts.get(cid)) is not None
                    for function in index.entrypoints_of(contract)
                ),
                confidence=Confidence.INFERRED,
                evidence=[
                    heuristic_evidence(
                        DETECTOR, f"{len(contract_ids)} contracts share this role",
                        ref=contract_ids[0],
                    )
                ],
            )
        )
    return result


__all__ = ["ROLE_TO_ARCHETYPE", "RULES", "RoleRule", "archetypes", "classify", "components"]
