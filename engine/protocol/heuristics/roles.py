"""Stage 2 — what each contract *is*, and stage 1 — what the protocol as a whole is.

```
SimpleVault  →  VAULT  →  archetype VAULT (weight 0.9)
```

Roles come first and the archetype is derived from them, not the other way round. A protocol
is what its contracts do; classifying the repository first and then forcing contracts to fit
that label is how a lending market's staking module gets mislabelled and its bug missed.

**Scoring, not first-match.** Each role is a set of weighted signals — required members,
supporting members, storage names, standards already detected. A contract gets every role
that cleared the bar, strongest first, because a `Vault` that is also an `ERC20` (its share
token) is genuinely both, and dropping the second loses the share-accounting half of every
finding.

**Two rules keep the scoring honest**, and both exist because the first version failed on
a real protocol — Arcadia, where 21 of 35 contracts came out as "vault", including its
price oracles and its registry:

1. **Whole-word matching.** `getUsdValueExposureToUnderlyingAssetAfterDeposit` is not a
   deposit function, and `assetToAssetInformation` is not a vault's `asset` handle.
   Substring matching read both as vault signals. Signals now match on camelCase word
   boundaries, and the defining ones must appear in *prefix* position — a function named
   for an action performs it; one that merely mentions it usually reports on it.
2. **Normalized scores.** Raw hit counts reward size: a 40-function registry accumulates
   more incidental matches than a 6-function vault and outscores it. Each role's score is
   now its share of the signals that role actually defines, so a small contract matching
   3 of 4 vault signals beats a large one matching 5 of 20.

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
    RoleAssignment,
    Standard,
    StandardClaim,
)
from engine.protocol.heuristics.signatures import (
    ProtocolIndex,
    has_token,
    starts_with_token,
)
from engine.protocol.ids import make_component_id, make_role_id

DETECTOR = "contract_role"

#: Normalized share of a role's own signals that must match before the role is recorded.
#: Below this the matches are incidental — one deposit-shaped name in a registry means
#: nothing, and admitting it is how 21 of Arcadia's 35 contracts became vaults.
ROLE_THRESHOLD = 0.34

#: A role beyond the first must clear this. Higher than the primary bar: a weak second role
#: adds noise to every downstream stage that iterates roles.
SECONDARY_THRESHOLD = 0.5

#: Roles beyond the primary that are worth carrying. More than this and the list stops
#: being a classification and becomes a shrug.
MAX_ROLES = 3

#: Matches that count as full credit for a category. **Enumerating synonyms must not dilute
#: a role's own score.** Under a `len(signals)` denominator, the well-specified rules lost to
#: the sketchy ones: Arcadia's `LendingPool` scored 0.29 for `lending_market` — under the
#: 0.34 bar — because that rule lists six function signals and the pool matches two of them
#: (`borrow`, `repay`), while `token` scored 0.89 on a single inherited ERC-20 standard. The
#: pool was therefore classified as a token, and every profile, purpose and invariant built
#: on that role inherited the mistake.
#:
#: A role is evidenced by *a few* of its defining signals appearing, not by all of them, so
#: the denominator is capped the same way `names` already caps at one. `names` and
#: `standards` are unchanged: a contract has one name and either implements a standard or
#: does not.
EXPECTED_FUNCTIONS = 3
EXPECTED_STORAGE = 2


@dataclass(frozen=True)
class RoleRule:
    """Weighted signals for one role. Weights are relative, not calibrated probabilities."""

    role: ContractRole
    functions: tuple[str, ...] = ()
    """Function *name* fragments (not signatures) — matched as whole words against the
    inheritance-flattened surface."""
    storage: tuple[str, ...] = ()
    names: tuple[str, ...] = ()
    """Contract-name fragments. Weakest signal, weighted lowest."""
    standards: tuple[Standard, ...] = ()
    requires: tuple[str, ...] = ()
    """Defining actions. At least one must appear as a whole-word **prefix** of some
    exposed function. A vault without any function actually named for depositing is not a
    vault, however many `total*` variables it has — and `getValueAfterDeposit` does not
    count, which is the whole reason this is prefix-matched."""

    excluded_by: tuple[ContractRole, ...] = ()
    """Roles that, when they score higher, make this one implausible rather than secondary.
    A pricing module scoring above `VAULT` means the deposit-shaped names were valuation
    hooks; carrying `VAULT` alongside would attach custody semantics to a contract that
    holds nothing."""

    function_weight: float = 1.0
    storage_weight: float = 1.0
    name_weight: float = 1.5
    """Higher than a single function hit: a contract *named* `ChainlinkOracleModule` is
    stating its purpose, which is stronger evidence than one incidental method name."""
    standard_weight: float = 4.0


RULES: tuple[RoleRule, ...] = (
    # ── Roles that must be tested for, because their absence is what made everything
    # else look like a vault on a real protocol ────────────────────────────────────────
    RoleRule(
        ContractRole.PRICING_MODULE,
        functions=(
            "getValue",
            "processDirectDeposit",
            "processIndirectDeposit",
            "processDirectWithdrawal",
            "processIndirectWithdrawal",
            "getUsdValue",
            "isAllowed",
            "getRiskFactors",
            "getUnderlyingAssets",
            "getRate",
            "setRiskParameters",
        ),
        storage=("assetToInformation", "riskParams", "exposure", "assetModule", "oracle"),
        names=("assetmodule", "am", "pricingmodule", "valuation", "adapter"),
        requires=("getValue", "processDirect", "processIndirect", "getUsdValue", "isAllowed"),
        excluded_by=(),
    ),
    RoleRule(
        ContractRole.ACCOUNT,
        functions=(
            "flashAction",
            "getAccountValue",
            "openMarginAccount",
            "closeMarginAccount",
            "transferOwnership",
            "generateAssetData",
            "getCollateralValue",
            "isAccountUnhealthy",
            "isAccountLiquidatable",
        ),
        storage=("owner", "creditor", "registry", "erc20Stored", "erc721Stored"),
        names=("account", "wallet", "position", "safe"),
        requires=("flashAction", "getAccountValue", "openMarginAccount", "isAccountLiquidatable"),
    ),
    RoleRule(
        ContractRole.GUARDIAN,
        functions=("pause", "unPause", "unpause", "setPauseFlag", "changeGuardian"),
        storage=("pauseTimestamp", "guardian", "paused"),
        names=("guardian",),
        requires=("pause", "changeGuardian"),
    ),
    RoleRule(
        ContractRole.MIGRATOR,
        functions=("migrate", "upgradeAccount", "endUpgrade"),
        names=("migrator", "migration"),
        requires=("migrate",),
    ),
    RoleRule(
        ContractRole.HOOK,
        functions=("beforeSwap", "afterSwap", "beforeAddLiquidity", "afterAddLiquidity"),
        names=("hook",),
        requires=("beforeSwap", "afterSwap"),
    ),
    RoleRule(
        ContractRole.VAULT,
        functions=(
            "deposit",
            "withdraw",
            "redeem",
            "mint",
            "previewDeposit",
            "convertToShares",
            "convertToAssets",
            "totalAssets",
        ),
        storage=("totalAssets", "totalShares", "shares", "asset", "totalSupply"),
        names=("vault", "erc4626", "tranche"),
        standards=(Standard.ERC4626,),
        requires=("deposit", "withdraw", "redeem", "mint"),
        # Every valuation adapter in existence has a `processDirectDeposit`; without this
        # they all read as vaults and inherit custody semantics they have no business with.
        excluded_by=(ContractRole.PRICING_MODULE, ContractRole.REGISTRY, ContractRole.ORACLE),
    ),
    RoleRule(
        ContractRole.LENDING_MARKET,
        functions=("borrow", "repay", "supply", "redeemUnderlying", "accrueInterest", "liquidate"),
        storage=("totalBorrows", "borrowIndex", "reserves", "collateral", "debt", "realisedDebt"),
        names=("lending", "ctoken", "atoken", "market", "comptroller", "lendingpool"),
        requires=("borrow", "repay"),
    ),
    RoleRule(
        ContractRole.LIQUIDATION_ENGINE,
        functions=(
            "liquidate",
            "liquidationCall",
            "seize",
            "healthFactor",
            "isCollateralized",
            "auction",
        ),
        storage=("liquidationThreshold", "closeFactor", "liquidationBonus", "healthFactor"),
        names=("liquidator", "liquidation", "auction"),
        requires=("liquidate", "liquidationCall", "startAuction"),
    ),
    RoleRule(
        ContractRole.POOL,
        functions=("swap", "getReserves", "addLiquidity", "removeLiquidity", "mint", "burn"),
        storage=("reserve0", "reserve1", "kLast", "liquidity", "sqrtPrice"),
        names=("pair", "pool", "amm", "curve"),
        requires=("swap",),
    ),
    RoleRule(
        ContractRole.ROUTER,
        functions=("swapExactTokensFor", "swapTokensForExact", "quote", "getAmountsOut",
                   "addLiquidity", "multicall"),
        names=("router", "aggregator", "zap"),
        requires=("swap",),
    ),
    RoleRule(
        ContractRole.ORACLE,
        functions=(
            "latestAnswer",
            "latestRoundData",
            "getPrice",
            # A price getter is almost never spelled `getPrice()`. Chainlink says
            # `latestRoundData`, Compound says `getUnderlyingPrice`, Aave says
            # `getAssetPrice`, and the requirement is prefix-matched — so a list holding
            # only the idealised spelling classified a textbook price oracle as `unknown`.
            "getAssetPrice",
            "getUnderlyingPrice",
            "getAssetValue",
            "getAmountFromValue",
            "setPrice",
            "registerFeed",
            "getFeed",
            "getRate",
            "consult",
            "peek",
            "addOracle",
            "isActive",
            "decommissionOracle",
        ),
        storage=(
            "priceFeed",
            "aggregator",
            "twap",
            "observations",
            "oracleInformation",
            "feeds",
            "stalenessThreshold",
        ),
        names=("oracle", "pricefeed", "aggregator", "om", "chainlink", "redstone", "pyth"),
        requires=(
            "getPrice",
            "getAssetPrice",
            "getUnderlyingPrice",
            "latestAnswer",
            "latestRoundData",
            "peek",
            "consult",
            "addOracle",
            "registerFeed",
        ),
    ),
    RoleRule(
        ContractRole.STAKING,
        functions=("stake", "unstake", "getReward", "earned", "exit", "claimReward"),
        storage=("rewardPerTokenStored", "rewardRate", "periodFinish", "staked"),
        names=("staking", "stake", "gauge"),
        requires=("stake",),
    ),
    RoleRule(
        ContractRole.REWARD_DISTRIBUTOR,
        functions=("claim", "getReward", "notifyRewardAmount", "distribute", "accrue"),
        storage=("rewards", "merkleRoot", "claimed", "rewardPerToken"),
        names=("reward", "distributor", "merkle", "airdrop"),
        requires=("claim", "distribute", "getReward"),
    ),
    RoleRule(
        ContractRole.GOVERNANCE,
        functions=("propose", "castVote", "execute", "queue", "quorum"),
        storage=("proposals", "votes", "quorum", "votingDelay", "votingPeriod"),
        names=("governor", "governance", "voting"),
        requires=("propose", "castVote"),
    ),
    RoleRule(
        ContractRole.TIMELOCK,
        functions=("schedule", "queueTransaction", "executeTransaction", "cancel", "delay"),
        storage=("delay", "queuedTransactions", "minDelay", "timestamps"),
        names=("timelock",),
        requires=("schedule", "queueTransaction"),
    ),
    RoleRule(
        ContractRole.BRIDGE,
        functions=("bridge", "finalizeWithdrawal", "relayMessage", "proveHash",
                   "sendMessage", "receiveMessage"),
        storage=("nonce", "processed", "messages", "remoteChain", "domain"),
        names=("bridge", "portal", "messenger", "crosschain", "l1", "l2"),
        requires=("bridge", "relayMessage", "sendMessage", "receiveMessage"),
    ),
    RoleRule(
        ContractRole.TOKEN,
        functions=("transfer", "approve", "balanceOf", "totalSupply", "allowance"),
        storage=("balanceOf", "allowance", "totalSupply"),
        names=("token", "erc20", "coin"),
        standards=(Standard.ERC20,),
        requires=("transfer",),
    ),
    RoleRule(
        ContractRole.FACTORY,
        functions=("createAccount", "createPair", "deploy", "clone", "getPair"),
        storage=("allPairs", "deployed", "implementation", "getPair", "accountIndex"),
        names=("factory", "deployer", "creator"),
        requires=("createAccount", "createPair", "deploy", "clone"),
    ),
    RoleRule(
        ContractRole.REGISTRY,
        functions=("addAsset", "isAllowed", "getAssetModule", "batchProcessDeposit",
                   "batchProcessWithdrawal", "addAssetModule", "addOracleModule"),
        storage=("registry", "whitelist", "allowlist", "assetToAssetInformation",
                 "isAssetModule", "isOracleModule"),
        names=("registry", "whitelist", "addressprovider", "resolver"),
        requires=("addAsset", "addAssetModule", "addOracleModule", "batchProcessDeposit"),
    ),
    RoleRule(
        ContractRole.STRATEGY,
        functions=("harvest", "invest", "divest", "rebalance", "report", "tend"),
        storage=("want", "strategist", "vault", "lastHarvest"),
        names=("strategy", "strat", "adapter"),
        requires=("harvest", "invest", "rebalance"),
    ),
    RoleRule(
        ContractRole.ESCROW,
        functions=("lock", "unlock", "release", "vest"),
        storage=("locked", "unlockTime", "vesting", "cliff"),
        names=("escrow", "vesting"),
        requires=("lock", "vest", "release"),
    ),
    RoleRule(
        ContractRole.ACCESS_CONTROL,
        functions=("hasRole", "grantRole", "revokeRole", "transferOwnership"),
        storage=("roles", "owner", "admin"),
        names=("access", "auth", "roles", "acl"),
        standards=(Standard.ACCESS_CONTROL,),
        requires=("hasRole", "grantRole", "transferOwnership"),
    ),
)


def classify(index: ProtocolIndex, standards: list[StandardClaim]) -> list[ContractClassification]:
    """One classification per audited contract, roles scored rather than first-matched."""
    by_contract: dict[str, list[StandardClaim]] = {}
    for claim in standards:
        by_contract.setdefault(claim.contract_id, []).append(claim)

    classifications: list[ContractClassification] = []
    for contract in index.audited:
        scored = _score(index, contract, by_contract.get(contract.id, []))
        roles = _pick(scored)

        classifications.append(
            ContractClassification(
                id=make_role_id(contract.id),
                contract_id=contract.id,
                name=contract.name,
                roles=roles,
                is_upgradeable=_is_upgradeable(index, contract, by_contract.get(contract.id, [])),
                is_pausable=any(
                    c.standard is Standard.PAUSABLE for c in by_contract.get(contract.id, [])
                ),
                is_entry_contract=bool(index.entrypoints_of(contract)),
                holds_funds=_holds_funds(index, contract),
                centrality=index.centrality_of(contract.id),
                confidence=Confidence.INFERRED if roles else Confidence.UNKNOWN,
                evidence=list(roles[0].evidence)
                if roles
                else [
                    heuristic_evidence(
                        DETECTOR, "no role signals matched this contract", ref=contract.id
                    )
                ],
            )
        )
    return classifications


def _score(
    index: ProtocolIndex, contract: Contract, standards: list[StandardClaim]
) -> list[RoleAssignment]:
    """Every role that matched, scored as a *share of that role's own signals*.

    Normalizing by the rule's own size is what stops a large contract winning every role
    by accumulating incidental hits: matching 3 of a vault's 4 defining actions beats
    matching 5 of a registry's 20 supporting names, which is the right way round and is
    not what raw counts produce.
    """
    surface = list(index.exposed(contract.id))
    storage = list(index.state_vars(contract.id))
    compliant = {
        claim.standard
        for claim in standards
        if claim.compliance in (Compliance.COMPLIANT, Compliance.PARTIAL, Compliance.DIVERGENT)
    }

    assignments: list[RoleAssignment] = []
    for rule in RULES:
        # The defining action must appear in *prefix* position on some exposed function.
        # `getUsdValueAfterDeposit` mentions depositing; it does not do it.
        if rule.requires and not any(
            _has_prefix(surface, needle) for needle in rule.requires
        ):
            continue

        earned = 0.0
        available = 0.0
        evidence: list[Evidence] = []

        if rule.functions:
            hits = [needle for needle in rule.functions if _matches(surface, needle)]
            available += rule.function_weight * min(len(rule.functions), EXPECTED_FUNCTIONS)
            earned += rule.function_weight * min(len(hits), EXPECTED_FUNCTIONS)
            if hits:
                evidence.append(
                    heuristic_evidence(
                        DETECTOR,
                        f"exposes {', '.join(hits[:5])} ({len(hits)}/{len(rule.functions)})",
                        ref=contract.id,
                    )
                )

        if rule.storage:
            storage_hits = [needle for needle in rule.storage if _matches(storage, needle)]
            available += rule.storage_weight * min(len(rule.storage), EXPECTED_STORAGE)
            earned += rule.storage_weight * min(len(storage_hits), EXPECTED_STORAGE)
            if storage_hits:
                evidence.append(
                    heuristic_evidence(
                        DETECTOR, f"stores {', '.join(storage_hits[:5])}", ref=contract.id
                    )
                )

        if rule.names:
            name_hits = [
                needle for needle in rule.names if needle in contract.name.lower()
            ]
            # A contract name states one purpose, so only the best hit counts toward the
            # denominator — otherwise a rule listing eight aliases is unwinnable on names.
            available += rule.name_weight
            earned += rule.name_weight if name_hits else 0.0
            if name_hits:
                evidence.append(
                    heuristic_evidence(DETECTOR, f"named for {name_hits[0]}", ref=contract.id)
                )

        if rule.standards:
            standard_hits = [s for s in rule.standards if s in compliant]
            available += rule.standard_weight
            earned += rule.standard_weight if standard_hits else 0.0
            if standard_hits:
                evidence.append(
                    heuristic_evidence(
                        DETECTOR,
                        f"implements {', '.join(s.value for s in standard_hits)}",
                        ref=contract.id,
                    )
                )

        score = earned / available if available else 0.0
        if score > 0:
            assignments.append(
                RoleAssignment(
                    role=rule.role,
                    score=round(score, 4),
                    rationale=f"{round(score * 100)}% of the signals that define this role",
                    confidence=Confidence.INFERRED,
                    evidence=evidence,
                )
            )
    return assignments


def _pick(scored: list[RoleAssignment]) -> list[RoleAssignment]:
    """Rank, drop the incidental, and remove roles a stronger one rules out."""
    ranked = sorted(scored, key=lambda a: (-a.score, a.role.value))
    ranked = [a for a in ranked if a.score >= ROLE_THRESHOLD]
    if not ranked:
        return []

    excluders = {a.role for a in ranked}
    kept: list[RoleAssignment] = []
    for position, assignment in enumerate(ranked):
        rule = _RULE_BY_ROLE.get(assignment.role)
        if rule is not None and any(
            other in excluders
            and any(o.role is other and o.score > assignment.score for o in ranked)
            for other in rule.excluded_by
        ):
            continue  # a stronger role makes this one implausible, not merely secondary
        if position > 0 and assignment.score < SECONDARY_THRESHOLD:
            continue
        kept.append(assignment)
    return kept[:MAX_ROLES]


_RULE_BY_ROLE: dict[ContractRole, RoleRule] = {rule.role: rule for rule in RULES}


def _matches(names: list[str], needle: str) -> bool:
    """Whole-word containment across a set of member names."""
    return any(has_token(name, needle) for name in names)


def _has_prefix(names: list[str], needle: str) -> bool:
    return any(starts_with_token(name, needle) for name in names)


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
    # A per-user smart account with a creditor is the shape of isolated-margin lending;
    # weighted low because the same shape also appears in plain account abstraction.
    ContractRole.ACCOUNT: (Archetype.ACCOUNT_ABSTRACTION, 0.5),
    ContractRole.PRICING_MODULE: (Archetype.ORACLE, 0.3),
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
