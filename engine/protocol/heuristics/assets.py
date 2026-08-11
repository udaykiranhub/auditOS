"""Stage 6 — what has value here.

```
IERC20 asset                     →  external ERC-20
mapping(address=>uint) shares    →  protocol-issued SHARE, backed by asset
uint256 totalBorrows             →  DEBT
msg.value / payable              →  native ETH
```

**Deliberately wider than "token".** Vault shares, recorded debt and accrued rewards are all
assets, because they are all things a user can gain or lose. An asset model limited to
`IERC20` addresses cannot express the accounting bugs that make up most vault findings —
the balance that got credited twice was never an ERC-20 in the first place.

Three sources, in descending confidence:

* a state variable typed as a token interface → `DERIVED`, the type says so;
* native ETH, from a `payable` function or a value-bearing call → `DERIVED`;
* a balance-shaped mapping or `total*` counter → `INFERRED`, the name is the only signal.

What this stage cannot know — whether an external token rebases, or charges a fee on
transfer — is emitted as a `SemanticGap` in stage 16 rather than defaulted to `False` and
left to read as a finding of fact.
"""

from __future__ import annotations

from engine.core.models.code import Contract, StateVar
from engine.core.models.evidence import (
    Confidence,
    Evidence,
    heuristic_evidence,
    source_evidence,
)
from engine.core.models.protocol import (
    Asset,
    AssetIdentity,
    AssetKind,
    AssetRole,
    Compliance,
    ContractClassification,
    ContractRole,
    Standard,
    StandardClaim,
    StateRole,
)
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.heuristics.state import classify_role
from engine.protocol.ids import make_asset_id

DETECTOR = "asset_model"

#: Type-name fragments that identify a token-typed state variable. Substring rather than
#: equality: `IERC20Metadata`, `IERC20Upgradeable` and `ERC20` are all ERC-20 handles.
TOKEN_TYPES = ("ierc20", "erc20", "ierc4626", "iweth", "itoken")
NFT_TYPES = ("ierc721", "erc721", "ierc1155", "erc1155")

#: Variable-name fragments → the accounting role the number plays. Ordered: the first match
#: wins, so `totalborrow` must be tested before the generic `total`.
NAME_KINDS: tuple[tuple[str, AssetKind, AssetRole], ...] = (
    ("totalborrow", AssetKind.DEBT, AssetRole.DEBT),
    ("borrow", AssetKind.DEBT, AssetRole.DEBT),
    ("debt", AssetKind.DEBT, AssetRole.DEBT),
    ("collateral", AssetKind.COLLATERAL, AssetRole.COLLATERAL),
    ("reward", AssetKind.REWARD, AssetRole.REWARD),
    ("fee", AssetKind.FEE, AssetRole.FEE),
    ("share", AssetKind.SHARE, AssetRole.SHARE),
    ("stake", AssetKind.SHARE, AssetRole.SHARE),
    ("liquidity", AssetKind.SHARE, AssetRole.SHARE),
    ("point", AssetKind.POINTS, AssetRole.TRACKED),
    ("balance", AssetKind.ERC20, AssetRole.UNDERLYING),
    ("deposit", AssetKind.ERC20, AssetRole.UNDERLYING),
    ("totalsupply", AssetKind.SHARE, AssetRole.SHARE),
    ("totalassets", AssetKind.ERC20, AssetRole.UNDERLYING),
)

#: Types that can hold an amount. A `mapping(address => bool)` is an allowlist, not a balance.
_NUMERIC = ("uint", "int")

#: State roles that describe a *parameter or a record*, never an amount of something owned.
#: Deferring to the state stage's classifier here is what stops `MAX_TOTAL_PENALTY`,
#: `originationFee` and `minRewardWeight` — all configuration — becoming protocol assets.
_NOT_ASSET_ROLES = frozenset(
    {
        StateRole.CONFIG,
        StateRole.RATE_PARAM,
        StateRole.PRICE,
        StateRole.EXCHANGE_RATE,
        StateRole.ACCUMULATOR,
        StateRole.FLAG,
        StateRole.LOCK,
        StateRole.NONCE,
        StateRole.TIMESTAMP,
        StateRole.ROLE_REGISTRY,
        StateRole.ADDRESS_REF,
        StateRole.CACHE,
    }
)

#: Per-account records of *someone else's* asset. `erc20Balance[account][token]` is an
#: exposure ledger inside a smart account, not a token the protocol issues — six account
#: contracts each declaring one produced six identical "erc20balance" assets on Arcadia.
_LEDGER_HINTS = ("stored", "exposure", "information", "state", "position", "data")


def detect(
    index: ProtocolIndex,
    classifications: list[ContractClassification],
    standards: list[StandardClaim],
) -> list[Asset]:
    """One asset per distinct thing of value, deduped across the contracts that touch it."""
    by_id: dict[str, Asset] = {}
    share_issuers = _share_issuers(classifications, standards)

    for classification in classifications:
        contract = index.contracts.get(classification.contract_id)
        if contract is None:
            continue
        for asset in _assets_of(index, contract, classification, share_issuers):
            existing = by_id.get(asset.id)
            by_id[asset.id] = _merge(existing, asset) if existing else asset

    assets = _collapse(list(by_id.values()), index)
    _link_backing(assets, share_issuers)
    return assets


def _collapse(assets: list[Asset], index: ProtocolIndex) -> list[Asset]:
    """Merge assets whose identity is *established*, and only those.

    ```
    IERC20 asset  (VaultA)  ──┐
    IERC20 asset  (VaultB)  ──┴─→  two assets, one identity_group, one open question
    ```

    The rule the refinement pass exists to enforce, in both directions:

    * **Same name is not same asset.** Two contracts each declaring `IERC20 public asset`
      receive their address at construction. They may hold the same token or two different
      ones, and the source cannot say. Merging asserts an identity nobody established.
    * **Different name is not different asset.** `want`, `underlying` and `asset` pointing
      at the same in-repo token contract are one asset with three aliases. Splitting those
      asserts a difference nobody established either.

    So the merge condition is resolvable identity: the same in-repo token contract, or the
    same address constant. Everything else keeps its own record and joins an
    `identity_group`, which is what stage 16 raises a single question about instead of one
    per sighting.
    """
    resolved: dict[str, Asset] = {}
    unresolved: list[Asset] = []

    for asset in assets:
        key = _resolved_key(asset, index)
        if key is None:
            unresolved.append(asset)
            continue
        existing = resolved.get(key)
        resolved[key] = _merge(existing, asset) if existing else asset

    merged = [*resolved.values(), *unresolved]
    for asset in merged:
        asset.aliases = sorted(set(asset.aliases))
    return merged


def _resolved_key(asset: Asset, index: ProtocolIndex) -> str | None:
    """A key two assets can share only when they are demonstrably the same thing."""
    if asset.identity is AssetIdentity.RESOLVED_CONSTANT:
        return f"constant:{asset.identity_group}"
    if asset.kind is AssetKind.NATIVE:
        return "native:eth"  # there is exactly one ETH

    # An accounting number is identified by the variable that declares it. Storage is
    # inheritance-flattened, so `LendingPool is DebtToken` exposes DebtToken's
    # `realisedDebt` too — one variable seen from two contracts, which produced two
    # identical `realiseddebt` assets. The declaring variable settles it.
    if asset.identity is AssetIdentity.RESOLVED_CONTRACT and asset.state_var_ids:
        return f"var:{sorted(asset.state_var_ids)[0]}"
    # A handle typed as a token contract that lives in this repository resolves: the type
    # names the implementation, so two handles of that type hold the same token.
    declared = asset.declared_type.strip().rstrip("[]").split()[0] if asset.declared_type else ""
    if declared:
        for contract in index.code.contracts:
            if contract.name == declared and contract.kind.value == "contract":
                return f"contract:{contract.id}"
    return None


def _assets_of(
    index: ProtocolIndex,
    contract: Contract,
    classification: ContractClassification,
    share_issuers: dict[str, str],
) -> list[Asset]:
    found: list[Asset] = []
    storage = index.state_vars(contract.id)

    if _accepts_native(index, contract):
        found.append(
            Asset(
                id=make_asset_id("eth"),
                symbol="ETH",
                name="native ether",
                kind=AssetKind.NATIVE,
                role=AssetRole.UNDERLYING,
                identity=AssetIdentity.RESOLVED_CONSTANT,
                identity_group="native:eth",
                aliases=["ETH"],
                declared_type="address",
                decimals=18,
                is_external=True,
                confidence=Confidence.DERIVED,
                evidence=[
                    source_evidence(
                        contract.id, "payable entrypoint or receive()", detector=DETECTOR
                    )
                ],
            )
        )

    for name, variable in sorted(storage.items()):
        asset = _from_variable(contract, classification, name, variable, share_issuers)
        if asset is not None:
            found.append(asset)

    return found


def _from_variable(
    contract: Contract,
    classification: ContractClassification,
    name: str,
    variable: StateVar,
    share_issuers: dict[str, str],
) -> Asset | None:
    lowered = variable.type.lower()
    evidence: list[Evidence] = [
        source_evidence(
            variable.id,
            f"{variable.type} {name}",
            path=contract.path,
            line=variable.line,
            detector=DETECTOR,
        )
    ]

    # 1. Typed token handle — the type says what it is, so this is DERIVED.
    if any(fragment in lowered for fragment in TOKEN_TYPES) or any(
        fragment in lowered for fragment in NFT_TYPES
    ):
        nft = any(fragment in lowered for fragment in NFT_TYPES)
        kind = (
            (AssetKind.ERC721 if "721" in lowered else AssetKind.ERC1155)
            if nft
            else AssetKind.ERC20
        )
        identity, group = _identity_of(variable, name, contract)
        return Asset(
            id=make_asset_id(name, ref=contract.id),
            symbol=name,
            name=f"{name} ({variable.type})",
            kind=kind,
            role=_role_of_handle(name),
            identity=identity,
            identity_group=group,
            aliases=[name],
            declared_type=variable.type,
            state_var_ids=[variable.id],
            is_external=True,
            confidence=Confidence.DERIVED,
            evidence=evidence,
        )

    # 2. A balance-shaped number. The state stage's classifier decides whether it is an
    #    amount at all, so a parameter cannot become an asset here.
    if not _holds_amount(variable):
        return None
    if classify_role(variable) in _NOT_ASSET_ROLES:
        return None
    if _is_ledger(name, variable):
        return None

    mapped = _kind_from_name(name)
    if mapped is None:
        return None
    kind, role = mapped

    issued = contract.id in share_issuers or role in (
        AssetRole.SHARE,
        AssetRole.DEBT,
    )
    symbol = _asset_symbol(name, kind)
    return Asset(
        id=make_asset_id(symbol, ref=contract.id),
        symbol=symbol,
        name=f"{name} ({variable.type})",
        kind=kind,
        role=role,
        # An accounting number is definitionally this contract's own: no external address
        # is involved, so its identity is settled by the contract that declares it.
        identity=AssetIdentity.RESOLVED_CONTRACT,
        identity_group=f"{contract.id}#{symbol}",
        aliases=[name],
        declared_type=variable.type,
        contract_id=contract.id if issued else None,
        state_var_ids=[variable.id],
        is_protocol_issued=issued,
        confidence=Confidence.INFERRED,
        evidence=[
            *evidence,
            heuristic_evidence(
                DETECTOR, f"name suggests {role.value} accounting", ref=variable.id
            ),
        ],
    )


def _identity_of(
    variable: StateVar, name: str, contract: Contract
) -> tuple[AssetIdentity, str]:
    """Do we actually know *which* token this handle points at?

    An `immutable` bound at construction is still a runtime value, so it is `UNRESOLVED`
    like any other handle — knowing the slot never changes does not tell us what is in it.
    Only a `constant` carries an address literal the source can be read for.

    The group is keyed on declared type + normalized name, which is what lets four staking
    modules each declaring `REWARD_TOKEN` be recognised as *possibly* one asset without
    asserting that they are.
    """
    group = f"{variable.type.strip()}#{name.lower().replace('_', '')}"
    if variable.is_constant:
        return AssetIdentity.RESOLVED_CONSTANT, group
    return AssetIdentity.UNRESOLVED, group


def _role_of_handle(name: str) -> AssetRole:
    lowered = name.lower().replace("_", "")
    for fragment, _, role in NAME_KINDS:
        if fragment in lowered:
            return role
    if "underlying" in lowered or lowered in ("asset", "token", "want"):
        return AssetRole.UNDERLYING
    return AssetRole.UNKNOWN


def _is_ledger(name: str, variable: StateVar) -> bool:
    """A per-account record of someone else's asset, rather than an asset of our own.

    `mapping(address account => mapping(address token => uint256)) erc20Balance` is an
    exposure ledger inside a smart account. It records other people's tokens; treating it
    as an asset produced six identical `erc20balance` assets across Arcadia's account
    versions, none of which named anything the protocol owns.
    """
    lowered = name.lower()
    if any(hint in lowered for hint in _LEDGER_HINTS):
        return True
    # A two-level mapping keyed by address twice is an account × token ledger.
    return variable.type.count("mapping") > 1


#: Names that mark a *rate* or an *accumulator* rather than an amount of something.
#: `borrowIndex` contains "borrow" and is not debt — it is the accrual multiplier debt is
#: measured against, and treating it as an asset puts a phantom asset in every flow and
#: conservation invariant that touches lending.
NOT_AN_AMOUNT = (
    "index",
    "rate",
    "bps",
    "multiplier",
    "factor",
    "threshold",
    "scalar",
    "weight",
    # A `maxX` or `minX` is a *bound on* an amount, which is a parameter. `maxReward` and
    # `minRewardWeight` are configuration; treating them as reward assets put two
    # non-existent tokens into Arcadia's lending model.
    "max",
    "min",
    "cap",
    "limit",
    "precision",
    "denominator",
)


def _kind_from_name(name: str) -> tuple[AssetKind, AssetRole] | None:
    lowered = name.lower().replace("_", "")
    if any(fragment in lowered for fragment in NOT_AN_AMOUNT):
        return None
    for fragment, kind, role in NAME_KINDS:
        if fragment in lowered:
            return kind, role
    return None


def _asset_symbol(name: str, kind: AssetKind) -> str:
    """Collapse `totalShares`, `shares` and `sharesOf` onto one asset.

    Three variables that account for the same thing must not become three assets, or every
    conservation invariant over them becomes trivially unprovable.
    """
    lowered = name.lower().replace("_", "")
    for prefix in ("total", "user", "account"):
        if lowered.startswith(prefix):
            lowered = lowered[len(prefix) :]
    for suffix in ("of", "s"):
        if lowered.endswith(suffix) and len(lowered) > len(suffix) + 2:
            lowered = lowered[: -len(suffix)]
    return lowered or kind.value


def _holds_amount(variable: StateVar) -> bool:
    lowered = variable.type.lower()
    if variable.is_constant:
        return False  # a constant is a parameter, not a balance
    if lowered.startswith("mapping"):
        value = lowered[lowered.rfind("=>") + 2 :].strip().rstrip(")")
        return any(fragment in value for fragment in _NUMERIC)
    return any(lowered.startswith(fragment) for fragment in _NUMERIC)


def _accepts_native(index: ProtocolIndex, contract: Contract) -> bool:
    functions = [*contract.functions, *contract.modifiers]
    return any(
        f.mutability == "payable" or f.kind.value in ("receive", "fallback") for f in functions
    )


def _share_issuers(
    classifications: list[ContractClassification], standards: list[StandardClaim]
) -> dict[str, str]:
    """contract_id → the asset symbol it issues, for contracts that mint a claim token.

    A vault that is also an ERC-20 issues shares; a bare ERC-20 issues itself. Separating
    the two is what makes `backing_asset_id` meaningful.
    """
    tokenish = {
        claim.contract_id
        for claim in standards
        if claim.standard in (Standard.ERC20, Standard.ERC4626)
        and claim.compliance
        in (Compliance.COMPLIANT, Compliance.PARTIAL, Compliance.DIVERGENT)
    }
    issuers: dict[str, str] = {}
    for classification in classifications:
        if classification.contract_id not in tokenish:
            continue
        if classification.role in (
            ContractRole.VAULT,
            ContractRole.LENDING_MARKET,
            ContractRole.STAKING,
            ContractRole.POOL,
        ):
            issuers[classification.contract_id] = "share"
    return issuers


def _link_backing(assets: list[Asset], share_issuers: dict[str, str]) -> None:
    """A share is a claim on something. Point it at the underlying, when there is exactly one.

    "Exactly one" is the important qualifier: a multi-asset pool has several underlyings and
    picking one arbitrarily would make every proportional-claim invariant wrong.
    """
    for contract_id in share_issuers:
        underlying = [
            asset
            for asset in assets
            if asset.is_external
            and asset.kind in (AssetKind.ERC20, AssetKind.NATIVE)
            and (asset.state_var_ids and contract_id in asset.state_var_ids[0])
        ]
        if len(underlying) != 1:
            continue
        for asset in assets:
            if (
                asset.kind is AssetKind.SHARE
                and asset.contract_id == contract_id
                and asset.backing_asset_id is None
            ):
                asset.backing_asset_id = underlying[0].id
                asset.evidence.append(
                    heuristic_evidence(
                        DETECTOR,
                        f"the only external token held by {contract_id}",
                        ref=underlying[0].id,
                    )
                )


def _merge(existing: Asset, incoming: Asset) -> Asset:
    """Two sightings of one asset become one record citing both."""
    return existing.model_copy(
        update={
            "state_var_ids": sorted(set(existing.state_var_ids) | set(incoming.state_var_ids)),
            "aliases": sorted({*existing.aliases, *incoming.aliases}),
            "evidence": [*existing.evidence, *incoming.evidence],
            "confidence": max(
                existing.confidence, incoming.confidence, key=lambda c: c.rank
            ),
            "is_protocol_issued": existing.is_protocol_issued or incoming.is_protocol_issued,
            "contract_id": existing.contract_id or incoming.contract_id,
            "role": existing.role if existing.role is not AssetRole.UNKNOWN else incoming.role,
        }
    )


def identity_groups(assets: list[Asset]) -> dict[str, list[Asset]]:
    """Unresolved assets that *might* be the same thing, grouped.

    Consumed by stage 16 so one question is raised per group rather than per sighting.
    """
    groups: dict[str, list[Asset]] = {}
    for asset in assets:
        if asset.identity is AssetIdentity.UNRESOLVED and asset.identity_group:
            groups.setdefault(asset.identity_group, []).append(asset)
    return {key: members for key, members in groups.items() if len(members) > 1}


__all__ = ["NAME_KINDS", "TOKEN_TYPES", "detect", "identity_groups"]
