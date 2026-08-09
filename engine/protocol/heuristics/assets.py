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
    AssetKind,
    Compliance,
    ContractClassification,
    ContractRole,
    Standard,
    StandardClaim,
)
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_asset_id

DETECTOR = "asset_model"

#: Type-name fragments that identify a token-typed state variable. Substring rather than
#: equality: `IERC20Metadata`, `IERC20Upgradeable` and `ERC20` are all ERC-20 handles.
TOKEN_TYPES = ("ierc20", "erc20", "ierc4626", "iweth", "itoken")
NFT_TYPES = ("ierc721", "erc721", "ierc1155", "erc1155")

#: Variable-name fragments → the accounting role the number plays. Ordered: the first match
#: wins, so `totalborrow` must be tested before the generic `total`.
NAME_KINDS: tuple[tuple[str, AssetKind], ...] = (
    ("totalborrow", AssetKind.DEBT),
    ("borrow", AssetKind.DEBT),
    ("debt", AssetKind.DEBT),
    ("collateral", AssetKind.COLLATERAL),
    ("reward", AssetKind.REWARD),
    ("fee", AssetKind.FEE),
    ("share", AssetKind.SHARE),
    ("stake", AssetKind.SHARE),
    ("liquidity", AssetKind.SHARE),
    ("point", AssetKind.POINTS),
    ("balance", AssetKind.ERC20),
    ("deposit", AssetKind.ERC20),
    ("totalsupply", AssetKind.SHARE),
    ("totalassets", AssetKind.ERC20),
)

#: Types that can hold an amount. A `mapping(address => bool)` is an allowlist, not a balance.
_NUMERIC = ("uint", "int")


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

    _link_backing(list(by_id.values()), share_issuers)
    return list(by_id.values())


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
    if any(fragment in lowered for fragment in TOKEN_TYPES):
        return Asset(
            id=make_asset_id(name, ref=contract.id),
            symbol=name,
            name=f"{name} ({variable.type})",
            kind=AssetKind.ERC20,
            state_var_ids=[variable.id],
            is_external=True,
            confidence=Confidence.DERIVED,
            evidence=evidence,
        )
    if any(fragment in lowered for fragment in NFT_TYPES):
        return Asset(
            id=make_asset_id(name, ref=contract.id),
            symbol=name,
            kind=AssetKind.ERC721 if "721" in lowered else AssetKind.ERC1155,
            state_var_ids=[variable.id],
            is_external=True,
            confidence=Confidence.DERIVED,
            evidence=evidence,
        )

    # 2. A balance-shaped number. Only the name suggests what it accounts for → INFERRED.
    if not _holds_amount(variable):
        return None
    kind = _kind_from_name(name)
    if kind is None:
        return None

    issued = contract.id in share_issuers or kind in (
        AssetKind.SHARE,
        AssetKind.DEBT,
        AssetKind.REWARD,
        AssetKind.POINTS,
    )
    return Asset(
        id=make_asset_id(_asset_symbol(name, kind), ref=contract.id),
        symbol=_asset_symbol(name, kind),
        name=f"{name} ({variable.type})",
        kind=kind,
        contract_id=contract.id if issued else None,
        state_var_ids=[variable.id],
        is_protocol_issued=issued,
        confidence=Confidence.INFERRED,
        evidence=[
            *evidence,
            heuristic_evidence(
                DETECTOR, f"name suggests {kind.value} accounting", ref=variable.id
            ),
        ],
    )


#: Names that mark a *rate* or an *accumulator* rather than an amount of something.
#: `borrowIndex` contains "borrow" and is not debt — it is the accrual multiplier debt is
#: measured against, and treating it as an asset puts a phantom asset in every flow and
#: conservation invariant that touches lending.
NOT_AN_AMOUNT = ("index", "rate", "bps", "multiplier", "factor", "threshold", "scalar")


def _kind_from_name(name: str) -> AssetKind | None:
    lowered = name.lower().replace("_", "")
    if any(fragment in lowered for fragment in NOT_AN_AMOUNT):
        return None
    for fragment, kind in NAME_KINDS:
        if fragment in lowered:
            return kind
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
    """Two contracts referencing the same asset is one asset with two sightings."""
    return existing.model_copy(
        update={
            "state_var_ids": sorted(set(existing.state_var_ids) | set(incoming.state_var_ids)),
            "evidence": [*existing.evidence, *incoming.evidence],
            "confidence": max(
                existing.confidence, incoming.confidence, key=lambda c: c.rank
            ),
            "is_protocol_issued": existing.is_protocol_issued or incoming.is_protocol_issued,
            "contract_id": existing.contract_id or incoming.contract_id,
        }
    )


__all__ = ["NAME_KINDS", "TOKEN_TYPES", "detect"]
