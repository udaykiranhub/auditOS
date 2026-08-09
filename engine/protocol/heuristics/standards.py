"""Stage 3 — standard detection, member by member.

```
SimpleVault  →  has deposit/withdraw  →  NOT ERC4626
Vault        →  full interface match  →  ERC4626 COMPLIANT
```

**The whole point of this module is to say no.** A vault with `deposit` and `withdraw` looks
like ERC-4626 and is not one, and claiming otherwise sends every downstream agent hunting
for inflation attacks in a protocol that never promised those semantics — while suppressing
the checks a `DIVERGENT` label would have triggered. So detection is by *required member
set*, never by name, and the receipts (`satisfied` / `missing`) ship with the claim.

Two sources of evidence, deliberately distinct:

* **Interface match** — the members exist, inheritance-flattened. `DERIVED`: it is a fact
  about the compiled surface.
* **Inheritance by name** — `is ERC20` in the source. Strong evidence of *intent*, weak
  evidence of *compliance*, because the base may be modified. Recorded as `via_inheritance`
  and never sufficient on its own to reach `COMPLIANT`.

Divergence checks are the security-relevant half and are checked explicitly: an ERC-20
`transfer` that returns nothing, an ERC-4626 whose `asset()` is missing, a UUPS proxy with
no `_authorizeUpgrade`.
"""

from __future__ import annotations

from engine.core.models.code import Contract
from engine.core.models.evidence import (
    Confidence,
    Evidence,
    heuristic_evidence,
    source_evidence,
)
from engine.core.models.protocol import Compliance, Standard, StandardClaim
from engine.protocol.heuristics.signatures import (
    ProtocolIndex,
    return_signature,
)
from engine.protocol.ids import make_standard_id

DETECTOR = "standards"

#: Required members per standard, as canonical signatures. Only *required* members belong
#: here — adding optional ones (`name()`, `symbol()`) would make every minimal but valid
#: token report as `PARTIAL`, and a status nobody trusts is a status nobody reads.
REQUIRED: dict[Standard, tuple[str, ...]] = {
    Standard.ERC20: (
        "totalSupply()",
        "balanceOf(address)",
        "transfer(address,uint256)",
        "transferFrom(address,address,uint256)",
        "approve(address,uint256)",
        "allowance(address,address)",
    ),
    Standard.ERC20_PERMIT: (
        "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        "nonces(address)",
        "DOMAIN_SEPARATOR()",
    ),
    Standard.ERC721: (
        "balanceOf(address)",
        "ownerOf(uint256)",
        "transferFrom(address,address,uint256)",
        "approve(address,uint256)",
        "setApprovalForAll(address,bool)",
        "getApproved(uint256)",
        "isApprovedForAll(address,address)",
    ),
    Standard.ERC1155: (
        "balanceOf(address,uint256)",
        "balanceOfBatch(address[],uint256[])",
        "setApprovalForAll(address,bool)",
        "isApprovedForAll(address,address)",
        "safeTransferFrom(address,address,uint256,uint256,bytes)",
        "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
    ),
    Standard.ERC4626: (
        "asset()",
        "totalAssets()",
        "convertToShares(uint256)",
        "convertToAssets(uint256)",
        "deposit(uint256,address)",
        "mint(uint256,address)",
        "withdraw(uint256,address,address)",
        "redeem(uint256,address,address)",
        "maxDeposit(address)",
        "maxMint(address)",
        "maxWithdraw(address)",
        "maxRedeem(address)",
        "previewDeposit(uint256)",
        "previewMint(uint256)",
        "previewWithdraw(uint256)",
        "previewRedeem(uint256)",
    ),
    Standard.ERC165: ("supportsInterface(bytes4)",),
    Standard.ERC2981: ("royaltyInfo(uint256,uint256)",),
    Standard.ERC3156: (
        "maxFlashLoan(address)",
        "flashFee(address,uint256)",
        "flashLoan(address,address,uint256,bytes)",
    ),
    Standard.ERC4337: ("validateUserOp((address,uint256,bytes,bytes,uint256,uint256,uint256,"
                       "uint256,uint256,bytes,bytes),bytes32,uint256)",),
    Standard.EIP1271: ("isValidSignature(bytes32,bytes)",),
    Standard.UUPS: ("upgradeTo(address)", "proxiableUUID()"),
    Standard.ACCESS_CONTROL: (
        "hasRole(bytes32,address)",
        "grantRole(bytes32,address)",
        "revokeRole(bytes32,address)",
    ),
    Standard.OWNABLE: ("owner()", "transferOwnership(address)"),
    Standard.PAUSABLE: ("paused()",),
    Standard.MULTICALL: ("multicall(bytes[])",),
}

#: Standards that are a *pattern* rather than an interface — detected from inherited names,
#: storage slots or modifier use, because there is no member set that defines them.
BY_INHERITANCE: dict[Standard, tuple[str, ...]] = {
    Standard.ERC1967: ("erc1967", "uupsupgradeable", "transparentupgradeableproxy"),
    Standard.TRANSPARENT_PROXY: ("transparentupgradeableproxy", "proxyadmin"),
    Standard.BEACON_PROXY: ("beaconproxy", "upgradeablebeacon"),
    Standard.MINIMAL_PROXY: ("clones", "clone"),
    Standard.DIAMOND: ("diamond", "diamondcut"),
    Standard.EIP712: ("eip712", "eip712upgradeable"),
    Standard.REENTRANCY_GUARD: ("reentrancyguard",),
    Standard.ERC777: ("erc777",),
}

#: Two thirds of the interface present means "this was meant to be X and is not quite".
#: Below that the shape is coincidental — `balanceOf` alone does not make a token.
PARTIAL_THRESHOLD = 0.66


def detect(index: ProtocolIndex) -> list[StandardClaim]:
    """One claim per (contract, standard) pair with anything to say."""
    claims: list[StandardClaim] = []
    for contract in index.audited:
        for standard, required in REQUIRED.items():
            claim = _measure(index, contract, standard, required)
            if claim is not None:
                claims.append(claim)
        claims.extend(_by_inheritance(index, contract))
    return claims


def _measure(
    index: ProtocolIndex, contract: Contract, standard: Standard, required: tuple[str, ...]
) -> StandardClaim | None:
    satisfied = index.present(contract.id, required)
    missing = index.missing(contract.id, required)
    ratio = len(satisfied) / len(required)
    declared = _declared_parent(index, contract, standard)

    if not satisfied and not declared:
        return None  # nothing to say; emitting ABSENT for every standard is noise

    if ratio == 1.0:
        compliance = Compliance.COMPLIANT
        confidence = Confidence.DERIVED
    elif ratio >= PARTIAL_THRESHOLD:
        compliance = Compliance.PARTIAL
        confidence = Confidence.DERIVED
    elif declared:
        # It says `is ERC20` but the members are not there — an unimplemented abstract base,
        # or an interface-only declaration. Worth recording; not worth calling ERC-20.
        compliance = Compliance.DECLARED_ONLY
        confidence = Confidence.INFERRED
    else:
        return None

    divergences = _divergences(index, contract, standard)
    if divergences and compliance is Compliance.COMPLIANT:
        # Full interface, broken semantics. The most security-relevant status there is.
        compliance = Compliance.DIVERGENT

    evidence: list[Evidence] = [
        heuristic_evidence(
            DETECTOR,
            f"{len(satisfied)}/{len(required)} required members present",
            ref=contract.id,
        )
    ]
    members = index.exposed(contract.id)
    evidence.extend(
        source_evidence(
            members[signature].id,
            f"{standard.value} member",
            path=contract.path,
            line=members[signature].line_start,
            detector=DETECTOR,
        )
        for signature in satisfied[:4]  # a sample; the full list is in `satisfied`
        if signature in members
    )

    return StandardClaim(
        id=make_standard_id(contract.id, standard.value),
        contract_id=contract.id,
        standard=standard,
        compliance=compliance,
        satisfied=satisfied,
        missing=missing,
        divergences=divergences,
        via_inheritance=declared,
        confidence=confidence,
        evidence=evidence,
    )


def _by_inheritance(index: ProtocolIndex, contract: Contract) -> list[StandardClaim]:
    """Patterns with no interface: proxies, EIP-712, reentrancy guards.

    Always `INFERRED`. A contract named `MyBeaconProxy` that implements nothing would match
    here, and there is no member set that could prove otherwise.
    """
    claims: list[StandardClaim] = []
    for standard, needles in BY_INHERITANCE.items():
        if not index.inherits_name(contract.id, *needles):
            continue
        claims.append(
            StandardClaim(
                id=make_standard_id(contract.id, standard.value),
                contract_id=contract.id,
                standard=standard,
                compliance=Compliance.PARTIAL,
                confidence=Confidence.INFERRED,
                evidence=[
                    heuristic_evidence(
                        DETECTOR,
                        f"inherits a contract named for {standard.value}",
                        ref=contract.id,
                    )
                ],
            )
        )
    return claims


def _declared_parent(
    index: ProtocolIndex, contract: Contract, standard: Standard
) -> str | None:
    """The ancestor whose name declares this standard, if any. Intent, not compliance."""
    needle = standard.value.replace("_", "")
    for ancestor_id in index.query.inheritance(contract.id):
        ancestor = index.contracts.get(ancestor_id)
        if ancestor is None or ancestor.id == contract.id:
            continue
        if needle in ancestor.name.lower().replace("_", ""):
            return ancestor.id
    for parent in contract.inherits:
        if needle in parent.lower().replace("_", ""):
            return parent
    return None


# ── Divergence checks ─────────────────────────────────────────────────────────


def _divergences(index: ProtocolIndex, contract: Contract, standard: Standard) -> list[str]:
    """Where the implementation contradicts a documented requirement of the standard.

    Deliberately narrow: only checks that are decidable from `CodeModel` without
    interpreting expressions. A check that needs to know *which way* a division rounds
    belongs to the Business Logic agent, and guessing it here would produce a `DIVERGENT`
    label nobody can act on.
    """
    members = index.exposed(contract.id)
    found: list[str] = []

    if standard is Standard.ERC20:
        for name in ("transfer(address,uint256)", "transferFrom(address,address,uint256)",
                     "approve(address,uint256)"):
            function = members.get(name)
            if function is not None and return_signature(function) != "(bool)":
                found.append(
                    f"{name} returns {return_signature(function)}, not (bool) — callers "
                    "that check the return value will revert or silently mis-handle it"
                )

    if standard is Standard.ERC4626:
        asset = members.get("asset()")
        if asset is not None and not index.is_view(asset):
            found.append("asset() is not view, which the standard requires")
        for preview in ("previewDeposit(uint256)", "previewRedeem(uint256)"):
            function = members.get(preview)
            if function is not None and not index.is_view(function):
                found.append(f"{preview} is not view")

    if standard is Standard.UUPS:
        # Without `_authorizeUpgrade` an inheriting UUPS implementation is upgradeable by
        # anyone. This is the highest-value single check in the module.
        if not any(name.startswith("_authorizeUpgrade") for name in members):
            found.append(
                "no _authorizeUpgrade override found; a UUPS implementation without one "
                "is upgradeable by any caller"
            )

    if standard is Standard.ERC165:
        function = members.get("supportsInterface(bytes4)")
        if function is not None and not index.is_view(function):
            found.append("supportsInterface(bytes4) is not view")

    return found


def erc20_like(index: ProtocolIndex, contract_id: str) -> bool:
    """Cheap reusable predicate: does this contract move balances like a token?

    Used by the asset and role detectors, which do not need the full compliance verdict.
    """
    return index.has(contract_id, "balanceOf(address)", "transfer(address,uint256)")


def is_proxy(claims: list[StandardClaim], contract_id: str) -> bool:
    proxy = {
        Standard.ERC1967,
        Standard.UUPS,
        Standard.TRANSPARENT_PROXY,
        Standard.BEACON_PROXY,
        Standard.MINIMAL_PROXY,
        Standard.DIAMOND,
    }
    return any(c.contract_id == contract_id and c.standard in proxy for c in claims)


__all__ = ["BY_INHERITANCE", "REQUIRED", "detect", "erc20_like", "is_proxy"]
