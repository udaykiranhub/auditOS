"""`ProtocolID` — stable identity for semantic entities (Protocol Model Phase A).

`SolidityID` (`engine/core/models/ids.py`) addresses things the compiler knows about. The
Protocol Model needs to address things it does not: an actor, an asset, a flow, an
invariant. Those need IDs with the same property — **the same protocol produces the same
IDs on every run and on every machine** — because the whole artifact is a web of
cross-references, and an ID that shifts between runs turns a diff into noise and a cached
enrichment into a miss.

Two ID shapes, chosen per entity type and never mixed within one type:

```
readable   role:src/Vault.sol:Vault          natural key exists → embed it
digest     flow:9f4b21c0a8de                 composite key → 12 hex of its parts
```

Readable wherever a natural key exists, because an ID a human can read is an ID a human can
check. Digest only where the key is a tuple (a flow is source × target × asset × operation),
since embedding four IDs produces a 300-character string that is worse than opaque.

**Invariants carry both.** `id` is content-derived and therefore stable across runs;
`label` (`INV-001`) is an ordinal assigned at assembly for humans to cite in a report. Using
the ordinal as the identity would renumber every invariant whenever one is added upstream.
"""

from __future__ import annotations

import hashlib
import re

#: Every namespace this module mints. Validation rejects a cross-reference outside it, which
#: is what catches a `SolidityID` used where a `ProtocolID` belongs (and vice versa).
NAMESPACES = frozenset(
    {
        "protocol",
        "component",
        "role",
        "std",
        "actor",
        "boundary",
        "asset",
        "flow",
        "op",
        "state",
        "transition",
        "dep",
        "qty",
        "rel",
        "surface",
        "docrule",
        "assume",
        "inv",
        "gap",
    }
)

_DIGEST_LENGTH = 12
_SLUG_RE = re.compile(r"[^a-z0-9]+")
_UNIT = "\x1f"  # ASCII unit separator: cannot occur in a SolidityID or a slug


def slug(text: str) -> str:
    """`"Chainlink Price Feed"` → `"chainlink-price-feed"`. Lossy but deterministic."""
    return _SLUG_RE.sub("-", text.strip().lower()).strip("-") or "unnamed"


def digest(*parts: str) -> str:
    """A short, collision-resistant key over an ordered tuple of parts.

    Joined with a separator that cannot appear in any part, so `("a", "bc")` and `("ab",
    "c")` cannot produce the same digest — the failure mode of naive concatenation, and one
    that would silently merge two distinct asset flows into one.
    """
    payload = _UNIT.join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:_DIGEST_LENGTH]


def namespace_of(protocol_id: str) -> str:
    """The namespace prefix, or `""` when this is not a `ProtocolID`."""
    prefix, separator, _ = protocol_id.partition(":")
    return prefix if separator and prefix in NAMESPACES else ""


def is_protocol_id(value: str) -> bool:
    return bool(namespace_of(value))


# ── 1–3. Identity, components, roles, standards ───────────────────────────────


def make_protocol_id(name: str) -> str:
    """`protocol:aave-v3`"""
    return f"protocol:{slug(name)}"


def make_component_id(name: str) -> str:
    """`component:lending-market` — a named subsystem, usually spanning several contracts."""
    return f"component:{slug(name)}"


def make_role_id(contract_id: str) -> str:
    """`role:src/Vault.sol:Vault` — one role record per contract, so the contract is the key."""
    return f"role:{contract_id}"


def make_standard_id(contract_id: str, standard: str) -> str:
    """`std:src/Vault.sol:Vault:erc4626` — a claim about one contract against one standard."""
    return f"std:{contract_id}:{slug(standard)}"


# ── 4–5. Actors and trust boundaries ──────────────────────────────────────────


def make_actor_id(kind: str, qualifier: str = "") -> str:
    """`actor:admin`, or `actor:admin.pauser_role` when one kind has several instances.

    Two distinct admin roles must not collapse into one actor: "who can call this" is the
    question the Access Control agent asks, and merging them answers it wrongly.
    """
    base = f"actor:{slug(kind)}"
    return f"{base}.{slug(qualifier)}" if qualifier else base


def make_boundary_id(inner: str, outer: str) -> str:
    """`boundary:actor:user->role:src/Vault.sol:Vault` — directed, and the direction is the
    security content: it names who is crossing into what."""
    return f"boundary:{inner}->{outer}"


# ── 6–7. Assets and flows ─────────────────────────────────────────────────────


def make_asset_id(symbol: str, *, ref: str = "") -> str:
    """`asset:usdc`, or `asset:shares@src/Vault.sol:Vault` when the asset is protocol-internal.

    Shares issued by two different vaults are two different assets. Keying purely on the
    symbol would merge them and make every conservation invariant meaningless.
    """
    base = f"asset:{slug(symbol)}"
    return f"{base}@{ref}" if ref else base


def make_flow_id(source: str, target: str, asset_id: str, operation_id: str = "") -> str:
    """`flow:1a2b3c4d5e6f` — digest, because the natural key is a four-tuple."""
    return f"flow:{digest(source, target, asset_id, operation_id)}"


# ── 8. Operations ─────────────────────────────────────────────────────────────


def make_operation_id(function_id: str) -> str:
    """`op:src/Vault.sol:Vault.deposit(uint256)`

    Keyed on the entrypoint `SolidityID`, so an operation joins straight back to the
    function — and so overloads stay distinct, which a name-based key would not manage.
    """
    return f"op:{function_id}"


# ── 9–10. State and transitions ───────────────────────────────────────────────


def make_state_id(state_var_id: str) -> str:
    """`state:src/Vault.sol:Vault#totalAssets`"""
    return f"state:{state_var_id}"


def make_transition_id(operation_id: str, state_id: str) -> str:
    """`transition:7c1d0f9ab234` — one operation's effect on one state item."""
    return f"transition:{digest(operation_id, state_id)}"


# ── 11. Dependencies ──────────────────────────────────────────────────────────


def make_dependency_id(name: str, *, ref: str = "") -> str:
    """`dep:chainlink-aggregator`, or `dep:ierc20@src/interfaces/IERC20.sol:IERC20`."""
    base = f"dep:{slug(name)}"
    return f"{base}@{ref}" if ref else base


# ── 12–13. Accounting and economics ───────────────────────────────────────────


def make_quantity_id(state_var_id: str) -> str:
    """`qty:src/Vault.sol:Vault#totalShares` — an accounting quantity backed by storage."""
    return f"qty:{state_var_id}"


def make_relationship_id(kind: str, operands: list[str]) -> str:
    """`rel:0f8e7d6c5b4a` — digest over the relation kind and its operands, in order.

    Order is significant and deliberately not normalized: `a = b / c` is not `a = c / b`.
    """
    return f"rel:{digest(kind, *operands)}"


def make_surface_id(kind: str, target: str) -> str:
    """`surface:rounding:src/Vault.sol:Vault.deposit(uint256)` — an economic or risk surface
    is always *somewhere*, so the target is part of its identity."""
    return f"surface:{slug(kind)}:{target}"


# ── 14. Documentation ─────────────────────────────────────────────────────────


def make_doc_rule_id(path: str, statement: str) -> str:
    """`docrule:3e2d1c0b9a88` — digest over source path and the sentence, so re-running on
    an unchanged README yields the same rule ID and reconciliation results stay comparable."""
    return f"docrule:{digest(path, statement.strip())}"


# ── 15. Assumptions and invariants ────────────────────────────────────────────


def make_assumption_id(statement: str) -> str:
    """`assume:c4b3a2918077`"""
    return f"assume:{digest(statement.strip())}"


def make_invariant_id(statement: str, targets: list[str]) -> str:
    """`inv:8a7b6c5d4e3f` — stable across runs, unlike the `INV-001` label beside it.

    Targets participate in the key so the same sentence asserted about two different
    contracts is two invariants, which is what it is.
    """
    return f"inv:{digest(statement.strip(), *sorted(targets))}"


def invariant_label(ordinal: int) -> str:
    """`INV-001` — the human-facing citation, assigned in canonical order at assembly.

    Never the identity: adding one invariant upstream would renumber every invariant after
    it, silently invalidating every reference in a stored report.
    """
    return f"INV-{ordinal:03d}"


# ── 16–17. Enrichment targets ─────────────────────────────────────────────────


def make_gap_id(subject: str, question: str) -> str:
    """`gap:5d4c3b2a1908` — a semantic question the deterministic pass could not answer.

    Content-keyed on purpose: it is the cache key for the Phase H enrichment call, so the
    same unanswered question does not get paid for twice.
    """
    return f"gap:{digest(subject, question.strip())}"


__all__ = [
    "NAMESPACES",
    "digest",
    "invariant_label",
    "is_protocol_id",
    "make_actor_id",
    "make_assumption_id",
    "make_asset_id",
    "make_boundary_id",
    "make_component_id",
    "make_dependency_id",
    "make_doc_rule_id",
    "make_flow_id",
    "make_gap_id",
    "make_invariant_id",
    "make_operation_id",
    "make_protocol_id",
    "make_quantity_id",
    "make_relationship_id",
    "make_role_id",
    "make_standard_id",
    "make_state_id",
    "make_surface_id",
    "make_transition_id",
    "namespace_of",
    "slug",
]
