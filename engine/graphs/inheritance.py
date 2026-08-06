"""Inheritance graph + C3 linearization (SPEC §13.1).

Build this **first**. The call graph depends on it: `super.f()` and every inherited call
resolve through the MRO, and SPEC names building the call graph on the *unlinearized*
contract as the common mistake that "produces a graph that looks fine and is quietly
wrong — the worst failure mode there is".

Solidity uses C3 linearization, like Python, with one difference that matters: **bases are
written most-base-like first**, so `contract C is A, B` linearizes as `[C, B, A, …]`. Get
that backwards and every diamond resolves to the wrong implementation.
"""

from __future__ import annotations

from collections.abc import Iterable

from engine.core.models.code import Contract, ContractKind, Function, FunctionKind
from engine.core.models.graph import (
    Confidence,
    Edge,
    EdgeKind,
    Unresolved,
)


class Linearizer:
    """C3 over a `contract_id → parent contract_ids` relation."""

    def __init__(self, contracts: dict[str, Contract]):
        self._contracts = contracts
        self._cache: dict[str, list[str]] = {}
        self.unresolved: list[Unresolved] = []

    def linearize(self, contract_id: str) -> list[str]:
        """The MRO for one contract, most-derived first. Always starts with itself."""
        return self._linearize(contract_id, frozenset())

    def _linearize(self, contract_id: str, visiting: frozenset[str]) -> list[str]:
        cached = self._cache.get(contract_id)
        if cached is not None:
            return cached

        contract = self._contracts.get(contract_id)
        if contract is None:
            return [contract_id]

        if contract_id in visiting:
            # Illegal in Solidity, but a partially-parsed repo can present one. Truncating
            # beats recursing forever.
            self.unresolved.append(
                Unresolved(
                    reason="AMBIGUOUS_LINEARIZATION",
                    function=contract_id,
                    detail="inheritance cycle; linearization truncated here",
                )
            )
            return [contract_id]

        deeper = visiting | {contract_id}
        # Solidity lists bases most-base-like first; C3 wants them most-derived first.
        bases = [pid for pid in reversed(contract.inherits_ids) if pid != contract_id]

        sequences = [self._linearize(base, deeper) for base in bases]
        sequences.append(list(bases))

        merged = _merge(sequences)
        if merged is None:
            # No valid linearization exists (Solidity would reject the contract). Fall back
            # to depth-first order so downstream work degrades instead of failing.
            self.unresolved.append(
                Unresolved(
                    reason="AMBIGUOUS_LINEARIZATION",
                    function=contract_id,
                    detail=f"no C3 linearization for bases {contract.inherits}; using DFS order",
                )
            )
            merged = _dedupe(item for sequence in sequences[:-1] for item in sequence)

        result = [contract_id] + [cid for cid in merged if cid != contract_id]
        self._cache[contract_id] = result
        return result


def _merge(sequences: list[list[str]]) -> list[str] | None:
    """The C3 merge. Returns None when no consistent order exists."""
    pending = [list(sequence) for sequence in sequences if sequence]
    result: list[str] = []

    while pending:
        head = None
        for sequence in pending:
            candidate = sequence[0]
            if not any(candidate in other[1:] for other in pending):
                head = candidate
                break
        if head is None:
            return None

        result.append(head)
        for sequence in pending:
            if sequence and sequence[0] == head:
                del sequence[0]
        pending = [sequence for sequence in pending if sequence]

    return result


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# ── Flattening ────────────────────────────────────────────────────────────────


def signature_of(function: Function) -> str:
    """`deposit(uint256,address)` — the key an override chain groups on."""
    return f"{function.name}({','.join(p.type for p in function.params)})"


class Flattened:
    """The resolved member set of one contract, including everything inherited."""

    def __init__(
        self,
        functions: dict[str, Function],
        chains: dict[str, list[Function]],
        modifiers: dict[str, Function],
        by_name: dict[str, list[Function]],
    ):
        self.functions = functions  # signature → the implementation that actually runs
        self.chains = chains  # signature → every definition, MRO order
        self.modifiers = modifiers  # modifier name → definition
        self.by_name = by_name  # function name → all implementations, MRO order

    def resolve(self, name: str, arg_count: int = -1) -> Function | None:
        """Name → the function that runs. Arity disambiguates overloads when known."""
        candidates = self.by_name.get(name)
        if not candidates:
            return None
        if arg_count >= 0:
            exact = [f for f in candidates if len(f.params) == arg_count]
            if exact:
                return exact[0]
            # Every parameter after the last required one may carry a default in some
            # dialects; fall through rather than guess wrong on a mismatch.
        return candidates[0]


def flatten(mro: list[str], contracts: dict[str, Contract]) -> Flattened:
    """Walk the MRO most-derived first; the first definition seen is the one that runs."""
    functions: dict[str, Function] = {}
    chains: dict[str, list[Function]] = {}
    modifiers: dict[str, Function] = {}
    by_name: dict[str, list[Function]] = {}

    for contract_id in mro:
        contract = contracts.get(contract_id)
        if contract is None:
            continue

        for function in contract.functions:
            if function.kind is FunctionKind.CONSTRUCTOR:
                continue  # constructors are not inherited as callable members
            signature = signature_of(function)
            chains.setdefault(signature, []).append(function)
            if signature not in functions and function.is_implemented:
                functions[signature] = function
            by_name.setdefault(function.name, []).append(function)

        for modifier in contract.modifiers:
            if modifier.name not in modifiers and modifier.is_implemented:
                modifiers[modifier.name] = modifier

    # An unimplemented-only signature still needs an entry so calls resolve to *something*.
    for signature, chain in chains.items():
        functions.setdefault(signature, chain[0])

    return Flattened(functions, chains, modifiers, by_name)


# ── Edges ─────────────────────────────────────────────────────────────────────


def inheritance_edges(
    contracts: dict[str, Contract],
    linearization: dict[str, list[str]],
    flattened: dict[str, Flattened],
) -> tuple[list[Edge], dict[str, list[str]], list[Unresolved]]:
    """INHERITS / IMPLEMENTS / OVERRIDES edges, plus the serializable override chains."""
    edges: list[Edge] = []
    chains: dict[str, list[str]] = {}
    unresolved: list[Unresolved] = []

    for contract_id, contract in sorted(contracts.items()):
        resolved = set(contract.inherits_ids)
        for parent_id in contract.inherits_ids:
            parent = contracts.get(parent_id)
            kind = (
                EdgeKind.IMPLEMENTS
                if parent is not None and parent.kind is ContractKind.INTERFACE
                else EdgeKind.INHERITS
            )
            confidence: Confidence = "high" if parent is not None else "medium"
            edges.append(
                Edge(
                    source=contract_id,
                    target=parent_id,
                    kind=kind,
                    confidence=confidence,
                    line=contract.line_start,
                    via=parent.name if parent else None,
                )
            )

        # A parent named in source that never resolved to an ID is a real gap in the graph:
        # every member it contributes is invisible to call resolution. Say so.
        if len(resolved) < len(contract.inherits):
            missing = len(contract.inherits) - len(resolved)
            unresolved.append(
                Unresolved(
                    reason="UNRESOLVED_PARENT",
                    function=contract_id,
                    detail=f"{missing} of {len(contract.inherits)} parents "
                    f"({', '.join(contract.inherits)}) not found in the repository",
                    line=contract.line_start,
                )
            )

    for contract_id in sorted(flattened):
        for signature, chain in sorted(flattened[contract_id].chains.items()):
            if len(chain) < 2:
                continue
            # Record the chain once, on the contract where it is most derived.
            if chain[0].contract_id != contract_id:
                continue
            chains[chain[0].id] = [function.id for function in chain[1:]]
            for child, overridden in zip(chain, chain[1:], strict=False):
                edges.append(
                    Edge(
                        source=child.id,
                        target=overridden.id,
                        kind=EdgeKind.OVERRIDES,
                        line=child.line_start,
                        via=signature,
                    )
                )

    return edges, chains, unresolved
