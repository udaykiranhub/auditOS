"""Stage 16b — the cross-contract graph, as records rather than as edges to be re-derived.

```
LendingPool ──inherits──────────▶ Ownable
            ──uses_library─────▶ SafeERC20
            ──calls────────────▶ InterestRateModel      (3 call sites)
            ──reads_state_from─▶ Registry                (view calls only)
            ──depends_on───────▶ dep:chainlink-aggregator
            ──transfers_to─────▶ Account
            ◀─callback_into──── Account                  (mutual call path)
```

`GraphModel` already holds every one of these facts at *function* granularity. What it does
not hold is the contract-level rollup, and the rollup is the level an auditor reasons at:
"what does this contract depend on, and who breaks if I change it" is one question, not four
hundred edge lookups. Doing it once here also means every consumer gets the same answer —
two agents rolling up the same edges with slightly different filters is exactly how a model
starts contradicting itself.

**Direction is the content.** `Pool calls Oracle` and `Oracle calls Pool` are different
facts, and the second is a callback. Nothing here is normalized or symmetrized.

**Every relationship names its call sites.** A relationship with nothing behind it would be
an assertion about architecture, and this artifact does not make those — if the only
evidence is a `using X for Y` directive, that directive is the evidence and the kind says
`USES_LIBRARY`, not `CALLS`.
"""

from __future__ import annotations

from engine.core.models.code import Contract, ContractKind
from engine.core.models.evidence import (
    Confidence,
    Evidence,
    graph_evidence,
    source_evidence,
)
from engine.core.models.graph import SENTINELS, EdgeKind
from engine.core.models.protocol import (
    AssetFlow,
    ContractClassification,
    ContractRelationKind,
    ContractRelationship,
    Dependency,
)
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_contract_relation_id

DETECTOR = "contract_relationships"

#: Call sites quoted per relationship. The full set is reachable through the graph; this is
#: the "where do I start reading" list, and a list of four hundred is not one.
MAX_CALL_SITES = 10


def detect(
    index: ProtocolIndex,
    classifications: list[ContractClassification],
    dependencies: list[Dependency],
    flows: list[AssetFlow],
) -> list[ContractRelationship]:
    """Every directed contract-to-contract edge, rolled up and evidence-backed."""
    sources = {c.contract_id for c in classifications}
    builder = _Builder(index, sources, dependencies)

    for contract_id in sorted(sources):
        contract = index.contracts.get(contract_id)
        if contract is None:
            continue
        builder.structural(contract)
        builder.calls(contract)

    builder.transfers(flows, {c.id: c.contract_id for c in classifications})
    builder.callbacks()
    return builder.finish()


class _Builder:
    """Accumulates one record per `(source, target, kind)` triple.

    Aggregating rather than emitting per call site is the whole point of the rollup: a pool
    that calls its oracle in eleven places has one dependency on it, and eleven records
    would bury that under its own detail.
    """

    def __init__(
        self,
        index: ProtocolIndex,
        sources: set[str],
        dependencies: list[Dependency],
    ):
        self.index = index
        self.sources = sources
        self.records: dict[tuple[str, str, ContractRelationKind], ContractRelationship] = {}
        self._dep_by_interface = {
            dependency.interface_id: dependency
            for dependency in dependencies
            if dependency.interface_id
        }
        self._called: set[tuple[str, str]] = set()

    # ── Sources ───────────────────────────────────────────────────────────────

    def structural(self, contract: Contract) -> None:
        """Inheritance, interfaces and libraries — declared, so read off the declaration."""
        for parent_id in contract.inherits_ids:
            parent = self.index.contracts.get(parent_id)
            if parent is None:
                continue
            kind = (
                ContractRelationKind.IMPLEMENTS
                if parent.kind is ContractKind.INTERFACE
                else ContractRelationKind.INHERITS
            )
            self._add(
                contract.id,
                parent_id,
                kind,
                parent.name,
                detail=f"declared `is {parent.name}`",
                evidence=source_evidence(
                    contract.id,
                    f"is {parent.name}",
                    path=contract.path,
                    line=contract.line_start,
                    detector=DETECTOR,
                ),
            )

        for directive in contract.using_for:
            library = self._contract_named(directive.library)
            self._add(
                contract.id,
                library.id if library is not None else directive.library,
                ContractRelationKind.USES_LIBRARY,
                directive.library,
                detail=f"using {directive.library} for {directive.target_type}",
                evidence=source_evidence(
                    contract.id,
                    f"using {directive.library} for {directive.target_type}",
                    path=contract.path,
                    detector=DETECTOR,
                ),
            )

    def calls(self, contract: Contract) -> None:
        """Call, delegatecall, staticcall and creation edges, grouped by callee contract."""
        # Grouped by declaring contract once on the index — walking the whole edge list per
        # contract is quadratic on anything real.
        for edge in self.index.call_edges_by_contract.get(contract.id, []):
            if edge.kind not in _RELATION_KIND:
                continue
            target_contract, kind = self._resolve(contract, edge.target, edge.kind)
            if target_contract is None or target_contract == contract.id:
                continue
            self._add(
                contract.id,
                target_contract,
                kind,
                self._name_of(target_contract),
                detail=edge.text or edge.kind.value,
                call_sites=[edge.source],
                evidence=graph_evidence(
                    edge.source,
                    edge.kind.value,
                    edge.target,
                    detail=edge.text,
                    detector=DETECTOR,
                ),
            )
            if kind in (ContractRelationKind.CALLS, ContractRelationKind.READS_STATE_FROM):
                self._called.add((contract.id, target_contract))

    def transfers(self, flows: list[AssetFlow], contract_of_role: dict[str, str]) -> None:
        """Value movements between two contracts of this protocol.

        Read off the flow records rather than re-derived from token edges, so the asset
        model and the relationship graph cannot disagree about who paid whom.
        """
        for flow in flows:
            source = contract_of_role.get(flow.source)
            target = contract_of_role.get(flow.target)
            if not source or not target or source == target:
                continue
            self._add(
                source,
                target,
                ContractRelationKind.TRANSFERS_ASSET_TO,
                self._name_of(target),
                detail=f"{flow.kind.value} of {flow.asset_id}",
                call_sites=[flow.call_site] if flow.call_site else [],
                evidence=graph_evidence(
                    flow.call_site or source,
                    flow.kind.value,
                    target,
                    detector=DETECTOR,
                ),
            )

    def callbacks(self) -> None:
        """A mutual call path: A reaches B and B reaches A.

        Structurally, that is a re-entry route into A, and it is worth stating once at the
        contract level rather than leaving each agent to notice the cycle. It is **not** a
        finding — a guard may cover it, the paths may be unreachable from one another, and
        deciding that needs the bodies. What it is, is the precondition.
        """
        for source, target in sorted(self._called):
            if (target, source) not in self._called:
                continue
            self._add(
                target,
                source,
                ContractRelationKind.CALLBACK_INTO,
                self._name_of(source),
                detail="mutual call path; re-entry into the caller is structurally possible",
                evidence=graph_evidence(target, "calls", source, detector=DETECTOR),
                confidence=Confidence.INFERRED,
            )

    # ── Plumbing ──────────────────────────────────────────────────────────────

    def _resolve(
        self, contract: Contract, target: str, edge_kind: EdgeKind
    ) -> tuple[str | None, ContractRelationKind]:
        """Map a call edge's target onto a contract (or a dependency) and a relation kind."""
        if edge_kind is EdgeKind.DELEGATECALLS:
            owner = self._owner(target)
            return (
                owner.id if owner is not None else None,
                ContractRelationKind.DELEGATES_TO,
            )
        if edge_kind is EdgeKind.CREATES:
            owner = self._owner(target)
            return (
                owner.id if owner is not None else None,
                ContractRelationKind.CREATES,
            )
        if target in SENTINELS:
            # A call into code the repository does not contain. Real, but it names no
            # contract, so it belongs to the trust-boundary stage rather than here.
            return None, ContractRelationKind.CALLS
        owner = self._owner(target)
        if owner is None:
            return None, ContractRelationKind.CALLS

        # A call through an interface is a dependency on whatever implements it, and the
        # dependency stage already worked out what that is.
        if owner.kind is ContractKind.INTERFACE:
            dependency = self._dep_by_interface.get(owner.id)
            return (
                dependency.id if dependency is not None else owner.id,
                ContractRelationKind.DEPENDS_ON_EXTERNAL,
            )
        if owner.kind is ContractKind.LIBRARY:
            return owner.id, ContractRelationKind.USES_LIBRARY
        if owner.id in self.index.query.inheritance(contract.id):
            # An inherited method call is not a cross-contract edge; the INHERITS record
            # already says everything true about it.
            return None, ContractRelationKind.CALLS

        callee = self.index.functions.get(target)
        if callee is not None and callee.mutability in ("view", "pure"):
            return owner.id, ContractRelationKind.READS_STATE_FROM
        return owner.id, ContractRelationKind.CALLS

    def _owner(self, function_id: str) -> Contract | None:
        function = self.index.functions.get(function_id)
        if function is not None and function.contract_id is not None:
            return self.index.contracts.get(function.contract_id)
        return self.index.contracts.get(function_id)

    def _contract_named(self, name: str) -> Contract | None:
        return next(
            (c for c in sorted(self.index.contracts.values(), key=lambda c: c.id)
             if c.name == name),
            None,
        )

    def _name_of(self, contract_id: str) -> str:
        contract = self.index.contracts.get(contract_id)
        if contract is not None:
            return contract.name
        return contract_id.rpartition(":")[2] or contract_id

    def _add(
        self,
        source: str,
        target: str,
        kind: ContractRelationKind,
        target_name: str,
        *,
        detail: str = "",
        call_sites: list[str] | None = None,
        evidence: Evidence | None = None,
        confidence: Confidence = Confidence.DERIVED,
    ) -> None:
        key = (source, target, kind)
        record = self.records.get(key)
        if record is None:
            record = ContractRelationship(
                id=make_contract_relation_id(source, target, kind.value),
                source=source,
                target=target,
                target_name=target_name,
                kind=kind,
                detail=detail,
                confidence=confidence,
            )
            self.records[key] = record
        else:
            record.occurrences += 1
        for site in call_sites or []:
            if site not in record.call_sites and len(record.call_sites) < MAX_CALL_SITES:
                record.call_sites.append(site)
        if evidence is not None and len(record.evidence) < MAX_CALL_SITES:
            record.evidence.append(evidence)

    def finish(self) -> list[ContractRelationship]:
        for record in self.records.values():
            record.call_sites = sorted(record.call_sites)
        return sorted(self.records.values(), key=lambda r: r.id)


#: Edge kinds that roll up into a contract-level relationship. `MODIFIED_BY`, `READS` and
#: `WRITES` are excluded on purpose: they never cross a contract boundary in Solidity.
_RELATION_KIND = frozenset(
    {
        EdgeKind.CALLS,
        EdgeKind.STATICCALLS,
        EdgeKind.DELEGATECALLS,
        EdgeKind.CREATES,
    }
)


__all__ = ["MAX_CALL_SITES", "detect"]
