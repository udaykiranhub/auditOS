"""`ProtocolQuery` — retrieve a coherent slice of the model around one anchor.

```
anchor: LendingPool.borrow(uint256)
            ↓
contract · operation · related operations · state it touches · assets · accounting
· flows · invariants · risk surfaces · open questions · evidence
```

**This is not the Context Builder.** It does no ranking, no token budgeting, no compression
and no prompt assembly — those are the Context Builder's job and are deliberately not
started here. What this provides is the thing that job is impossible without: a way to ask
*"what belongs with this?"* and get a connected answer instead of the whole artifact.

The Protocol Model is a web of cross-references, and until something walks them the
relationships are theoretical. Writing the traversal here rather than downstream means the
model's own tests prove the connectivity — a stage that emits an operation without linking
its state fails a test in this package, not silently in an agent prompt three phases later.

**Closure is one hop by default, and that is a deliberate limit.** An anchor's neighbours
are the entities that reference it or that it references; expanding transitively pulls in
the whole protocol within three hops on anything real. `depth` exists for the caller who
knows what they are asking for.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from engine.core.models.evidence import Evidence
from engine.core.models.protocol import (
    AccountingQuantity,
    AccountingRelation,
    Actor,
    Asset,
    AssetFlow,
    ContractClassification,
    ContractProfile,
    ContractRelationship,
    EconomicRelationship,
    FunctionBehavior,
    Invariant,
    Operation,
    Permission,
    ProtocolModel,
    RiskSurface,
    SemanticGap,
    StateItem,
    StateTransition,
    SurfaceDomain,
)

#: Neighbour hops. One is the useful default; two already reaches most of a small protocol.
DEFAULT_DEPTH = 1


@dataclass
class ProtocolSlice:
    """Everything connected to one anchor. Ordered deterministically by ID throughout."""

    anchor: str
    contracts: list[ContractClassification] = field(default_factory=list)
    profiles: list[ContractProfile] = field(default_factory=list)
    """The contract-level view of everything in the slice. Carries the per-function effect
    sequences, so a caller that needs "what does `borrow` do, in order" has it here rather
    than having to go back to the source."""
    behaviors: list[FunctionBehavior] = field(default_factory=list)
    """Just the function bodies relevant to this anchor — a narrower cut than every function
    on every profile, which on a large contract is most of the file."""
    permissions: list[Permission] = field(default_factory=list)
    relationships_out: list[ContractRelationship] = field(default_factory=list)
    operations: list[Operation] = field(default_factory=list)
    actors: list[Actor] = field(default_factory=list)
    state: list[StateItem] = field(default_factory=list)
    transitions: list[StateTransition] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    flows: list[AssetFlow] = field(default_factory=list)
    quantities: list[AccountingQuantity] = field(default_factory=list)
    relations: list[AccountingRelation] = field(default_factory=list)
    relationships: list[EconomicRelationship] = field(default_factory=list)
    invariants: list[Invariant] = field(default_factory=list)
    surfaces: list[RiskSurface] = field(default_factory=list)
    gaps: list[SemanticGap] = field(default_factory=list)

    @property
    def solidity_ids(self) -> list[str]:
        """Every `SolidityID` in the slice — what a context request would actually fetch."""
        found: set[str] = {c.contract_id for c in self.contracts}
        found |= {o.function_id for o in self.operations}
        found |= {s.state_var_id for s in self.state}
        return sorted(found)

    @property
    def evidence(self) -> list[Evidence]:
        """The trail behind everything in the slice, deduped."""
        from engine.core.models.evidence import dedupe_evidence

        claims = [
            *self.contracts,
            *self.profiles,
            *self.behaviors,
            *self.permissions,
            *self.relationships_out,
            *self.operations,
            *self.actors,
            *self.state,
            *self.transitions,
            *self.assets,
            *self.flows,
            *self.quantities,
            *self.relations,
            *self.relationships,
            *self.invariants,
            *self.surfaces,
        ]
        return dedupe_evidence([item for claim in claims for item in claim.evidence])

    @property
    def counts(self) -> dict[str, int]:
        return {
            "contracts": len(self.contracts),
            "profiles": len(self.profiles),
            "behaviors": len(self.behaviors),
            "permissions": len(self.permissions),
            "relationships_out": len(self.relationships_out),
            "operations": len(self.operations),
            "actors": len(self.actors),
            "state": len(self.state),
            "transitions": len(self.transitions),
            "assets": len(self.assets),
            "flows": len(self.flows),
            "quantities": len(self.quantities),
            "relations": len(self.relations),
            "relationships": len(self.relationships),
            "invariants": len(self.invariants),
            "surfaces": len(self.surfaces),
            "gaps": len(self.gaps),
        }

    @property
    def is_empty(self) -> bool:
        return not any(self.counts.values())


class ProtocolQuery:
    """Indexed read-only access to a `ProtocolModel`.

    Indexes once on construction, like `GraphQuery` does for the graph. A caller that
    queries many anchors — which is every caller — should reuse one instance.
    """

    def __init__(self, model: ProtocolModel):
        self.model = model

        self._operation_by_function = {o.function_id: o for o in model.operations}
        self._state_by_var = {s.state_var_id: s for s in model.state}
        self._asset_by_id = {a.id: a for a in model.assets}
        self._quantity_by_state = {
            q.state_id: q for q in model.accounting.quantities if q.state_id
        }

        self._operations_by_contract: dict[str, list[Operation]] = {}
        for operation in model.operations:
            self._operations_by_contract.setdefault(operation.contract_id or "", []).append(
                operation
            )

        self._state_by_contract: dict[str, list[StateItem]] = {}
        for item in model.state:
            self._state_by_contract.setdefault(item.contract_id, []).append(item)

    # ── Anchoring ─────────────────────────────────────────────────────────────

    def resolve(self, anchor: str) -> str | None:
        """Accept a `SolidityID`, a `ProtocolID`, or a bare contract/function name.

        Callers hold different vocabularies — an agent has a `SolidityID`, a report has a
        name, a UI has a `ProtocolID` — and forcing one on all of them just moves the
        translation somewhere it will be done inconsistently.
        """
        if anchor in self._operation_by_function or anchor in self._state_by_var:
            return anchor
        if self.model.contract(anchor) is not None:
            return anchor
        if (operation := self.model.operation(anchor)) is not None:
            return operation.function_id
        if (item := self.model.state_item(anchor)) is not None:
            return item.state_var_id
        if anchor.startswith("role:"):
            return anchor.removeprefix("role:")

        by_name = self.model.contract_by_name(anchor)
        if by_name is not None:
            return by_name.contract_id
        named = self.model.operation_by_name(anchor)
        return named.function_id if named is not None else None

    # ── Retrieval ─────────────────────────────────────────────────────────────

    def around(
        self,
        anchor: str,
        *,
        depth: int = DEFAULT_DEPTH,
        domains: list[SurfaceDomain] | None = None,
    ) -> ProtocolSlice:
        """The connected slice around one anchor.

        `domains` narrows the *surfaces and their invariants*, not the structure: an
        accounting-focused request still needs the operation's guards and external calls to
        reason about, so filtering the whole slice by domain would remove the context that
        makes the answer correct.
        """
        resolved = self.resolve(anchor)
        if resolved is None:
            return ProtocolSlice(anchor=anchor)

        if self.model.contract(resolved) is not None:
            slice_ = self._around_contract(resolved)
        elif resolved in self._state_by_var:
            slice_ = self._around_state(resolved)
        else:
            slice_ = self._around_operation(resolved, depth=depth)

        self._attach_contract_view(slice_)

        if domains:
            wanted = set(domains)
            slice_.surfaces = [s for s in slice_.surfaces if wanted & set(s.domains)]
            keep = {iid for surface in slice_.surfaces for iid in surface.invariant_ids}
            if keep:
                slice_.invariants = [i for i in slice_.invariants if i.id in keep]
        return slice_

    def _attach_contract_view(self, slice_: ProtocolSlice) -> None:
        """Hang the contract-level records off a slice that already has its structure.

        Done once here rather than in each `_around_*` because the rule is the same in all
        three cases: the profiles are those of the contracts already in the slice, and the
        behaviours are those of the functions already in it — **plus one hop into their
        internal callees**, which is where a Solidity protocol keeps its actual accounting.
        A slice containing `withdraw` but not the `_burnShares` it delegates to describes
        the wrapper and omits the arithmetic.
        """
        contract_ids = {c.contract_id for c in slice_.contracts}
        contract_ids |= {o.contract_id for o in slice_.operations if o.contract_id}
        contract_ids |= {item.contract_id for item in slice_.state}

        profiles = [p for p in self.model.profiles if p.contract_id in contract_ids]
        slice_.profiles = sorted(profiles, key=lambda p: p.id)

        wanted = {o.function_id for o in slice_.operations}
        wanted.add(slice_.anchor)
        by_function = {b.function_id: b for p in profiles for b in p.functions}

        selected = {fid: by_function[fid] for fid in wanted if fid in by_function}
        for described in list(selected.values()):
            for callee in described.internal_calls:
                if callee in by_function:
                    selected.setdefault(callee, by_function[callee])

        slice_.behaviors = sorted(selected.values(), key=lambda b: b.id)
        slice_.permissions = sorted(
            (
                permission
                for profile in profiles
                for permission in profile.permissions
                if permission.function_id in wanted
            ),
            key=lambda p: p.id,
        )
        slice_.relationships_out = sorted(
            (r for r in self.model.contract_relationships if r.source in contract_ids),
            key=lambda r: r.id,
        )

    def _around_operation(self, function_id: str, *, depth: int) -> ProtocolSlice:
        operation = self._operation_by_function.get(function_id)
        if operation is None:
            return ProtocolSlice(anchor=function_id)

        operations = {operation.id: operation}
        for _ in range(max(depth, 0)):
            for related_id in [
                related
                for current in list(operations.values())
                for related in current.related_operations
            ]:
                related = self.model.operation(related_id)
                if related is not None:
                    operations[related.id] = related

        state_ids = {
            sid for current in operations.values() for sid in (*current.reads, *current.writes)
        }
        state = [
            item for item in self.model.state if item.id in state_ids
        ]
        # The anchor's own writes first — a slice about `borrow` is about what `borrow`
        # changes, and the read-only context is supporting material.
        assets = self._assets_for(operations.values(), state)
        function_ids = sorted({o.function_id for o in operations.values()})
        contract_ids = sorted({o.contract_id for o in operations.values() if o.contract_id})

        return ProtocolSlice(
            anchor=function_id,
            contracts=[
                c
                for c in self.model.contracts
                if c.contract_id in contract_ids
            ],
            operations=sorted(operations.values(), key=lambda o: o.id),
            actors=[
                a
                for a in self.model.actors
                if any(c.function_id in function_ids for c in a.capabilities)
            ],
            state=sorted(state, key=lambda s: s.id),
            transitions=[
                t
                for t in self.model.state_transitions
                if t.operation_id in operations
            ],
            assets=assets,
            flows=[f for f in self.model.asset_flows if f.operation_id in operations],
            quantities=[
                q
                for q in self.model.accounting.quantities
                if q.state_id in {item.id for item in state}
            ],
            relations=self._relations_for({item.id for item in state}),
            relationships=self._relationships_for({item.id for item in state}, assets),
            invariants=self.model.invariants_touching(
                *function_ids, *[item.state_var_id for item in state]
            ),
            surfaces=self.model.surfaces_touching(*function_ids),
            gaps=self.model.gaps_touching(
                *function_ids,
                *[o.id for o in operations.values()],
                *[a.id for a in assets],
            ),
        )

    def _around_contract(self, contract_id: str) -> ProtocolSlice:
        classification = self.model.contract(contract_id)
        operations = self._operations_by_contract.get(contract_id, [])
        state = self._state_by_contract.get(contract_id, [])
        assets = self._assets_for(operations, state)
        function_ids = sorted({o.function_id for o in operations})

        return ProtocolSlice(
            anchor=contract_id,
            contracts=[classification] if classification is not None else [],
            operations=sorted(operations, key=lambda o: o.id),
            actors=[
                a
                for a in self.model.actors
                if contract_id in a.controlled_contracts
                or any(c.function_id in function_ids for c in a.capabilities)
            ],
            state=sorted(state, key=lambda s: s.id),
            transitions=[
                t
                for t in self.model.state_transitions
                if t.state_id in {item.id for item in state}
            ],
            assets=assets,
            flows=[
                f
                for f in self.model.asset_flows
                if f.call_site in function_ids
                or (classification is not None and classification.id in (f.source, f.target))
            ],
            quantities=[
                q
                for q in self.model.accounting.quantities
                if q.state_id in {item.id for item in state}
            ],
            relations=self._relations_for({item.id for item in state}),
            relationships=self._relationships_for({item.id for item in state}, assets),
            invariants=self.model.invariants_touching(
                contract_id, *function_ids, *[item.state_var_id for item in state]
            ),
            surfaces=self.model.surfaces_touching(contract_id, *function_ids),
            gaps=self.model.gaps_touching(
                contract_id,
                *([classification.id] if classification is not None else []),
                *[o.id for o in operations],
                *[item.id for item in state],
                # Asset-scoped questions ("does this token charge a fee?") are asked about
                # the asset, not the contract holding it. Omitting them left a slice that
                # looked complete while hiding the one question the accounting depends on.
                *[a.id for a in assets],
                *[sid for item in state for sid in [item.state_var_id]],
            ),
        )

    def _around_state(self, state_var_id: str) -> ProtocolSlice:
        item = self._state_by_var[state_var_id]
        touching = [
            operation
            for operation in self.model.operations
            if item.id in operation.reads or item.id in operation.writes
        ]
        assets = self._assets_for(touching, [item])

        return ProtocolSlice(
            anchor=state_var_id,
            contracts=[
                c for c in self.model.contracts if c.contract_id == item.contract_id
            ],
            operations=sorted(touching, key=lambda o: o.id),
            state=[item],
            transitions=[
                t for t in self.model.state_transitions if t.state_id == item.id
            ],
            assets=assets,
            quantities=[
                q for q in self.model.accounting.quantities if q.state_id == item.id
            ],
            relations=self._relations_for({item.id}),
            relationships=self._relationships_for({item.id}, assets),
            invariants=self.model.invariants_touching(state_var_id),
            surfaces=self.model.surfaces_touching(state_var_id),
            gaps=self.model.gaps_touching(state_var_id, item.id),
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _assets_for(
        self, operations: Iterable[Operation], state: list[StateItem]
    ) -> list[Asset]:
        ids = {
            asset_id
            for operation in operations
            for asset_id in (*operation.inputs, *operation.outputs)
        }
        ids |= {item.asset_id for item in state if item.asset_id}
        return sorted(
            (self._asset_by_id[aid] for aid in ids if aid in self._asset_by_id),
            key=lambda a: a.id,
        )

    def _relations_for(self, state_ids: set[str]) -> list[AccountingRelation]:
        quantity_ids = {
            q.id for q in self.model.accounting.quantities if q.state_id in state_ids
        }
        return [
            relation
            for relation in self.model.accounting.relations
            if quantity_ids & set(relation.quantity_ids)
        ]

    def _relationships_for(
        self, state_ids: set[str], assets: list[Asset]
    ) -> list[EconomicRelationship]:
        endpoints = {
            q.id for q in self.model.accounting.quantities if q.state_id in state_ids
        } | {asset.id for asset in assets}
        return [
            relationship
            for relationship in self.model.economics.relationships
            if {relationship.left, relationship.right} & endpoints
        ]

    # ── Topic entry points ────────────────────────────────────────────────────

    def anchors_for_domain(self, domain: SurfaceDomain, limit: int = 20) -> list[str]:
        """Where a given kind of reasoning should start, highest priority first.

        The entry point an Orchestrator needs: given an agent whose declared capability is
        `accounting`, which anchors are worth spending it on? Ordered by the surfaces'
        own priority, so the answer is the model's ranking rather than the caller's guess.
        """
        ranked = sorted(
            (s for s in self.model.risk_surfaces if domain in s.domains),
            key=lambda s: (-s.priority, s.id),
        )
        anchors: list[str] = []
        for surface in ranked:
            for target in surface.targets:
                if target not in anchors:
                    anchors.append(target)
                if len(anchors) >= limit:
                    return anchors
        return anchors

    def profile_of(self, anchor: str) -> ContractProfile | None:
        """The contract profile an anchor belongs to, whatever vocabulary the anchor is in.

        `borrow`, `src/LendingPool.sol:LendingPool.borrow(uint256)`,
        `op:src/LendingPool.sol:LendingPool.borrow(uint256)` and `LendingPool` all land on
        the same profile — which is the point of having `resolve` at all.
        """
        resolved = self.resolve(anchor)
        if resolved is None:
            return None
        if (profile := self.model.profile(resolved)) is not None:
            return profile
        operation = self._operation_by_function.get(resolved)
        if operation is not None and operation.contract_id:
            return self.model.profile(operation.contract_id)
        item = self._state_by_var.get(resolved)
        return self.model.profile(item.contract_id) if item is not None else None

    def domains(self) -> dict[str, int]:
        """How much of the protocol calls for each kind of reasoning."""
        counts: dict[str, int] = {}
        for surface in self.model.risk_surfaces:
            for domain in surface.domains:
                counts[domain.value] = counts.get(domain.value, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


__all__ = ["DEFAULT_DEPTH", "ProtocolQuery", "ProtocolSlice"]
