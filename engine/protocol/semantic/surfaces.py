"""Risk surfaces derived from graph patterns, not looked up by operation name.

```
BEFORE   OperationKind.DEPOSIT → {first_depositor, rounding, donation}
         Every protocol with a `deposit` receives identical text. Including protocols
         with no shares, no exchange rate and no oracle.

AFTER    a WRITES edge positioned after a CALLS edge that leaves the frame,
         on a variable the same function also READS
         → reentrancy surface, naming that variable and that call
```

The difference is not phrasing. A table cannot be wrong about a specific protocol because
it never looked at one; it also cannot be *right* about one. A pattern match over this
protocol's own graph produces a surface only where the shape genuinely occurs, names the
concrete node it occurs on, and stays silent otherwise — which is what makes an empty
result meaningful.

**Still not findings.** Every surface here is a place to look, phrased as questions. A
`CONSTRAINS` edge that exists tells an agent the protocol enforces a rule; a *missing* one
where the graph shows value leaving tells it where to start. Neither says anything is
exploitable — that determination needs execution semantics this layer does not have.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from engine.core.models.evidence import Confidence, graph_evidence
from engine.core.models.protocol import (
    RiskSurface,
    SurfaceDomain,
    SurfaceKind,
)
from engine.core.models.semantic import EdgeKind, NodeKind, SemanticGraph, SemanticNode
from engine.protocol.ids import make_surface_id

DETECTOR = "graph_surfaces"

#: Call targets that hand control to code this protocol does not own. A call to a node the
#: graph resolved inside the repository stays in the trust domain; an `EXTERNAL` node does
#: not, and neither does anything named like a token movement.
_VALUE_MOVING = ("transfer", "send", "call", "safetransfer", "sweep", "withdraw")


@dataclass
class _Finding:
    """One matched pattern, before it becomes a `RiskSurface`."""

    kind: SurfaceKind
    domains: tuple[SurfaceDomain, ...]
    title: str
    description: str
    questions: tuple[str, ...]
    contract_id: str
    targets: list[str] = field(default_factory=list)
    priority: float = 0.5
    evidence_ref: str = ""


def derive(graph: SemanticGraph) -> list[RiskSurface]:
    """Every surface this protocol's own graph supports, ranked.

    Returns an empty list on a graph with no expression-level edges rather than falling
    back to a template — an empty result at text fidelity means "nothing was visible", and
    `SemanticGraph.fidelity` is where a reader checks which.
    """
    if not graph.edges:
        return []

    by_id = {node.id: node for node in graph.nodes}
    found: list[_Finding] = []
    found.extend(_reentrancy(graph, by_id))
    found.extend(_unconstrained_value_exit(graph, by_id))
    found.extend(_unbounded_privileged_write(graph, by_id))
    found.extend(_cross_contract_state_dependence(graph, by_id))

    surfaces: dict[str, RiskSurface] = {}
    for finding in found:
        identifier = make_surface_id(
            finding.kind.value, finding.targets[0] if finding.targets else finding.title
        )
        surfaces.setdefault(
            identifier,
            RiskSurface(
                id=identifier,
                kind=finding.kind,
                title=finding.title,
                description=finding.description,
                targets=finding.targets[:6],
                contract_id=finding.contract_id,
                priority=round(min(finding.priority, 1.0), 3),
                domains=sorted(set(finding.domains), key=lambda d: d.value),
                questions=list(finding.questions),
                # `DERIVED`: the pattern was matched against edges read from the AST, not
                # inferred from an operation's name.
                confidence=Confidence.DERIVED,
                evidence=[
                    graph_evidence(
                        finding.evidence_ref or finding.contract_id,
                        finding.kind.value,
                        finding.targets[0] if finding.targets else finding.contract_id,
                        finding.description,
                        detector=DETECTOR,
                    )
                ],
            ),
        )
    return sorted(surfaces.values(), key=lambda s: (-s.priority, s.id))


# ── Patterns ──────────────────────────────────────────────────────────────────


def _reentrancy(
    graph: SemanticGraph, by_id: dict[str, SemanticNode]
) -> list[_Finding]:
    """A state write positioned after a call that leaves the frame.

    The order is the whole content. An unordered list of the same reads, writes and calls
    cannot distinguish a write before an external call from a write after one, and that
    distinction is the entire question. Matched per function and named per variable, so the
    surface points at `LendingPool.withdraw` and `reserve.totalSupplyShares` rather than at
    "functions that look like withdrawals".
    """
    found: list[_Finding] = []
    for function in graph.of_kind(NodeKind.FUNCTION):
        calls = [
            edge
            for edge in graph.out_edges(function.id, EdgeKind.CALLS)
            if _leaves_frame(edge.target, edge.detail, by_id)
        ]
        if not calls:
            continue
        first = min(edge.order for edge in calls)

        after = [
            edge
            for edge in graph.out_edges(function.id, EdgeKind.WRITES)
            if edge.order > first and by_id.get(edge.target, _blank()).kind
            is NodeKind.STATE_VAR
        ]
        if not after:
            continue

        names = sorted({by_id[edge.target].name for edge in after if edge.target in by_id})
        call = min(calls, key=lambda e: e.order)
        found.append(
            _Finding(
                kind=SurfaceKind.REENTRANCY,
                domains=(SurfaceDomain.REENTRANCY, SurfaceDomain.EXTERNAL_INTERACTION),
                title=f"{function.qualified_name}: storage written after control leaves",
                description=(
                    f"{function.qualified_name} calls {call.detail} and then writes "
                    f"{', '.join(names[:4])}. A reentrancy guard may cover this; the "
                    "ordering is what makes it worth checking."
                ),
                questions=(
                    f"can {call.detail} re-enter this contract before "
                    f"{names[0]} is updated?",
                    "is a reentrancy guard applied, and does it cover every path here?",
                    f"does any view read {names[0]} between the call and the write?",
                ),
                contract_id=function.contract_id,
                targets=[function.solidity_id or function.id],
                priority=0.9 if function.is_entrypoint else 0.6,
                evidence_ref=function.solidity_id,
            )
        )
    return found


def _unconstrained_value_exit(
    graph: SemanticGraph, by_id: dict[str, SemanticNode]
) -> list[_Finding]:
    """Value leaves, and nothing in this function guards it.

    The *absence* of a `GUARDS` edge is the signal, and it is only meaningful because the
    graph records guards positively when they exist. On a protocol whose withdrawal is
    checked, this fires nowhere; on one where a path out is unchecked, it names that path.
    """
    found: list[_Finding] = []
    for function in graph.of_kind(NodeKind.FUNCTION):
        if not function.is_entrypoint:
            continue
        # A modifier is applied, so this function *is* guarded by something. Authorization
        # is usually `msg.sender != owner` inside a modifier, and this graph deliberately
        # does not record a disequality as a constraint — so reading "no GUARDS edges" as
        # "unguarded" reported `Ownable.transferOwnership` and every `onlyOwner` setter in
        # the protocol as an unprotected path out. Absence is only evidence where the graph
        # could have seen the thing that is absent.
        if function.modifier_count or graph.out_edges(function.id, EdgeKind.GUARDS):
            continue

        # The call must actually leave the frame. Matching on the call *text* alone made
        # `emit OwnershipTransferStarted(…)` and `error TransferNotFound()` look like token
        # movements, because both contain "transfer".
        moving = [
            edge
            for edge in graph.out_edges(function.id, EdgeKind.CALLS)
            if _leaves_frame(edge.target, edge.detail, by_id)
            and any(token in edge.detail.lower() for token in _VALUE_MOVING)
        ]
        if not moving:
            continue

        found.append(
            _Finding(
                kind=SurfaceKind.ACCESS_CONTROL,
                domains=(SurfaceDomain.ACCESS_CONTROL, SurfaceDomain.EXTERNAL_INTERACTION),
                title=f"{function.qualified_name}: value moves with no comparison guarding it",
                description=(
                    f"{function.qualified_name} is externally callable and reaches "
                    f"{moving[0].detail}, and this pass found no comparison standing "
                    "between the caller and that path."
                ),
                questions=(
                    "what stops an arbitrary caller from reaching this transfer?",
                    "is the amount bounded by anything the caller does not control?",
                    "is authorization enforced by a modifier this pass could not read?",
                ),
                contract_id=function.contract_id,
                targets=[function.solidity_id or function.id],
                priority=0.85,
                evidence_ref=function.solidity_id,
            )
        )
    return found


def _unbounded_privileged_write(
    graph: SemanticGraph, by_id: dict[str, SemanticNode]
) -> list[_Finding]:
    """A configuration variable written with no bound anywhere on it.

    Its sibling in the same protocol usually *is* bounded, which is what makes the absence
    informative rather than a generic "parameters can be changed" note.
    """
    found: list[_Finding] = []
    for variable in graph.of_kind(NodeKind.STATE_VAR):
        # A *numeric scalar* is what "bounded parameter" means. A mapping of records, an
        # allowance ledger and an owner address are all written outright by design, and
        # reporting each as an unbounded parameter buried the two that really are one.
        if variable.is_constant or not _is_tunable(variable.type_name):
            continue

        setters = [
            edge
            for edge in graph.in_edges(variable.id, EdgeKind.WRITES)
            if edge.operator == "set"
            and by_id.get(edge.source, _blank()).is_entrypoint
            # Centralization is about a *privileged* party. A value any caller may set is
            # a different question, and belongs to whoever asks it.
            and by_id.get(edge.source, _blank()).modifier_count > 0
        ]
        if not setters:
            continue
        if _is_bounded(graph, variable.id):
            continue

        writer = by_id.get(setters[0].source)
        if writer is None:
            continue
        found.append(
            _Finding(
                kind=SurfaceKind.CENTRALIZATION,
                domains=(SurfaceDomain.ACCESS_CONTROL, SurfaceDomain.GOVERNANCE),
                title=f"{variable.qualified_name}: set outright, with no bound on the value",
                description=(
                    f"{writer.qualified_name} assigns {variable.name} directly and no "
                    "comparison anywhere in this protocol constrains what it may hold."
                ),
                questions=(
                    f"what values of {variable.name} would trap funds or halt the protocol?",
                    "should this be bounded the way the neighbouring parameters are?",
                    "is the setter behind a timelock?",
                ),
                contract_id=variable.contract_id,
                targets=[variable.solidity_id or variable.id],
                priority=0.6,
                evidence_ref=variable.solidity_id,
            )
        )
    return found


def _cross_contract_state_dependence(
    graph: SemanticGraph, by_id: dict[str, SemanticNode]
) -> list[_Finding]:
    """A guard whose two sides live in different contracts.

    The rule spans a trust boundary: one side is state this contract does not own and
    cannot constrain, so the property holds only while the other contract cooperates.
    """
    found: list[_Finding] = []
    for edge in graph.edges:
        if edge.kind is not EdgeKind.CONSTRAINS:
            continue
        left, right = by_id.get(edge.source), by_id.get(edge.target)
        if left is None or right is None:
            continue
        if not left.contract_id or not right.contract_id:
            continue
        if left.contract_id == right.contract_id:
            continue

        found.append(
            _Finding(
                kind=SurfaceKind.STATE_SYNC,
                domains=(SurfaceDomain.ACCOUNTING, SurfaceDomain.EXTERNAL_INTERACTION),
                title=(
                    f"{left.name} and {right.name} are compared across a contract boundary"
                ),
                description=(
                    f"`{edge.detail}` relates {left.qualified_name} to "
                    f"{right.qualified_name}, which are owned by different contracts."
                ),
                questions=(
                    f"can {right.name} change between the check and its use?",
                    f"who may write {right.name}, and is that the same trust domain?",
                    "is the comparison performed on a value read once or read twice?",
                ),
                contract_id=left.contract_id,
                targets=[left.solidity_id or left.id, right.solidity_id or right.id],
                priority=0.7,
                evidence_ref=edge.function_id or left.solidity_id,
            )
        )
    return found


# ── Helpers ───────────────────────────────────────────────────────────────────


def _leaves_frame(target: str, detail: str, by_id: dict[str, SemanticNode]) -> bool:
    """Whether a call hands control outside this contract.

    An `EXTERNAL` node is one the graph could not resolve inside the repository. A resolved
    callee in another contract counts too; a call into this contract's own code does not,
    and neither does a library, whose body runs in this frame.
    """
    node = by_id.get(target)
    if node is None:
        return True
    if node.kind is NodeKind.EXTERNAL:
        # Errors and events are emitted, not called into. They are `FunctionCall` nodes in
        # the AST and would otherwise read as a trust-boundary crossing in every guarded
        # function in the protocol.
        return not _is_diagnostic(node.name, detail)
    return False


def _is_diagnostic(name: str, detail: str) -> bool:
    """`ZeroAddress()`, `Transfer(…)`, `uint256(…)` — not a call that transfers control."""
    head = (name or detail).split("(")[0].strip()
    if not head:
        return True
    if head[:1].isupper():
        # A custom error, an event, or a type cast. All start with a capital by convention
        # and none of them hand control to another contract.
        return True
    return head in ("require", "assert", "revert", "keccak256", "abi", "address")


def _is_tunable(type_name: str) -> bool:
    """A plain numeric scalar — the only shape "should this be bounded?" is a question about."""
    bare = type_name.strip()
    if bare.endswith("]") or bare.startswith("mapping") or "=>" in bare:
        return False
    return bare.startswith(("uint", "int"))


def _is_bounded(graph: SemanticGraph, node_id: str) -> bool:
    """Whether anything constrains this variable, directly or through what it is set from.

    The indirection matters: `feeBps = feeBps_` after `require(feeBps_ <= MAX_FEE_BPS)`
    bounds the storage, but the constraint edge lands on the *parameter*. Checking only the
    storage node reported every validated setter in the protocol as unbounded.
    """
    if graph.in_edges(node_id, EdgeKind.CONSTRAINS) or graph.out_edges(
        node_id, EdgeKind.CONSTRAINS
    ):
        return True
    for edge in graph.in_edges(node_id, EdgeKind.DERIVES_FROM):
        if graph.in_edges(edge.source, EdgeKind.CONSTRAINS) or graph.out_edges(
            edge.source, EdgeKind.CONSTRAINS
        ):
            return True
    return False


def _blank() -> SemanticNode:
    return SemanticNode(id="", kind=NodeKind.EXTERNAL)


__all__ = ["DETECTOR", "derive"]
