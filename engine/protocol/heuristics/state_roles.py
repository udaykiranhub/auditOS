"""What a state variable *means*, decided from several independent signals.

```
_positions   mapping(address => mapping(address => UserPosition))
  ├─ shape       key→key→struct           → POSITION        0.60
  ├─ writers     borrow, deposit, repay, withdraw (4, mixed direction)
  ├─ guards      read by a comparison that gates a transfer out
  └─ name        "position"                → POSITION        0.30
                                              ────────────────────
                                              POSITION, DERIVED
```

**Why several.** The previous classifier took one argument — the declaration — and matched
its name against a table. That table is right about `totalSupply` and silent about
everything a real protocol is mostly made of: on a live lending market it left twelve of
thirty-five variables `unknown`, and because roles feed quantities, quantities feed
relations and relations feed invariants, that silence propagated all the way to an empty
accounting model.

Each signal here is independently checkable and carries its own evidence:

| Signal | Reads | Strongest at |
|---|---|---|
| **shape** | the declared type | telling a record store from a balance |
| **direction** | `+=` / `-=` / `=` on the write edges | telling a quantity from a parameter |
| **flow** | what the value derives from | tying a balance to a transferred amount |
| **constraint** | what compares against it | finding thresholds and caps |
| **operation** | which protocol operation writes it | debt vs collateral |
| **pairing** | a scalar total moved with a mapping | totals and their ledgers |
| **name** | the identifier | last, and never alone above `INFERRED` |

**Name matching never wins on its own.** It contributes a weak vote like any other signal,
so `MAX_TOTAL_PENALTY` no longer becomes an accounting total on the strength of "total", and
`getUsdValueAfterDeposit` no longer makes a valuation adapter look like a vault. Where the
structural signals are silent and only the name speaks, the result is `INFERRED` and says
so.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from engine.core.models.code import StateVar
from engine.core.models.evidence import (
    Confidence,
    Evidence,
    graph_evidence,
    heuristic_evidence,
    source_evidence,
)
from engine.core.models.protocol import Operation, OperationKind, StateRole
from engine.core.models.semantic import EdgeKind, NodeKind, SemanticGraph

DETECTOR = "state_role"

#: A signal must reach this to be stated at all. Below it the variable stays `UNKNOWN`,
#: which is a real answer and not a failure.
MIN_SCORE = 0.30

#: Above this, enough independent signals agreed that the claim is structural rather than
#: a reading of the name.
DERIVED_SCORE = 0.55


@dataclass
class Verdict:
    """One variable's role, with how it was reached."""

    role: StateRole = StateRole.UNKNOWN
    confidence: Confidence = Confidence.UNKNOWN
    evidence: list[Evidence] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)
    runner_up: StateRole | None = None
    """The next-best role when the top two are close. A near-tie is worth surfacing, not
    hiding behind a confident-looking single answer."""


class RoleInference:
    """Scores every state variable once, so the signals are computed a single time."""

    def __init__(
        self,
        graph: SemanticGraph,
        operations: list[Operation],
        *,
        transitions: list[tuple[str, str, str]] | None = None,
    ) -> None:
        self.graph = graph
        self._node_by_solidity = {
            node.solidity_id: node
            for node in graph.of_kind(NodeKind.STATE_VAR)
            if node.solidity_id
        }
        self._function_role = {
            operation.function_id: operation.kind for operation in operations
        }
        # function SolidityID → the operation kind it implements, reached through the graph
        # node rather than by name, so an internal helper called only by `borrow` is not
        # mistaken for an entrypoint of its own.
        self._transitions = transitions or []

    # ── The public answer ─────────────────────────────────────────────────────

    def classify(self, variable: StateVar, state_var_id: str, name_role: StateRole) -> Verdict:
        """The role of one variable, from every signal that has something to say."""
        if variable.is_constant or variable.is_immutable:
            kept = "constant" if variable.is_constant else "immutable"
            # A value that cannot change is a parameter, whatever it is called.
            # `MAX_TOTAL_PENALTY` contains "total" and earned a solvency invariant asserting
            # the protocol's assets must cover a compile-time constant.
            return Verdict(
                role=_constant_role(variable, name_role),
                confidence=Confidence.DERIVED,
                evidence=[
                    source_evidence(
                        state_var_id,
                        f"{variable.type} {variable.name} is {kept}",
                        detector=DETECTOR,
                    )
                ],
                rationale=["declared constant or immutable, so it is a parameter"],
            )

        scores: dict[StateRole, float] = defaultdict(float)
        evidence: list[Evidence] = []
        rationale: list[str] = []

        for signal in (
            self._by_shape,
            self._by_direction,
            self._by_operation,
            self._by_constraint,
            self._by_flow,
        ):
            signal(variable, state_var_id, scores, evidence, rationale)

        # The name votes last and weakly. It is the signal most likely to be a coincidence,
        # and the one that produced every misclassification worth fixing.
        if name_role is not StateRole.UNKNOWN and _type_allows(variable.type, name_role):
            scores[name_role] += 0.30
            rationale.append(f"named like a {name_role.value}")
            evidence.append(
                heuristic_evidence(
                    DETECTOR, f"`{variable.name}` reads as {name_role.value}", ref=state_var_id
                )
            )

        if not scores:
            return Verdict(rationale=["no signal identified this variable"])

        ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0].value))
        best, score = ranked[0]
        if score < MIN_SCORE:
            return Verdict(rationale=["signals were too weak to name a role"])

        runner_up = (
            ranked[1][0] if len(ranked) > 1 and ranked[1][1] >= score * 0.8 else None
        )
        return Verdict(
            role=best,
            confidence=(
                Confidence.DERIVED if score >= DERIVED_SCORE else Confidence.INFERRED
            ),
            evidence=evidence[:5],
            rationale=rationale,
            runner_up=runner_up,
        )

    # ── Signals ───────────────────────────────────────────────────────────────

    def _by_shape(
        self,
        variable: StateVar,
        state_var_id: str,
        scores: dict[StateRole, float],
        evidence: list[Evidence],
        rationale: list[str],
    ) -> None:
        """The declared type, which is the one signal that is never a guess.

        A `mapping(address => Struct)` is a record store whatever it is called; a
        `mapping(key => bool)` is a set; a `string` is metadata. These are the kinds the old
        vocabulary had no word for, which is why they all landed in `unknown`.
        """
        shape = _shape_of(variable.type)
        if shape is None:
            return
        role, weight, why = shape
        scores[role] += weight
        rationale.append(why)
        evidence.append(
            source_evidence(state_var_id, f"{variable.type} {variable.name}", detector=DETECTOR)
        )

    def _by_direction(
        self,
        variable: StateVar,
        state_var_id: str,
        scores: dict[StateRole, float],
        evidence: list[Evidence],
        rationale: list[str],
    ) -> None:
        """How the code changes it.

        A variable moved with `+=` and `-=` is a *quantity* — something accumulates in it.
        One only ever assigned with `=` is a parameter or a record. This separates
        `totalDeposits` from `treasury` without reading either name, and it is the signal
        that makes a threshold distinguishable from a balance.
        """
        node = self._node_by_solidity.get(state_var_id)
        if node is None:
            return
        writes = self.graph.in_edges(node.id, EdgeKind.WRITES)
        if not writes:
            return

        moved = {edge.operator for edge in writes} & {"increase", "decrease"}

        # Only ever goes up, and nothing ever takes it down. A balance that cannot fall is
        # not a balance — it is a sequence, and `nextTransferId++` is the shape.
        # A counter is a single sequence, so a mapping is never one however it moves: a
        # per-account ledger that happens to be written only through `+=` in the paths this
        # graph saw is still a ledger.
        scalar = not variable.type.strip().lower().startswith("mapping")
        if moved == {"increase"} and scalar and _type_allows(variable.type, StateRole.COUNTER):
            scores[StateRole.COUNTER] += 0.45
            rationale.append("only ever increases; nothing decreases it")
            evidence.append(
                graph_evidence(
                    node.id, "writes", state_var_id, writes[0].detail, detector=DETECTOR
                )
            )
            return

        if moved:
            scores[StateRole.ACCOUNTING_TOTAL] += 0.20
            scores[StateRole.USER_BALANCE] += 0.20
            rationale.append(
                f"accumulated in ({', '.join(sorted(moved))}) by {len(writes)} writes"
            )
            evidence.append(
                graph_evidence(
                    node.id, "writes", state_var_id, writes[0].detail, detector=DETECTOR
                )
            )
        elif all(edge.operator == "set" for edge in writes):
            # Assigned outright and never accumulated. A configured value, or a record
            # replaced wholesale.
            scores[StateRole.CONFIG] += 0.15
            scores[StateRole.THRESHOLD] += 0.15
            rationale.append("only ever assigned, never accumulated")

    def _by_operation(
        self,
        variable: StateVar,
        state_var_id: str,
        scores: dict[StateRole, float],
        evidence: list[Evidence],
        rationale: list[str],
    ) -> None:
        """Which protocol operation writes it.

        A variable that `BORROW` increases and `REPAY` decreases is a debt record; the same
        shape under `DEPOSIT`/`WITHDRAW` is a balance. This is the signal that separates the
        two, and neither name nor type can.
        """
        node = self._node_by_solidity.get(state_var_id)
        if node is None:
            return

        kinds: set[OperationKind] = set()
        for edge in self.graph.in_edges(node.id, EdgeKind.WRITES):
            writer = self.graph.node(edge.source)
            if writer is None or not writer.solidity_id:
                continue
            kind = self._function_role.get(writer.solidity_id)
            if kind is not None:
                kinds.add(kind)
        if not kinds:
            return

        for kind, role, weight in _BY_OPERATION:
            if kind in kinds:
                scores[role] += weight
                rationale.append(f"written by a {kind.value} operation")
                evidence.append(
                    heuristic_evidence(
                        DETECTOR,
                        f"{variable.name} changes under {kind.value}",
                        ref=state_var_id,
                    )
                )
                break

    def _by_constraint(
        self,
        variable: StateVar,
        state_var_id: str,
        scores: dict[StateRole, float],
        evidence: list[Evidence],
        rationale: list[str],
    ) -> None:
        """Whether the protocol compares against it, and on which side.

        A variable that appears on the *bounding* side of a reverting comparison is a
        threshold or a cap — that is what being a bound means. One on the constrained side
        is a quantity being kept in range.
        """
        node = self._node_by_solidity.get(state_var_id)
        if node is None:
            return

        bounding = list(self.graph.out_edges(node.id, EdgeKind.CONSTRAINS))
        bounded = list(self.graph.in_edges(node.id, EdgeKind.CONSTRAINS))

        # A bound proven on a parameter that is then stored is a bound on the storage.
        # `if (threshold > 3600) revert; stalenessThreshold = threshold;` constrains the
        # parameter, and checking only the storage node missed every validated setter —
        # which is most of the configuration in a real protocol.
        for edge in self.graph.in_edges(node.id, EdgeKind.DERIVES_FROM):
            bounding.extend(self.graph.out_edges(edge.source, EdgeKind.CONSTRAINS))
            bounded.extend(self.graph.in_edges(edge.source, EdgeKind.CONSTRAINS))

        if bounding:
            scores[StateRole.THRESHOLD] += 0.35
            rationale.append(f"bounds {len(bounding)} other quantities")
            evidence.append(
                graph_evidence(
                    node.id, "constrains", bounding[0].target, bounding[0].detail,
                    detector=DETECTOR,
                )
            )
        if bounded:
            scores[StateRole.ACCOUNTING_TOTAL] += 0.15
            scores[StateRole.USER_BALANCE] += 0.15
            rationale.append("kept within a bound the protocol enforces")

    def _by_flow(
        self,
        variable: StateVar,
        state_var_id: str,
        scores: dict[StateRole, float],
        evidence: list[Evidence],
        rationale: list[str],
    ) -> None:
        """What its value is computed from, one hop.

        A variable assigned from a timestamp is a timestamp; one assigned from another
        quantity inherits some of that quantity's character. Weak on purpose — one hop of
        dataflow is a hint, not a derivation.
        """
        node = self._node_by_solidity.get(state_var_id)
        if node is None:
            return
        for edge in self.graph.in_edges(node.id, EdgeKind.DERIVES_FROM):
            detail = edge.detail.lower()
            if "timestamp" in detail or "block.number" in detail:
                scores[StateRole.TIMESTAMP] += 0.40
                rationale.append("assigned from a block value")
                evidence.append(
                    graph_evidence(
                        edge.source, "derives_from", node.id, edge.detail, detector=DETECTOR
                    )
                )
                return
            if "+ 1" in detail or "++" in detail:
                scores[StateRole.COUNTER] += 0.35
                rationale.append("incremented by one when something is created")
                return


# ── Shape rules ───────────────────────────────────────────────────────────────


def _shape_of(type_name: str) -> tuple[StateRole, float, str] | None:
    """The role a declared type implies on its own, with why.

    Ordered most specific first. Every branch here is a fact about the declaration rather
    than an interpretation of it, which is why the weights are the highest in the module.
    """
    bare = type_name.strip()
    lowered = bare.lower()

    if lowered.startswith("string"):
        return StateRole.METADATA, 0.55, "declared as text"

    if lowered.startswith("mapping"):
        # Nested mappings are the normal shape for per-account records, so the innermost
        # value is what carries the meaning. Stopping at the first level read
        # `mapping(address => mapping(address => bool))` as unclassifiable when it is
        # plainly a two-key allowlist.
        value, depth = _innermost(bare)
        keyed = "behind two keys" if depth > 1 else "a mapping"

        if value.startswith("bool"):
            return StateRole.MEMBERSHIP, 0.55, f"{keyed} to bool, used as a set"
        if value.endswith("[]"):
            return StateRole.INDEX_LIST, 0.55, f"{keyed} to a list, used to enumerate"
        if value[:1].isupper():
            if depth > 1:
                return StateRole.POSITION, 0.60, "a per-account record behind two keys"
            weight = 0.55 if not value.startswith("I") else 0.45
            return StateRole.RECORD_STORE, weight, "a mapping to a struct — a record store"
        return None

    if bare.endswith("[]"):
        return StateRole.INDEX_LIST, 0.45, "an array, used to enumerate"
    return None


def _value_type(type_name: str) -> str:
    """`mapping(address => Foo)` → `Foo`, one level."""
    inner = type_name.strip()
    if not inner.lower().startswith("mapping"):
        return inner
    body = inner[inner.find("(") + 1 : inner.rfind(")")]
    return body.partition("=>")[2].strip()


def _innermost(type_name: str) -> tuple[str, int]:
    """`mapping(a => mapping(b => Foo))` → `("Foo", 2)`. The depth is the key count."""
    value, depth = type_name.strip(), 0
    while value.lower().startswith("mapping") and depth < 4:
        value = _value_type(value)
        depth += 1
    return value, depth


#: Operation kind → what a variable it writes probably is. First match wins, so the more
#: specific kinds come first.
_BY_OPERATION: tuple[tuple[OperationKind, StateRole, float], ...] = (
    (OperationKind.BORROW, StateRole.DEBT_RECORD, 0.35),
    (OperationKind.REPAY, StateRole.DEBT_RECORD, 0.30),
    (OperationKind.LIQUIDATE, StateRole.COLLATERAL_RECORD, 0.25),
    (OperationKind.DEPOSIT, StateRole.USER_BALANCE, 0.30),
    (OperationKind.WITHDRAW, StateRole.USER_BALANCE, 0.25),
    (OperationKind.STAKE, StateRole.USER_BALANCE, 0.30),
    (OperationKind.MINT, StateRole.SHARE_SUPPLY, 0.25),
    (OperationKind.CONFIGURE, StateRole.CONFIG, 0.30),
)

#: Roles a non-numeric type cannot hold, however the variable is named. `IERC20 public
#: collateralToken` contains "collateral" and is a handle, not a balance.
_NUMERIC_ONLY = frozenset(
    {
        StateRole.ACCOUNTING_TOTAL,
        StateRole.USER_BALANCE,
        StateRole.DEBT_RECORD,
        StateRole.COLLATERAL_RECORD,
        StateRole.SHARE_SUPPLY,
        StateRole.EXCHANGE_RATE,
        StateRole.ACCUMULATOR,
        StateRole.PRICE,
        StateRole.THRESHOLD,
        StateRole.COUNTER,
    }
)


def _type_allows(type_name: str, role: StateRole) -> bool:
    if role not in _NUMERIC_ONLY:
        return True
    lowered = type_name.strip().lower()
    if lowered.startswith("mapping"):
        return _value_type(type_name).lower().startswith(("uint", "int"))
    return lowered.startswith(("uint", "int"))


def _constant_role(variable: StateVar, name_role: StateRole) -> StateRole:
    """A constant is a parameter — but *which* kind is still worth saying.

    `MAX_FEE_BPS` is a ceiling and `BPS` is a scale factor; calling both `config` loses the
    distinction that decides whether "is this bounded?" is even a question.
    """
    lowered = variable.name.lower()
    if any(token in lowered for token in ("max", "min", "cap", "limit", "threshold")):
        return StateRole.THRESHOLD
    if name_role in (StateRole.METADATA, StateRole.ADDRESS_REF, StateRole.ROLE_REGISTRY):
        return name_role
    return StateRole.CONFIG


__all__ = ["DETECTOR", "RoleInference", "Verdict"]
