"""Stage 12b — how the protocol's own storage is constrained, read out of its guards.

```
require(deposits[msg.sender] - amount >= debt[msg.sender] * 2)
→ BOUND       deposits ≥ debt · 2                       two storage variables

if (initiationWeight_ + penaltyWeight_ + terminationWeight_ > MAX_TOTAL_PENALTY) revert
→ BOUND       initiationWeight + penaltyWeight + terminationWeight ≤ MAX_TOTAL_PENALTY

if (startPriceMultiplier_ < 10_000) revert   …then  startPriceMultiplier = startPriceMultiplier_
→ BOUND       startPriceMultiplier ∈ [10000, …]         a validated setter proves a range

if (realisedLiquidityOf[msg.sender] < assets) revert
→ BOUND       realisedLiquidityOf ≥ (the amount this operation moves)
```

**Storage, not "quantities".** The first version of this pass keyed on `AccountingQuantity`,
which exists only where the state pass inferred a role it recognises. On Arcadia that is 3
variables out of 49, so the pass had almost nothing to read and produced nothing — it worked
on a toy lending market and did nothing on a real one. Every constraint here is keyed on
`StateItem` instead, which exists for all 49.

**Contract-scoped.** Names are resolved against the declaring contract and its ancestors, so
two contracts that both have a `debt` no longer collide, and neither is dropped.

**Guards are evidence; names are not.** A condition that reverts is the protocol stating a
rule about itself. That is why this pass can assert a relationship where a role-pair table
would only be guessing — and why an unrecognised guard produces nothing rather than
something plausible. It does not evaluate, simplify or solve expressions: `CodeModel` does
not model expressions (SPEC §12.2), and writing a parser here is the scope trap that section
warns about. It splits on comparisons, classifies each operand against things it can name,
quotes the source, and stops.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from engine.core.models.code import Contract, Function
from engine.core.models.evidence import Confidence, source_evidence
from engine.core.models.protocol import (
    AccountingRelation,
    Operation,
    RelationKind,
    StateItem,
    StateRole,
    StateTransition,
)
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_relationship_id

DETECTOR = "guard_constraints"

#: Comparison operators, and whether the left side is the constrained one when read as
#: written. `<` and `<=` are mirrored so `a <= b` and `b >= a` produce one record.
_MIRROR = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}

_COMPARISON = re.compile(
    r"(?P<left>[^<>=!]+?)\s*(?P<op>>=|<=|==|!=|>|<)\s*(?P<right>[^<>=!].*)"
)

#: A named reference: `deposits`, `auctionInformation_.startTime`, `debt[msg.sender]`.
#: The head is what identifies the storage; the subscript and the field do not change which
#: variable is being constrained.
_REFERENCE = re.compile(r"\b([A-Za-z_]\w*)")

#: A numeric literal, with Solidity's underscore separators and hex.
_LITERAL = re.compile(r"^(?:0x[0-9a-fA-F_]+|\d[\d_]*(?:e\d+)?)$")

#: Tokens that mean "this operand is not a storage reference": a call, a cast, a message
#: property. Kept coarse on purpose — a wrong classification here silently invents a
#: relationship, so anything unrecognised falls into `OTHER` and is dropped.
_NOT_STORAGE = ("msg.", "block.", "tx.", "address(", "type(")

MAX_RELATIONS = 120
MAX_OPERANDS = 4

#: Marks a relation whose bound is checked on the path that *writes* the variable, rather
#: than merely read on entry to some operation. The distinction decides whether a bound may
#: be stated as a standing range on the variable or only as a precondition of one function:
#: `if (auctionsInProgress > 0) revert` inside `addTranche` says nothing about what
#: `auctionsInProgress` may hold in general.
WRITE_ENFORCED = "enforced on writes through"


@dataclass(frozen=True)
class GuardRelation:
    """One comparison found in a guard, resolved onto the storage it constrains."""

    left: tuple[str, ...]
    """`state:` ProtocolIDs on the constrained side. More than one means they were summed."""
    right: tuple[str, ...]
    """`state:` ProtocolIDs on the bounding side. Empty when the bound is a literal."""
    kind: RelationKind
    expression: str
    """The guard as written. Quoted, never reconstructed."""
    operator: str = ">="
    factor: str = ""
    """A literal multiplier on the bounding side, when there is exactly one: `2`."""
    literal: str = ""
    """The bounding side when it is a constant: `10000`. Mutually exclusive with `right`."""
    left_terms: tuple[str, ...] = ()
    """Readable names for the constrained side, whether or not they resolved to storage."""
    right_terms: tuple[str, ...] = ()
    contract_id: str = ""
    function_id: str = ""
    operation_id: str = ""
    via_parameter: str = ""
    """Set when the guard constrained a parameter that the same function writes to this
    storage — the bounded-setter shape, where the range is proven only for writes through
    this path."""

    @property
    def state_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((*self.left, *self.right)))


@dataclass
class _Scope:
    """What names mean inside one contract."""

    contract: Contract
    state: dict[str, StateItem] = field(default_factory=dict)


def detect(
    index: ProtocolIndex,
    state: list[StateItem],
    operations: list[Operation],
) -> tuple[list[AccountingRelation], list[GuardRelation]]:
    """Every constraint the protocol enforces on its own storage, across all contracts.

    Reads guards from every implemented function, not only from classified entrypoints: on
    a real protocol the validation that proves a configuration range lives in an `onlyOwner`
    setter, and the accounting checks live in the internal functions the entrypoints call.
    """
    scopes = _scopes(index, state)
    operation_by_function = {o.function_id: o.id for o in operations}

    found: dict[str, GuardRelation] = {}
    for contract in index.contracts.values():
        scope = scopes.get(contract.id)
        if scope is None:
            continue
        for function in contract.functions:
            if not function.is_implemented:
                continue
            written = _written_names(function, scope)
            for guard, reverts_when_true in _guards_of(function):
                for relation in _read(
                    guard, reverts_when_true, scope, function, written
                ):
                    resolved = GuardRelation(
                        **{
                            **relation.__dict__,
                            "operation_id": operation_by_function.get(function.id, ""),
                        }
                    )
                    # First occurrence wins, so the record cites the first place the
                    # protocol enforces the rule rather than an arbitrary one.
                    found.setdefault(_key(resolved), resolved)

    ordered = sorted(found.values(), key=lambda r: (r.state_ids, r.expression))[
        :MAX_RELATIONS
    ]
    names = {item.id: item.name for item in state}
    return [_as_accounting_relation(r, names) for r in ordered], ordered


def _key(relation: GuardRelation) -> str:
    # The operator is part of the identity: an upper and a lower bound on one variable are
    # two halves of a range, not one rule seen twice.
    return "|".join(
        (
            *(relation.left or relation.left_terms),
            "::",
            *(relation.right or relation.right_terms),
            relation.kind,
            relation.operator,
            relation.literal,
        )
    )


def _scopes(index: ProtocolIndex, state: list[StateItem]) -> dict[str, _Scope]:
    """contract_id → the storage visible inside it, inheritance flattened.

    Flattened because a guard in a child reads storage declared in a parent, and a scope
    holding only locally-declared variables finds nothing on any inherited accounting.
    """
    by_contract: dict[str, dict[str, StateItem]] = {}
    for item in state:
        by_contract.setdefault(item.contract_id, {})[item.name] = item

    scopes: dict[str, _Scope] = {}
    for contract_id, contract in index.contracts.items():
        visible: dict[str, StateItem] = {}
        for ancestor_id in reversed(index.query.inheritance(contract_id)):
            visible.update(by_contract.get(ancestor_id, {}))
        if visible:
            scopes[contract_id] = _Scope(contract=contract, state=visible)
    return scopes


#: Negating a comparison. `if (x > MAX) revert` and `require(x <= MAX)` state the same rule,
#: and reading the first one literally records the exact opposite of what the code enforces.
_NEGATE = {">": "<=", ">=": "<", "<": ">=", "<=": ">", "==": "!=", "!=": "=="}


def _guards_of(function: Function) -> list[tuple[str, bool]]:
    """Conditions in this body, with whether the condition is the *failure* case.

    `require(x)` asserts `x`. `if (x) revert` asserts `not x`. Both appear constantly and
    the difference is the entire meaning: `if (cutoffTime > 64800) revert` establishes that
    `cutoffTime <= 64800`, and recording the guard as written would state the reverse of
    what the protocol enforces.

    Read off `raw` rather than through `operations.preconditions()`, which renders for a
    human — it re-prefixes `require(` and truncates — and this needs the expression.
    """
    found: list[tuple[str, bool]] = [
        (match.group(1), False) for match in _REQUIRE.finditer(function.raw)
    ]
    found.extend((match.group(1), True) for match in _IF_REVERT.finditer(function.raw))
    return found


_REQUIRE = re.compile(r"\brequire\s*\(\s*(.+?)\s*(?:,\s*\"[^\"]*\"\s*)?\)\s*;", re.S)
_IF_REVERT = re.compile(r"\bif\s*\(\s*(.+?)\s*\)\s*(?:\{\s*)?revert\b", re.S)


def _written_names(function: Function, scope: _Scope) -> dict[str, StateItem]:
    """Parameter name → the storage this function assigns it to.

    `setStartPriceMultiplier(uint16 startPriceMultiplier_)` validates the parameter and then
    writes it to `startPriceMultiplier`. A bound proven on the parameter is therefore a bound
    on the storage — but only for writes through this function, which is why the resulting
    relation records `via_parameter` and says so.

    The link is required to be structural on both sides: the trailing-underscore convention
    names the candidate, and the function must actually write that variable for it to count.
    """
    written = {name for name in scope.state if _writes(function, name)}
    mapped: dict[str, StateItem] = {}
    for param in function.params:
        if not param.name:
            continue
        target = param.name.rstrip("_")
        if target != param.name and target in written:
            mapped[param.name] = scope.state[target]
    return mapped


def _writes(function: Function, name: str) -> bool:
    return any(access.name == name for access in function.accesses if access.kind.value == "write")


def _read(
    guard: str,
    reverts_when_true: bool,
    scope: _Scope,
    function: Function,
    written: dict[str, StateItem],
) -> list[GuardRelation]:
    """Every comparison in one guard that constrains storage this contract owns."""
    inner = " ".join(guard.split())
    # `||` joins alternatives: either side may be the one that held, so neither is enforced
    # on its own and reading one as a rule would assert something the code does not.
    if "||" in inner:
        return []

    parameters = frozenset(p.name for p in function.params if p.name)
    locals_ = frozenset(_LOCAL.findall(function.raw))

    found: list[GuardRelation] = []
    for clause in inner.split("&&"):
        match = _COMPARISON.search(clause)
        if match is None:
            continue
        operator = match.group("op")
        if reverts_when_true:
            operator = _NEGATE[operator]
        # `!=` is a disequality, not an ordering or an equality. It appears almost entirely
        # in authorization (`msg.sender != owner`), which the permission pass handles.
        if operator == "!=":
            continue

        left = _operands(match.group("left"), scope, written, parameters, locals_)
        right = _operands(match.group("right"), scope, written, parameters, locals_)
        if left is None or right is None:
            continue

        relation = _relate(left, right, operator, inner, scope, function)
        if relation is not None:
            found.append(relation)
    return found


@dataclass(frozen=True)
class _Side:
    """One side of a comparison, classified."""

    items: tuple[StateItem, ...]
    literal: str
    factor: str
    via_parameter: str
    terms: tuple[str, ...] = ()
    """Names this side denotes when they are *not* storage: `totalDebtUsd` from
    `account.totalDebtUsd`, or a declared local. Populated alongside `items` when the side
    mixes both, and alone when the side is entirely local."""

    @property
    def named(self) -> tuple[str, ...]:
        return (*(item.name for item in self.items), *self.terms)


#: `DataTypes.AccountData memory account = …` / `uint256 balance = …` — a local declaration.
#: Only used to establish that an identifier is a local of *this* function, so that a guard
#: mentioning it is a guard about something nameable rather than something unresolved.
_LOCAL = re.compile(
    r"^\s*(?:[A-Za-z_][\w.\[\]]*)\s+(?:memory|storage|calldata\s+)?\s*"
    r"([a-z_]\w*)\s*=",
    re.M,
)

#: `account.totalDebtUsd` — a field read off a local struct. The *field* is the name that
#: carries the meaning; `account` is a temporary.
_FIELD = re.compile(r"^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$")

#: Terms that read as an amount of value rather than an index, id or flag. Used only to pick
#: the invariant's *kind*, never to decide whether the relation exists.
_VALUE_TERMS = (
    "debt",
    "collateral",
    "borrow",
    "supply",
    "balance",
    "liquidity",
    "limit",
    "amount",
    "shares",
    "assets",
    "value",
    "usd",
)


def _operands(
    side: str,
    scope: _Scope,
    written: dict[str, StateItem],
    parameters: frozenset[str],
    locals_: frozenset[str],
) -> _Side | None:
    """Classify one side, or `None` when it contains something unrecognised.

    Returning `None` rather than a best guess is the whole safety property: an operand this
    pass cannot name is an operand it must not relate.
    """
    text = side.strip().strip("()")
    if not text:
        return None
    if any(token in text for token in _NOT_STORAGE):
        # A subscript by `msg.sender` is normal and does not disqualify the operand — it is
        # the same storage viewed per account. Anything else opaque does.
        text = re.sub(r"\[[^\]]*\]", "", text)
        if any(token in text for token in _NOT_STORAGE):
            return None
    if "(" in text:
        # A call result. Its value is not storage, and treating it as such would attach a
        # rule to the wrong thing.
        return None

    if _LITERAL.match(text.replace(" ", "")):
        return _Side((), text.replace("_", "").replace(" ", ""), "", "")

    # `account.totalDebtUsd` — a field read off a local struct. This is where a real
    # protocol keeps the quantities its core invariants are about: the health check in a
    # lending pool compares two fields of an in-memory `AccountData`, never two storage
    # slots. Requiring storage on both sides made the pass blind to exactly the rule that
    # matters most. The receiver must be a declared local of this function, so the name is
    # established rather than assumed.
    field = _FIELD.match(text)
    if field is not None and field.group(1) in locals_:
        return _Side((), "", "", "", (field.group(2),))

    # A bare local: `if (withdrawAmount > balance) revert`. Both names are declared in this
    # body, so the rule "a withdrawal may not exceed the balance" is nameable and quoted
    # even though neither side is a storage slot. Restricted to *declared* locals — an
    # unknown identifier is still refused.
    if text in locals_:
        return _Side((), "", "", "", (text,))

    items: list[StateItem] = []
    factor = ""
    via = ""
    for token in _REFERENCE.findall(re.sub(r"\[[^\]]*\]", "", text)):
        if token in written:
            # A parameter this function validates and then stores. The bound proven on it
            # is a bound on that storage, for writes through this path.
            items.append(written[token])
            via = token
        elif token in scope.state:
            items.append(scope.state[token])
        elif token in parameters:
            # A declared parameter of this function. Not storage, but *known* — so a term
            # like `- amount` does not stop us relating the storage on either side of the
            # comparison. The verbatim guard is on the evidence, so the parameter is not
            # lost; it just is not something this protocol has a standing rule about.
            continue
        else:
            # A local, a constant from elsewhere, a type keyword — something this pass
            # cannot name. Relating operands it cannot identify is how a pass invents.
            return None

    for number in re.findall(r"(?<![\w.])(\d[\d_]*)(?![\w.])", text):
        factor = number.replace("_", "")

    # Deduplicate by ID: `StateItem` is a Pydantic model and is not hashable, and the same
    # variable can legitimately appear twice on one side (`deposits[a] - deposits[b]`).
    unique = list({item.id: item for item in items}.values())
    if not unique or len(unique) > MAX_OPERANDS:
        return None
    return _Side(tuple(unique), "", factor, via)


def _relate(
    left: _Side,
    right: _Side,
    operator: str,
    expression: str,
    scope: _Scope,
    function: Function,
) -> GuardRelation | None:
    """Turn two classified sides into one directed relation, or nothing."""
    # Orientation is decided by which side names storage, not by the operator. Mirroring
    # unconditionally on `<`/`<=` moved the constrained variable onto the empty side of
    # `cutoffTime <= 64800` and dropped the whole upper half of every configured range.
    if not left.named and right.named:
        left, right = right, left
        operator = _MIRROR[operator]
    elif left.named and right.named and operator in ("<", "<="):
        # Both sides name storage, so either reading is valid; normalise to the `>=` form
        # so `a <= b` and `b >= a` produce one record rather than two.
        left, right = right, left
        operator = _MIRROR[operator]

    if not left.named:
        # Neither side named anything. Nothing about this protocol is being said.
        return None

    kind = RelationKind.EQUALITY if operator == "==" else RelationKind.BOUND
    if not right.named and not right.literal:
        return None
    if left.named == right.named:
        return None

    return GuardRelation(
        left=tuple(item.id for item in left.items),
        right=tuple(item.id for item in right.items),
        left_terms=left.named,
        right_terms=right.named,
        kind=kind,
        expression=expression[:200],
        operator=operator,
        factor=right.factor,
        literal=right.literal,
        contract_id=scope.contract.id,
        function_id=function.id,
        via_parameter=left.via_parameter or right.via_parameter,
    )


def _rule_text(relation: GuardRelation, names: dict[str, str]) -> str:
    """The rule the guard establishes, normalised: `cutoffTime <= 64800`.

    Not the guard as written. `if (cutoffTime_ > 64_800) revert` establishes the *opposite*
    of its own condition, and the operator here has already been negated and mirrored, so
    the raw text would contradict it. The verbatim guard is not lost — it is the evidence
    excerpt on this relation, which is where a quotation belongs.
    """
    left = " + ".join(relation.left_terms) or " + ".join(
        names.get(i, i) for i in relation.left
    )
    if relation.right_terms or relation.right:
        right = " + ".join(relation.right_terms) or " + ".join(
            names.get(i, i) for i in relation.right
        )
        if relation.factor:
            right = f"{right} * {relation.factor}"
    else:
        right = relation.literal
    return f"{left} {relation.operator} {right}"


def _as_accounting_relation(
    relation: GuardRelation, names: dict[str, str]
) -> AccountingRelation:
    return AccountingRelation(
        # The operator and the bound are part of the identity: `cutoffTime >= 3600` and
        # `cutoffTime <= 64800` constrain one variable and are two distinct rules.
        id=make_relationship_id(
            f"{relation.kind.value}{relation.operator}{relation.literal}",
            list(relation.state_ids)
            or [relation.function_id, *relation.left_terms, *relation.right_terms],
        ),
        kind=relation.kind,
        expression=_rule_text(relation, names),
        # Order carries meaning — `a >= b` is not `b >= a` — so this list is deliberately
        # not sorted. Downstream phrasing reads position 0 as the constrained side.
        state_ids=list(relation.state_ids),
        holds_when=(
            f"{WRITE_ENFORCED} {_name_of(relation.function_id)}"
            if relation.via_parameter
            else f"enforced on entry to {_name_of(relation.function_id)}"
        ),
        # `DERIVED`: quoted from a condition that reverts, not inferred from naming. Not
        # `STATED` — nobody documented it as a rule the protocol promises.
        confidence=Confidence.DERIVED,
        evidence=[
            source_evidence(
                relation.function_id, relation.expression, detector=DETECTOR
            )
        ],
    )


def _name_of(function_id: str) -> str:
    return function_id.rpartition(":")[2] or function_id


# ── Conservation ──────────────────────────────────────────────────────────────


def conservation(
    state: list[StateItem], transitions: list[StateTransition]
) -> list[AccountingRelation]:
    """`totalDeposits == Σ deposits[account]`, where the code moves the two in lockstep.

    The evidence is a *complete* correspondence, not a resemblance in the names. A scalar
    total and a per-account mapping in the same contract are paired only when every
    operation that changes one changes the other in the same direction, and neither is ever
    written alone. One operation that touches the mapping without the total is exactly the
    case where the sum does not hold, so it disqualifies the pairing rather than being
    averaged away.
    """
    state_by_id = {item.id: item for item in state}

    moves: dict[str, dict[str, str]] = {}
    for transition in transitions:
        if transition.effect not in ("increase", "decrease"):
            continue
        moves.setdefault(transition.state_id, {})[transition.operation_id] = (
            transition.effect
        )

    found: list[AccountingRelation] = []
    for total_id, total_moves in sorted(moves.items()):
        total = state_by_id.get(total_id)
        if total is None or not _is_scalar_total(total):
            continue

        for mapping_id, mapping_moves in sorted(moves.items()):
            item = state_by_id.get(mapping_id)
            if item is None or item.contract_id != total.contract_id:
                continue
            if not _is_per_account(item) or mapping_moves != total_moves:
                continue

            expression = f"{total.name} == sum({item.name}[account])"
            found.append(
                AccountingRelation(
                    id=make_relationship_id(
                        RelationKind.SUM.value, [total.id, item.id]
                    ),
                    kind=RelationKind.SUM,
                    expression=expression,
                    state_ids=[total.id, item.id],
                    holds_when="every operation that writes one writes the other",
                    # Observed over every recorded write of both variables, not inferred
                    # from the `total` prefix. A single unmatched write disqualifies above.
                    confidence=Confidence.DERIVED,
                    evidence=[
                        source_evidence(
                            total.state_var_id,
                            f"{total.name} and {item.name} change together under "
                            f"{len(total_moves)} operations",
                            detector=DETECTOR,
                        )
                    ],
                )
            )
    return found


def _is_scalar_total(item: StateItem) -> bool:
    return "mapping" not in item.type and item.role is StateRole.ACCOUNTING_TOTAL


def _is_per_account(item: StateItem) -> bool:
    return item.type.startswith("mapping") and "address" in item.type


__all__ = ["DETECTOR", "GuardRelation", "conservation", "detect"]
