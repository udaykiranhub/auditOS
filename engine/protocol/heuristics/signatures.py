"""Shared index every detector reads from — built once, queried many times.

Each of stages 1–15 needs the same handful of questions answered: what does this contract
expose, what does this function's name look like, what does it inherit from, what modifiers
guard it. Recomputing that per detector is both slow and — worse — an invitation for two
detectors to answer the same question differently, which produces a `ProtocolModel` that
contradicts itself.

**The signature index is the load-bearing piece.** Solidity's dispatch is
inheritance-flattened: a contract that inherits `ERC20` exposes `transfer(address,uint256)`
even though its own body defines nothing. A standards detector that looks only at
`contract.functions` reports `ABSENT` for every OpenZeppelin-based token in existence. So
`exposed()` walks the C3 linearization the Graph Engine already computed, and every detector
that asks "does this contract have X" gets the flattened answer.
"""

from __future__ import annotations

import re
from functools import cached_property

from engine.core.models.code import (
    CodeModel,
    Contract,
    ContractKind,
    Function,
    FunctionKind,
    Param,
    StateVar,
)
from engine.core.models.graph import Edge, EdgeKind, GraphModel
from engine.graphs.query import GraphQuery

#: Modifier names that conventionally gate an admin-only path. Name-based, so this only ever
#: produces `INFERRED` claims — it is a starting point for the Access Control agent, never a
#: conclusion. `onlyRole(...)` is matched by prefix because the argument varies per protocol.
PRIVILEGED_MODIFIERS = (
    "onlyowner",
    "onlyadmin",
    "onlygovernance",
    "onlygovernor",
    "onlyguardian",
    "onlyauthorized",
    "onlyrole",
    "onlykeeper",
    "onlyoperator",
    "onlymanager",
    "onlyminter",
    "onlypauser",
    "onlystrategist",
    "onlytimelock",
    "onlyfactory",
    "onlyself",
    "onlyproxy",
    "requiresauth",
    "auth",
    "restricted",
)

#: Names whose presence in a contract or file name means "not the protocol".
NON_PROTOCOL_HINTS = ("mock", "test", "harness", "stub", "fake", "echidna", "invariant")


def camel_tokens(name: str) -> list[str]:
    """`batchProcessDeposit` → `["batch", "process", "deposit"]`.

    Solidity names are camelCase by universal convention, so the word boundaries are
    recoverable — and recovering them is what separates a real signal from a coincidence.
    Naive substring matching reads `getUsdValueExposureToUnderlyingAssetAfterDeposit` as a
    deposit function; on Arcadia that made every valuation module score as a vault, which
    then propagated into its assets, its invariants and its risk surfaces.
    """
    return [token for token in _TOKEN_SPLIT.findall(name) if token]


def has_token(name: str, needle: str) -> bool:
    """Does `name` contain `needle` as a whole word (or run of words)?

    `has_token("batchProcessDeposit", "deposit")` is True; `has_token("assetModule",
    "asset")` is True; `has_token("assetToAssetInformation", "asset")` is True — all
    correct, because `asset` really is a word there. What it rejects is `has_token("index",
    "de")` and, crucially, the accidental matches inside longer words.
    """
    tokens = _folded(name)
    needle_tokens = _folded(needle)
    if not needle_tokens:
        return False
    span = len(needle_tokens)
    return any(
        tokens[i : i + span] == needle_tokens for i in range(len(tokens) - span + 1)
    )


def starts_with_token(name: str, needle: str) -> bool:
    """Whole-word prefix. `withdrawAll` starts with `withdraw`; `withdrawnAt` does not.

    Prefix position carries meaning that mere presence does not: a function *named for*
    an action performs it, while one that merely mentions it usually reports on it —
    `getUsdValueAfterDeposit` is a view about deposits, not a deposit.
    """
    tokens = _folded(name)
    needle_tokens = _folded(needle)
    return bool(needle_tokens) and tokens[: len(needle_tokens)] == needle_tokens


def _folded(name: str) -> list[str]:
    """Tokens, case-folded for comparison.

    `camel_tokens` preserves case because it is a tokenizer and the original spelling is
    what a reader recognizes. Matching folds, because `Deposit` and `deposit` are the same
    word and only the boundary between words carries meaning here.
    """
    return [token.lower() for token in camel_tokens(name)]


_TOKEN_SPLIT = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+")

#: Edge kinds whose target is a callee. `MODIFIED_BY` is excluded: a modifier is applied to
#: a function, not called from a position in its body, so it has no order to join on.
_CALL_EDGE_KINDS = frozenset(
    {
        EdgeKind.CALLS,
        EdgeKind.DELEGATECALLS,
        EdgeKind.STATICCALLS,
        EdgeKind.CREATES,
    }
)


def signature_of(function: Function) -> str:
    """`deposit(uint256,address)` — the canonical form standards are declared in."""
    return f"{function.name}({','.join(param.type for param in function.params)})"


def return_signature(function: Function) -> str:
    """`(uint256)` — needed because ERC-20's `transfer` must return `bool`, and a token
    whose `transfer` returns nothing is the single most common integration hazard."""
    return f"({','.join(param.type for param in function.returns)})"


class ProtocolIndex:
    """Everything the detectors need about one repository, computed once.

    Holds `RepoModel`-free state on purpose: documentation lives on `RepoModel` and is read
    by exactly one stage (§14), so making every detector carry it would be noise.
    """

    def __init__(self, code: CodeModel, graph: GraphModel):
        self.code = code
        self.graph = graph
        self.query = GraphQuery(graph)
        self.contracts: dict[str, Contract] = {c.id: c for c in code.contracts}

    # ── Scope ─────────────────────────────────────────────────────────────────

    @cached_property
    def audited(self) -> list[Contract]:
        """Contracts worth interpreting: in scope, implemented, not a mock or a test.

        Interfaces are excluded here and handled separately — an interface tells us what a
        *dependency* looks like (stage 11), not what this protocol does. Classifying
        `IERC20` as a token role would put a role record on every import in the repo.
        """
        return [
            contract
            for contract in self.code.in_scope_contracts
            if contract.kind in (ContractKind.CONTRACT, ContractKind.ABSTRACT)
            and not self.is_non_protocol(contract)
        ]

    @cached_property
    def interfaces(self) -> list[Contract]:
        return [c for c in self.code.contracts if c.kind is ContractKind.INTERFACE]

    def is_non_protocol(self, contract: Contract) -> bool:
        """Mock and test contracts contain deliberately broken code and attack payloads.

        The Reader already flags files (SPEC §9.3); this catches a `MockOracle` declared
        inside an otherwise in-scope file, which the path-based check cannot see.
        """
        haystack = f"{contract.name} {contract.path}".lower()
        return any(hint in haystack for hint in NON_PROTOCOL_HINTS)

    # ── Inheritance-flattened members ─────────────────────────────────────────

    @cached_property
    def _exposed(self) -> dict[str, dict[str, Function]]:
        """contract_id → signature → the *most derived* definition, over the C3 MRO.

        Most-derived wins because that is what Solidity dispatches to. Taking the base
        definition would report an overridden `transfer` as OpenZeppelin's, hiding exactly
        the modification an auditor cares about.
        """
        flattened: dict[str, dict[str, Function]] = {}
        for contract in self.code.contracts:
            members: dict[str, Function] = {}
            # Reversed MRO: least-derived first, so more-derived definitions overwrite.
            for ancestor_id in reversed(self.query.inheritance(contract.id)):
                ancestor = self.contracts.get(ancestor_id)
                if ancestor is None:
                    continue
                for function in ancestor.functions:
                    if function.kind is FunctionKind.FUNCTION:
                        members[signature_of(function)] = function
                # A public state variable is a getter as far as an interface is concerned:
                # OpenZeppelin's `totalSupply` is a function, Solmate's is a public var.
                # Missing this reports every Solmate token as ERC-20 non-compliant.
                for variable in ancestor.state_vars:
                    if variable.visibility == "public":
                        getter = _getter_of(variable, ancestor)
                        members.setdefault(signature_of(getter), getter)
            flattened[contract.id] = members
        return flattened

    def exposed(self, contract_id: str) -> dict[str, Function]:
        """Every callable member of a contract, inheritance flattened."""
        return self._exposed.get(contract_id, {})

    def has(self, contract_id: str, *signatures: str) -> bool:
        members = self.exposed(contract_id)
        return all(signature in members for signature in signatures)

    def present(self, contract_id: str, signatures: tuple[str, ...]) -> list[str]:
        members = self.exposed(contract_id)
        return [signature for signature in signatures if signature in members]

    def missing(self, contract_id: str, signatures: tuple[str, ...]) -> list[str]:
        members = self.exposed(contract_id)
        return [signature for signature in signatures if signature not in members]

    @cached_property
    def _state_vars(self) -> dict[str, dict[str, StateVar]]:
        """contract_id → name → declaration, inheritance flattened.

        Storage is inherited too, and a vault whose `totalAssets` is declared in a base
        contract is still a vault.
        """
        flattened: dict[str, dict[str, StateVar]] = {}
        for contract in self.code.contracts:
            members: dict[str, StateVar] = {}
            for ancestor_id in reversed(self.query.inheritance(contract.id)):
                ancestor = self.contracts.get(ancestor_id)
                if ancestor is not None:
                    members.update({v.name: v for v in ancestor.state_vars})
            flattened[contract.id] = members
        return flattened

    def state_vars(self, contract_id: str) -> dict[str, StateVar]:
        return self._state_vars.get(contract_id, {})

    def ancestors(self, contract_id: str) -> set[str]:
        """Every ancestor name as written, lowercased — for `is Ownable`-style detection."""
        names: set[str] = set()
        for ancestor_id in self.query.inheritance(contract_id):
            ancestor = self.contracts.get(ancestor_id)
            if ancestor is not None:
                names.add(ancestor.name.lower())
                names.update(parent.lower() for parent in ancestor.inherits)
        return names

    def inherits_name(self, contract_id: str, *needles: str) -> bool:
        """True when any ancestor's name contains one of `needles`.

        Substring rather than equality: `ERC20Upgradeable`, `ERC20Permit` and `ERC20Burnable`
        are all ERC-20, and enumerating every vendor's naming convention is a losing game.
        """
        ancestors = self.ancestors(contract_id)
        return any(needle in name for name in ancestors for needle in needles)

    # ── Functions ─────────────────────────────────────────────────────────────

    @cached_property
    def functions(self) -> dict[str, Function]:
        return {
            function.id: function
            for contract in self.code.contracts
            for function in (*contract.functions, *contract.modifiers)
        }

    def entrypoints_of(self, contract: Contract) -> list[Function]:
        """The externally reachable surface an actor can call on a live contract.

        Constructors are excluded: they run once at deployment, before any actor exists, so
        modelling one as an operation puts a phantom `UNKNOWN` action on every contract and
        attributes its state writes to a caller who cannot exist.
        """
        return [
            function
            for function in contract.functions
            if function.is_entrypoint
            and function.is_implemented
            and function.kind
            not in (FunctionKind.MODIFIER, FunctionKind.CONSTRUCTOR)
        ]

    def is_privileged(self, function: Function) -> bool:
        """Whether *something* gates this function against an arbitrary caller.

        Modifier-name based, so `INFERRED` only. A false negative here is a function that
        looks permissionless and is not; a false positive is a function that looks guarded
        and is not. Both are handed to the Access Control agent to settle, which is why
        `Capability.gated_by` carries the modifier names rather than just a boolean.
        """
        return bool(self.guards(function))

    def guards(self, function: Function) -> list[str]:
        return privileged_names(function.modifiers)

    def is_view(self, function: Function) -> bool:
        return function.mutability in ("view", "pure")

    @cached_property
    def modifier_table(self) -> dict[str, dict[str, Function]]:
        """contract_id → modifier name → its definition, inheritance flattened.

        Flattened because `onlyOwner` is almost never declared on the contract that uses it,
        and a table that only knows about locally-declared modifiers finds nothing on any
        OpenZeppelin-based protocol.

        Lives here rather than in a stage because two stages need the same answer: the
        behaviour pass, to decide whether a modifier actually gates a caller, and the
        permission pass, to read the check out of its body. Two copies of this table are two
        chances for one artifact to describe the same modifier in contradictory ways.
        """
        table: dict[str, dict[str, Function]] = {}
        for contract in self.code.contracts:
            found: dict[str, Function] = {}
            for ancestor_id in reversed(self.query.inheritance(contract.id)):
                ancestor = self.contracts.get(ancestor_id)
                if ancestor is not None:
                    found.update({m.name: m for m in ancestor.modifiers})
            table[contract.id] = found
        return table

    @cached_property
    def libraries_by_name(self) -> dict[str, Contract]:
        """Every in-repo `library`, by bare name. Receivers of `SafeCastLib.toUint128(x)`."""
        return {
            contract.name: contract
            for contract in self.code.contracts
            if contract.kind is ContractKind.LIBRARY
        }

    def bound_library_members(self, contract_id: str) -> frozenset[str]:
        """Function names reachable through `using L for T` on this contract or an ancestor.

        `amount.mulDivUp(x, y)` is syntactically indistinguishable from an external call on
        an address, and typing it as one puts a phantom trust-boundary crossing in the middle
        of every accounting function in the repository. The `using` directive is the evidence
        that the receiver is a value and the callee is in-frame.
        """
        members: set[str] = set()
        for ancestor_id in self.query.inheritance(contract_id):
            ancestor = self.contracts.get(ancestor_id)
            if ancestor is None:
                continue
            for directive in ancestor.using_for:
                library = self.libraries_by_name.get(directive.library)
                if library is not None:
                    members.update(f.name for f in library.functions)
        return frozenset(members)

    # ── Graph shortcuts ───────────────────────────────────────────────────────

    @cached_property
    def token_edges_by_function(self) -> dict[str, list[tuple[EdgeKind, str, str, int]]]:
        """function_id → [(kind, receiver-or-target, text, line)] for token-flow edges.

        Signature-derived by the Graph Engine (`graphs/tokens.py`), so this is a fact about
        what the code calls, not an interpretation of what it means.
        """
        flows: dict[str, list[tuple[EdgeKind, str, str, int]]] = {}
        for edge in self.query.token_flows():
            flows.setdefault(edge.source, []).append(
                (edge.kind, edge.via or edge.target, edge.text, edge.line)
            )
        return flows

    @cached_property
    def call_targets_by_order(self) -> dict[str, dict[int, str]]:
        """function_id → {call order → resolved target}.

        `order` is the one field a `CallSite` and its `Edge` are guaranteed to share, so it
        is how the parser's ordered body and the graph's resolved targets are joined. Built
        once for the whole repository: doing it per function turns the behaviour stage
        quadratic on anything with a few thousand call sites.
        """
        joined: dict[str, dict[int, str]] = {}
        for edge in self.graph.edges:
            if edge.kind in _CALL_EDGE_KINDS and edge.order >= 0:
                joined.setdefault(edge.source, {}).setdefault(edge.order, edge.target)
        return joined

    @cached_property
    def call_edges_by_contract(self) -> dict[str, list[Edge]]:
        """declaring contract_id → every outgoing call edge from its functions.

        The rollup the cross-contract relationship stage needs. Grouped once because the
        alternative — scanning `graph.edges` per contract — is quadratic, and a real
        protocol has six figures of edges.
        """
        grouped: dict[str, list[Edge]] = {}
        for edge in self.graph.edges:
            if edge.kind not in _CALL_EDGE_KINDS:
                continue
            function = self.functions.get(edge.source)
            if function is None or function.contract_id is None:
                continue
            grouped.setdefault(function.contract_id, []).append(edge)
        for edges in grouped.values():
            edges.sort(key=lambda edge: edge.key())
        return grouped

    @cached_property
    def token_targets_by_order(self) -> dict[str, dict[int, str]]:
        """function_id → {call order → the token or receiver a movement went through}."""
        joined: dict[str, dict[int, str]] = {}
        for edge in self.query.token_flows():
            if edge.order >= 0:
                joined.setdefault(edge.source, {}).setdefault(
                    edge.order, edge.via or edge.target
                )
        return joined

    @cached_property
    def contract_rank(self) -> dict[str, float]:
        return self.query.contract_centrality()

    def centrality_of(self, contract_id: str) -> float:
        return self.contract_rank.get(contract_id, 0.0)


def _getter_of(variable: StateVar, contract: Contract) -> Function:
    """Synthesize the implicit getter a public state variable compiles to.

    Not a fiction: solc really does emit this function, and it really does satisfy an
    interface requirement. Modelling it is what makes Solmate-style tokens detectable.

    The parameters matter as much as the return: `mapping(address => uint256) balanceOf`
    compiles to `balanceOf(address)`, not `balanceOf()`. Getting that wrong would make
    every ERC-20 check miss `balanceOf(address)` and `allowance(address,address)` — the
    two members most likely to be declared as public mappings.
    """
    params, return_type = _getter_shape(variable.type)
    return Function(
        id=f"{contract.id}.{variable.name}({','.join(params)})",
        name=variable.name,
        contract_id=contract.id,
        visibility="public",
        mutability="view",
        params=[_param(type_name) for type_name in params],
        returns=[_param(return_type)],
        line_start=variable.line,
        line_end=variable.line,
    )


def _getter_shape(type_name: str) -> tuple[list[str], str]:
    """`mapping(address => mapping(address => uint256))` → `(["address","address"], "uint256")`.

    Unwraps nested mappings and arrays the way solc does when it generates the accessor.
    """
    params: list[str] = []
    current = type_name.strip()
    while True:
        if current.startswith("mapping"):
            inner = current[current.find("(") + 1 : current.rfind(")")]
            key, _, value = inner.partition("=>")
            params.append(_key_type(key.strip()))
            current = value.strip()
        elif current.endswith("]"):
            params.append("uint256")  # array index
            current = current[: current.rfind("[")].strip()
        else:
            return params, current


def _key_type(key: str) -> str:
    """A mapping key declaration may carry a name: `mapping(address owner => uint256)`."""
    return key.split()[0] if key else key


def _param(type_name: str) -> Param:
    return Param(type=type_name)


def _normalize(name: str) -> str:
    return name.lower().replace("_", "")


def privileged_names(modifiers: list[str]) -> list[str]:
    """Those of `modifiers` whose *name* matches the conventional admin vocabulary.

    Name-based, so `INFERRED` at best, and blind to protocol-specific guards like
    `onlyTranche`. Callers that can read modifier bodies should do so as well — see
    `behaviour._guards`.
    """
    return sorted({m for m in modifiers if _normalize(m).startswith(PRIVILEGED_MODIFIERS)})


__all__ = [
    "NON_PROTOCOL_HINTS",
    "PRIVILEGED_MODIFIERS",
    "ProtocolIndex",
    "camel_tokens",
    "has_token",
    "privileged_names",
    "return_signature",
    "signature_of",
    "starts_with_token",
]
