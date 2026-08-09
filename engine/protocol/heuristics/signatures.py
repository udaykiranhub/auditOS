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
from engine.core.models.graph import EdgeKind, GraphModel
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
        return sorted(
            {
                modifier
                for modifier in function.modifiers
                if _normalize(modifier).startswith(PRIVILEGED_MODIFIERS)
            }
        )

    def is_view(self, function: Function) -> bool:
        return function.mutability in ("view", "pure")

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


__all__ = [
    "NON_PROTOCOL_HINTS",
    "PRIVILEGED_MODIFIERS",
    "ProtocolIndex",
    "return_signature",
    "signature_of",
]
