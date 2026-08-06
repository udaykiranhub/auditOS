"""Node construction, plus the structural `CONTAINS` / `DECLARES` skeleton.

Every node ID is a `SolidityID` (§7.2) so the graph joins the rest of the spine without a
translation table. The two sentinels are the only exception, and they are prefixed with `@`
precisely so they can never collide with a real path-derived ID.
"""

from __future__ import annotations

from engine.core.models.code import (
    CodeModel,
    Contract,
    ContractKind,
    Function,
    FunctionKind,
)
from engine.core.models.graph import (
    UNKNOWN_EXTERNAL,
    UNTRUSTED_EXTERNAL,
    Edge,
    EdgeKind,
    Node,
    NodeKind,
)
from engine.core.models.ids import make_contract_id, make_modifier_id, make_state_var_id

_CONTRACT_NODE_KIND = {
    ContractKind.CONTRACT: NodeKind.CONTRACT,
    ContractKind.ABSTRACT: NodeKind.CONTRACT,
    ContractKind.INTERFACE: NodeKind.INTERFACE,
    ContractKind.LIBRARY: NodeKind.LIBRARY,
}


def sentinel_nodes() -> list[Node]:
    return [
        Node(
            id=UNTRUSTED_EXTERNAL,
            kind=NodeKind.SENTINEL,
            name="UNTRUSTED_EXTERNAL",
            type="low-level call / delegatecall / staticcall — untrusted code runs here",
        ),
        Node(
            id=UNKNOWN_EXTERNAL,
            kind=NodeKind.SENTINEL,
            name="UNKNOWN_EXTERNAL",
            type="typed external call whose target is not in this repository",
        ),
    ]


def build_nodes(code: CodeModel, included: set[str]) -> tuple[list[Node], list[Edge]]:
    """Nodes for every selected contract's members, plus their containment edges."""
    nodes: list[Node] = sentinel_nodes()
    edges: list[Edge] = []

    paths = {contract.path for contract in code.contracts if contract.id in included}
    for source in code.sources:
        if source.path not in paths and not source.in_scope:
            continue
        nodes.append(
            Node(
                id=source.path,
                kind=NodeKind.FILE,
                name=source.path.rpartition("/")[2],
                path=source.path,
                in_scope=source.in_scope,
            )
        )

    for contract in code.contracts:
        if contract.id not in included:
            continue
        nodes.append(_contract_node(contract))
        if contract.path in paths:
            edges.append(
                Edge(
                    source=contract.path,
                    target=contract.id,
                    kind=EdgeKind.CONTAINS,
                    line=contract.line_start,
                )
            )
        _add_members(contract, nodes, edges)

    # File-level functions (Solidity >= 0.7). A contract can call one, so it must be a node
    # or the edge terminates nowhere.
    for source in code.sources:
        if source.path not in paths and not source.in_scope:
            continue
        for function in source.free_functions:
            nodes.append(function_node(function))
            edges.append(
                Edge(
                    source=source.path,
                    target=function.id,
                    kind=EdgeKind.CONTAINS,
                    line=function.line_start,
                )
            )

    return nodes, edges


def _contract_node(contract: Contract) -> Node:
    return Node(
        id=contract.id,
        kind=_CONTRACT_NODE_KIND.get(contract.kind, NodeKind.CONTRACT),
        name=contract.name,
        path=contract.path,
        line=contract.line_start,
        type=contract.kind.value,
        in_scope=contract.in_scope,
        is_dependency=contract.is_dependency,
    )


def _add_members(contract: Contract, nodes: list[Node], edges: list[Edge]) -> None:
    def contained(target: str, line: int) -> None:
        edges.append(
            Edge(source=contract.id, target=target, kind=EdgeKind.CONTAINS, line=line)
        )

    for function in contract.functions:
        nodes.append(function_node(function, contract))
        contained(function.id, function.line_start)

    for modifier in contract.modifiers:
        nodes.append(function_node(modifier, contract, kind=NodeKind.MODIFIER))
        contained(modifier.id, modifier.line_start)

    for state_var in contract.state_vars:
        nodes.append(
            Node(
                id=state_var.id,
                kind=NodeKind.STATE_VAR,
                name=state_var.name,
                path=contract.path,
                contract_id=contract.id,
                line=state_var.line,
                visibility=state_var.visibility,
                type=state_var.type,
                slot=state_var.slot,
                in_scope=contract.in_scope,
                is_dependency=contract.is_dependency,
            )
        )
        contained(state_var.id, state_var.line)

    for event in contract.events:
        nodes.append(
            Node(
                id=_event_id(contract, event.name),
                kind=NodeKind.EVENT,
                name=event.name,
                path=contract.path,
                contract_id=contract.id,
                line=event.line,
                in_scope=contract.in_scope,
                is_dependency=contract.is_dependency,
            )
        )
        contained(_event_id(contract, event.name), event.line)

    for error in contract.errors:
        nodes.append(
            Node(
                id=_error_id(contract, error.name),
                kind=NodeKind.ERROR,
                name=error.name,
                path=contract.path,
                contract_id=contract.id,
                line=error.line,
                in_scope=contract.in_scope,
                is_dependency=contract.is_dependency,
            )
        )
        contained(_error_id(contract, error.name), error.line)


def function_node(
    function: Function,
    contract: Contract | None = None,
    kind: NodeKind = NodeKind.FUNCTION,
) -> Node:
    if function.kind is FunctionKind.MODIFIER:
        kind = NodeKind.MODIFIER
    return Node(
        id=function.id,
        kind=kind,
        name=function.name,
        path=contract.path if contract else "",
        contract_id=function.contract_id,
        line=function.line_start,
        visibility=function.visibility,
        mutability=function.mutability,
        in_scope=contract.in_scope if contract else True,
        is_dependency=contract.is_dependency if contract else False,
        is_entrypoint=function.is_entrypoint,
        is_implemented=function.is_implemented,
        has_assembly=function.has_assembly,
    )


# Events and errors are not addressed by SPEC §7.2 — it defines IDs for contracts,
# functions, state variables and modifiers. `Contract#Event` extends the state-var form
# rather than inventing a fourth separator, and stays unambiguous because Solidity forbids
# an event and a state variable sharing a name in one contract.
def _event_id(contract: Contract, name: str) -> str:
    return make_state_var_id(contract.path, contract.name, name)


def _error_id(contract: Contract, name: str) -> str:
    return f"{make_contract_id(contract.path, contract.name)}!{name}"


def modifier_id(contract: Contract, name: str) -> str:
    return make_modifier_id(contract.path, contract.name, name)
