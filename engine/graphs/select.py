"""Which contracts enter the graph (SPEC §13, *Performance*).

> "Fine on NetworkX to ~5k nodes. If a monorepo blows past that, filter to in-scope + their
> transitive parents **before** graphing, not after."

This is not an optimization detail — it decides correctness of the answers above. A real
protocol parses to thousands of contracts of which a hundred are audited; graphing all of
them buries every query in OpenZeppelin. But filtering to *only* in-scope code breaks
inheritance resolution the moment a contract extends `ERC20`, so the closure below pulls in
exactly the dependency code the in-scope code needs:

1. every in-scope contract — the seed;
2. their transitive parents — without these, `super.f()` and inherited members vanish;
3. libraries reachable through `using L for T` — library calls resolve through them;
4. contracts referenced by declared type — `IVault vault` needs `IVault` present;
5. implementers of any interface already included — SPEC §13.2's interface fan-out, capped.
"""

from __future__ import annotations

from engine.core.models.code import CodeModel, Contract, ContractKind
from engine.core.models.graph import Unresolved

#: How many implementers one interface may fan out to. `IERC20` has hundreds in a monorepo
#: and each is a low-confidence edge; past a couple of dozen the fan-out is noise that
#: crowds out the signal, so it is capped and the cap is reported rather than hidden.
MAX_INTERFACE_FANOUT = 24


def select_contracts(code: CodeModel) -> tuple[set[str], list[Unresolved], list[str]]:
    """Return ``(contract_ids, unresolved, notes)`` — the closure described above."""
    contracts = {contract.id: contract for contract in code.contracts}
    notes: list[str] = []
    unresolved: list[Unresolved] = []

    seeds = {contract.id for contract in code.contracts if contract.in_scope}
    if not seeds:
        # The Reader already warns loudly about empty scope; a graph over nothing is worse
        # than a graph over everything, so degrade rather than return an empty artifact.
        seeds = set(contracts)
        notes.append(
            "no contract is in scope; graphed the whole repository instead "
            "(check the Reader's SCOPE_EMPTY note)"
        )

    included = set(seeds)
    _add_ancestors(included, contracts)
    _add_by_name(included, seeds, contracts, code)
    _add_ancestors(included, contracts)  # types pulled in above bring parents of their own

    _add_interface_implementers(included, contracts, unresolved)

    if len(included) < len(contracts):
        notes.append(
            f"graphed {len(included)} of {len(contracts)} contracts: "
            f"{len(seeds)} in scope plus their inheritance and interface closure"
        )
    return included, unresolved, notes


def _add_ancestors(included: set[str], contracts: dict[str, Contract]) -> None:
    frontier = list(included)
    while frontier:
        contract = contracts.get(frontier.pop())
        if contract is None:
            continue
        for parent_id in contract.inherits_ids:
            if parent_id not in included and parent_id in contracts:
                included.add(parent_id)
                frontier.append(parent_id)


def _add_by_name(
    included: set[str],
    seeds: set[str],
    contracts: dict[str, Contract],
    code: CodeModel,
) -> None:
    """Pull in contracts named by a seed's declared types and `using for` directives."""
    by_name: dict[str, list[str]] = {}
    for contract in code.contracts:
        by_name.setdefault(contract.name, []).append(contract.id)

    wanted: set[str] = set()
    for contract_id in seeds:
        seed = contracts.get(contract_id)
        if seed is None:
            continue
        for directive in seed.using_for:
            wanted.add(directive.library)
        for state_var in seed.state_vars:
            wanted.add(_base_type(state_var.type))
        for function in (*seed.functions, *seed.modifiers):
            for param in (*function.params, *function.returns):
                wanted.add(_base_type(param.type))

    for name in wanted:
        candidates = by_name.get(name, [])
        # An ambiguous name (several contracts declare it) is not worth guessing at here;
        # including all of them is cheap and keeps resolution honest downstream.
        included.update(candidates)


def _base_type(type_name: str) -> str:
    """`IVault[]` → `IVault`, `mapping(address => IVault)` → `IVault`."""
    text = type_name.strip()
    if text.startswith("mapping"):
        text = text.rpartition("=>")[2].strip().rstrip(")").strip()
    while text.endswith("]"):
        text = text[: text.rfind("[")].strip()
    return text.removeprefix("contract ").removeprefix("struct ").strip()


def _add_interface_implementers(
    included: set[str],
    contracts: dict[str, Contract],
    unresolved: list[Unresolved],
) -> None:
    """SPEC §13.2: `IVault(a).f()` fans out to every contract implementing `IVault`."""
    children: dict[str, list[str]] = {}
    for contract in contracts.values():
        for parent_id in contract.inherits_ids:
            children.setdefault(parent_id, []).append(contract.id)

    interfaces = sorted(
        cid
        for cid in included
        if (candidate := contracts.get(cid)) is not None
        and candidate.kind is ContractKind.INTERFACE
    )

    for interface_id in interfaces:
        implementers = sorted(set(children.get(interface_id, [])) - included)
        if len(implementers) > MAX_INTERFACE_FANOUT:
            unresolved.append(
                Unresolved(
                    reason="INTERFACE_FANOUT_CAPPED",
                    function=interface_id,
                    detail=f"{len(implementers)} implementers; kept the first "
                    f"{MAX_INTERFACE_FANOUT} by id",
                )
            )
            implementers = implementers[:MAX_INTERFACE_FANOUT]
        included.update(implementers)
