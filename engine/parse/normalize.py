"""Parse one file, and resolve what can only be resolved across files (SPEC §12).

Two jobs:

* **`parse_file`** — bytes → (`SourceUnit`, `Contract[]`, `ParseError[]`). Error-tolerant:
  a file with a missing brace yields a partial model plus a `ParseError`, and never raises
  (SPEC §12.3).
* **`resolve_cross_file`** — turn import paths into repo-relative paths and parent *names*
  into `SolidityID`s, now that every file has been seen.

Inheritance is resolved by name here only where the name is unambiguous. Full linearization
(Solidity's C3 MRO) belongs to the Graph Engine, which SPEC §13.1 makes responsible for it.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from engine.core.models.code import Contract, ParseError, SourceUnit
from engine.core.models.ids import normalize_path
from engine.parse.bodies import analyze_body
from engine.parse.declarations import (
    CONTRACT_NODES,
    build_source_unit,
    recover_from_error,
)
from engine.parse.treesitter import error_nodes, line_of, parse_source

# One file can produce a great many error nodes once the parser desynchronizes; reporting
# every one buries the first, which is the only one that usually matters.
MAX_ERRORS_PER_FILE = 5


def parse_file(path: str, source: bytes) -> tuple[SourceUnit, list[Contract], list[ParseError]]:
    """Parse one Solidity file. Never raises — a broken file is data, not an exception."""
    path = normalize_path(path)
    errors: list[ParseError] = []

    try:
        tree = parse_source(source)
    except Exception as exc:  # a grammar-level failure must not take the run with it
        return (
            SourceUnit(path=path, has_syntax_error=True),
            [],
            [ParseError(path=path, message=f"parser crashed: {exc}", severity="error")],
        )

    root = tree.root_node
    unit, contracts = build_source_unit(root, source, path)

    if root.has_error:
        unit.has_syntax_error = True
        broken = error_nodes(root)

        for node in broken[:MAX_ERRORS_PER_FILE]:
            errors.append(
                ParseError(
                    path=path,
                    line=line_of(node),
                    message=(
                        "missing syntax element" if node.is_missing else "unparsable region"
                    ),
                    severity="warning",
                )
            )

        # A truncated file collapses into an ERROR node with no structure inside it, so
        # the declarations there have to be read off the token stream (SPEC §12.3: a
        # broken file must still yield a *partial* CodeModel).
        known = {contract.name for contract in contracts}
        for node in broken:
            for recovered in recover_from_error(node, source, path):
                if recovered.name in known:
                    continue
                known.add(recovered.name)
                contracts.append(recovered)
                unit.contract_ids.append(recovered.id)
                errors.append(
                    ParseError(
                        path=path,
                        line=recovered.line_start,
                        message=(
                            f"recovered {recovered.name} lexically from an unparsable "
                            "region; parameters and bodies are unavailable"
                        ),
                    )
                )

    # Bodies are analysed against their own contract, so state-variable identifiers can be
    # resolved and locals can shadow them correctly.
    type_names = _type_names(unit, contracts)
    by_name = {contract.name: contract for contract in contracts}

    for node in root.named_children:
        if node.type not in CONTRACT_NODES:
            continue
        contract = by_name.get(_contract_name(node, source))
        if contract is None:
            continue
        body = node.child_by_field_name("body")
        if body is None:
            continue
        for member in body.named_children:
            function = _match_function(contract, member.start_byte)
            if function is not None:
                analyze_body(member, source, function, contract, type_names)

    for node in root.named_children:
        if node.type == "function_definition":
            function = next(
                (f for f in unit.free_functions if f.src_start == node.start_byte), None
            )
            if function is not None:
                analyze_body(node, source, function, None, type_names)

    return unit, contracts, errors


def _type_names(unit: SourceUnit, contracts: list[Contract]) -> set[str]:
    """Names usable as a type cast in this file — declared here, or imported by name.

    `IERC20(token).transfer(…)` is a cast followed by a call, not a call to `IERC20`.
    Without this set the cast becomes a phantom internal-call edge to a function that does
    not exist, in every file that talks to an interface — which is most of them.
    """
    names = {contract.name for contract in contracts}
    names |= {struct.name for struct in unit.structs}
    names |= {enum.name for enum in unit.enums}
    names |= set(unit.user_defined_types)

    for contract in contracts:
        names |= {struct.name for struct in contract.structs}
        names |= {enum.name for enum in contract.enums}

    for imported in unit.imports:
        for symbol in imported.symbols:
            # `{IERC20 as IT}` binds the alias, not the original name.
            alias = symbol.split(" as ")[-1].strip()
            if alias:
                names.add(alias)

    return names


def _contract_name(node, source: bytes) -> str:
    from engine.parse.treesitter import text_of

    return text_of(node.child_by_field_name("name"), source)


def _match_function(contract: Contract, src_start: int):
    for function in (*contract.functions, *contract.modifiers):
        if function.src_start == src_start:
            return function
    return None


# ── Cross-file resolution ─────────────────────────────────────────────────────

def resolve_cross_file(
    sources: list[SourceUnit],
    contracts: list[Contract],
    remappings: dict[str, str],
) -> list[ParseError]:
    """Resolve import targets and parent contract names into repo-relative IDs."""
    errors: list[ParseError] = []
    known_paths = {unit.path for unit in sources}

    for unit in sources:
        for imported in unit.imports:
            imported.resolved_path = _resolve_import(
                imported.path, unit.path, remappings, known_paths
            )

    # A parent name is unambiguous when exactly one contract in the repository declares it.
    by_name: dict[str, list[Contract]] = {}
    for contract in contracts:
        by_name.setdefault(contract.name, []).append(contract)

    for contract in contracts:
        for parent in contract.inherits:
            candidates = by_name.get(parent, [])
            if len(candidates) == 1:
                contract.inherits_ids.append(candidates[0].id)
            elif len(candidates) > 1:
                # Prefer a candidate the file actually imports; several protocols vendor
                # two versions of the same library (OpenZeppelin v3.4 *and* v4.9).
                resolved = _disambiguate(contract, candidates, sources)
                contract.inherits_ids.append(resolved.id if resolved else candidates[0].id)
                # Only worth reporting for code that will actually be audited. Vendored
                # dependencies duplicate names constantly — eight copies of forge-std's
                # `CommonBase` is normal, and reporting each one buried the 30 warnings
                # that matter under 700 that do not.
                if resolved is None and contract.in_scope:
                    errors.append(
                        ParseError(
                            path=contract.path,
                            line=contract.line_start,
                            message=(
                                f"{contract.name} inherits {parent}, which is declared in "
                                f"{len(candidates)} files; picked {candidates[0].path}"
                            ),
                        )
                    )
            elif contract.in_scope:
                errors.append(
                    ParseError(
                        path=contract.path,
                        line=contract.line_start,
                        message=f"{contract.name} inherits {parent}, which was not found",
                    )
                )

    return errors


def _disambiguate(
    contract: Contract, candidates: list[Contract], sources: list[SourceUnit]
) -> Contract | None:
    unit = next((s for s in sources if s.path == contract.path), None)
    if unit is None:
        return None
    imported = {i.resolved_path for i in unit.imports if i.resolved_path}
    matches = [c for c in candidates if c.path in imported]
    return matches[0] if len(matches) == 1 else None


def _resolve_import(
    target: str,
    importing_path: str,
    remappings: dict[str, str],
    known_paths: set[str],
) -> str | None:
    """Apply remappings and relative-path rules, the way solc does."""
    if not target:
        return None

    if target.startswith("."):
        base = PurePosixPath(importing_path).parent
        candidate = normalize_path(str(base / target))
        candidate = _collapse(candidate)
        return candidate if candidate in known_paths else None

    # Longest matching prefix wins, which is solc's rule.
    for prefix in sorted(remappings, key=len, reverse=True):
        if target.startswith(prefix):
            candidate = _collapse(normalize_path(remappings[prefix] + target[len(prefix) :]))
            if candidate in known_paths:
                return candidate

    direct = _collapse(normalize_path(target))
    if direct in known_paths:
        return direct

    # Last resort: a unique basename match. Common for `import "forge-std/Test.sol"` in a
    # project whose remappings were not fully recovered.
    name = PurePosixPath(target).name
    matches = [path for path in known_paths if path.endswith("/" + name)]
    return matches[0] if len(matches) == 1 else None


def _collapse(path: str) -> str:
    """Resolve `.` and `..` without touching the filesystem."""
    parts: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)
