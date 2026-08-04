"""Layer 1 & 2: symbols and their relationships (SPEC §12.2).

Everything a file *declares* — contracts, functions, state variables, modifiers, events,
errors, structs, enums, `using for` directives, imports, free functions — and how those
declarations relate: inheritance, overrides, library bindings.

Nothing here looks inside a function body; that is `bodies.py`. The split matters because
declarations are what make code *addressable* and bodies are what make it *graphable*, and
they fail differently: a malformed body still leaves a usable signature.
"""

from __future__ import annotations

import hashlib

from tree_sitter import Node

from engine.core.models.code import (
    Contract,
    ContractKind,
    CustomError,
    EnumDef,
    Event,
    Function,
    FunctionKind,
    Import,
    Mutability,
    Param,
    SourceUnit,
    StateVar,
    StructDef,
    UsingDirective,
    Visibility,
)
from engine.core.models.ids import (
    canonical_type,
    make_contract_id,
    make_function_id,
    make_modifier_id,
    make_state_var_id,
)
from engine.parse.treesitter import (
    end_line_of,
    line_of,
    named_children,
    natspec_before,
    text_of,
)

CONTRACT_NODES = ("contract_declaration", "interface_declaration", "library_declaration")

_VISIBILITIES = {"public", "external", "internal", "private"}


# ── Types and parameters ──────────────────────────────────────────────────────

def type_text(node: Node | None, source: bytes) -> str:
    """A type as written, canonicalized (`uint` → `uint256`) and whitespace-collapsed."""
    if node is None:
        return ""
    return canonical_type(" ".join(text_of(node, source).split()))


def _param(node: Node, source: bytes) -> Param:
    raw = text_of(node, source)
    return Param(
        name=text_of(node.child_by_field_name("name"), source),
        type=type_text(node.child_by_field_name("type"), source),
        indexed="indexed" in raw.split(),
        location=next(
            (word for word in ("memory", "storage", "calldata") if word in raw.split()), None
        ),
    )


def _params(node: Node, source: bytes, kind: str = "parameter") -> list[Param]:
    return [_param(child, source) for child in named_children(node, kind)]


def _returns(node: Node, source: bytes) -> list[Param]:
    definition = node.child_by_field_name("return_type")
    return _params(definition, source) if definition is not None else []


# ── Modifiers on a declaration ────────────────────────────────────────────────

def _token_types(node: Node) -> set[str]:
    """Every child token type, anonymous ones included.

    `constant` and `indexed` are anonymous tokens in this grammar while `immutable` is a
    named node — so keyword detection cannot rely on named children alone.
    """
    return {child.type for child in node.children}


def _visibility(node: Node, source: bytes, default: Visibility) -> Visibility:
    for child in named_children(node, "visibility"):
        value = text_of(child, source).strip()
        if value in _VISIBILITIES:
            return value  # type: ignore[return-value]
    return default


def _mutability(node: Node, source: bytes) -> Mutability:
    for child in named_children(node, "state_mutability"):
        value = text_of(child, source).strip()
        if value in ("pure", "view", "payable"):
            return value  # type: ignore[return-value]
    return "nonpayable"


def _modifier_names(node: Node, source: bytes) -> list[str]:
    """Applied modifiers, including base-constructor invocations such as `Base(x)`."""
    return [
        text_of(child.named_children[0], source) if child.named_children else text_of(child, source)
        for child in named_children(node, "modifier_invocation")
    ]


def _body_hash(node: Node, source: bytes) -> str:
    """Hash of the whitespace-normalized body — dedupes a body from its redefinition."""
    body = node.child_by_field_name("body")
    if body is None:
        return ""
    normalized = " ".join(text_of(body, source).split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


# ── Functions ─────────────────────────────────────────────────────────────────

def build_function(
    node: Node,
    source: bytes,
    path: str,
    contract_name: str | None,
    kind: FunctionKind,
) -> Function:
    """One callable: function, constructor, fallback, receive, modifier or free function."""
    if kind is FunctionKind.CONSTRUCTOR:
        name = "constructor"
    elif kind in (FunctionKind.FALLBACK, FunctionKind.RECEIVE):
        name = kind.value
    else:
        name = text_of(node.child_by_field_name("name"), source)

    params = _params(node, source)
    param_types = [p.type for p in params]

    if contract_name is None:
        identifier = f"{path}:{name}({','.join(param_types)})"
        contract_id = None
    elif kind is FunctionKind.MODIFIER:
        identifier = make_modifier_id(path, contract_name, name)
        contract_id = make_contract_id(path, contract_name)
    else:
        identifier = make_function_id(path, contract_name, name, param_types)
        contract_id = make_contract_id(path, contract_name)

    # An interface method or an unimplemented `virtual` has no body — that is a fact the
    # call graph needs, not an error.
    body = node.child_by_field_name("body")

    default_visibility: Visibility = (
        "public" if kind in (FunctionKind.CONSTRUCTOR, FunctionKind.MODIFIER) else "internal"
    )

    return Function(
        id=identifier,
        name=name,
        contract_id=contract_id,
        kind=kind,
        visibility=_visibility(node, source, default_visibility),
        mutability=_mutability(node, source),
        is_virtual=bool(named_children(node, "virtual")),
        is_override=bool(named_children(node, "override_specifier")),
        is_implemented=body is not None,
        modifiers=_modifier_names(node, source),
        params=params,
        returns=_returns(node, source),
        src_start=node.start_byte,
        src_end=node.end_byte,
        line_start=line_of(node),
        line_end=end_line_of(node),
        body_hash=_body_hash(node, source),
        raw=text_of(node, source),
        natspec=natspec_before(node, source),
    )


def _fallback_kind(node: Node, source: bytes) -> FunctionKind:
    """`fallback_receive_definition` covers both; only the keyword distinguishes them."""
    head = text_of(node, source).lstrip()
    return FunctionKind.RECEIVE if head.startswith("receive") else FunctionKind.FALLBACK


# ── State variables ───────────────────────────────────────────────────────────

def build_state_var(node: Node, source: bytes, path: str, contract_name: str) -> StateVar:
    name = text_of(node.child_by_field_name("name"), source)
    tokens = _token_types(node)
    location = text_of(node.child_by_field_name("location"), source)

    return StateVar(
        id=make_state_var_id(path, contract_name, name),
        name=name,
        type=type_text(node.child_by_field_name("type"), source),
        contract_id=make_contract_id(path, contract_name),
        visibility=_visibility(node, source, "internal"),
        is_constant="constant" in tokens,
        is_immutable="immutable" in tokens,
        is_transient=location.strip() == "transient",
        line=line_of(node),
    )


# ── Member declarations ───────────────────────────────────────────────────────

def build_event(node: Node, source: bytes) -> Event:
    return Event(
        name=text_of(node.child_by_field_name("name"), source),
        params=_params(node, source, "event_parameter"),
        is_anonymous="anonymous" in _token_types(node),
        line=line_of(node),
    )


def build_error(node: Node, source: bytes) -> CustomError:
    return CustomError(
        name=text_of(node.child_by_field_name("name"), source),
        params=_params(node, source, "error_parameter"),
        line=line_of(node),
    )


def build_struct(node: Node, source: bytes) -> StructDef:
    body = node.child_by_field_name("body") or node
    fields = [
        Param(
            name=text_of(member.child_by_field_name("name"), source),
            type=type_text(member.child_by_field_name("type"), source),
        )
        for member in named_children(body, "struct_member")
    ]
    return StructDef(
        name=text_of(node.child_by_field_name("name"), source),
        fields=fields,
        line=line_of(node),
    )


def build_enum(node: Node, source: bytes) -> EnumDef:
    body = node.child_by_field_name("body") or node
    return EnumDef(
        name=text_of(node.child_by_field_name("name"), source),
        values=[text_of(v, source) for v in named_children(body, "enum_value")],
        line=line_of(node),
    )


def build_using(node: Node, source: bytes) -> UsingDirective:
    """`using L for T` — how a library call becomes resolvable (SPEC §13.2)."""
    raw = " ".join(text_of(node, source).split())
    library, _, rest = raw.partition("using ")[2].partition(" for ")
    target = rest.rstrip(";").replace("global", "").strip()
    return UsingDirective(
        library=library.strip(),
        target_type=canonical_type(target) if target and target != "*" else "*",
        is_global="global" in raw.split(),
    )


def build_import(node: Node, source: bytes) -> Import:
    raw = " ".join(text_of(node, source).split())
    quoted = [
        text_of(child, source).strip("\"'")
        for child in named_children(node, "string")
    ]
    symbols: list[str] = []
    if "{" in raw:
        inner = raw[raw.index("{") + 1 : raw.index("}")] if "}" in raw else ""
        symbols = [part.strip() for part in inner.split(",") if part.strip()]

    return Import(
        path=quoted[0] if quoted else "",
        symbols=symbols,
        line=line_of(node),
    )


# ── Contracts ─────────────────────────────────────────────────────────────────

def _contract_kind(node: Node, source: bytes) -> ContractKind:
    if node.type == "interface_declaration":
        return ContractKind.INTERFACE
    if node.type == "library_declaration":
        return ContractKind.LIBRARY
    if "abstract" in _token_types(node) or text_of(node, source).lstrip().startswith("abstract"):
        return ContractKind.ABSTRACT
    return ContractKind.CONTRACT


def build_contract(node: Node, source: bytes, path: str) -> Contract:
    """One contract/interface/library, with its members but not their bodies analysed."""
    name = text_of(node.child_by_field_name("name"), source)
    contract_id = make_contract_id(path, name)

    inherits = [
        text_of(spec.child_by_field_name("ancestor") or spec, source).split("(")[0].strip()
        for spec in named_children(node, "inheritance_specifier")
    ]

    contract = Contract(
        id=contract_id,
        name=name,
        path=path,
        kind=_contract_kind(node, source),
        inherits=inherits,
        natspec=natspec_before(node, source),
        line_start=line_of(node),
        line_end=end_line_of(node),
    )

    body = node.child_by_field_name("body")
    if body is None:
        return contract

    for member in body.named_children:
        if member.type == "function_definition":
            contract.functions.append(
                build_function(member, source, path, name, FunctionKind.FUNCTION)
            )
        elif member.type == "constructor_definition":
            contract.functions.append(
                build_function(member, source, path, name, FunctionKind.CONSTRUCTOR)
            )
        elif member.type == "fallback_receive_definition":
            contract.functions.append(
                build_function(member, source, path, name, _fallback_kind(member, source))
            )
        elif member.type == "modifier_definition":
            contract.modifiers.append(
                build_function(member, source, path, name, FunctionKind.MODIFIER)
            )
        elif member.type == "state_variable_declaration":
            contract.state_vars.append(build_state_var(member, source, path, name))
        elif member.type == "event_definition":
            contract.events.append(build_event(member, source))
        elif member.type == "error_declaration":
            contract.errors.append(build_error(member, source))
        elif member.type == "struct_declaration":
            contract.structs.append(build_struct(member, source))
        elif member.type == "enum_declaration":
            contract.enums.append(build_enum(member, source))
        elif member.type == "using_directive":
            contract.using_for.append(build_using(member, source))

    return contract


# ── File level ────────────────────────────────────────────────────────────────

def recover_from_error(node: Node, source: bytes, path: str) -> list[Contract]:
    """Salvage declarations from an unparsable region.

    When a file is truncated mid-body the closing braces never arrive, so tree-sitter
    cannot build a `contract_declaration` at all — the whole region collapses into one
    ERROR node holding raw tokens. Returning nothing there would mean a half-written
    contract is invisible to the audit, which is precisely the case tree-sitter was chosen
    to handle.

    So the tokens are read directly: `contract <name>` and `function <name>` are
    unambiguous even without structure. Parameters are **not** recovered — they cannot be
    read reliably from a token stream — so a recovered function's ID carries an empty
    parameter list and the caller records a `ParseError` saying so.
    """
    contracts: list[Contract] = []
    tokens = list(node.children)
    index = 0

    while index < len(tokens):
        token = tokens[index]

        if token.type in ("contract", "interface", "library"):
            name_node = _next_identifier(tokens, index + 1)
            if name_node is not None:
                name = text_of(name_node, source)
                kind = {
                    "contract": ContractKind.CONTRACT,
                    "interface": ContractKind.INTERFACE,
                    "library": ContractKind.LIBRARY,
                }[token.type]
                contracts.append(
                    Contract(
                        id=make_contract_id(path, name),
                        name=name,
                        path=path,
                        kind=kind,
                        line_start=line_of(token),
                        line_end=end_line_of(node),
                    )
                )

        elif token.type == "function" and contracts:
            name_node = _next_identifier(tokens, index + 1)
            if name_node is not None:
                name = text_of(name_node, source)
                contract = contracts[-1]
                visibility = _following_visibility(tokens, index + 1, source)
                contract.functions.append(
                    Function(
                        id=make_function_id(path, contract.name, name, []),
                        name=name,
                        contract_id=contract.id,
                        kind=FunctionKind.FUNCTION,
                        visibility=visibility,
                        line_start=line_of(token),
                        line_end=line_of(token),
                        src_start=token.start_byte,
                        src_end=token.end_byte,
                        raw=text_of(token, source),
                    )
                )

        index += 1

    return contracts


def _next_identifier(tokens: list[Node], start: int) -> Node | None:
    for token in tokens[start : start + 3]:
        if token.type == "identifier":
            return token
    return None


def _following_visibility(tokens: list[Node], start: int, source: bytes) -> Visibility:
    for token in tokens[start : start + 8]:
        if token.type in ("{", ";", "function", "contract"):
            break
        if token.type == "visibility":
            value = text_of(token, source).strip()
            if value in _VISIBILITIES:
                return value  # type: ignore[return-value]
    return "internal"


def build_source_unit(root: Node, source: bytes, path: str) -> tuple[SourceUnit, list[Contract]]:
    """File-level declarations plus every contract the file defines."""
    unit = SourceUnit(path=path)
    contracts: list[Contract] = []

    for node in root.named_children:
        if node.type in CONTRACT_NODES:
            contract = build_contract(node, source, path)
            contracts.append(contract)
            unit.contract_ids.append(contract.id)
        elif node.type == "pragma_directive":
            unit.pragma = " ".join(text_of(node, source).split()).rstrip(";")
        elif node.type == "import_directive":
            unit.imports.append(build_import(node, source))
        elif node.type == "function_definition":
            # A free function (Solidity >= 0.7). Addressed by file, not by contract.
            unit.free_functions.append(
                build_function(node, source, path, None, FunctionKind.FREE)
            )
        elif node.type == "struct_declaration":
            unit.structs.append(build_struct(node, source))
        elif node.type == "enum_declaration":
            unit.enums.append(build_enum(node, source))
        elif node.type == "error_declaration":
            unit.errors.append(build_error(node, source))
        elif node.type == "event_definition":
            unit.events.append(build_event(node, source))
        elif node.type == "user_defined_type_definition":
            unit.user_defined_types.append(
                text_of(node.child_by_field_name("name"), source)
            )

    return unit, contracts
