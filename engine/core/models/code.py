"""`CodeModel` — what code exists and how it behaves (SPEC §7.4, §12).

```
RepoModel (+ BuildModel)  →  Parser  →  CodeModel
```

**The scope rule that governs this whole file** (SPEC §12.2, called out there as *the single
biggest scope trap in the project*):

> Do not attempt full expression-level AST modeling. `CodeModel` exists to make code
> **addressable, sliceable and graphable** — not to make it *interpretable*. That is the
> model's job.

So: a function records *which* state variables it touches, *which* calls it makes, and in
*what order* — because SPEC §13 needs exactly that to build the four graphs and to compute
reentrancy candidates. It does not record a syntax tree of every expression, a symbolic
value for `shares`, or a model of each loop. The agent reads `raw` for that.

Everything is addressed by `SolidityID` (§7.2), the join key shared with `GraphModel`,
`BuildModel`, static-analyzer output, `ContextBundle` and `Finding`.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0.0"

Visibility = Literal["public", "external", "internal", "private"]
Mutability = Literal["pure", "view", "nonpayable", "payable"]


class ContractKind(StrEnum):
    CONTRACT = "contract"
    INTERFACE = "interface"
    LIBRARY = "library"
    ABSTRACT = "abstract"


class FunctionKind(StrEnum):
    FUNCTION = "function"
    CONSTRUCTOR = "constructor"
    FALLBACK = "fallback"
    RECEIVE = "receive"
    MODIFIER = "modifier"
    FREE = "free"  # file-level function (Solidity >= 0.7)


class CallKind(StrEnum):
    """How a call site resolves — the confidence ladder from SPEC §13.2.

    `LOW_LEVEL` is the load-bearing one: `.call`/`.delegatecall`/`.staticcall` is where
    reentrancy, untrusted callbacks and oracle manipulation live.
    """

    INTERNAL = "internal"  # f(...)             — same contract or inherited
    THIS = "this"  # this.f(...)        — external call to self
    SUPER = "super"  # super.f(...)       — resolved via C3 linearization
    MEMBER = "member"  # x.f(...)           — external, library, or struct member
    LOW_LEVEL = "low_level"  # .call / .delegatecall / .staticcall
    NEW = "new"  # new C(...)         — contract creation
    BUILTIN = "builtin"  # require/assert/keccak256/…


class AccessKind(StrEnum):
    READ = "read"
    WRITE = "write"


class Param(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = ""
    type: str  # canonical solc spelling (`uint256`, never `uint`)
    indexed: bool = False  # event parameters only
    location: str | None = None  # memory | storage | calldata


class CallSite(BaseModel):
    """One call expression, recorded as a *reference*, not as a parsed expression."""

    model_config = ConfigDict(extra="forbid")

    kind: CallKind
    name: str  # the callee as written: `transfer`, `add`, `call`
    receiver: str | None = None  # `token` in `token.transfer(...)`
    text: str  # the callee expression as written, for evidence
    line: int
    order: int  # position within the body — CEI analysis needs the sequence
    sends_value: bool = False  # `{value: …}`
    is_delegate: bool = False
    is_static: bool = False
    is_try: bool = False


class StateAccess(BaseModel):
    """A read or write of a *state* variable. Shadowed locals are excluded (SPEC §13.3)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    state_var_id: str
    kind: AccessKind
    line: int
    order: int


class Function(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    contract_id: str | None  # None for a free function
    kind: FunctionKind = FunctionKind.FUNCTION
    visibility: Visibility = "internal"
    mutability: Mutability = "nonpayable"
    is_virtual: bool = False
    is_override: bool = False
    is_implemented: bool = True  # false for an interface / unimplemented `virtual`
    modifiers: list[str] = Field(default_factory=list)
    params: list[Param] = Field(default_factory=list)
    returns: list[Param] = Field(default_factory=list)

    src_start: int = 0
    src_end: int = 0
    line_start: int = 0
    line_end: int = 0
    body_hash: str = ""  # dedupes an inherited body from its redefinition
    # SPEC §7.4: stored, not fetched lazily by offset. The Context Builder slices at
    # function granularity hundreds of times per run; making that IO is a false economy
    # that produces off-by-one bugs at scale.
    raw: str = ""
    natspec: str | None = None

    # ── Behaviour: references and order, never expression trees ───────────────
    calls: list[CallSite] = Field(default_factory=list)
    accesses: list[StateAccess] = Field(default_factory=list)
    emits: list[str] = Field(default_factory=list)
    reverts: list[str] = Field(default_factory=list)

    has_assembly: bool = False
    has_loop: bool = False
    has_unchecked: bool = False

    @property
    def reads(self) -> list[str]:
        return sorted({a.state_var_id for a in self.accesses if a.kind is AccessKind.READ})

    @property
    def writes(self) -> list[str]:
        return sorted({a.state_var_id for a in self.accesses if a.kind is AccessKind.WRITE})

    @property
    def is_entrypoint(self) -> bool:
        """Reachable by an external actor — the starting point of every attack path."""
        return self.visibility in ("public", "external") or self.kind in (
            FunctionKind.FALLBACK,
            FunctionKind.RECEIVE,
        )

    @property
    def writes_after_external_call(self) -> bool:
        """A state write ordered after an external call — the CEI-violation candidate.

        A *candidate*, not a finding: the write may be guarded by a reentrancy lock. The
        graph engine and the agents decide; this only flags where to look (SPEC §13.3).
        """
        external = [c.order for c in self.calls if c.kind in (CallKind.LOW_LEVEL, CallKind.MEMBER)]
        if not external:
            return False
        first = min(external)
        return any(a.order > first for a in self.accesses if a.kind is AccessKind.WRITE)


class StateVar(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    type: str
    contract_id: str
    visibility: Visibility = "internal"
    is_constant: bool = False
    is_immutable: bool = False
    is_transient: bool = False
    slot: int | None = None  # solc enrichment only — tree-sitter cannot know this
    offset: int | None = None
    line: int = 0


class UsingDirective(BaseModel):
    """`using L for T` — needed to resolve library calls in the call graph (SPEC §13.2)."""

    model_config = ConfigDict(extra="forbid")

    library: str
    target_type: str  # `*` for `using L for *`
    is_global: bool = False


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    params: list[Param] = Field(default_factory=list)
    is_anonymous: bool = False
    line: int = 0


class CustomError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    params: list[Param] = Field(default_factory=list)
    line: int = 0


class StructDef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    fields: list[Param] = Field(default_factory=list)
    line: int = 0


class EnumDef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    values: list[str] = Field(default_factory=list)
    line: int = 0


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    path: str
    kind: ContractKind = ContractKind.CONTRACT
    inherits: list[str] = Field(default_factory=list)  # direct parents, by name as written
    inherits_ids: list[str] = Field(default_factory=list)  # resolved SolidityIDs where known

    functions: list[Function] = Field(default_factory=list)
    modifiers: list[Function] = Field(default_factory=list)
    state_vars: list[StateVar] = Field(default_factory=list)
    events: list[Event] = Field(default_factory=list)
    errors: list[CustomError] = Field(default_factory=list)
    structs: list[StructDef] = Field(default_factory=list)
    enums: list[EnumDef] = Field(default_factory=list)
    using_for: list[UsingDirective] = Field(default_factory=list)

    natspec: str | None = None
    is_dependency: bool = False
    in_scope: bool = True
    line_start: int = 0
    line_end: int = 0

    @property
    def entrypoints(self) -> list[Function]:
        return [f for f in self.functions if f.is_entrypoint]


class Import(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str  # as written in the source
    resolved_path: str | None = None  # repo-relative, once remappings are applied
    symbols: list[str] = Field(default_factory=list)  # `{A, B as C}` → ["A", "B as C"]
    line: int = 0


class SourceUnit(BaseModel):
    """One `.sol` file: what it declares at file level, and what it pulls in."""

    model_config = ConfigDict(extra="forbid")

    path: str
    pragma: str | None = None
    imports: list[Import] = Field(default_factory=list)
    contract_ids: list[str] = Field(default_factory=list)
    free_functions: list[Function] = Field(default_factory=list)
    structs: list[StructDef] = Field(default_factory=list)
    enums: list[EnumDef] = Field(default_factory=list)
    errors: list[CustomError] = Field(default_factory=list)
    events: list[Event] = Field(default_factory=list)
    user_defined_types: list[str] = Field(default_factory=list)  # `type Price is uint128`
    in_scope: bool = True
    has_syntax_error: bool = False


class ParseError(BaseModel):
    """Non-fatal: tree-sitter is error-tolerant, so a broken file yields a partial model."""

    model_config = ConfigDict(extra="forbid")

    path: str
    line: int | None = None
    message: str
    severity: Literal["error", "warning"] = "warning"


class CodeModel(BaseModel):
    """The single source of truth for every phase after parsing."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    content_hash: str = ""
    repo_content_hash: str = ""
    build_content_hash: str | None = None  # set when solc enrichment was applied

    sources: list[SourceUnit] = Field(default_factory=list)
    contracts: list[Contract] = Field(default_factory=list)
    parse_errors: list[ParseError] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    enriched: bool = False  # did a BuildModel contribute types/slots?

    # ── Derived views ─────────────────────────────────────────────────────────

    @property
    def in_scope_contracts(self) -> list[Contract]:
        return [c for c in self.contracts if c.in_scope]

    @property
    def counts(self) -> dict[str, int]:
        functions = [f for c in self.contracts for f in c.functions]
        in_scope = [c for c in self.contracts if c.in_scope]
        return {
            "sources": len(self.sources),
            "contracts": len(self.contracts),
            "in_scope_contracts": len(in_scope),
            "interfaces": sum(c.kind is ContractKind.INTERFACE for c in self.contracts),
            "libraries": sum(c.kind is ContractKind.LIBRARY for c in self.contracts),
            "functions": len(functions),
            "entrypoints": sum(f.is_entrypoint for f in functions),
            "state_vars": sum(len(c.state_vars) for c in self.contracts),
            "modifiers": sum(len(c.modifiers) for c in self.contracts),
            "events": sum(len(c.events) for c in self.contracts),
            "free_functions": sum(len(s.free_functions) for s in self.sources),
            "parse_errors": len(self.parse_errors),
        }

    def contract(self, contract_id: str) -> Contract | None:
        return next((c for c in self.contracts if c.id == contract_id), None)

    def function(self, function_id: str) -> Function | None:
        for contract in self.contracts:
            for function in (*contract.functions, *contract.modifiers):
                if function.id == function_id:
                    return function
        for source in self.sources:
            for function in source.free_functions:
                if function.id == function_id:
                    return function
        return None

    def hash_payload(self) -> dict:
        return self.model_dump(mode="json", exclude={"content_hash"})

    def with_content_hash(self) -> CodeModel:
        from engine.core.artifacts import content_hash as _hash

        return self.model_copy(update={"content_hash": _hash(self.hash_payload())})
