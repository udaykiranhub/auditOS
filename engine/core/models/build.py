"""`BuildModel` — the second artifact in the spine (SPEC §10).

```
RepoModel  →  Build Pipeline  →  BuildModel
```

**Purpose** — obtain the two things only a compiler can give you: a **resolved AST** and a
**storage layout**. Everything else the parser can do alone.

**Failure is Degraded, never Fatal.** A protocol that does not compile must still be
auditable — audit targets are routinely mid-refactor, missing dependencies, or pinned to
an unavailable solc. A failed build produces a `BuildModel` with `build_available=False`,
the diagnostics that explain why, and `status="failed"`. The pipeline continues, and the
report's "Coverage & Limitations" section states exactly what was lost.

Two size decisions, both deliberate:

* **ASTs are written to disk, not embedded.** A single mid-size contract's solc AST is
  megabytes of JSON; embedding them would make `build.json` unusable. `SourceUnit` records
  the path and hash, exactly as `RepoModel.docs` records paths rather than content.
* **Bytecode is recorded as a size, not as bytes.** Deployed bytecode is enormous and
  tells you nothing at source level — except its length, which is a real finding
  (EIP-170's 24,576-byte deployment limit).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0.0"

# EIP-170: a contract whose deployed bytecode exceeds this cannot be deployed at all.
MAX_DEPLOYED_BYTECODE_BYTES = 24_576

Builder = Literal["foundry", "hardhat", "solc", "none"]
BuildStatus = Literal["success", "partial", "failed", "skipped"]


class DiagnosticSeverity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class Diagnostic(BaseModel):
    """One compiler message, normalized across Foundry / Hardhat / direct solc.

    These are not findings. They are evidence: an unreachable-code warning or a shadowed
    declaration is context an agent may use, never a report entry on its own.
    """

    model_config = ConfigDict(extra="forbid")

    severity: DiagnosticSeverity
    message: str
    error_code: str | None = None
    path: str | None = None  # repo-relative, POSIX
    line: int | None = None  # 1-indexed; derived from solc's byte offset
    column: int | None = None


class StorageSlot(BaseModel):
    """One entry of a contract's storage layout — the thing only a compiler knows."""

    model_config = ConfigDict(extra="forbid")

    label: str
    slot: int
    offset: int  # byte offset within the slot; non-zero means the variable is packed
    type_label: str  # the human-readable type, e.g. "mapping(address => uint256)"
    bytes_size: int | None = None
    encoding: str | None = None  # inplace | mapping | dynamic_array | bytes


class ContractArtifact(BaseModel):
    """Per-contract compiler output."""

    model_config = ConfigDict(extra="forbid")

    id: str  # SolidityID contract form: "src/Vault.sol:Vault"
    path: str
    name: str
    in_scope: bool  # carried over from RepoModel, so consumers need not re-join

    storage: list[StorageSlot] = Field(default_factory=list)
    method_identifiers: dict[str, str] = Field(default_factory=dict)  # signature → selector

    # Inlined only for in-scope contracts: a repo's dependency ABIs add megabytes and no
    # agent ever reasons about OpenZeppelin's external interface.
    abi: list[dict] = Field(default_factory=list)
    abi_omitted: bool = False

    bytecode_size: int | None = None
    deployed_bytecode_size: int | None = None

    @property
    def exceeds_size_limit(self) -> bool:
        size = self.deployed_bytecode_size
        return size is not None and size > MAX_DEPLOYED_BYTECODE_BYTES


class SourceUnit(BaseModel):
    """One compiled source file and, where available, its AST on disk."""

    model_config = ConfigDict(extra="forbid")

    path: str  # repo-relative, POSIX
    # Relative to the run directory, e.g. "build/ast/src/Vault.sol.json".
    ast_path: str | None = None
    ast_sha256: str | None = None
    ast_nodes: int | None = None  # top-level node count — a cheap sanity signal


class CompilerSettings(BaseModel):
    """Normalized compiler settings, so downstream code never parses foundry.toml again."""

    model_config = ConfigDict(extra="forbid")

    optimizer_enabled: bool | None = None
    optimizer_runs: int | None = None
    evm_version: str | None = None
    via_ir: bool | None = None
    remappings: list[str] = Field(default_factory=list)


class BuildModel(BaseModel):
    """The Build Pipeline's only output (SPEC §10)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    content_hash: str = ""
    repo_content_hash: str = ""  # ties this artifact to the RepoModel it was built from

    builder: Builder
    status: BuildStatus
    build_available: bool  # False → storage layout and Slither-with-compile are lost

    solc_version_requested: str | None = None  # what the project's config asked for
    solc_version_resolved: str | None = None  # what actually ran; they differ more than you expect
    settings: CompilerSettings = Field(default_factory=CompilerSettings)

    sources: list[SourceUnit] = Field(default_factory=list)
    contracts: list[ContractArtifact] = Field(default_factory=list)
    diagnostics: list[Diagnostic] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def errors(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.severity is DiagnosticSeverity.ERROR]

    @property
    def warnings(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.severity is DiagnosticSeverity.WARNING]

    @property
    def counts(self) -> dict[str, int]:
        return {
            "sources": len(self.sources),
            "contracts": len(self.contracts),
            "with_ast": sum(1 for s in self.sources if s.ast_path),
            "with_storage": sum(1 for c in self.contracts if c.storage),
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "oversize": sum(1 for c in self.contracts if c.exceeds_size_limit),
        }

    def hash_payload(self) -> dict:
        """Inputs the content hash derives from (SPEC §7.1 rule 3).

        No timestamps, no durations, no absolute paths — a build of the same sources with
        the same compiler must hash identically on any machine.
        """
        return self.model_dump(mode="json", exclude={"content_hash"})

    def with_content_hash(self) -> BuildModel:
        from engine.core.artifacts import content_hash as _hash

        return self.model_copy(update={"content_hash": _hash(self.hash_payload())})
