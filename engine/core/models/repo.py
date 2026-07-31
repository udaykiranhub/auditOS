"""`RepoModel` — the first artifact in the spine (SPEC §7.3).

```
ZIP | Folder | Git URL  →  Repository Reader  →  RepoModel
```

``is_dependency`` / ``is_test`` / ``is_mock`` are the highest-leverage fields in the whole
system: they are what stop the engine from auditing OpenZeppelin for the tenth time. On a
real protocol 85–95% of `.sol` files are out of scope, and getting it wrong does not merely
waste tokens — it *poisons* the audit, because mocks contain deliberately broken code and
tests contain attack code that pattern-matches as vulnerable.

**Scope is metadata, not a filter.** Out-of-scope files stay in the inventory: the Parser
and Graph Engine still need them for inheritance resolution, imports and call-graph
completeness. The flag propagates; it never deletes.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0.0"

Origin = Literal["zip", "folder", "git"]


class ProjectKind(StrEnum):
    """How the repository is built (SPEC §9.2)."""

    FOUNDRY = "FOUNDRY"
    HARDHAT = "HARDHAT"
    RAW = "RAW"  # only *.sol — parse-only mode: no build, no Slither-with-compile
    UNKNOWN = "UNKNOWN"


class ScopeOverride(BaseModel):
    """The escape hatch (SPEC §9.3).

    The heuristics *will* be wrong on some protocol, and the user must be able to fix it
    without editing code. Patterns are POSIX globs matched against repo-relative paths
    (e.g. ``src/vendor/**``). ``exclude`` wins over ``include``.
    """

    model_config = ConfigDict(extra="forbid")

    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.include and not self.exclude


class SourceFile(BaseModel):
    """One `.sol` file in the repository — in scope or not."""

    model_config = ConfigDict(extra="forbid")

    path: str  # repo-relative, POSIX separators
    sha256: str  # of the raw bytes, never of decoded text
    loc: int  # non-blank, non-comment lines
    is_test: bool = False
    is_mock: bool = False
    is_dependency: bool = False
    is_interface_only: bool = False
    in_scope: bool = True
    scope_reason: str = ""  # why this file was included/excluded — the heuristic is auditable


class RepoModel(BaseModel):
    """The Repository Reader's only output (SPEC §7.3).

    Deterministic: given the same input, every field except ``root`` is identical across
    runs and machines (SPEC §9.4). ``content_hash`` therefore excludes ``root``.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    content_hash: str = ""  # sha256 over everything below except root — cache/resume key

    root: str  # absolute path to run/<run_id>/repo — the ONLY machine-dependent field
    origin: Origin
    kind: ProjectKind

    files: list[SourceFile] = Field(default_factory=list)  # sorted by path

    solidity_version: str | None = None
    solidity_version_source: str | None = None  # foundry.toml | hardhat.config | pragma | None
    remappings: dict[str, str] = Field(default_factory=dict)
    config_raw: dict = Field(default_factory=dict)  # parsed foundry.toml / raw hardhat text

    readme: str | None = None  # README *content* — Protocol Understanding reads this (§8)
    docs: list[str] = Field(default_factory=list)  # repo-relative paths only; PDFs unparsed

    scope_override: ScopeOverride = Field(default_factory=ScopeOverride)
    notes: list[str] = Field(default_factory=list)  # detection/degradation notes (P6)

    # ── Derived counts (properties, not fields — they stay out of the hash) ────

    @property
    def in_scope_files(self) -> list[SourceFile]:
        return [f for f in self.files if f.in_scope]

    @property
    def counts(self) -> dict[str, int]:
        return {
            "total": len(self.files),
            "in_scope": sum(f.in_scope for f in self.files),
            "tests": sum(f.is_test for f in self.files),
            "mocks": sum(f.is_mock for f in self.files),
            "dependencies": sum(f.is_dependency for f in self.files),
            "interfaces": sum(f.is_interface_only for f in self.files),
        }

    # ── Hashing ───────────────────────────────────────────────────────────────

    def hash_payload(self) -> dict:
        """The inputs the content hash is derived from (SPEC §7.1 rule 3).

        Deliberately excludes ``root`` (an absolute temp path) and ``content_hash``
        itself. Everything else is content, and content must hash identically on any
        machine — that is what makes the artifact cache a valid resume mechanism.
        """
        payload = self.model_dump(mode="json", exclude={"root", "content_hash"})
        return payload

    def with_content_hash(self) -> RepoModel:
        """Return a copy with ``content_hash`` filled in."""
        from engine.core.artifacts import content_hash as _hash

        return self.model_copy(update={"content_hash": _hash(self.hash_payload())})
