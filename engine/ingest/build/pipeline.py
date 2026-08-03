"""Build pipeline orchestration (SPEC §10).

```
RepoModel  →  pick a builder  →  compile  →  BuildModel
```

**Degrades, never dies (§10.2).** Every exit from this module produces a `BuildModel`. If
nothing compiled, it is a `BuildModel` with `build_available=False`, `status="failed"` and
the diagnostics that say why — because a protocol that does not compile must still be
auditable, and the report's "Coverage & Limitations" section needs to state precisely what
was lost.

What is lost when the build fails: **storage slots and packing**, and Slither (which needs
compilation). The parser is unaffected — tree-sitter reads code that does not compile.

Builder selection:

| Project | First choice | Fallback |
|---|---|---|
| FOUNDRY | `forge build` | direct solc |
| HARDHAT | direct solc *(Hardhat only with `--allow-hardhat`)* | — |
| RAW     | direct solc | — |
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from engine.core.artifacts import save_artifact
from engine.core.models.build import BuildModel, BuildStatus, Diagnostic, DiagnosticSeverity
from engine.core.models.repo import ProjectKind, RepoModel
from engine.ingest.build.base import Builder, BuildResult
from engine.ingest.build.foundry import FoundryBuilder
from engine.ingest.build.hardhat import HardhatBuilder
from engine.ingest.build.solc import SolcBuilder

ARTIFACT_NAME = "build"

# solc error codes worth explaining rather than repeating.
UNRESOLVED_IMPORT = "6275"
_NOT_FOUND_RE = re.compile(r'Source "([^"]+)" not found')
_VERSION_MISMATCH_RE = re.compile(r"requires different compiler version")


def select_builders(repo: RepoModel, allow_hardhat: bool | None = None) -> list[Builder]:
    """Ordered candidates for this project, best first."""
    solc = SolcBuilder()

    if repo.kind is ProjectKind.FOUNDRY:
        return [FoundryBuilder(), solc]
    if repo.kind is ProjectKind.HARDHAT:
        hardhat = HardhatBuilder(allow_hardhat)
        # Direct solc first: it needs no node_modules and executes none of the target's JS.
        return [solc, hardhat] if not hardhat.allowed else [hardhat, solc]
    return [solc]


def build_repository(
    repo: RepoModel,
    run_dir: Path,
    *,
    allow_hardhat: bool | None = None,
) -> BuildModel:
    """Compile a materialized repository. Always returns a `BuildModel`."""
    notes: list[str] = []
    attempted: list[str] = []
    result: BuildResult | None = None
    builder_name = "none"

    for builder in select_builders(repo, allow_hardhat):
        if not builder.available(repo):
            notes.append(f"{builder.name}: unavailable, skipped")
            continue

        attempted.append(builder.name)
        try:
            candidate = builder.build(repo, run_dir)
        except Exception as exc:  # a builder must not be able to abort the pipeline
            notes.append(f"{builder.name}: crashed ({type(exc).__name__}: {exc})")
            continue

        notes.extend(f"{builder.name}: {note}" for note in candidate.notes)
        errors = sum(1 for d in candidate.diagnostics if d.severity is DiagnosticSeverity.ERROR)
        notes.append(
            f"{builder.name}: attempted — {len(candidate.contracts)} contracts, {errors} errors"
        )

        if candidate.ok:
            result = candidate
            builder_name = builder.name
            break
        if result is None:
            # Keep the first attempt's diagnostics even though it failed — and remember
            # *which* builder produced them. Reporting "none" here hid the fact that a
            # compiler had run at all.
            result = candidate
            builder_name = builder.name

    if not attempted:
        notes.append("no builder was available; the audit continues without compiler output")

    return _to_model(repo, result, builder_name, notes).with_content_hash()


def summarize_failures(diagnostics: list[Diagnostic]) -> list[str]:
    """Collapse repetitive compiler errors into one actionable sentence each.

    A project missing one dependency emits the same "Source not found" error once per
    import — 58 identical lines that say one thing. The note says the one thing.
    """
    notes: list[str] = []
    errors = [d for d in diagnostics if d.severity is DiagnosticSeverity.ERROR]

    unresolved = [d for d in errors if d.error_code == UNRESOLVED_IMPORT]
    if unresolved:
        roots: Counter[str] = Counter()
        for diagnostic in unresolved:
            match = _NOT_FOUND_RE.search(diagnostic.message)
            if match:
                roots[match.group(1).split("/")[0]] += 1
        listed = ", ".join(f"{name} (×{count})" for name, count in roots.most_common(5))
        notes.append(
            f"{len(unresolved)} imports could not be resolved: {listed or 'unknown'}. "
            "The dependency sources or their remapping files are missing — for Foundry run "
            "`forge install` / `git submodule update --init --recursive` on the source, and "
            "make sure every nested lib/*/remappings.txt is present."
        )

    if any(_VERSION_MISMATCH_RE.search(d.message) for d in errors):
        notes.append(
            "The available solc does not satisfy the project's pragma. Install a matching "
            "one with `solc-select install <version>`, or let Foundry auto-detect it."
        )

    return notes


def build_and_save(
    repo: RepoModel,
    run_dir: Path,
    *,
    allow_hardhat: bool | None = None,
) -> tuple[BuildModel, Path]:
    model = build_repository(repo, run_dir, allow_hardhat=allow_hardhat)
    return model, save_artifact(model, run_dir, ARTIFACT_NAME)


def _to_model(
    repo: RepoModel,
    result: BuildResult | None,
    builder_name: str,
    notes: list[str],
) -> BuildModel:
    if result is None:
        return BuildModel(
            repo_content_hash=repo.content_hash,
            builder="none",
            status="skipped",
            build_available=False,
            solc_version_requested=repo.solidity_version,
            notes=[*notes, "BUILD_DEGRADED: no compiler output — storage layout unavailable"],
        )

    has_errors = any(d.severity is DiagnosticSeverity.ERROR for d in result.diagnostics)
    status: BuildStatus
    if not result.ok:
        status = "failed"
    elif has_errors:
        status = "partial"
    else:
        status = "success"

    if status != "success":
        notes.extend(summarize_failures(result.diagnostics))
        notes.append(
            "BUILD_DEGRADED: storage layout and compile-dependent analysis are incomplete"
        )

    return BuildModel(
        repo_content_hash=repo.content_hash,
        builder=builder_name,  # type: ignore[arg-type]
        status=status,
        build_available=result.ok,
        solc_version_requested=repo.solidity_version,
        solc_version_resolved=result.solc_version,
        settings=result.settings,
        sources=sorted(result.sources, key=lambda s: s.path),
        contracts=result.contracts,
        diagnostics=result.diagnostics,
        notes=notes,
    )
