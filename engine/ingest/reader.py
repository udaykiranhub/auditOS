"""The Repository Reader (SPEC §9).

```
ZIP bytes | local path | git URL (+ optional ref)  →  RepoModel
```

**Dependencies** — none. **Failure** — Fatal.

This module makes the single most consequential judgment in the pipeline: *what code is in
scope*. Everything downstream inherits that judgment, so the algorithm below follows SPEC
§9.1 step for step, with one deliberate reordering: **configuration is extracted before
classification**, because `foundry.toml`'s `libs = [...]` is the authoritative list of
dependency roots for this project. Guessing them when the project has told us is a bug.

Determinism (SPEC §9.4): given the same input, every field of the resulting `RepoModel`
except `root` is identical across runs and machines. Paths are sorted, POSIX and
repo-relative; nothing here reads the clock or the environment.
"""

from __future__ import annotations

from pathlib import Path

from engine.core.artifacts import create_run_dir, save_artifact, sha256_bytes
from engine.core.errors import FatalError, IngestCode
from engine.core.models.repo import ProjectKind, RepoModel, ScopeOverride, SourceFile
from engine.ingest import classify as scope
from engine.ingest import materialize as mat
from engine.ingest.config import extract_config, solidity_version_from_pragmas
from engine.ingest.detect import detect_kind
from engine.ingest.docs import discover_docs

ARTIFACT_NAME = "repo"

# Directories that never contain auditable Solidity. Skipping them during enumeration is
# a traversal optimization only — nothing here changes a file's classification.
SKIP_TRAVERSAL = {".git", ".venv", "__pycache__", "node_modules/.bin"}


def read_repository(
    source: str | Path,
    *,
    ref: str | None = None,
    scope_override: ScopeOverride | None = None,
    run_root: Path | None = None,
    run_id: str | None = None,
    run_dir: Path | None = None,
) -> tuple[RepoModel, Path]:
    """Turn an input of any supported shape into a `RepoModel`.

    Returns ``(model, run_dir)``. The caller decides whether to persist the artifact;
    :func:`ingest` does both.
    """
    override = scope_override or ScopeOverride()
    run_dir = run_dir or create_run_dir(run_root, run_id)
    repo_root = (run_dir / "repo").resolve()
    repo_root.mkdir(parents=True, exist_ok=True)

    notes: list[str] = []

    # 1. Materialize ──────────────────────────────────────────────────────────
    origin, materialize_notes = mat.materialize(source, repo_root, ref)
    notes += materialize_notes

    # 2. Detect the project kind ──────────────────────────────────────────────
    kind, markers, detect_notes = detect_kind(repo_root)
    notes += detect_notes

    # Foundry dependencies *are* submodules, and you cannot know the project is Foundry
    # until it is on disk — so this necessarily runs after detection, not during clone.
    if origin == "git":
        if kind is ProjectKind.FOUNDRY:
            notes += mat.init_submodules(repo_root)
        mat.strip_git_metadata(repo_root)

    # 3. Extract configuration (before classification — it defines dependency roots) ──
    config = extract_config(repo_root, kind, markers)
    notes += config.notes
    dependency_roots = config.libs or scope.DEFAULT_DEPENDENCY_ROOTS
    if config.libs:
        notes.append(f"dependency roots taken from foundry.toml libs: {list(config.libs)}")

    # 4. Enumerate and 5. classify ────────────────────────────────────────────
    files, stripped_sources = _enumerate_and_classify(repo_root, dependency_roots, override)

    if not files:
        raise FatalError(
            "No Solidity files found in the repository.",
            code=IngestCode.NO_SOLIDITY_FILES,
            hint="AuditOS audits Solidity. Check that the input is a contracts repository.",
        )

    # 6. Documentation ────────────────────────────────────────────────────────
    readme, docs = discover_docs(repo_root, dependency_roots)

    # Fall back to pragmas when configuration gave us nothing (always true for RAW).
    solidity_version = config.solidity_version
    version_source = config.solidity_version_source
    if not solidity_version:
        in_scope_sources = [
            (f.path, stripped_sources[f.path]) for f in files if f.in_scope
        ]
        solidity_version = solidity_version_from_pragmas(in_scope_sources)
        version_source = "pragma" if solidity_version else None

    model = RepoModel(
        root=repo_root.as_posix(),
        origin=origin,
        kind=kind,
        files=files,
        solidity_version=solidity_version,
        solidity_version_source=version_source,
        remappings=dict(sorted(config.remappings.items())),
        config_raw=config.raw,
        readme=readme,
        docs=docs,
        scope_override=override,
        notes=notes,
    ).with_content_hash()

    return model, run_dir


def ingest(
    source: str | Path,
    *,
    ref: str | None = None,
    scope_override: ScopeOverride | None = None,
    run_root: Path | None = None,
    run_id: str | None = None,
) -> tuple[RepoModel, Path]:
    """`read_repository` + persist to ``run/<run_id>/artifacts/repo.json``."""
    model, run_dir = read_repository(
        source,
        ref=ref,
        scope_override=scope_override,
        run_root=run_root,
        run_id=run_id,
    )
    artifact = save_artifact(model, run_dir, ARTIFACT_NAME)
    return model, artifact


# ── Enumeration ───────────────────────────────────────────────────────────────

def _enumerate_and_classify(
    repo_root: Path,
    dependency_roots: tuple[str, ...],
    override: ScopeOverride,
) -> tuple[list[SourceFile], dict[str, str]]:
    """Find every ``*.sol`` file, hash it, classify it.

    Ordering is by repo-relative POSIX path, never by filesystem traversal order — that
    is what makes `RepoModel` byte-identical across machines.
    """
    paths = sorted(
        (path for path in repo_root.rglob("*.sol") if path.is_file()),
        key=lambda p: p.relative_to(repo_root).as_posix(),
    )

    files: list[SourceFile] = []
    stripped_sources: dict[str, str] = {}

    for path in paths:
        rel = path.relative_to(repo_root).as_posix()
        if any(part in SKIP_TRAVERSAL for part in Path(rel).parts):
            continue

        raw = path.read_bytes()
        stripped = scope.strip_comments_and_strings(raw.decode("utf-8", errors="replace"))
        stripped_sources[rel] = stripped

        flags = scope.classify(rel, stripped, dependency_roots)
        reason = scope.scope_reason(flags)
        in_scope, override_reason = scope.apply_scope_override(
            rel, flags["in_scope"], override.include, override.exclude
        )

        files.append(
            SourceFile(
                path=rel,
                sha256=sha256_bytes(raw),
                loc=scope.count_loc(stripped),
                is_test=flags["is_test"],
                is_mock=flags["is_mock"],
                is_dependency=flags["is_dependency"],
                is_interface_only=flags["is_interface_only"],
                in_scope=in_scope,
                scope_reason=override_reason or reason,
            )
        )

    return files, stripped_sources
