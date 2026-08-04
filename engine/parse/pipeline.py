"""The Parsing Engine (SPEC §12).

```
RepoModel (+ BuildModel)  →  CodeModel
```

**Failure — fatal if zero contracts parse**, degraded otherwise. Tree-sitter is
error-tolerant, so a repository where some files are broken still produces a usable
`CodeModel` plus `ParseError`s. A repository where *nothing* parses is not auditable, and
saying so plainly beats handing the next stage an empty model.

Every out-of-scope file is parsed too. SPEC §9.3: out-of-scope code is *parsed and graphed
but never audited* — the Graph Engine needs it for inheritance resolution and call-graph
completeness. The flag propagates; it does not filter.
"""

from __future__ import annotations

from pathlib import Path

from engine.core.artifacts import save_artifact
from engine.core.errors import FatalError
from engine.core.models.build import BuildModel
from engine.core.models.code import CodeModel, ParseError
from engine.core.models.repo import RepoModel
from engine.parse.normalize import parse_file, resolve_cross_file
from engine.parse.solc_ast import enrich

ARTIFACT_NAME = "code"


class ParseCode:
    """Stable failure codes for the parser (part of the CLI/API contract)."""

    NO_CONTRACTS = "PARSE_NO_CONTRACTS"
    NO_SOURCES = "PARSE_NO_SOURCES"


def parse_repository(repo: RepoModel, build: BuildModel | None = None) -> CodeModel:
    """Turn a `RepoModel` into a `CodeModel`."""
    root = Path(repo.root)
    code = CodeModel(repo_content_hash=repo.content_hash)

    scope_by_path = {source.path: source.in_scope for source in repo.files}
    dependency_by_path = {source.path: source.is_dependency for source in repo.files}

    unreadable = 0
    for source_file in repo.files:
        path = root / source_file.path
        try:
            raw = path.read_bytes()
        except OSError as exc:
            unreadable += 1
            code.parse_errors.append(
                ParseError(path=source_file.path, message=f"unreadable: {exc}", severity="error")
            )
            continue

        unit, contracts, errors = parse_file(source_file.path, raw)
        unit.in_scope = source_file.in_scope
        for contract in contracts:
            contract.in_scope = scope_by_path.get(contract.path, True)
            contract.is_dependency = dependency_by_path.get(contract.path, False)

        code.sources.append(unit)
        code.contracts.extend(contracts)
        code.parse_errors.extend(errors)

    if not code.sources:
        raise FatalError(
            "No Solidity sources could be read.",
            code=ParseCode.NO_SOURCES,
            hint="The run directory may have been moved or deleted since ingestion.",
        )

    if not code.contracts and not any(s.free_functions for s in code.sources):
        raise FatalError(
            f"Parsed {len(code.sources)} files but found no contracts, interfaces or "
            "libraries.",
            code=ParseCode.NO_CONTRACTS,
            hint="Check that the input is Solidity source and not, say, generated ABI files.",
        )

    code.parse_errors.extend(
        resolve_cross_file(code.sources, code.contracts, repo.remappings)
    )

    enrich(code, build)

    # Deterministic ordering: the artifact must be byte-identical across runs (SPEC §7.1).
    code.sources.sort(key=lambda unit: unit.path)
    code.contracts.sort(key=lambda contract: contract.id)
    code.parse_errors.sort(key=lambda error: (error.path, error.line or 0, error.message))

    broken = sum(1 for unit in code.sources if unit.has_syntax_error)
    if broken:
        code.notes.append(
            f"{broken} of {len(code.sources)} files contain syntax errors; parsed what was "
            "recoverable (tree-sitter is error-tolerant by design)"
        )
    if unreadable:
        code.notes.append(f"{unreadable} files could not be read")

    return code.with_content_hash()


def parse_and_save(
    repo: RepoModel,
    run_dir: Path,
    build: BuildModel | None = None,
) -> tuple[CodeModel, Path]:
    """`parse_repository` + persist to ``run/<run_id>/artifacts/code.json``."""
    code = parse_repository(repo, build)
    return code, save_artifact(code, run_dir, ARTIFACT_NAME)
