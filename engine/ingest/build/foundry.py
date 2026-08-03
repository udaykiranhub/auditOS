"""Foundry builder — the happy path (SPEC §10).

```
forge build --ast --extra-output storageLayout evm.methodIdentifiers --skip test script
```

The two `--extra-output` selectors and `--ast` make the per-contract artifacts under
`out/` carry everything the pipeline needs. Foundry resolves remappings, `libs`, and the
solc version itself — including downloading a compiler the project's pragma requires —
which is exactly why it is the happy path: none of that has to be re-derived here.

**No `--json`.** It writes the complete standard-JSON output to stdout, every dependency
AST included: 321 MB on a real protocol against ~1 KB of ordinary console output for the
same build, and every byte of it has to be piped and parsed. The artifacts it contains are
written to `out/` regardless, so the only thing lost is structured diagnostics — recovered
from the console by `parse_text_diagnostics`.

Foundry does not execute project-supplied JavaScript, so unlike Hardhat this is safe to
run unattended on a repository under audit.
"""

from __future__ import annotations

import json
from pathlib import Path

from engine.core.models.build import CompilerSettings
from engine.core.models.ids import normalize_path
from engine.core.models.repo import RepoModel
from engine.ingest.build.base import (
    TIMEOUT_RETURNCODE,
    Builder,
    BuildResult,
    build_contract_artifact,
    parse_text_diagnostics,
    parse_tool_messages,
    run_command,
    write_ast,
)


class FoundryBuilder(Builder):
    name = "foundry"

    def available(self, repo: RepoModel) -> bool:
        code, _, _ = run_command(["forge", "--version"], Path(repo.root), timeout=30)
        return code == 0

    def build(self, repo: RepoModel, run_dir: Path) -> BuildResult:
        root = Path(repo.root)
        result = BuildResult()

        code, stdout, stderr = run_command(
            [
                "forge",
                "build",
                "--ast",
                "--extra-output",
                "storageLayout",
                "evm.methodIdentifiers",
                # Tests and scripts are out of scope by definition (SPEC §9.3) and are
                # routinely the largest thing in a repository. Not compiling them is the
                # cheapest speed-up available.
                "--skip",
                "test",
                "script",
            ],
            cwd=root,
        )

        # Deliberately no `--json`: it prints the whole standard-JSON output, every
        # dependency AST included — 321 MB on a real protocol, versus ~1 KB of console
        # output for the same build. Everything it carried is written to `out/` anyway;
        # only the diagnostics need recovering, and those are on the console.
        console = f"{stdout}\n{stderr}"
        result.diagnostics = parse_text_diagnostics(console)
        result.notes.extend(parse_tool_messages(console))

        out_dir = root / _out_dir(repo)
        if out_dir.is_dir():
            _collect_artifacts(repo, run_dir, out_dir, result)

        # Artifacts on disk mean partial output is usable — a repo where one file fails to
        # compile is the normal case, not an aborted run.
        result.ok = bool(result.contracts)

        if not result.contracts:
            reason = (
                f"forge build exceeded the build timeout (exit {code})"
                if code == TIMEOUT_RETURNCODE
                else stderr.strip().splitlines()[0]
                if stderr.strip()
                else f"forge build produced no artifacts (exit {code})"
            )
            result.notes.append(reason[:400])

        return result


def _out_dir(repo: RepoModel) -> str:
    profile = (repo.config_raw.get("foundry.toml") or {}).get("profile") or {}
    default = profile.get("default") or {}
    return str(default.get("out") or "out")


def _parse_json(text: str) -> dict | None:
    """`forge build --json` prints one JSON object, sometimes after unrelated log lines."""
    stripped = text.strip()
    if not stripped:
        return None
    start = stripped.find("{")
    if start == -1:
        return None
    try:
        return json.loads(stripped[start:])
    except json.JSONDecodeError:
        return None


def _read_sources(repo: RepoModel, root: Path) -> dict[str, str]:
    sources: dict[str, str] = {}
    for source_file in repo.files:
        path = root / source_file.path
        if path.is_file():
            sources[source_file.path] = path.read_text(encoding="utf-8", errors="replace")
    return sources


def _collect_artifacts(repo: RepoModel, run_dir: Path, out_dir: Path, result: BuildResult) -> None:
    """Walk `out/**/*.json`, keeping only artifacts that map back to a repository file."""
    in_scope = {f.path: f.in_scope for f in repo.files}
    seen_sources: dict[str, dict] = {}

    for artifact_path in sorted(out_dir.rglob("*.json")):
        if "build-info" in artifact_path.parts:
            continue
        try:
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(artifact, dict) or "abi" not in artifact:
            continue

        ast = artifact.get("ast") or {}
        source_path = normalize_path(ast.get("absolutePath") or "")
        if not source_path:
            source_path = _source_from_metadata(artifact)
        if source_path not in in_scope:
            continue  # generated or out-of-repo artifact — not ours to describe

        name = artifact_path.stem
        result.contracts.append(
            build_contract_artifact(source_path, name, artifact, in_scope[source_path])
        )

        # ASTs only for code that will be audited. Forge emits one per compiled file, which
        # on a real protocol is 537 files / 43 MB — of which 87 are in scope. The Parser is
        # tree-sitter-primary (SPEC §12.1), so a dependency's *compiler* AST is enrichment
        # of code that is never audited: the most expensive thing here, for the least use.
        if ast and in_scope[source_path] and source_path not in seen_sources:
            seen_sources[source_path] = ast

        if result.solc_version is None:
            result.solc_version = _solc_version(artifact)
        if not result.settings.remappings:
            result.settings = _settings(artifact)

    for source_path in sorted(seen_sources):
        result.sources.append(write_ast(run_dir, source_path, seen_sources[source_path]))

    result.contracts.sort(key=lambda c: c.id)


def _source_from_metadata(artifact: dict) -> str:
    """Fall back to `metadata.settings.compilationTarget` when no AST was emitted."""
    metadata = artifact.get("metadata") or {}
    target = (metadata.get("settings") or {}).get("compilationTarget") or {}
    for path in target:
        return normalize_path(path)
    return ""


def _solc_version(artifact: dict) -> str | None:
    metadata = artifact.get("metadata") or {}
    version = (metadata.get("compiler") or {}).get("version")
    return str(version) if version else None


def _settings(artifact: dict) -> CompilerSettings:
    settings = (artifact.get("metadata") or {}).get("settings") or {}
    optimizer = settings.get("optimizer") or {}
    remappings = settings.get("remappings") or []
    return CompilerSettings(
        optimizer_enabled=optimizer.get("enabled"),
        optimizer_runs=optimizer.get("runs"),
        evm_version=settings.get("evmVersion"),
        via_ir=settings.get("viaIR"),
        remappings=sorted(str(r) for r in remappings),
    )
