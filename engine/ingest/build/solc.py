"""Direct-solc builder — the RAW path and the universal fallback (SPEC §10.1).

```
solc --standard-json  <  {language, sources: {path: {content}}, settings: {...}}
```

Used when there is no Foundry project (RAW), when `forge` is unavailable or fails, and as
the default for Hardhat — because compiling through Hardhat means executing the project's
JavaScript (see `hardhat.py`).

Sources are passed as **content**, not as URLs: it sidesteps `--allow-paths`, base-path
and Windows path-separator issues entirely, and it makes the compilation input a pure
function of the `RepoModel`.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from pathlib import Path

from engine.core.models.build import CompilerSettings
from engine.core.models.ids import normalize_path
from engine.core.models.repo import RepoModel
from engine.ingest.build.base import (
    Builder,
    BuildResult,
    build_contract_artifact,
    line_index,
    normalize_diagnostics,
    run_command,
    write_ast,
)

CONTRACT_OUTPUTS = [
    "abi",
    "evm.methodIdentifiers",
    "evm.bytecode.object",
    "evm.deployedBytecode.object",
    "storageLayout",
]
FILE_OUTPUTS = ["ast"]

_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def output_selection(repo: RepoModel) -> dict[str, dict[str, list[str]]]:
    """Ask solc for output only where the pipeline will use it.

    Dependencies still have to be **compiled** — they carry the types and base contracts
    the in-scope code resolves against — but nothing downstream reads their storage
    layout, ABI or AST. Requesting output per file rather than under a `"*"` wildcard
    skips code generation for the other 97% of a real protocol, which is most of the
    compiler's work and nearly all of the output size.
    """
    selection = {
        source.path: {"*": CONTRACT_OUTPUTS, "": FILE_OUTPUTS}
        for source in repo.files
        if source.in_scope
    }
    # Nothing in scope should be impossible (the Reader is fatal on an empty repo), but a
    # scope_override could produce it — and a build with no requested output is useless.
    return selection or {"*": {"*": CONTRACT_OUTPUTS, "": FILE_OUTPUTS}}


def resolve_remappings(repo: RepoModel) -> tuple[list[str], list[str]]:
    """The remapping set to compile with, and any notes about where it came from.

    `forge remappings` is authoritative when Foundry is present: it merges the profile's
    remappings with the ones auto-derived from `lib/`, *including context-scoped entries
    for nested dependencies* (`lib/v4-periphery:@uniswap/v4-core/=…`). Those nested
    mappings are invisible in `foundry.toml`, and without them a dependency's own imports
    do not resolve — which surfaces as dozens of "Source not found" errors that look like
    missing code rather than missing configuration.
    """
    from engine.core.models.repo import ProjectKind

    configured = [f"{key}={value}" for key, value in sorted(repo.remappings.items())]
    if repo.kind is not ProjectKind.FOUNDRY:
        return configured, []

    code, stdout, _ = run_command(["forge", "remappings"], Path(repo.root), timeout=60)
    if code != 0 or not stdout.strip():
        return configured, ["forge remappings unavailable; using foundry.toml only"]

    derived = sorted({line.strip() for line in stdout.splitlines() if "=" in line})
    merged = sorted(set(derived) | set(configured))
    return merged, [f"remappings resolved via `forge remappings` ({len(merged)} entries)"]


class SolcBuilder(Builder):
    name = "solc"

    def available(self, repo: RepoModel) -> bool:
        return find_solc(repo.solidity_version) is not None

    def build(self, repo: RepoModel, run_dir: Path) -> BuildResult:
        result = BuildResult()
        root = Path(repo.root)

        binary = find_solc(repo.solidity_version)
        if binary is None:
            result.notes.append("no solc binary found (install one with solc-select)")
            return result

        sources = {
            source.path: (root / source.path).read_text(encoding="utf-8", errors="replace")
            for source in repo.files
            if (root / source.path).is_file()
        }
        if not sources:
            result.notes.append("no readable Solidity sources")
            return result

        remappings, remapping_notes = resolve_remappings(repo)
        result.notes.extend(remapping_notes)

        standard_input = {
            "language": "Solidity",
            "sources": {path: {"content": text} for path, text in sorted(sources.items())},
            "settings": {
                "remappings": remappings,
                "outputSelection": output_selection(repo),
            },
        }

        code, stdout, stderr = run_command(
            [str(binary), "--standard-json"],
            cwd=root,
            stdin=json.dumps(standard_input),
        )

        if not stdout.strip():
            result.notes.append(
                f"solc produced no output (exit {code}): {stderr.strip()[:400] or 'no stderr'}"
            )
            return result

        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            result.notes.append("solc returned output that is not valid JSON")
            return result

        result.solc_version = _version_of(binary)
        result.settings = CompilerSettings(
            remappings=standard_input["settings"]["remappings"],  # type: ignore[index]
        )
        result.diagnostics = normalize_diagnostics(payload.get("errors") or [], line_index(sources))

        in_scope = {f.path: f.in_scope for f in repo.files}

        for raw_path, entry in sorted((payload.get("sources") or {}).items()):
            path = normalize_path(raw_path)
            if path in in_scope and entry.get("ast"):
                result.sources.append(write_ast(run_dir, path, entry["ast"]))

        for raw_path, contracts in sorted((payload.get("contracts") or {}).items()):
            path = normalize_path(raw_path)
            if path not in in_scope:
                continue
            for name, artifact in sorted(contracts.items()):
                result.contracts.append(
                    build_contract_artifact(path, name, artifact, in_scope[path])
                )

        result.contracts.sort(key=lambda c: c.id)
        result.ok = bool(result.contracts)
        return result


# ── Binary discovery ──────────────────────────────────────────────────────────

def solc_select_root() -> Path:
    return Path(os.environ.get("SOLC_SELECT_HOME", Path.home() / ".solc-select")) / "artifacts"


def installed_solc_versions() -> dict[tuple[int, int, int], Path]:
    """Every solc that solc-select has already downloaded, newest last."""
    versions: dict[tuple[int, int, int], Path] = {}
    root = solc_select_root()
    if not root.is_dir():
        return versions

    for directory in sorted(root.iterdir()):
        match = _VERSION_RE.search(directory.name)
        if not match or not directory.is_dir():
            continue
        version = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        for candidate in (directory / directory.name, directory / f"{directory.name}.exe"):
            if candidate.is_file():
                versions[version] = candidate
                break
    return versions


def find_solc(pragma: str | None = None) -> Path | None:
    """Pick a solc binary, preferring one that satisfies the project's pragma.

    Order: an installed solc-select build matching the pragma → the newest installed
    build → a `solc` on PATH → the venv's solc-select shim.
    """
    installed = installed_solc_versions()

    if installed:
        floor = _pragma_floor(pragma)
        if floor is not None:
            exact = [v for v in installed if v[:2] == floor[:2] and v >= floor]
            if exact:
                return installed[max(exact)]
        return installed[max(installed)]

    on_path = shutil.which("solc")
    if on_path:
        return Path(on_path)

    shim = Path(sys.executable).parent / ("solc.exe" if os.name == "nt" else "solc")
    return shim if shim.is_file() else None


def _pragma_floor(pragma: str | None) -> tuple[int, int, int] | None:
    """The lowest version a pragma admits — `^0.8.20` → (0, 8, 20)."""
    if not pragma:
        return None
    match = _VERSION_RE.search(pragma)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def _version_of(binary: Path) -> str | None:
    code, stdout, _ = run_command([str(binary), "--version"], cwd=binary.parent, timeout=30)
    if code != 0:
        return None
    match = re.search(r"Version:\s*(\S+)", stdout)
    return match.group(1) if match else None
