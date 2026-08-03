"""Hardhat builder — **opt-in, because it executes the repository's JavaScript.**

`npx hardhat compile` loads `hardhat.config.js` and every plugin it requires. That is
arbitrary code from the repository under audit, running with the engine's privileges, on
the machine doing the auditing. The Repository Reader refuses to execute that same file
for exactly this reason (SPEC §9.1: *"do not execute the config file — it is arbitrary
JS. Parse it as text."*), and it would be incoherent for the next stage to shrug and run
it unprompted.

So Hardhat projects compile through direct solc by default, which needs no JavaScript at
all. This builder runs only when the operator explicitly asks for it:

```
python -m engine build <src> --allow-hardhat        # or AUDITOS_ALLOW_HARDHAT=1
```

It also requires `node_modules` to be present — Hardhat cannot compile without its
plugins, and `npm install` is emphatically not something to run on an audit target.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from engine.core.models.build import CompilerSettings
from engine.core.models.ids import normalize_path
from engine.core.models.repo import RepoModel
from engine.ingest.build.base import (
    Builder,
    BuildResult,
    build_contract_artifact,
    run_command,
    write_ast,
)

ALLOW_ENV = "AUDITOS_ALLOW_HARDHAT"


def hardhat_allowed(explicit: bool | None = None) -> bool:
    if explicit is not None:
        return explicit
    return os.environ.get(ALLOW_ENV, "").strip().lower() in {"1", "true", "yes"}


class HardhatBuilder(Builder):
    name = "hardhat"

    def __init__(self, allowed: bool | None = None) -> None:
        self.allowed = hardhat_allowed(allowed)

    def available(self, repo: RepoModel) -> bool:
        if not self.allowed:
            return False
        root = Path(repo.root)
        if not (root / "node_modules" / "hardhat").is_dir():
            return False
        code, _, _ = run_command(["npx", "--no-install", "hardhat", "--version"], root, timeout=60)
        return code == 0

    def build(self, repo: RepoModel, run_dir: Path) -> BuildResult:
        result = BuildResult()
        root = Path(repo.root)

        if not self.allowed:
            result.notes.append(
                "hardhat compile not run: it executes hardhat.config.js from the audit "
                f"target. Pass --allow-hardhat or set {ALLOW_ENV}=1 to permit it."
            )
            return result

        code, _, stderr = run_command(["npx", "--no-install", "hardhat", "compile"], cwd=root)
        if code != 0:
            result.notes.append(f"hardhat compile failed: {stderr.strip()[:400]}")

        # Hardhat writes one build-info file holding the whole standard-JSON input/output.
        build_info = sorted((root / "artifacts" / "build-info").glob("*.json"))
        if not build_info:
            result.notes.append("hardhat produced no build-info; falling back")
            return result

        in_scope = {f.path: f.in_scope for f in repo.files}

        for info_path in build_info:
            try:
                info = json.loads(info_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            result.solc_version = result.solc_version or info.get("solcLongVersion")
            output = info.get("output") or {}

            for raw_path, entry in sorted((output.get("sources") or {}).items()):
                path = normalize_path(raw_path)
                if path in in_scope and entry.get("ast"):
                    result.sources.append(write_ast(run_dir, path, entry["ast"]))

            for raw_path, contracts in sorted((output.get("contracts") or {}).items()):
                path = normalize_path(raw_path)
                if path not in in_scope:
                    continue
                for name, artifact in sorted(contracts.items()):
                    result.contracts.append(
                        build_contract_artifact(path, name, artifact, in_scope[path])
                    )

            settings = (info.get("input") or {}).get("settings") or {}
            optimizer = settings.get("optimizer") or {}
            result.settings = CompilerSettings(
                optimizer_enabled=optimizer.get("enabled"),
                optimizer_runs=optimizer.get("runs"),
                evm_version=settings.get("evmVersion"),
                remappings=sorted(str(r) for r in settings.get("remappings") or []),
            )

        result.contracts.sort(key=lambda c: c.id)
        result.ok = bool(result.contracts)
        return result
