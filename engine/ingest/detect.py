"""Step 2: `ProjectKind` detection (SPEC §9.2).

| Signal                                | Kind    | Confidence |
|---------------------------------------|---------|------------|
| `foundry.toml` present                | FOUNDRY | high       |
| `hardhat.config.{js,ts}` present      | HARDHAT | high       |
| both present                          | FOUNDRY | high — prefer Foundry, record a note |
| `package.json` with a `hardhat` dep   | HARDHAT | medium     |
| only `*.sol` files                    | RAW     | parse-only: no build, no Slither-with-compile |
| no `*.sol` files                      | fatal   | — (enforced by the reader, after enumeration) |

Detection is deterministic and reads configuration **as text**. A `hardhat.config.js` is
arbitrary JavaScript; it is never executed.
"""

from __future__ import annotations

import json
from pathlib import Path

from engine.core.models.repo import ProjectKind

FOUNDRY_MARKER = "foundry.toml"
HARDHAT_MARKERS = (
    "hardhat.config.js",
    "hardhat.config.ts",
    "hardhat.config.cjs",
    "hardhat.config.mjs",
)

# How deep below the root to look for a marker before giving up. Monorepos routinely put
# the contracts package one or two levels down (`packages/contracts/foundry.toml`).
MAX_MARKER_DEPTH = 2

# Never descend into these when hunting for markers — a Hardhat dependency inside
# node_modules must not make the *project* Hardhat.
SKIP_DIRS = {"node_modules", "lib", ".git", "out", "cache", "artifacts", "vendor", "external"}


def _find_marker(root: Path, names: tuple[str, ...] | str) -> Path | None:
    """Breadth-first, depth-bounded, deterministic search for a marker file."""
    wanted = (names,) if isinstance(names, str) else names
    frontier = [(root, 0)]
    while frontier:
        directory, depth = frontier.pop(0)
        for name in wanted:
            candidate = directory / name
            if candidate.is_file():
                return candidate
        if depth >= MAX_MARKER_DEPTH:
            continue
        for child in sorted(p for p in directory.iterdir() if p.is_dir()):
            if child.name in SKIP_DIRS or child.name.startswith("."):
                continue
            frontier.append((child, depth + 1))
    return None


def _package_json_has_hardhat(root: Path) -> Path | None:
    """A `hardhat` entry in package.json dependencies — medium-confidence signal."""
    for candidate in (root / "package.json",):
        if not candidate.is_file():
            continue
        try:
            data = json.loads(candidate.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue
        for section in ("dependencies", "devDependencies"):
            deps = data.get(section) or {}
            if not isinstance(deps, dict):
                continue
            if any(key == "hardhat" or key.startswith("@nomic") for key in deps):
                return candidate
    return None


def detect_kind(root: Path) -> tuple[ProjectKind, dict[str, Path], list[str]]:
    """Detect the project kind.

    Returns ``(kind, markers, notes)`` where ``markers`` maps a marker name to its path so
    the config extractor does not have to search for the same files again.
    """
    notes: list[str] = []
    markers: dict[str, Path] = {}

    foundry = _find_marker(root, FOUNDRY_MARKER)
    hardhat = _find_marker(root, HARDHAT_MARKERS)

    if foundry:
        markers["foundry.toml"] = foundry
    if hardhat:
        markers["hardhat.config"] = hardhat

    if foundry and hardhat:
        notes.append(
            "both foundry.toml and hardhat.config are present — treating the project as "
            "FOUNDRY (SPEC §9.2)"
        )
        _note_if_nested(root, foundry, notes)
        return ProjectKind.FOUNDRY, markers, notes

    if foundry:
        _note_if_nested(root, foundry, notes)
        return ProjectKind.FOUNDRY, markers, notes

    if hardhat:
        _note_if_nested(root, hardhat, notes)
        return ProjectKind.HARDHAT, markers, notes

    package_json = _package_json_has_hardhat(root)
    if package_json:
        markers["package.json"] = package_json
        notes.append(
            "no hardhat.config found; detected HARDHAT from a hardhat dependency in "
            "package.json (medium confidence)"
        )
        return ProjectKind.HARDHAT, markers, notes

    # No build config at all. Whether this is RAW or fatal depends on whether any Solidity
    # exists, which the reader decides after enumeration.
    return ProjectKind.RAW, markers, notes


def _note_if_nested(root: Path, marker: Path, notes: list[str]) -> None:
    rel = marker.relative_to(root).as_posix()
    if "/" in rel:
        notes.append(f"project marker found below the repository root: {rel}")
