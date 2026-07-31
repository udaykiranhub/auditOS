"""Step 5: configuration extraction (SPEC §9.1).

* `foundry.toml` → `src`, `out`, `libs`, `solc` version, remappings. Parsed with the
  standard-library `tomllib`.
* `remappings.txt` → merged over the `foundry.toml` remappings.
* `hardhat.config.{js,ts}` → **read as text, never executed.** It is arbitrary JavaScript.
  Conservative regexes recover `solidity.version` and `paths.sources`; anything uncertain
  is left empty and the raw text is stored instead of a guess.

The `libs` value matters beyond configuration: it tells scope classification which
directories are actually dependency roots for *this* project, rather than guessing.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from engine.core.models.repo import ProjectKind

# Hardhat config text is stored verbatim for later inspection; cap it so a generated or
# bundled config cannot bloat the artifact.
MAX_CONFIG_TEXT_BYTES = 64 * 1024

_REMAPPING_RE = re.compile(r"^\s*([^=\s]+)\s*=\s*(.+?)\s*$")
_HARDHAT_VERSION_RE = re.compile(r"""version\s*:\s*["']([^"']+)["']""")
_HARDHAT_SOURCES_RE = re.compile(r"""sources\s*:\s*["']([^"']+)["']""")
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")


class RepoConfig:
    """Normalized project configuration — the reader's view of foundry/hardhat settings."""

    def __init__(self) -> None:
        self.src: str | None = None
        self.out: str | None = None
        self.libs: tuple[str, ...] = ()
        self.remappings: dict[str, str] = {}
        self.solidity_version: str | None = None
        self.solidity_version_source: str | None = None
        self.raw: dict = {}
        self.notes: list[str] = []


# ── Foundry ───────────────────────────────────────────────────────────────────

def parse_remappings_text(text: str) -> dict[str, str]:
    """Parse ``from=to`` remapping lines, ignoring blanks and ``#`` comments."""
    remappings: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _REMAPPING_RE.match(stripped)
        if match:
            remappings[match.group(1)] = match.group(2)
    return remappings


def _load_foundry(config: RepoConfig, foundry_toml: Path, repo_root: Path) -> None:
    try:
        data = tomllib.loads(foundry_toml.read_text(encoding="utf-8", errors="replace"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        config.notes.append(f"foundry.toml could not be parsed ({type(exc).__name__}); ignoring it")
        return

    config.raw["foundry.toml"] = data
    config.raw["foundry_toml_path"] = foundry_toml.relative_to(repo_root).as_posix()

    profile = (data.get("profile") or {}).get("default") or {}
    config.src = profile.get("src")
    config.out = profile.get("out")

    libs = profile.get("libs")
    if isinstance(libs, list):
        config.libs = tuple(str(lib).strip("./") for lib in libs if isinstance(lib, str))

    for key in ("solc", "solc_version"):
        value = profile.get(key)
        if isinstance(value, str) and value:
            config.solidity_version = value
            config.solidity_version_source = "foundry.toml"
            break

    inline = profile.get("remappings")
    if isinstance(inline, list):
        for entry in inline:
            if isinstance(entry, str) and "=" in entry:
                left, right = entry.split("=", 1)
                config.remappings[left.strip()] = right.strip()

    # remappings.txt sits next to foundry.toml and takes precedence over the inline list.
    remappings_txt = foundry_toml.parent / "remappings.txt"
    if remappings_txt.is_file():
        config.remappings.update(
            parse_remappings_text(remappings_txt.read_text(encoding="utf-8", errors="replace"))
        )
        config.raw["remappings_txt_path"] = remappings_txt.relative_to(repo_root).as_posix()


# ── Hardhat ───────────────────────────────────────────────────────────────────

def _load_hardhat(config: RepoConfig, hardhat_config: Path, repo_root: Path) -> None:
    text = hardhat_config.read_text(encoding="utf-8", errors="replace")

    config.raw["hardhat_config_path"] = hardhat_config.relative_to(repo_root).as_posix()
    config.raw["hardhat_config_text"] = text[:MAX_CONFIG_TEXT_BYTES]
    if len(text) > MAX_CONFIG_TEXT_BYTES:
        config.raw["hardhat_config_truncated"] = True

    versions = _HARDHAT_VERSION_RE.findall(text)
    if len(set(versions)) == 1:
        config.solidity_version = versions[0]
        config.solidity_version_source = "hardhat.config"
    elif versions:
        # Multi-compiler setups are common. Guessing which one applies to which file is
        # the Build phase's job, not the Reader's.
        config.notes.append(
            f"hardhat.config declares {len(set(versions))} solc versions; "
            "leaving solidity_version unset (see config_raw)"
        )

    sources = _HARDHAT_SOURCES_RE.search(text)
    if sources:
        config.src = sources.group(1).strip("./")


# ── Pragma fallback ───────────────────────────────────────────────────────────

def solidity_version_from_pragmas(sources: list[tuple[str, str]]) -> str | None:
    """Most common ``pragma solidity`` across in-scope files; ties break alphabetically.

    RAW projects have no configuration at all, and leaving `solidity_version` empty would
    force the Build phase to guess. Reading the pragma is deterministic and cheap.
    """
    counts: dict[str, int] = {}
    for _, stripped in sources:
        match = _PRAGMA_RE.search(stripped)
        if match:
            pragma = " ".join(match.group(1).split())
            counts[pragma] = counts.get(pragma, 0) + 1
    if not counts:
        return None
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


# ── Entry point ───────────────────────────────────────────────────────────────

def extract_config(repo_root: Path, kind: ProjectKind, markers: dict[str, Path]) -> RepoConfig:
    """Build the normalized configuration for a detected project."""
    config = RepoConfig()

    if kind is ProjectKind.FOUNDRY and "foundry.toml" in markers:
        _load_foundry(config, markers["foundry.toml"], repo_root)
    elif kind is ProjectKind.HARDHAT and "hardhat.config" in markers:
        _load_hardhat(config, markers["hardhat.config"], repo_root)
    elif kind is ProjectKind.HARDHAT and "package.json" in markers:
        config.raw["package_json_path"] = markers["package.json"].relative_to(repo_root).as_posix()

    # A root remappings.txt is valid even without foundry.toml.
    root_remappings = repo_root / "remappings.txt"
    if root_remappings.is_file() and "remappings_txt_path" not in config.raw:
        config.remappings.update(
            parse_remappings_text(root_remappings.read_text(encoding="utf-8", errors="replace"))
        )
        config.raw["remappings_txt_path"] = "remappings.txt"

    return config
