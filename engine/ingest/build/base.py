"""The `Builder` interface and the normalization every builder shares (SPEC §10).

Foundry, Hardhat and direct solc disagree about almost everything except the shape of a
solc artifact. So each builder's only job is to *produce* compiler output; turning that
output into a `BuildModel` happens once, here.

**Failure is degraded, never fatal.** A builder returns a `BuildResult` describing what it
managed; it does not raise to abort the pipeline.
"""

from __future__ import annotations

import re
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from engine.core.artifacts import sha256_bytes
from engine.core.models.build import (
    CompilerSettings,
    ContractArtifact,
    Diagnostic,
    DiagnosticSeverity,
    SourceUnit,
    StorageSlot,
)
from engine.core.models.ids import make_contract_id, normalize_path
from engine.core.models.repo import RepoModel

# A build compiles code from the repository under audit. It gets a hard wall-clock
# ceiling so a pathological project cannot hang the run.
BUILD_TIMEOUT_SECONDS = 600

# `timeout`'s conventional exit code, used here so a timeout is distinguishable from an
# ordinary compiler failure without inspecting the message.
TIMEOUT_RETURNCODE = 124


@dataclass
class BuildResult:
    """What a builder managed to produce. Never an exception."""

    ok: bool = False
    sources: list[SourceUnit] = field(default_factory=list)
    contracts: list[ContractArtifact] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    settings: CompilerSettings = field(default_factory=CompilerSettings)
    solc_version: str | None = None
    notes: list[str] = field(default_factory=list)


class Builder(ABC):
    """One compilation strategy."""

    name: str

    @abstractmethod
    def available(self, repo: RepoModel) -> bool:
        """Can this builder run at all — is its toolchain present?"""

    @abstractmethod
    def build(self, repo: RepoModel, run_dir: Path) -> BuildResult:
        """Compile, and return whatever came out. Must not raise."""


# ── Process helper ────────────────────────────────────────────────────────────

def run_command(
    args: list[str],
    cwd: Path,
    timeout: int = BUILD_TIMEOUT_SECONDS,
    stdin: str | None = None,
) -> tuple[int, str, str]:
    """Run a build command. Returns `(returncode, stdout, stderr)`; never raises.

    A timeout or a missing binary is reported as a non-zero return code with the reason on
    stderr, because at this layer every failure is the same kind of failure: degraded.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - argv list, never a shell string
            args,
            cwd=cwd,
            input=stdin,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
        return completed.returncode, completed.stdout or "", completed.stderr or ""
    except FileNotFoundError:
        return 127, "", f"{args[0]} is not installed or not on PATH"
    except subprocess.TimeoutExpired:
        return TIMEOUT_RETURNCODE, "", f"{args[0]} exceeded the {timeout}s build timeout"
    except OSError as exc:  # permissions, exec format, …
        return 1, "", f"{args[0]} could not be started: {exc}"


# ── solc output normalization ─────────────────────────────────────────────────

_SEVERITY = {
    "error": DiagnosticSeverity.ERROR,
    "warning": DiagnosticSeverity.WARNING,
    "info": DiagnosticSeverity.INFO,
}


def line_index(sources: dict[str, str]) -> dict[str, list[int]]:
    """Per-file newline offsets, so byte offsets can become line numbers."""
    index: dict[str, list[int]] = {}
    for path, text in sources.items():
        offsets = [0]
        for position, char in enumerate(text):
            if char == "\n":
                offsets.append(position + 1)
        index[path] = offsets
    return index


def offset_to_line_column(offsets: list[int], offset: int) -> tuple[int, int]:
    """1-indexed line and column for a byte offset. solc reports offsets, humans read lines."""
    low, high = 0, len(offsets) - 1
    while low < high:
        middle = (low + high + 1) // 2
        if offsets[middle] <= offset:
            low = middle
        else:
            high = middle - 1
    return low + 1, offset - offsets[low] + 1


def normalize_diagnostics(
    raw: list[dict],
    offsets: dict[str, list[int]] | None = None,
) -> list[Diagnostic]:
    """Turn solc's `errors` array into `Diagnostic`s, sorted for determinism."""
    result: list[Diagnostic] = []

    for entry in raw:
        location = entry.get("sourceLocation") or {}
        path = location.get("file")
        path = normalize_path(path) if path else None
        start = location.get("start", -1)

        line: int | None = None
        column: int | None = None
        if path and offsets and path in offsets and isinstance(start, int) and start >= 0:
            line, column = offset_to_line_column(offsets[path], start)

        severity = _SEVERITY.get(str(entry.get("severity", "")).lower())
        if severity is None:
            severity = (
                DiagnosticSeverity.ERROR
                if str(entry.get("type", "")).lower().endswith("error")
                else DiagnosticSeverity.WARNING
            )

        code = entry.get("errorCode")
        result.append(
            Diagnostic(
                severity=severity,
                message=str(entry.get("message", "")).strip(),
                error_code=str(code) if code is not None else None,
                path=path,
                line=line,
                column=column,
            )
        )

    result.sort(key=lambda d: (d.path or "", d.line or 0, d.error_code or "", d.message))
    return result


# solc's human-readable diagnostic format, which `forge` passes through unchanged:
#
#     Error (6275): Source "x.sol" not found: File not found.
#      --> lib/periphery/src/Manager.sol:2:1:
#
_TEXT_DIAGNOSTIC_RE = re.compile(
    r"^(?P<severity>Error|Warning|Info)(?: \((?P<code>\d+)\))?:\s+(?P<message>.+)$"
)
_TEXT_LOCATION_RE = re.compile(r"^\s*-->\s+(?P<path>.+?):(?P<line>\d+):(?P<column>\d+)")

# Wrapper lines that restate a diagnostic already captured from the line above.
_TEXT_NOISE = ("Compiler run failed", "Compilation failed")


def _scan_console(text: str) -> list[tuple[re.Match, str, str | None, int | None, int | None]]:
    """Yield `(match, message, path, line, column)` for every entry in console output."""
    found: list[tuple[re.Match, str, str | None, int | None, int | None]] = []
    lines = text.splitlines()

    for index, line in enumerate(lines):
        match = _TEXT_DIAGNOSTIC_RE.match(line.strip())
        if not match:
            continue

        message = match.group("message").strip()
        if any(message.startswith(noise) for noise in _TEXT_NOISE):
            continue

        path: str | None = None
        line_number: int | None = None
        column: int | None = None
        # The location arrow follows within a line or two of its message.
        for follower in lines[index + 1 : index + 4]:
            location = _TEXT_LOCATION_RE.match(follower)
            if location:
                path = normalize_path(location.group("path"))
                line_number = int(location.group("line"))
                column = int(location.group("column"))
                break

        found.append((match, message, path, line_number, column))

    return found


def parse_text_diagnostics(text: str) -> list[Diagnostic]:
    """Parse diagnostics out of a compiler's **console** output.

    Needed because `forge build --json` writes the entire standard-JSON output — every
    AST of every dependency — to stdout: 321 MB on a real protocol, which cost more time
    to pipe and parse than the compilation itself. Without `--json` the same information
    is on disk in `out/`, and only the diagnostics have to be recovered from the console.
    """
    diagnostics: list[Diagnostic] = []
    seen: set[tuple] = set()

    for match, message, path, line_number, column in _scan_console(text):
        # A solc diagnostic always carries an error code or a source location. Forge's own
        # tool-level failures do not — `Error: Lint failed` is the linter reporting on
        # itself, and letting it through downgraded a fully successful compilation (598
        # contracts, 537 ASTs) to "partial" with a BUILD_DEGRADED banner.
        if match.group("code") is None and path is None:
            continue

        severity = _SEVERITY.get(match.group("severity").lower(), DiagnosticSeverity.WARNING)
        key = (severity, match.group("code"), message, path, line_number)
        if key in seen:
            continue  # solc repeats a diagnostic once per import that triggered it
        seen.add(key)

        diagnostics.append(
            Diagnostic(
                severity=severity,
                message=message,
                error_code=match.group("code"),
                path=path,
                line=line_number,
                column=column,
            )
        )

    diagnostics.sort(key=lambda d: (d.path or "", d.line or 0, d.error_code or "", d.message))
    return diagnostics


def parse_tool_messages(text: str) -> list[str]:
    """Tool-level failures the build driver reported about *itself*, not about the code.

    These belong in `notes` — they are worth stating (P6: never silently omitted) but must
    not count as compiler errors, because they say nothing about whether the contracts
    compiled.
    """
    messages: list[str] = []
    for match, message, path, _line, _column in _scan_console(text):
        if match.group("code") is not None or path is not None:
            continue  # a coded or located entry is a compiler diagnostic, not a tool message
        if message not in messages:
            messages.append(message)
    return messages


def normalize_storage_layout(layout: dict | None) -> list[StorageSlot]:
    """Flatten solc's `storageLayout` into slots with their types resolved."""
    if not layout:
        return []

    types = layout.get("types") or {}
    slots: list[StorageSlot] = []

    for entry in layout.get("storage") or []:
        type_key = entry.get("type", "")
        type_info = types.get(type_key) or {}
        raw_bytes = type_info.get("numberOfBytes")
        slots.append(
            StorageSlot(
                label=entry.get("label", ""),
                slot=int(entry.get("slot", 0)),
                offset=int(entry.get("offset", 0)),
                type_label=type_info.get("label") or type_key,
                bytes_size=int(raw_bytes) if raw_bytes is not None else None,
                encoding=type_info.get("encoding"),
            )
        )

    return slots


def build_contract_artifact(
    path: str,
    name: str,
    artifact: dict,
    in_scope: bool,
) -> ContractArtifact:
    """One solc contract output → one `ContractArtifact`.

    Accepts both shapes: standard-JSON nests bytecode under `evm`, Foundry hoists it.
    """
    evm = artifact.get("evm") or {}
    bytecode = artifact.get("bytecode") or evm.get("bytecode") or {}
    deployed = artifact.get("deployedBytecode") or evm.get("deployedBytecode") or {}
    identifiers = artifact.get("methodIdentifiers") or evm.get("methodIdentifiers") or {}

    return ContractArtifact(
        id=make_contract_id(path, name),
        path=normalize_path(path),
        name=name,
        in_scope=in_scope,
        storage=normalize_storage_layout(artifact.get("storageLayout")),
        method_identifiers=dict(sorted(identifiers.items())),
        # Dependency ABIs add megabytes and no agent reasons about OpenZeppelin's
        # external interface; the flag records that the omission was a choice.
        abi=list(artifact.get("abi") or []) if in_scope else [],
        abi_omitted=not in_scope and bool(artifact.get("abi")),
        bytecode_size=_hex_size(bytecode.get("object")),
        deployed_bytecode_size=_hex_size(deployed.get("object")),
    )


def _hex_size(value: str | None) -> int | None:
    if not value:
        return None
    return len(value.removeprefix("0x")) // 2


def write_ast(run_dir: Path, path: str, ast: dict) -> SourceUnit:
    """Persist one AST beside the run and return the `SourceUnit` that points at it.

    ASTs live on disk rather than in the artifact because a single mid-size contract's
    AST is megabytes of JSON.
    """
    import json

    relative = normalize_path(path)
    target = run_dir / "build" / "ast" / f"{relative}.json"
    target.parent.mkdir(parents=True, exist_ok=True)

    payload = json.dumps(ast, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    encoded = payload.encode("utf-8")
    target.write_bytes(encoded)

    return SourceUnit(
        path=relative,
        ast_path=target.relative_to(run_dir).as_posix(),
        ast_sha256=sha256_bytes(encoded),
        ast_nodes=len(ast.get("nodes") or []),
    )
