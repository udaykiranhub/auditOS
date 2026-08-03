"""Console diagnostic parsing (SPEC §10).

`forge build --json` writes the whole standard-JSON output — every dependency AST — to
stdout: 321 MB on a real protocol, against ~1 KB of ordinary console output for the same
build. Dropping `--json` means the diagnostics have to be recovered from the console
instead, which is what these tests pin down.
"""

from __future__ import annotations

from engine.core.models.build import DiagnosticSeverity
from engine.ingest.build.base import parse_text_diagnostics, parse_tool_messages

# Real `forge build` output, trimmed.
FORGE_STDERR = """\
Error: Compiler run failed:
Error (6275): Source "@dex/core/src/IPool.sol" not found: File not found.
ParserError: Source "@dex/core/src/IPool.sol" not found: File not found.
 --> lib/periphery/src/Manager.sol:2:1:
  |
2 | import {IPool} from "@dex/core/src/IPool.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Warning (2018): Function state mutability can be restricted to pure
 --> src/Vault.sol:14:5:
   |
14 |     function ping() public view returns (uint256) {
   |     ^ (Relevant source part starts here and spans across multiple lines).
"""


def test_errors_and_warnings_are_recovered_with_their_locations():
    diagnostics = parse_text_diagnostics(FORGE_STDERR)

    assert len(diagnostics) == 2

    error = next(d for d in diagnostics if d.severity is DiagnosticSeverity.ERROR)
    assert error.error_code == "6275"
    assert error.path == "lib/periphery/src/Manager.sol"
    assert error.line == 2
    assert error.column == 1
    assert "not found" in error.message

    warning = next(d for d in diagnostics if d.severity is DiagnosticSeverity.WARNING)
    assert warning.error_code == "2018"
    assert warning.path == "src/Vault.sol"
    assert warning.line == 14


def test_the_compiler_run_failed_wrapper_is_not_a_diagnostic():
    """`Error: Compiler run failed:` restates the real error on the next line."""
    assert all(
        not d.message.startswith("Compiler run failed")
        for d in parse_text_diagnostics(FORGE_STDERR)
    )


def test_repeated_diagnostics_are_deduplicated():
    """solc repeats an unresolved-import error once per import that triggered it."""
    repeated = "\n".join(['Error (6275): Source "x.sol" not found: File not found.'] * 5)
    assert len(parse_text_diagnostics(repeated)) == 1


def test_a_diagnostic_without_a_location_is_still_reported():
    [diagnostic] = parse_text_diagnostics("Error (1878): SPDX license identifier not provided")

    assert diagnostic.severity is DiagnosticSeverity.ERROR
    assert diagnostic.path is None
    assert diagnostic.line is None


def test_ordinary_build_chatter_produces_nothing():
    noise = "Compiling 2 files with Solc 0.8.35\nSolc 0.8.35 finished in 186.60ms\n"
    assert parse_text_diagnostics(noise) == []


# ── forge's own failures are not the code's failures ──────────────────────────

# `forge build` runs its linter, and a lint failure is reported in the same shape as a
# compiler error. Treating it as one downgraded a fully successful build — 598 contracts,
# 537 ASTs, 186 storage layouts — to "partial" behind a BUILD_DEGRADED banner.
FORGE_LINT_FAILURE = """\
Compiling 537 files with Solc 0.8.35
Solc 0.8.35 finished in 96.32s
Error: Lint failed
"""


def test_a_forge_lint_failure_is_not_a_compiler_diagnostic():
    assert parse_text_diagnostics(FORGE_LINT_FAILURE) == []


def test_a_forge_lint_failure_is_still_reported_as_a_note():
    """P6: a failed subsystem is stated, never silently omitted — it just isn't an error."""
    assert parse_tool_messages(FORGE_LINT_FAILURE) == ["Lint failed"]


def test_a_coded_diagnostic_is_never_treated_as_a_tool_message():
    assert parse_tool_messages(FORGE_STDERR) == []


def test_a_located_but_uncoded_diagnostic_is_kept_as_a_diagnostic():
    text = "Error: something the compiler disliked\n --> src/Vault.sol:3:1:\n"

    [diagnostic] = parse_text_diagnostics(text)
    assert diagnostic.path == "src/Vault.sol"
    assert parse_tool_messages(text) == []


def test_output_is_sorted_for_determinism():
    text = """\
Warning (2018): later
 --> src/Z.sol:9:1:
Warning (2018): earlier
 --> src/A.sol:1:1:
"""
    paths = [d.path for d in parse_text_diagnostics(text)]
    assert paths == sorted(paths)
