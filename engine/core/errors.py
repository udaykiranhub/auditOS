"""Error taxonomy for the engine (SPEC §7, P6: fail loud in the core, soft at the edge).

Two kinds of failure, and only two:

* :class:`FatalError`   — the pipeline cannot continue. Raised by the deterministic core
  (Repo Reader, Parser, Graph Engine, Validation, Report). The run stops.
* :class:`DegradedError` — a subsystem failed but the audit remains possible. Recorded on
  the artifact and surfaced in the report's "Coverage & Limitations" section. Never
  silently swallowed.

Every error carries a stable machine-readable ``code`` so the API, the CLI and the tests
can branch on the failure without string-matching a message that will be reworded.
"""

from __future__ import annotations


class AuditOSError(Exception):
    """Base class for every error the engine raises deliberately."""

    code: str = "AUDITOS_ERROR"

    def __init__(self, message: str, *, code: str | None = None, hint: str | None = None):
        self.message = message
        if code is not None:
            self.code = code
        self.hint = hint
        super().__init__(message)

    def __str__(self) -> str:
        base = f"[{self.code}] {self.message}"
        return f"{base}\n  hint: {self.hint}" if self.hint else base


class FatalError(AuditOSError):
    """The run cannot continue. Surfaces to the user as a clean message, never a traceback."""

    code = "FATAL"


class DegradedError(AuditOSError):
    """A subsystem failed; the audit continues with a recorded gap."""

    code = "DEGRADED"


# ── Stable failure codes ───────────────────────────────────────────────────────
# Keep these in sync with the tests; they are part of the CLI/API contract.

class IngestCode:
    """Failure codes emitted by the Repository Reader (SPEC §9)."""

    SOURCE_NOT_FOUND = "INGEST_SOURCE_NOT_FOUND"
    UNSUPPORTED_SOURCE = "INGEST_UNSUPPORTED_SOURCE"
    NO_SOLIDITY_FILES = "INGEST_NO_SOLIDITY_FILES"
    ZIP_INVALID = "INGEST_ZIP_INVALID"
    ZIP_SLIP = "INGEST_ZIP_SLIP"
    ZIP_TOO_LARGE = "INGEST_ZIP_TOO_LARGE"
    ZIP_TOO_MANY_ENTRIES = "INGEST_ZIP_TOO_MANY_ENTRIES"
    ZIP_UNSAFE_ENTRY = "INGEST_ZIP_UNSAFE_ENTRY"
    GIT_CLONE_FAILED = "INGEST_GIT_CLONE_FAILED"
    COPY_FAILED = "INGEST_COPY_FAILED"
