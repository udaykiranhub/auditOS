"""Phase I — the only stage that can promote an invariant to `VERIFIED`.

Every other stage reasons about what should hold. This one runs `forge` and finds out.
Optional, off by default, and honest about what it cannot check: an invariant that does not
translate into a mechanical assertion stays `CANDIDATE`, because a generated test that
asserts an approximation would produce a confident `FAIL` on correct code.
"""

from __future__ import annotations

from engine.protocol.verify.forge import VerificationRun, available, verify

__all__ = ["VerificationRun", "available", "verify"]
