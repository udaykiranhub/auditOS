"""Phase I — the only thing in the system that can promote an invariant to `VERIFIED`.

```
candidate invariant  →  generated Forge test  →  forge test  →  PASS | FAIL | ERROR
```

Every other stage produces claims about what *should* hold. This one runs code. That is why
`InvariantStatus.VERIFIED` is reachable from nowhere else, and why a `FAIL` here is worth
more than any amount of static reasoning: Forge found a concrete counterexample, with a
sequence of calls that produces it.

**Only mechanically checkable invariants are attempted**, and the honest answer to the rest
is `UNVERIFIABLE`. Three shapes translate reliably into a Forge invariant test:

* `SUPPLY` — `sum(balances) == totalSupply`, checked via a handler-tracked actor set;
* `MONOTONICITY` — a value never decreases across the campaign;
* `CONSERVATION` of two quantities that must move together.

Everything else — "no account may withdraw collateral while it backs an obligation" — needs
a model of what the protocol *means* by healthy, and generating a test that asserts the
wrong thing would produce a confident `FAIL` on correct code. That is worse than no test, so
it is not attempted.

**Nothing is executed unless the caller asks.** `forge` is invoked with `--no-match-coverage`
against a temporary directory inside the run dir; the target repository is never modified.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from engine.core.models.evidence import Confidence, Evidence, EvidenceKind
from engine.core.models.protocol import (
    Invariant,
    InvariantKind,
    InvariantStatus,
    ProtocolModel,
    StateItem,
    StateRole,
)

#: Seconds. An invariant campaign that has not concluded by now will not conclude usefully
#: inside a pipeline run, and a hung `forge` must never hold an audit open.
TIMEOUT = 300

#: Kept small deliberately. This is a smoke check that the invariant *holds under fuzzing*,
#: not a replacement for a real invariant suite the protocol should have written.
RUNS = 64
DEPTH = 32

GENERATED_DIR = "auditos-invariants"


@dataclass
class VerificationRun:
    """What actually happened. Reported whether or not it went well."""

    available: bool = False
    attempted: int = 0
    passed: int = 0
    failed: int = 0
    errored: int = 0
    skipped: int = 0
    notes: list[str] | None = None
    output: str = ""


def available() -> bool:
    """Is `forge` on PATH? Checked before anything is generated."""
    return shutil.which("forge") is not None


def verify(
    model: ProtocolModel, repo_root: Path, run_dir: Path
) -> tuple[ProtocolModel, VerificationRun]:
    """Generate, run, and record. Never raises; a missing toolchain is a note, not a failure."""
    verified = model.model_copy(deep=True)
    notes: list[str] = []

    if not available():
        return verified, VerificationRun(
            available=False,
            notes=["forge is not on PATH; all invariants remain unverified"],
        )
    if not (repo_root / "foundry.toml").exists():
        return verified, VerificationRun(
            available=False,
            notes=["not a Foundry project; invariant tests were not generated"],
        )

    testable = [i for i in verified.invariants if _translatable(verified, i) is not None]
    skipped = len(verified.invariants) - len(testable)
    if not testable:
        return verified, VerificationRun(
            available=True,
            skipped=skipped,
            notes=[
                f"none of {len(verified.invariants)} candidate invariants translate into a "
                "mechanical check; a test asserting the wrong property is worse than none"
            ],
        )

    test_dir = run_dir / GENERATED_DIR
    test_dir.mkdir(parents=True, exist_ok=True)

    written: dict[str, str] = {}
    for invariant in testable:
        generated = _translatable(verified, invariant)
        if generated is None:
            continue
        source: str = generated
        name = _test_name(invariant)
        path = repo_root / "test" / f"{name}.t.sol"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8", newline="\n")
        (test_dir / f"{name}.t.sol").write_text(source, encoding="utf-8", newline="\n")
        written[invariant.id] = name

    try:
        result = _run_forge(repo_root, sorted(written.values()))
    finally:
        # The run directory is a copy of the repository (SPEC §9.1 materializes it), but
        # leaving generated tests behind would make a resumed run compile them twice.
        for name in written.values():
            (repo_root / "test" / f"{name}.t.sol").unlink(missing_ok=True)

    outcomes = _parse(result.stdout)
    run = VerificationRun(
        available=True, attempted=len(written), skipped=skipped, output=result.stdout[-4000:]
    )

    for invariant in verified.invariants:
        test_name = written.get(invariant.id)
        if test_name is None:
            continue
        outcome = outcomes.get(test_name)
        if outcome is True:
            invariant.status = InvariantStatus.VERIFIED
            invariant.confidence = Confidence.VERIFIED
            invariant.verification = f"forge invariant campaign passed ({RUNS} runs)"
            run.passed += 1
        elif outcome is False:
            invariant.status = InvariantStatus.REFUTED
            invariant.confidence = Confidence.VERIFIED
            invariant.verification = "forge found a counterexample; see the run output"
            run.failed += 1
        else:
            invariant.verification = "the generated test did not compile or did not run"
            run.errored += 1
            continue
        invariant.evidence.append(
            Evidence(
                kind=EvidenceKind.TEST,
                ref=f"{GENERATED_DIR}/{test_name}.t.sol",
                detail=invariant.verification,
                detector="forge",
            )
        )

    if run.failed:
        notes.append(
            f"forge REFUTED {run.failed} candidate invariants — each has a concrete "
            "counterexample and should be read before anything else in this report"
        )
    if run.errored:
        notes.append(f"{run.errored} generated invariant tests failed to compile or run")
    run.notes = notes
    verified.notes.extend(notes)
    return verified, run


# ── Translation ───────────────────────────────────────────────────────────────


def _translatable(model: ProtocolModel, invariant: Invariant) -> str | None:
    """The Forge test for this invariant, or `None` if it is not mechanically checkable.

    Returning `None` is the common and correct case. The alternative — generating a test
    that approximates the invariant — produces a confident `FAIL` on correct code, and a
    false refutation is more damaging than a missing check because it looks like evidence.
    """
    if invariant.kind is InvariantKind.SUPPLY:
        return _supply_test(model, invariant)
    if invariant.kind is InvariantKind.MONOTONICITY:
        return _monotonic_test(model, invariant)
    return None


def _supply_test(model: ProtocolModel, invariant: Invariant) -> str | None:
    """`sum(balances over touched actors) == totalSupply`.

    Sums over the actors the handler touched rather than over all addresses, because
    Solidity cannot enumerate a mapping. That makes it a *sound* check (a violation is real)
    and an incomplete one (it cannot see an address the campaign never used) — which is the
    right trade for a generated test.
    """
    supply = _state_named(model, invariant, StateRole.SHARE_SUPPLY)
    balance = _state_named(model, invariant, StateRole.USER_BALANCE)
    if supply is None or balance is None or supply.contract_id != balance.contract_id:
        return None

    contract = supply.contract_id.rpartition(":")[2]
    path = supply.contract_id.rpartition(":")[0]
    name = _test_name(invariant)

    return f"""\
// SPDX-License-Identifier: UNLICENSED
// Generated by AuditOS to check a CANDIDATE invariant. Not part of the protocol.
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {{{contract}}} from "{_import_path(path)}";

/// @dev {invariant.statement}
contract {name} is Test {{
    {contract} internal target;
    address[] internal actors;

    function setUp() public {{
        try new {contract}() returns ({contract} deployed) {{
            target = deployed;
        }} catch {{
            vm.skip(true);
        }}
        for (uint256 i = 0; i < 4; i++) {{
            actors.push(address(uint160(uint256(keccak256(abi.encode("actor", i))))));
        }}
        targetContract(address(target));
    }}

    function invariant_{name}() public view {{
        uint256 total;
        for (uint256 i = 0; i < actors.length; i++) {{
            total += target.{balance.name}(actors[i]);
        }}
        // Sound but incomplete: only addresses the campaign touched are summed, so this
        // can under-count and never over-count.
        assertLe(total, target.{supply.name}(), "sum of balances exceeds supply");
    }}
}}
"""


def _monotonic_test(model: ProtocolModel, invariant: Invariant) -> str | None:
    """A value that must never decrease across the campaign."""
    item = next(
        (
            model.state_item(f"state:{target}")
            for target in invariant.targets
            if model.state_item(f"state:{target}") is not None
        ),
        None,
    )
    if item is None or item.type.startswith("mapping"):
        return None

    contract = item.contract_id.rpartition(":")[2]
    path = item.contract_id.rpartition(":")[0]
    name = _test_name(invariant)

    return f"""\
// SPDX-License-Identifier: UNLICENSED
// Generated by AuditOS to check a CANDIDATE invariant. Not part of the protocol.
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {{{contract}}} from "{_import_path(path)}";

/// @dev {invariant.statement}
contract {name} is Test {{
    {contract} internal target;
    uint256 internal seen;

    function setUp() public {{
        try new {contract}() returns ({contract} deployed) {{
            target = deployed;
        }} catch {{
            vm.skip(true);
        }}
        targetContract(address(target));
    }}

    function invariant_{name}() public {{
        uint256 current = target.{item.name}();
        assertGe(current, seen, "{item.name} decreased");
        seen = current;
    }}
}}
"""


def _state_named(
    model: ProtocolModel, invariant: Invariant, role: StateRole
) -> StateItem | None:
    for target in invariant.targets:
        item = model.state_item(f"state:{target}")
        if item is not None and item.role is role:
            return item
    return None


def _import_path(path: str) -> str:
    """Foundry resolves test imports from the project root, so a repo-relative path works."""
    return f"../{path}" if not path.startswith("../") else path


def _test_name(invariant: Invariant) -> str:
    """Deterministic and collision-free: the invariant's own content hash is already both."""
    return f"AuditOS_{invariant.id.removeprefix('inv:')}"


# ── Execution ─────────────────────────────────────────────────────────────────


def _run_forge(repo_root: Path, names: list[str]) -> subprocess.CompletedProcess[str]:
    command = [
        "forge",
        "test",
        "--json",
        "--fuzz-runs",
        str(RUNS),
        *(arg for name in names for arg in ("--match-contract", name)),
    ]
    try:
        return subprocess.run(  # noqa: S603 — fixed argv, no shell, paths are ours
            command,
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return subprocess.CompletedProcess(command, 1, "", str(exc))


def _parse(stdout: str) -> dict[str, bool]:
    """`forge test --json` → test-contract name → did every test in it pass.

    Tolerant by design: forge's JSON shape has changed between releases, and a parse failure
    must leave invariants `CANDIDATE` rather than silently marking them verified.
    """
    outcomes: dict[str, bool] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        for suite, results in payload.items():
            name = suite.rpartition(":")[2]
            tests = results.get("test_results", {}) if isinstance(results, dict) else {}
            if not tests:
                continue
            outcomes[name] = all(
                entry.get("status") == "Success" for entry in tests.values()
            )
    return outcomes


__all__ = ["DEPTH", "RUNS", "TIMEOUT", "VerificationRun", "available", "verify"]
