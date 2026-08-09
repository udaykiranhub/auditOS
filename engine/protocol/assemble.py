"""Stage 17 — assemble, label, measure, validate, hash, write.

```
stages 1–16 fill a ProtocolModel  →  finalize()  →  protocol.json
```

Every stage from Phase B onward appends to a `ProtocolModel` and hands it on. This module
is the only place that closes one out, and it does five things in a fixed order because
each depends on the last:

1. **canonicalize** — one deterministic order, evidence deduped (`order.py`).
2. **label** — `INV-001…` assigned over that order, so labels are stable for a given
   protocol rather than dependent on which detector ran first.
3. **measure** — `Coverage`, computed from the model rather than reported by the stages
   that filled it. A stage counting its own coverage always finds it excellent.
4. **validate** — fatal on structural corruption, notes on epistemic gaps.
5. **hash** — `content_hash` over the finished payload.

Hashing last is not stylistic: labels, coverage and notes are all part of the artifact, so
a hash computed before them would identify a document that was never written.
"""

from __future__ import annotations

from pathlib import Path

from engine.core.artifacts import load_artifact, save_artifact
from engine.core.models.code import CodeModel, ContractKind
from engine.core.models.graph import GraphModel
from engine.core.models.protocol import (
    ARTIFACT_NAME,
    ContractRole,
    Coverage,
    ProtocolModel,
    StateRole,
)
from engine.core.models.repo import RepoModel
from engine.protocol.ids import invariant_label
from engine.protocol.order import canonicalize
from engine.protocol.validate import validate


def new_model(
    repo: RepoModel | None = None,
    code: CodeModel | None = None,
    graph: GraphModel | None = None,
) -> ProtocolModel:
    """An empty `ProtocolModel` wired to the artifacts it will be built from.

    The three input hashes are recorded up front so a `ProtocolModel` is never ambiguous
    about which parse and which graph it describes — the check `_code_notes` performs, and
    the key the resume cache uses.
    """
    return ProtocolModel(
        repo_content_hash=repo.content_hash if repo else "",
        code_content_hash=code.content_hash if code else "",
        graph_content_hash=graph.content_hash if graph else "",
    )


def finalize(model: ProtocolModel, code: CodeModel | None = None) -> ProtocolModel:
    """Close out a `ProtocolModel`: order it, label it, measure it, check it, hash it.

    Pure — the input model is not mutated, so a stage may keep working with its own copy.
    """
    ordered = canonicalize(model)
    ordered = _assign_labels(ordered)
    ordered.coverage = measure(ordered, code)
    ordered.notes = _dedupe_notes([*ordered.notes, *validate(ordered, code)])
    return ordered.with_content_hash()


def save(model: ProtocolModel, run_dir: Path) -> tuple[ProtocolModel, Path]:
    """`finalize` is the caller's job — this only writes, so an unvalidated model cannot
    reach disk by accident and a finalized one is never re-hashed on the way out."""
    return model, save_artifact(model, run_dir, ARTIFACT_NAME)


def load(path: Path) -> ProtocolModel:
    return load_artifact(ProtocolModel, path)


# ── Steps ─────────────────────────────────────────────────────────────────────


def _assign_labels(model: ProtocolModel) -> ProtocolModel:
    """`INV-001`, `INV-002`, … over the canonical order.

    Assigned here, at the end, rather than when each invariant is minted: a label handed out
    at mint time depends on detector execution order, which would renumber the whole set
    whenever a detector is added. The stable identity is `Invariant.id`; this is the
    citation humans read in a report.
    """
    model.invariants = [
        invariant.model_copy(update={"label": invariant_label(ordinal)})
        for ordinal, invariant in enumerate(model.invariants, start=1)
    ]
    return model


def measure(model: ProtocolModel, code: CodeModel | None = None) -> Coverage:
    """Compute what the model actually managed to say.

    Counted from the finished artifact, never accumulated by the stages. The denominators
    come from `CodeModel` when it is available, because "we classified 4 contracts" means
    nothing without "out of 47".
    """
    classified = sum(1 for c in model.contracts if c.role is not ContractRole.UNKNOWN)
    explained = sum(1 for s in model.state if s.role is not StateRole.UNKNOWN)

    contracts_total = len(model.contracts)
    entrypoints_total = len(model.entrypoints)
    state_total = len(model.state)
    if code is not None:
        # Interfaces are excluded from the denominator because they are excluded from
        # classification: an interface describes a *dependency's* shape, not this
        # protocol's. Counting them makes the rate unreachable — a protocol where every
        # contract was classified would still report 50% because it imported IERC20.
        classifiable = [
            contract
            for contract in code.in_scope_contracts
            if contract.kind in (ContractKind.CONTRACT, ContractKind.ABSTRACT)
        ]
        contracts_total = len(classifiable)
        entrypoints_total = sum(len(c.entrypoints) for c in classifiable)
        state_total = sum(len(c.state_vars) for c in classifiable)

    claims = model.claims()
    grounded = sum(1 for claim in claims if claim.is_grounded)

    return Coverage(
        contracts_total=contracts_total,
        contracts_classified=classified,
        entrypoints_total=entrypoints_total,
        operations_modelled=len(model.operations),
        state_vars_total=state_total,
        state_vars_explained=explained,
        grounded_claims=grounded,
        ungrounded_claims=len(claims) - grounded,
        unmodelled=sorted(set(model.coverage.unmodelled)),
    )


def _dedupe_notes(notes: list[str]) -> list[str]:
    """Order-preserving dedupe. Two stages reporting the same blind spot is one blind spot,
    and notes are read in the order they were raised."""
    seen: set[str] = set()
    out: list[str] = []
    for note in notes:
        if note not in seen:
            seen.add(note)
            out.append(note)
    return out


__all__ = ["ARTIFACT_NAME", "finalize", "load", "measure", "new_model", "save"]
