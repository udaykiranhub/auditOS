"""The stage pipeline — `CodeModel + GraphModel + RepoModel → ProtocolModel` (SPEC §8).

```
1 discovery → 2 roles → 3 standards → 4 actors → 5 boundaries → 6 assets → 7 flows
→ 8 operations → 9 state → 10 transitions → 11 dependencies → 12 accounting
→ 13 economics → 14 documentation → 15 invariants → 16 gaps → 17 assemble
```

**Order is a dependency order, not a preference.** Standards run before roles because a
confirmed ERC-4626 is the strongest role signal there is. Assets run before flows because a
flow moves an asset. Accounting runs before invariants because a candidate invariant is a
relation someone asserted should hold. Reordering does not produce a worse model — it
produces an empty one, because each stage reads what the last emitted.

**No LLM, no API key, no network.** Every stage here is a deterministic function of the
upstream artifacts. What cannot be answered deterministically becomes a `SemanticGap`
(stage 16), which is the input to the optional Phase H enrichment pass. That split is what
makes "did the model help?" a measurable question rather than an article of faith.

Failure is **Fatal** (SPEC §8): nothing downstream works without this artifact. But a
*sparse* model is not a failure — a protocol we understood poorly is a legitimate outcome,
reported honestly in `Coverage`, and still worth auditing.
"""

from __future__ import annotations

from pathlib import Path

from engine.core.errors import FatalError
from engine.core.models.code import CodeModel
from engine.core.models.graph import GraphModel
from engine.core.models.protocol import ARTIFACT_NAME, ProtocolIdentity, ProtocolModel
from engine.core.models.repo import RepoModel
from engine.protocol.assemble import finalize, new_model, save
from engine.protocol.heuristics import (
    accounting as accounting_stage,
)
from engine.protocol.heuristics import (
    actors as actors_stage,
)
from engine.protocol.heuristics import (
    assets as assets_stage,
)
from engine.protocol.heuristics import (
    boundaries as boundaries_stage,
)
from engine.protocol.heuristics import (
    dependencies as dependencies_stage,
)
from engine.protocol.heuristics import (
    docs as docs_stage,
)
from engine.protocol.heuristics import (
    economics as economics_stage,
)
from engine.protocol.heuristics import (
    flows as flows_stage,
)
from engine.protocol.heuristics import (
    gaps as gaps_stage,
)
from engine.protocol.heuristics import (
    invariants as invariants_stage,
)
from engine.protocol.heuristics import (
    operations as operations_stage,
)
from engine.protocol.heuristics import (
    roles as roles_stage,
)
from engine.protocol.heuristics import (
    standards as standards_stage,
)
from engine.protocol.heuristics import (
    state as state_stage,
)
from engine.protocol.heuristics import (
    summary as summary_stage,
)
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_protocol_id


class UnderstandCode:
    """Stable failure codes — part of the CLI/API contract."""

    NO_CONTRACTS = "PROTOCOL_NO_CONTRACTS"


def understand(
    code: CodeModel, graph: GraphModel, repo: RepoModel | None = None
) -> ProtocolModel:
    """Run all seventeen stages. Deterministic; no network access of any kind."""
    if not code.in_scope_contracts:
        raise FatalError(
            "No in-scope contracts to interpret.",
            code=UnderstandCode.NO_CONTRACTS,
            hint="Every contract was classified as a test, mock or dependency. Re-run "
            "ingest with --include to force something into scope.",
        )

    index = ProtocolIndex(code, graph)
    model = new_model(repo, code, graph)
    model.identity = _identity(repo, code, index)

    # ── 3 → 2 → 1. Standards first: a confirmed ERC-4626 is the strongest role signal ──
    model.standards = standards_stage.detect(index)
    model.contracts = roles_stage.classify(index, model.standards)
    model.archetypes = roles_stage.archetypes(model.contracts)
    model.components = roles_stage.components(index, model.contracts)

    # ── 4–5. Who acts, and where the trust domains meet ───────────────────────
    model.actors = actors_stage.detect(index, model.contracts)
    model.trust_boundaries = boundaries_stage.detect(index, model.contracts, model.actors)
    # An outbound boundary names a counterparty that must exist as an actor, or the
    # reference dangles. Minted only when such a boundary was actually found.
    model.actors.extend(boundaries_stage.extra_actors(model.trust_boundaries))

    # ── 6. Assets — before flows, because a flow moves one ────────────────────
    model.assets = assets_stage.detect(index, model.contracts, model.standards)

    # ── 9. State — before operations, which reference state items ─────────────
    model.state = state_stage.detect(index, model.contracts, model.assets)

    # ── 8. Operations, then 7 flows and 10 transitions hung off them ──────────
    model.operations = operations_stage.detect(
        index, model.contracts, model.actors, model.assets, model.state, model.components
    )
    model.asset_flows = flows_stage.detect(index, model.operations, model.assets, model.contracts)
    model.state_transitions = state_stage.transitions(index, model.operations, model.state)
    operations_stage.link(model.operations, model.asset_flows, model.state_transitions)

    model.entrypoints = sorted({o.function_id for o in model.operations})
    model.privileged = sorted({o.function_id for o in model.operations if o.is_privileged})

    # ── 11. External dependencies ─────────────────────────────────────────────
    model.dependencies = dependencies_stage.detect(index, model.contracts)

    # ── 12–13. Accounting, then the economics built on it ─────────────────────
    model.accounting = accounting_stage.detect(index, model.state, model.assets, model.operations)
    model.economics = economics_stage.detect(
        index, model.operations, model.accounting, model.assets, model.contracts
    )
    model.risk_surfaces = economics_stage.risk_surfaces(
        index, model.operations, model.contracts, model.economics, model.dependencies
    )

    # ── 14. What the docs claim, and whether the code agrees ──────────────────
    model.documentation_rules = docs_stage.detect(index, repo, model)

    # ── 15. Candidate invariants, and what they rest on ───────────────────────
    model.assumptions = invariants_stage.assumptions(index, model)
    model.invariants = invariants_stage.detect(index, model)
    economics_stage.link_invariants(model.risk_surfaces, model.invariants)

    # ── 16. Honest about what is missing ──────────────────────────────────────
    model.gaps = gaps_stage.detect(index, model)
    model.core_contracts = _core_contracts(index, model)
    model.summary = summary_stage.write(model)
    model.coverage.unmodelled = _unmodelled(index, graph)

    # ── 17. Assemble ──────────────────────────────────────────────────────────
    return finalize(model, code)


def understand_and_save(
    code: CodeModel, graph: GraphModel, run_dir: Path, repo: RepoModel | None = None
) -> tuple[ProtocolModel, Path]:
    """`understand` + persist to ``run/<run_id>/artifacts/protocol.json``."""
    return save(understand(code, graph, repo), run_dir)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _identity(
    repo: RepoModel | None, code: CodeModel, index: ProtocolIndex | None = None
) -> ProtocolIdentity:
    name = _name_of(repo, code, index)
    return ProtocolIdentity(
        id=make_protocol_id(name),
        name=name,
        origin=repo.origin if repo else "",
        solidity_version=repo.solidity_version if repo else None,
        description=_readme_lede(repo.readme if repo else None),
    )


def _name_of(
    repo: RepoModel | None, code: CodeModel, index: ProtocolIndex | None = None
) -> str:
    """The protocol's name, best-effort.

    A README's first heading is the most reliable source a repository offers. The fallback
    is the **most central audited contract**, not the first one in the list: file order is
    alphabetical, so "first" reliably picks an interface like `IERC20` and names the whole
    protocol after a dependency.
    """
    if repo is not None and repo.readme:
        for line in repo.readme.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                heading = stripped.lstrip("#").strip()
                if heading:
                    return heading

    if index is not None and index.audited:
        ranked = sorted(
            index.audited, key=lambda c: (-index.centrality_of(c.id), c.id)
        )
        return ranked[0].name

    contracts = code.in_scope_contracts
    return contracts[0].name if contracts else "unknown"


def _readme_lede(readme: str | None) -> str:
    """The first real paragraph — verbatim, never summarized.

    A paraphrase here would be an unattributed interpretation sitting in a field that reads
    like a quotation, which is exactly the confusion the evidence model exists to prevent.
    """
    if not readme:
        return ""
    paragraph: list[str] = []
    for line in readme.splitlines():
        stripped = line.strip()
        if stripped.startswith(("#", "!", "[![", "|", "```", "---")):
            if paragraph:
                break
            continue
        if not stripped:
            if paragraph:
                break
            continue
        paragraph.append(stripped)
    return " ".join(paragraph)[:1000]


def _core_contracts(index: ProtocolIndex, model: ProtocolModel) -> list[str]:
    """Ranked most-central first — drives context selection (SPEC §7.6).

    PageRank alone ranks a widely-used math library above the vault everyone deposits into,
    so a contract that was actually classified into a role gets a multiplier. The ranking
    exists to answer "where should an agent look first", and the answer is never SafeMath.
    """
    scored: list[tuple[float, str]] = []
    for classification in model.contracts:
        weight = index.centrality_of(classification.contract_id)
        if classification.role.value != "unknown":
            weight *= 2.0
        if classification.holds_funds:
            weight *= 1.5
        scored.append((weight, classification.contract_id))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [contract_id for _, contract_id in scored]


def _unmodelled(index: ProtocolIndex, graph: GraphModel) -> list[str]:
    """Named blind spots. Silence here would read as completeness.

    Sourced from the Graph Engine's own `unresolved` list rather than re-derived, so the
    two artifacts cannot disagree about what was not seen.
    """
    by_reason: dict[str, int] = {}
    for item in graph.unresolved:
        by_reason[item.reason] = by_reason.get(item.reason, 0) + 1

    gaps: list[str] = []
    if count := by_reason.get("UNRESOLVED_ASSEMBLY_ACCESS"):
        gaps.append(
            f"{count} functions use inline assembly; storage and calls made in Yul are "
            "invisible to every stage of this model"
        )
    if count := by_reason.get("UNRESOLVED_DELEGATECALL"):
        gaps.append(
            f"{count} delegatecall sites target a runtime value; the implementation's "
            "behaviour is not modelled here"
        )
    if count := by_reason.get("UNRESOLVED_PARENT"):
        gaps.append(
            f"{count} contracts inherit a parent absent from the repository; their "
            "inherited members are invisible to standards and role detection"
        )
    if count := by_reason.get("UNRESOLVED_EXTERNAL_CALL"):
        gaps.append(f"{count} external calls have an untypeable receiver")
    interfaces = len(index.interfaces)
    if interfaces:
        gaps.append(
            f"{interfaces} interfaces describe external code whose implementation is not "
            "in this repository and therefore not audited"
        )
    return gaps


__all__ = ["ARTIFACT_NAME", "UnderstandCode", "understand", "understand_and_save"]
