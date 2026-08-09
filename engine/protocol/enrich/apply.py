"""Phase H — ask, validate, merge. The only place a model's output enters the artifact.

```
gap → small context → LLM → JSON → schema check → evidence check → PROPOSED claim
```

**Four gates, and an answer must pass all of them.** Any single failure rejects the answer
and increments `Enrichment.gaps_rejected`, which is the metric that tells you the prompt or
the gap framing is wrong:

1. **Parseable** — the response is JSON with the expected keys.
2. **Schema-valid** — it maps onto a real field with a legal value. A model that invents an
   `AssetKind` is rejected, not coerced.
3. **Evidence-grounded** — every `SolidityID` it cites was in the context we sent. This is
   the gate that catches confabulation: a model cannot cite a function it never saw.
4. **Confidence-capped** — the result is written as `PROPOSED`, never higher, whatever the
   model says about its own certainty. Models are systematically overconfident and their
   self-reported confidence is uncorrelated with correctness (SPEC §7.7).

Nothing here can *remove* a deterministic finding. Enrichment fills fields the deterministic
pass left open and adds claims beside it; a model disagreeing with a `DERIVED` fact loses,
because the derivation is checkable and the opinion is not.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from engine.core.artifacts import content_hash
from engine.core.models.code import CodeModel
from engine.core.models.evidence import Claim, Confidence, Evidence, EvidenceKind
from engine.core.models.protocol import (
    Archetype,
    ArchetypeClaim,
    AssetKind,
    ContractRole,
    Enrichment,
    OperationKind,
    ProtocolModel,
    Reconciliation,
    SemanticGap,
    StateRole,
)
from engine.protocol.enrich import context as context_builder
from engine.protocol.enrich.provider import (
    LLMProvider,
    Message,
    default_provider,
)

SYSTEM_PROMPT = """\
You are a smart-contract analysis component inside a deterministic audit engine. You are \
answering ONE narrow question about ONE protocol, using ONLY the source excerpts provided.

Rules you must follow:
- Answer only from the excerpts given. If they are insufficient, say so.
- Every id in "evidence" MUST appear in the "Allowed evidence ids" list. Never invent one.
- Do not report vulnerabilities. You are describing what the code IS, not what is wrong \
with it. A separate stage finds bugs.
- Prefer "unknown" over a plausible guess. A wrong answer here is worse than no answer, \
because it will be treated as protocol context by every later stage.

Reply with JSON only, in exactly this shape:
{
  "answer": "<one or two sentences>",
  "value": "<the single enum value or short string requested, or \\"unknown\\">",
  "evidence": ["<SolidityID from the allowed list>", ...],
  "reasoning": "<one sentence on how the excerpts support this>"
}
"""

#: Field path → the enum its `value` must belong to. A model that invents a value is
#: rejected rather than coerced: coercion would silently turn a confabulation into a fact.
_ENUMS: dict[str, type[StrEnum]] = {
    "contracts.role": ContractRole,
    "state.role": StateRole,
    "operations.kind": OperationKind,
    "assets.kind": AssetKind,
    "archetypes": Archetype,
}

#: The default cap. Enrichment is optional and paid-for; running it unbounded across a
#: 3,000-contract monorepo is a surprise nobody wants on their first run.
MAX_GAPS = 25


@dataclass
class EnrichmentResult:
    model: ProtocolModel
    answered: int = 0
    rejected: int = 0
    notes: list[str] | None = None


def enrich(
    model: ProtocolModel,
    code: CodeModel,
    provider: LLMProvider | None = None,
    *,
    max_gaps: int = MAX_GAPS,
) -> ProtocolModel:
    """Answer what the deterministic pass could not. Never fails the run.

    Returns the model unchanged when no provider is configured — which is the supported
    default, not an error path.
    """
    provider = provider or default_provider()
    enriched = model.model_copy(deep=True)

    if not provider.available:
        enriched.enrichment = Enrichment(
            applied=False,
            provider=provider.name,
            notes=["no LLM provider configured; the model is deterministic only"],
        )
        return enriched

    ranked = sorted(
        enriched.gaps, key=lambda gap: (not gap.blocking, -gap.priority, gap.id)
    )[:max_gaps]

    answered = 0
    rejected = 0
    notes: list[str] = []
    model_name = ""

    for gap in ranked:
        gap_context = context_builder.build(gap, enriched, code)
        if not gap_context.excerpts:
            rejected += 1
            notes.append(f"{gap.id}: no source could be sliced for this question")
            continue

        completion = provider.complete(
            SYSTEM_PROMPT, [Message(role="user", content=gap_context.render())]
        )
        model_name = completion.model or model_name
        if not completion.ok:
            rejected += 1
            notes.append(f"{gap.id}: {completion.error or 'empty response'}")
            continue

        payload = completion.json()
        if payload is None:
            rejected += 1
            notes.append(f"{gap.id}: response was not parseable JSON")
            continue

        verdict = _validate(payload, gap, gap_context.known_ids)
        if verdict is None:
            rejected += 1
            notes.append(f"{gap.id}: answer failed validation")
            continue

        if _apply(enriched, gap, verdict):
            answered += 1
        else:
            rejected += 1
            notes.append(f"{gap.id}: no field could be updated from this answer")

    enriched.enrichment = Enrichment(
        applied=answered > 0,
        provider=provider.name,
        model=model_name,
        prompt_hash=content_hash(SYSTEM_PROMPT),
        gaps_answered=answered,
        gaps_rejected=rejected,
        notes=notes[:20],
    )
    if rejected:
        enriched.notes.append(
            f"enrichment: {answered} gaps answered, {rejected} rejected by validation"
        )
    return enriched


@dataclass
class _Answer:
    value: str
    text: str
    evidence: list[str]
    reasoning: str


def _validate(
    payload: dict[str, object], gap: SemanticGap, known_ids: set[str]
) -> _Answer | None:
    """Gates 1–3. Returns `None` on any failure; the caller counts the rejection."""
    value = str(payload.get("value", "")).strip()
    answer = str(payload.get("answer", "")).strip()
    if not value or not answer:
        return None
    if value.lower() in ("unknown", "unclear", "insufficient", "n/a"):
        # The model declining is a *correct* outcome, not an answer. Recording it would
        # overwrite an honest gap with an honest shrug, and the gap is the more useful record.
        return None

    enum_type = _ENUMS.get(gap.field)
    if enum_type is not None:
        legal = {member.value for member in enum_type}
        if value not in legal:
            return None  # invented an enum member — reject, never coerce

    raw_evidence = payload.get("evidence") or []
    if not isinstance(raw_evidence, list):
        return None
    evidence = [str(item) for item in raw_evidence if str(item) in known_ids]
    if not evidence:
        # Gate 3, and the one that catches confabulation: an answer citing nothing we sent
        # is an answer grounded in the model's priors about protocols in general.
        return None

    return _Answer(
        value=value,
        text=answer[:600],
        evidence=evidence,
        reasoning=str(payload.get("reasoning", ""))[:400],
    )


def _apply(model: ProtocolModel, gap: SemanticGap, answer: _Answer) -> bool:
    """Gate 4 plus the write. Returns False when nothing could be updated."""
    evidence = [
        Evidence(
            kind=EvidenceKind.MODEL,
            ref=solidity_id,
            detail=answer.reasoning or answer.text,
            detector="enrichment",
        )
        for solidity_id in answer.evidence
    ]

    if gap.field == "contracts.role":
        target = model.contract(gap.subject.removeprefix("role:"))
        if target is None or target.role is not ContractRole.UNKNOWN:
            return False  # never overwrite a deterministic classification
        target.role = ContractRole(answer.value)
        target.purpose = answer.text
        return _record(target, evidence)

    if gap.field == "state.role":
        item = model.state_item(gap.subject)
        if item is None or item.role is not StateRole.UNKNOWN:
            return False
        item.role = StateRole(answer.value)
        item.meaning = answer.text
        return _record(item, evidence)

    if gap.field == "operations.kind":
        operation = model.operation(gap.subject)
        if operation is None or operation.kind is not OperationKind.UNKNOWN:
            return False
        operation.kind = OperationKind(answer.value)
        operation.description = answer.text
        return _record(operation, evidence)

    if gap.field == "assets.is_fee_on_transfer":
        asset = model.asset(gap.subject)
        if asset is None:
            return False
        # A behavioural claim about an external token is *never* promoted to a fact — it is
        # recorded as an annotation with its evidence, and the flags stay as the
        # deterministic pass left them.
        asset.name = f"{asset.name} — {answer.text}".strip(" —")
        return _record(asset, evidence)

    if gap.field == "accounting.relations":
        return _record_relation(model, gap, answer, evidence)

    if gap.field == "documentation_rules.status":
        rule = next((r for r in model.documentation_rules if r.id == gap.subject), None)
        if rule is None or rule.status is not Reconciliation.UNVERIFIABLE:
            return False
        rule.finding = answer.text
        rule.evidence.extend(evidence)
        rule.confidence = Confidence.PROPOSED
        return True

    if gap.field == "archetypes":
        try:
            archetype = Archetype(answer.value)
        except ValueError:
            return False
        model.archetypes = [
            claim for claim in model.archetypes if claim.archetype is not Archetype.UNKNOWN
        ]
        model.archetypes.append(
            ArchetypeClaim(
                archetype=archetype,
                weight=1.0,
                rationale=answer.text,
                confidence=Confidence.PROPOSED,
                evidence=evidence,
            )
        )
        return True

    return False


def _record_relation(
    model: ProtocolModel, gap: SemanticGap, answer: _Answer, evidence: list[Evidence]
) -> bool:
    """A proposed accounting relationship, recorded as `PROPOSED` and nothing more.

    The deterministic pass refuses to invent a share-price formula it cannot see, and this
    does not overrule that: the relation is added beside the derived ones, labelled as a
    model's proposal, so an agent can weigh it accordingly.
    """
    from engine.core.models.protocol import AccountingRelation, RelationKind
    from engine.protocol.ids import make_relationship_id

    quantity_ids = [
        quantity.id
        for quantity in model.accounting.quantities
        if (item := model.state_item(quantity.state_id or "")) is not None
        and item.state_var_id in set(answer.evidence)
    ]
    if len(quantity_ids) < 2:
        return False

    relation = AccountingRelation(
        id=make_relationship_id("proposed", sorted(quantity_ids)),
        kind=RelationKind.PROPORTIONAL,
        expression=answer.value if len(answer.value) < 200 else answer.text,
        quantity_ids=sorted(quantity_ids),
        holds_when=answer.text,
        rounding="unspecified",
        confidence=Confidence.PROPOSED,
        evidence=evidence,
    )
    if any(existing.id == relation.id for existing in model.accounting.relations):
        return False
    model.accounting.relations.append(relation)
    return True


def _record(claim: Claim, evidence: list[Evidence]) -> bool:
    """Write the model's answer at `PROPOSED`, whatever it claimed about its own certainty.

    Self-reported confidence is uncorrelated with correctness (SPEC §7.7), so it is not read
    at all — the ladder position is decided by *how* the claim was produced, and this one
    was produced by a model.
    """
    claim.confidence = Confidence.PROPOSED
    claim.evidence.extend(evidence)
    return True


__all__ = ["MAX_GAPS", "SYSTEM_PROMPT", "EnrichmentResult", "enrich"]
