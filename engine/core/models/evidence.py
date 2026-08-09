"""Evidence and confidence — how every semantic claim justifies itself (Protocol Model §16).

```
fact  →  where did it come from?  →  how certain is it?
```

`CodeModel` and `GraphModel` state facts: this function exists, that edge resolves. The
Protocol Model states *interpretations*: this contract is a vault, that variable is a share
supply, this operation mints. An interpretation without a trail back to code is a guess
wearing the costume of a fact, and a guess that reaches an agent becomes a hallucinated
finding two phases later.

So every interpretive field in `protocol.py` inherits :class:`Claim`, which forces two
questions to be answered inline:

* **:class:`Confidence`** — a ladder, not a float. A model that reports `0.83` is reporting
  a number it made up; `INFERRED` versus `DERIVED` is a statement about *method* that a
  reviewer can check. (`Finding.confidence` stays a float because SPEC §7.7 says the
  validator computes it from corroboration — a different thing entirely.)
* **:class:`Evidence`** — a pointer, not prose. A `SolidityID`, a graph edge, a doc span,
  a detector name. `Evidence.detector` records *which rule fired*, so a wrong claim is
  traceable to the code that produced it rather than to a vibe.

This module is shared with `findings.py`: the chain a `Finding` cites is the same chain a
`ProtocolModel` claim cites, so they must be the same type.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field


class Confidence(StrEnum):
    """How a claim was arrived at. Ordered by :attr:`rank`, weakest first.

    The distinction that matters most in practice is `DERIVED` vs `INFERRED`:

    * `DERIVED`  — a documented rule over `CodeModel`/`GraphModel` that is *right by
      construction*. "`deposit` writes `totalAssets`" is derived: the WRITES edge exists.
    * `INFERRED` — a heuristic, usually over names or signatures. "A function called
      `deposit` is a deposit" is inferred, and `deposit` in a governance contract is where
      it breaks.

    Downstream ranking treats them very differently, so a detector that blurs the two costs
    more than one that reports `INFERRED` honestly.
    """

    REFUTED = "refuted"
    """An explicit check disagreed. Kept, never deleted — a refuted claim is a fact about
    the protocol and stops the same wrong guess being re-proposed."""

    PROPOSED = "proposed"
    """Produced by a model and not yet corroborated (Phase H). Never promoted by assertion."""

    INFERRED = "inferred"
    """A heuristic — names, signatures, conventional shapes. Plausible, falsifiable."""

    DERIVED = "derived"
    """Computed by a documented deterministic rule over an upstream artifact."""

    STATED = "stated"
    """Read literally from an authoritative source: the code, solc's output, a NatSpec tag."""

    VERIFIED = "verified"
    """An independent check confirmed it — compiler output, ERC compliance, a Forge run."""

    @property
    def rank(self) -> int:
        return _RANKS[self]

    @property
    def is_grounded(self) -> bool:
        """True when the claim rests on something checkable rather than on a guess."""
        return self.rank >= Confidence.DERIVED.rank

    @classmethod
    def weakest(cls, *values: Confidence) -> Confidence:
        """Combine confidences the only sound way: a chain is as strong as its weakest link.

        A `DERIVED` operation over an `INFERRED` asset is an `INFERRED` fact. Propagating the
        *stronger* value — or averaging — is how a naming guess launders itself into a
        certainty by the time an agent reads it.
        """
        if not values:
            return cls.INFERRED
        return min(values, key=lambda value: value.rank)


_RANKS: dict[Confidence, int] = {
    Confidence.REFUTED: 0,
    Confidence.PROPOSED: 1,
    Confidence.INFERRED: 2,
    Confidence.DERIVED: 3,
    Confidence.STATED: 4,
    Confidence.VERIFIED: 5,
}


class EvidenceKind(StrEnum):
    """Where a piece of evidence was read from. The provenance, not the argument."""

    SOURCE = "source"
    """A `SolidityID` and a line span in `CodeModel` — a declaration or a body."""

    GRAPH = "graph"
    """A `GraphModel` edge or a path over it, written `src --kind--> dst`."""

    DOC = "doc"
    """README, NatSpec, or a docs file. What the protocol *says* about itself."""

    BUILD = "build"
    """solc output: a storage slot, a selector, a resolved type."""

    STATIC = "static"
    """A Slither or Aderyn detector that fired."""

    HEURISTIC = "heuristic"
    """A named detector in `engine/protocol/heuristics/` matched. Weakest useful evidence:
    it says a *pattern* held, not that a fact was observed."""

    MODEL = "model"
    """An LLM response (Phase H). Carries the prompt hash so the claim is reproducible."""

    TEST = "test"
    """A Forge run (Phase I) — the only evidence kind that can justify `VERIFIED`."""


class Evidence(BaseModel):
    """One pointer back to something a reader can open and check.

    Deliberately not a free-text justification. `detail` is a single line of *what this
    shows*; the argument itself lives in the claim, and the proof lives at `ref`.
    """

    model_config = ConfigDict(extra="forbid")

    kind: EvidenceKind
    ref: str = ""
    """What it points at, in the vocabulary of `kind`: a `SolidityID` for `SOURCE`, an edge
    string for `GRAPH`, a repo-relative path for `DOC`, a detector ID for `STATIC`."""

    detail: str = ""
    """One line: what this reference demonstrates. Not a paragraph, not a conclusion."""

    path: str = ""
    line: int = 0
    line_end: int = 0
    excerpt: str = ""
    """The exact text, when short enough to be worth carrying. Never a summary of it — a
    paraphrased excerpt is indistinguishable from a fabricated one downstream."""

    detector: str = ""
    """The rule that produced this claim (`erc4626_interface`, `vault_share_accounting`).
    Makes a wrong claim traceable to a line of Python instead of to a judgement call."""

    def key(self) -> tuple[str, str, str, int, str]:
        """Deterministic sort/dedupe key. Artifact ordering is part of the contract (§7.1)."""
        return (self.kind.value, self.ref, self.path, self.line, self.detector)


class Claim(BaseModel):
    """Base for every interpretive record in the Protocol Model.

    Inheriting this is what makes "every important fact says where it came from and how
    certain it is" a *type-level* guarantee rather than a convention that erodes.
    """

    model_config = ConfigDict(extra="forbid")

    confidence: Confidence = Confidence.INFERRED
    """`INFERRED`, not `DERIVED`, on purpose: a record built without stating a confidence
    is a record nobody justified, and the default must describe that honestly. Defaulting
    to `DERIVED` would make the laziest construction path produce the stronger claim."""

    evidence: list[Evidence] = Field(default_factory=list)

    @property
    def is_grounded(self) -> bool:
        """A claim is grounded when it is both confident *and* cites something."""
        return self.confidence.is_grounded and bool(self.evidence)

    def sources(self) -> list[str]:
        """Every `SolidityID` this claim rests on, deduped and sorted."""
        return sorted({e.ref for e in self.evidence if e.kind is EvidenceKind.SOURCE and e.ref})

    def with_evidence(self, *items: Evidence) -> Self:
        """Append evidence, keeping the list deduped and canonically ordered."""
        merged = {item.key(): item for item in (*self.evidence, *items)}
        return self.model_copy(
            update={"evidence": [merged[key] for key in sorted(merged)]}
        )


def dedupe_evidence(items: list[Evidence]) -> list[Evidence]:
    """Canonical evidence list: deduped by `key()`, sorted. Two detectors finding the same
    line must not double-count as two independent corroborations."""
    merged = {item.key(): item for item in items}
    return [merged[key] for key in sorted(merged)]


def source_evidence(
    solidity_id: str,
    detail: str = "",
    *,
    path: str = "",
    line: int = 0,
    line_end: int = 0,
    detector: str = "",
    excerpt: str = "",
) -> Evidence:
    """The common case: "this claim comes from this declaration"."""
    return Evidence(
        kind=EvidenceKind.SOURCE,
        ref=solidity_id,
        detail=detail,
        path=path,
        line=line,
        line_end=line_end,
        detector=detector,
        excerpt=excerpt,
    )


def graph_evidence(
    source: str, edge_kind: str, target: str, detail: str = "", *, detector: str = ""
) -> Evidence:
    """A resolved relationship: `src --writes--> dst`. Cheap, deterministic, checkable."""
    return Evidence(
        kind=EvidenceKind.GRAPH,
        ref=f"{source} --{edge_kind}--> {target}",
        detail=detail,
        detector=detector,
    )


def doc_evidence(path: str, excerpt: str, detail: str = "", *, line: int = 0) -> Evidence:
    """What the documentation says — the input side of reconciliation (Protocol Model §14)."""
    return Evidence(
        kind=EvidenceKind.DOC, ref=path, path=path, line=line, excerpt=excerpt, detail=detail
    )


def heuristic_evidence(detector: str, detail: str, *, ref: str = "") -> Evidence:
    """A named pattern matched. Pair with `Confidence.INFERRED`, never anything higher."""
    return Evidence(kind=EvidenceKind.HEURISTIC, ref=ref, detail=detail, detector=detector)


__all__ = [
    "Claim",
    "Confidence",
    "Evidence",
    "EvidenceKind",
    "dedupe_evidence",
    "doc_evidence",
    "graph_evidence",
    "heuristic_evidence",
    "source_evidence",
]
