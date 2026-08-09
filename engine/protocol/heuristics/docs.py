"""Stage 14 — what the documentation claims, and whether the code agrees.

```
README: "Only the owner can pause the protocol."
code:   pause() has no modifier
                                     →  CONFLICTS
```

A documented promise the code breaks is the highest-signal record this artifact can hold: it
is a finding with the *intent* already established, which is the part a security agent
normally has to argue for.

**Only normative sentences are extracted.** "Shares represent proportional ownership" is a
rule; "this repo uses Foundry" is not. A rule set diluted with prose makes reconciliation
meaningless, because almost everything will trivially "agree" and the one real conflict is
lost in the noise. The filter is modal verbs plus a subject the model already knows about —
if a sentence names nothing in the `ProtocolModel`, it cannot be reconciled and is dropped
rather than carried as `UNVERIFIABLE` clutter.

Reconciliation itself is deliberately narrow. Only claims decidable from the model are
checked: who can call something, what is pausable, what is upgradeable, whether a named
function exists. Everything else is `UNVERIFIABLE`, which is honest, and becomes a
`SemanticGap` for the enrichment pass rather than a guess.
"""

from __future__ import annotations

import re

from engine.core.models.evidence import Confidence, doc_evidence, source_evidence
from engine.core.models.protocol import (
    DocumentationRule,
    ProtocolModel,
    Reconciliation,
    TrustLevel,
)
from engine.core.models.repo import RepoModel
from engine.protocol.heuristics.signatures import ProtocolIndex
from engine.protocol.ids import make_doc_rule_id

DETECTOR = "documentation"

#: A sentence is normative when it says something *must*, *should*, or *only* holds. Without
#: this filter every README paragraph becomes a "rule" and the stage reports nothing useful.
NORMATIVE = re.compile(
    r"\b(must|must not|should|should never|shall|cannot|can only|only\s+the|only\s+a|"
    r"is required to|are required to|guarantees?|ensures?|always|never|no one|nobody)\b",
    re.IGNORECASE,
)

#: Sentences about the repository rather than the protocol. Excluded before anything else.
BOILERPLATE = re.compile(
    r"\b(install|npm|yarn|forge install|clone|licen[cs]e|contribut|audit report|"
    r"disclaimer|test suite|run the tests|documentation is|see the docs)\b",
    re.IGNORECASE,
)

_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n{2,}")

MAX_RULES = 60
MIN_SENTENCE_CHARS = 25


def detect(
    index: ProtocolIndex, repo: RepoModel | None, model: ProtocolModel
) -> list[DocumentationRule]:
    """Extract normative statements from README and NatSpec, then reconcile each."""
    rules: dict[str, DocumentationRule] = {}
    subjects = _subject_index(model)

    if repo is not None and repo.readme:
        for rule in _from_text(repo.readme, "README.md", "readme", subjects):
            rules.setdefault(rule.id, rule)

    for rule in _from_natspec(index, subjects):
        rules.setdefault(rule.id, rule)

    ordered = list(rules.values())[:MAX_RULES]
    for rule in ordered:
        _reconcile(rule, index, model)
    return ordered


def _from_text(
    text: str, path: str, source_kind: str, subjects: dict[str, list[str]]
) -> list[DocumentationRule]:
    rules: list[DocumentationRule] = []
    line_number = 1
    for block in text.split("\n"):
        line_number += 1
        for sentence in _SENTENCE.split(block):
            statement = " ".join(sentence.split())
            if len(statement) < MIN_SENTENCE_CHARS:
                continue
            if BOILERPLATE.search(statement) or not NORMATIVE.search(statement):
                continue
            matched = _subjects_of(statement, subjects)
            if not matched:
                # A rule with no subject cannot be reconciled. Carrying it would inflate the
                # count while making the stage's output less trustworthy, not more.
                continue
            rules.append(
                DocumentationRule(
                    id=make_doc_rule_id(path, statement),
                    statement=statement[:400],
                    source_path=path,
                    source_kind=source_kind,
                    line=line_number,
                    subject_ids=matched,
                    confidence=Confidence.STATED,
                    evidence=[doc_evidence(path, statement[:300], "documented rule",
                                           line=line_number)],
                )
            )
    return rules


def _from_natspec(
    index: ProtocolIndex, subjects: dict[str, list[str]]
) -> list[DocumentationRule]:
    """NatSpec is documentation written *at* the code, so its subject is already known."""
    rules: list[DocumentationRule] = []
    for contract in index.audited:
        for function in contract.functions:
            if not function.natspec:
                continue
            for sentence in _SENTENCE.split(function.natspec):
                statement = " ".join(sentence.replace("///", " ").replace("*", " ").split())
                if len(statement) < MIN_SENTENCE_CHARS or not NORMATIVE.search(statement):
                    continue
                rules.append(
                    DocumentationRule(
                        id=make_doc_rule_id(function.id, statement),
                        statement=statement[:400],
                        source_path=contract.path,
                        source_kind="natspec",
                        line=function.line_start,
                        subject_ids=[function.id],
                        confidence=Confidence.STATED,
                        evidence=[
                            source_evidence(
                                function.id,
                                "NatSpec on this function",
                                path=contract.path,
                                line=function.line_start,
                                excerpt=statement[:300],
                                detector=DETECTOR,
                            )
                        ],
                    )
                )
    return rules


def _subject_index(model: ProtocolModel) -> dict[str, list[str]]:
    """lowercased name → the IDs it could refer to.

    Names, not IDs, because documentation says "the Vault", never
    "src/Vault.sol:Vault". Short names are excluded: matching "fee" would attach half the
    README to one variable.
    """
    index: dict[str, list[str]] = {}
    for classification in model.contracts:
        if len(classification.name) > 3:
            index.setdefault(classification.name.lower(), []).append(
                classification.contract_id
            )
    for operation in model.operations:
        if len(operation.name) > 3:
            index.setdefault(operation.name.lower(), []).append(operation.function_id)
    for item in model.state:
        if len(item.name) > 4:
            index.setdefault(item.name.lower(), []).append(item.state_var_id)
    return index


def _subjects_of(statement: str, subjects: dict[str, list[str]]) -> list[str]:
    lowered = statement.lower()
    found: set[str] = set()
    for name, ids in subjects.items():
        if re.search(rf"\b{re.escape(name)}\b", lowered):
            found.update(ids)
    return sorted(found)[:6]


# ── Reconciliation ────────────────────────────────────────────────────────────


def _reconcile(rule: DocumentationRule, index: ProtocolIndex, model: ProtocolModel) -> None:
    """Check the claims that are decidable; be explicit about the ones that are not."""
    lowered = rule.statement.lower()

    if checked := _check_access(rule, lowered, model):
        rule.status, rule.finding = checked
        return
    if checked := _check_existence(rule, index):
        rule.status, rule.finding = checked
        return
    if checked := _check_upgradeability(rule, lowered, model):
        rule.status, rule.finding = checked
        return

    rule.status = Reconciliation.UNVERIFIABLE
    rule.finding = "no deterministic check applies to this statement"


def _check_access(
    rule: DocumentationRule, lowered: str, model: ProtocolModel
) -> tuple[Reconciliation, str] | None:
    """"Only the owner can X" — check that X is actually gated.

    The highest-value check in the module, because an unenforced access claim is an
    access-control finding with the documentation as its intent evidence.
    """
    if not re.search(r"\bonly\s+(the\s+)?(owner|admin|governance|governor|guardian)\b", lowered):
        return None

    operations = [
        operation
        for operation in model.operations
        if operation.function_id in rule.subject_ids
    ]
    if not operations:
        return None

    ungated = [o for o in operations if not o.is_privileged]
    if ungated:
        return (
            Reconciliation.CONFLICTS,
            "documentation restricts this to a privileged caller, but "
            + ", ".join(o.function_id for o in ungated[:3])
            + " carries no access-control modifier",
        )

    untrusted = [
        o
        for o in operations
        for actor_id in o.actor_ids
        if (actor := model.actor(actor_id)) is not None
        and actor.trust is TrustLevel.UNTRUSTED
    ]
    if untrusted:
        return (
            Reconciliation.CONFLICTS,
            "documentation restricts this to a privileged caller, but an untrusted actor "
            "can reach it",
        )
    return (Reconciliation.AGREES, "the named functions are gated by a privileged modifier")


def _check_existence(
    rule: DocumentationRule, index: ProtocolIndex
) -> tuple[Reconciliation, str] | None:
    """A rule whose subject was resolved to a function that is not implemented."""
    missing = [
        subject
        for subject in rule.subject_ids
        if (function := index.functions.get(subject)) is not None
        and not function.is_implemented
    ]
    if missing:
        return (
            Reconciliation.UNIMPLEMENTED,
            f"{', '.join(missing[:3])} is declared but has no implementation here",
        )
    return None


def _check_upgradeability(
    rule: DocumentationRule, lowered: str, model: ProtocolModel
) -> tuple[Reconciliation, str] | None:
    """"The contracts are immutable / non-upgradeable" versus a proxy in the code."""
    claims_immutable = re.search(
        r"\b(immutable|not upgradeable|non-upgradeable|cannot be upgraded)\b", lowered
    )
    if not claims_immutable:
        return None
    upgradeable = [
        c.contract_id
        for c in model.contracts
        if c.is_upgradeable and c.contract_id in rule.subject_ids
    ]
    if upgradeable:
        return (
            Reconciliation.CONFLICTS,
            f"documentation claims immutability but {', '.join(upgradeable[:3])} "
            "sits behind an upgrade mechanism",
        )
    return (Reconciliation.AGREES, "no upgrade mechanism was detected on the named contracts")


__all__ = ["BOILERPLATE", "NORMATIVE", "detect"]
