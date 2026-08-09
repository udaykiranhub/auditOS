"""Small contexts — one gap, a few `SolidityID`s, nothing else.

```
gap  →  the exact declarations it names  →  a prompt that fits in a page
```

This is the cost-control mechanism for the whole enrichment layer, and it is also the
*correctness* mechanism. A prompt containing the whole repository invites the model to
answer from vibes about what protocols usually do; a prompt containing four declarations and
one question can only be answered from those declarations — and an answer that cites
something not in the context is detectably wrong, which is what `apply.py` checks.

So the budget here is small on purpose. If a gap needs more than this, the gap is too broad
and the fix belongs in stage 16, not in a larger budget.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from engine.core.models.code import CodeModel, Contract, Function, StateVar
from engine.core.models.protocol import ProtocolModel, SemanticGap

#: Characters of source per gap. ~4 chars/token, so roughly 1.5k tokens of code — enough for
#: a handful of declarations and one function body, and not enough to paste a contract.
MAX_CONTEXT_CHARS = 6000

#: A single function body longer than this is elided in the middle. A 900-line function is
#: not answerable from its text anyway, and truncating the *end* would hide the return.
MAX_BODY_CHARS = 1800


@dataclass
class GapContext:
    """Everything one enrichment call is allowed to see."""

    gap: SemanticGap
    excerpts: list[tuple[str, str]] = field(default_factory=list)
    """(SolidityID, source text) — the *only* code the model gets."""
    facts: list[str] = field(default_factory=list)
    """Deterministic findings relevant to the question, so the model is not asked to
    re-derive what the engine already knows."""

    @property
    def known_ids(self) -> set[str]:
        """What an answer is allowed to cite. Anything else is a fabricated reference."""
        return {solidity_id for solidity_id, _ in self.excerpts}

    def render(self) -> str:
        parts = [f"# Question\n{self.gap.question}"]
        if self.facts:
            parts.append(
                "# What the deterministic analysis already established\n"
                + "\n".join(f"- {fact}" for fact in self.facts)
            )
        if self.excerpts:
            parts.append(
                "# Source\n"
                + "\n\n".join(
                    f"## {solidity_id}\n```solidity\n{text}\n```"
                    for solidity_id, text in self.excerpts
                )
            )
        parts.append(
            "# Allowed evidence ids\n"
            + "\n".join(f"- {solidity_id}" for solidity_id in sorted(self.known_ids))
        )
        return "\n\n".join(parts)


def build(gap: SemanticGap, model: ProtocolModel, code: CodeModel) -> GapContext:
    """Slice the minimum needed to answer one question."""
    context = GapContext(gap=gap, facts=_facts(gap, model))

    budget = MAX_CONTEXT_CHARS
    for solidity_id in gap.context_ids:
        excerpt = _excerpt(solidity_id, code)
        if excerpt is None:
            continue
        text = excerpt[:budget]
        if not text:
            break
        context.excerpts.append((solidity_id, text))
        budget -= len(text)
    return context


def _excerpt(solidity_id: str, code: CodeModel) -> str | None:
    """The declaration this ID names, as source. `None` when it names nothing.

    Returning `None` rather than a placeholder matters: a context that silently contains
    "// not found" invites the model to answer anyway, and the answer would be grounded in
    nothing.
    """
    for contract in code.contracts:
        if contract.id == solidity_id:
            return _contract_sketch(contract)
        for function in (*contract.functions, *contract.modifiers):
            if function.id == solidity_id:
                return _body(function)
        for variable in contract.state_vars:
            if variable.id == solidity_id:
                return _declaration(variable, contract)
    for source in code.sources:
        for function in source.free_functions:
            if function.id == solidity_id:
                return _body(function)
    return None


def _body(function: Function) -> str:
    """The function as written, elided in the middle if it is very long.

    The middle rather than the tail: a truncated tail hides the return statement and the
    state writes that follow the loop, which is usually the part the question is about.
    """
    raw = function.raw or f"function {function.name}(...);"
    if len(raw) <= MAX_BODY_CHARS:
        return raw
    half = MAX_BODY_CHARS // 2
    return f"{raw[:half]}\n\n// … {len(raw) - MAX_BODY_CHARS} characters elided …\n\n{raw[-half:]}"


def _declaration(variable: StateVar, contract: Contract) -> str:
    modifiers = " ".join(
        part
        for part in (
            variable.visibility,
            "constant" if variable.is_constant else "",
            "immutable" if variable.is_immutable else "",
        )
        if part
    )
    return f"// in contract {contract.name}\n{variable.type} {modifiers} {variable.name};"


def _contract_sketch(contract: Contract) -> str:
    """A contract's *shape*: declaration, state, and function signatures — never bodies.

    A question about what a contract is for is answerable from its surface. Including
    bodies would blow the budget on the first contract and starve every other excerpt.
    """
    lines = [f"contract {contract.name}"]
    if contract.inherits:
        lines[0] += f" is {', '.join(contract.inherits)}"
    lines[0] += " {"
    for variable in contract.state_vars[:20]:
        lines.append(f"    {variable.type} {variable.visibility} {variable.name};")
    for function in contract.functions[:25]:
        params = ",".join(param.type for param in function.params)
        returns = ",".join(param.type for param in function.returns)
        suffix = f" returns ({returns})" if returns else ""
        modifiers = " ".join(function.modifiers)
        lines.append(
            f"    function {function.name}({params}) {function.visibility} "
            f"{function.mutability} {modifiers}{suffix};".replace("  ", " ")
        )
    lines.append("}")
    return "\n".join(lines)


def _facts(gap: SemanticGap, model: ProtocolModel) -> list[str]:
    """What the engine already knows about this subject.

    Supplied so the model answers the open question rather than re-deriving — and
    re-deriving *differently from* — what the deterministic pass already established.
    """
    facts: list[str] = []
    subject = gap.subject

    if (classification := model.contract(subject.removeprefix("role:"))) is not None:
        facts.append(f"role detected: {classification.role.value}")
        facts.append(f"holds funds: {classification.holds_funds}")
    if (item := model.state_item(subject)) is not None:
        facts.append(f"type: {item.type}")
        facts.append(f"written by {len(item.writers)} functions, read by {len(item.readers)}")
    if (operation := model.operation(subject)) is not None:
        facts.append(f"visibility: {'privileged' if operation.is_privileged else 'open'}")
        facts.append(f"writes {len(operation.writes)} state items")
        if operation.preconditions:
            facts.append(f"guards: {'; '.join(operation.preconditions[:3])}")
    if (asset := model.asset(subject)) is not None:
        facts.append(f"asset kind: {asset.kind.value}")
        facts.append(f"protocol-issued: {asset.is_protocol_issued}")

    if model.archetypes:
        facts.append(f"protocol archetype: {', '.join(model.archetype[:3])}")
    return facts


__all__ = ["MAX_BODY_CHARS", "MAX_CONTEXT_CHARS", "GapContext", "build"]
