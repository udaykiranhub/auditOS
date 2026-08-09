"""`LLMProvider` — the one interface a model reaches the engine through (SPEC §4).

> **No SDK types may leak past this interface.**

That is a hard rule in SPEC's technology table and it is enforced structurally here: this
module's public surface is `Message`, `Completion`, `LLMProvider`, and two implementations.
Nothing above it imports `anthropic` or `openai`, so swapping providers, adding a cache, or
running the whole engine with no provider at all touches this file and nothing else.

**No provider is required.** `NullProvider` is the default and returns nothing, which is
what makes "V1 produces a complete `ProtocolModel` with no API key" true rather than
aspirational — the enrichment stage runs, finds no provider, records that fact on
`Enrichment`, and the artifact is finished exactly as it would have been.

The SDKs are imported lazily inside the methods that need them, so `pip install -r
requirements.txt` without the optional extras still imports this module cleanly.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

#: Deliberately conservative. Enrichment answers small, specific questions; a large budget
#: here would mean the gap was too broad, which is a bug in stage 16, not a budget problem.
DEFAULT_MAX_TOKENS = 1500

#: Zero, because the same repository must produce the same artifact twice (SPEC §7.1). This
#: does not make an LLM deterministic — nothing does — which is precisely why every answer
#: is validated against evidence before it is allowed into the model.
DEFAULT_TEMPERATURE = 0.0


Role = Literal["user", "assistant"]


@dataclass(frozen=True)
class Message:
    role: Role
    content: str


@dataclass
class Completion:
    """One response, plus what it cost. Provider-agnostic by construction."""

    text: str = ""
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    error: str = ""
    """Set instead of raising. An enrichment failure is `DegradedError` territory (P6): the
    deterministic model is already complete, so a provider outage must not fail the run."""

    @property
    def ok(self) -> bool:
        return bool(self.text) and not self.error

    def json(self) -> dict[str, Any] | None:
        """Parse the response as JSON, tolerating the fences models like to add.

        Returns `None` rather than raising: a malformed response is a rejected answer, not
        a crashed pipeline, and `Enrichment.gaps_rejected` is where that gets counted.
        """
        text = self.text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0]
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1:
            return None
        try:
            parsed = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None


class LLMProvider(Protocol):
    """What the engine needs from a model. Nothing more is permitted through."""

    name: str

    @property
    def available(self) -> bool:
        """False when no credential is configured. Checked before any work is prepared, so
        a run without a key never pays the cost of building contexts it cannot use."""
        ...

    def complete(
        self, system: str, messages: list[Message], *, max_tokens: int = DEFAULT_MAX_TOKENS
    ) -> Completion: ...


@dataclass
class NullProvider:
    """The default. Answers nothing, fails nothing.

    Its existence is the architecture: the deterministic model is the product, and
    enrichment is a layer that may simply be absent.
    """

    name: str = "none"

    @property
    def available(self) -> bool:
        return False

    def complete(
        self, system: str, messages: list[Message], *, max_tokens: int = DEFAULT_MAX_TOKENS
    ) -> Completion:
        return Completion(error="no LLM provider is configured")


@dataclass
class AnthropicProvider:
    """Claude via the Anthropic Messages API (SPEC §4: primary)."""

    model: str = "claude-sonnet-4-5"
    api_key: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY", ""))
    name: str = "anthropic"

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def complete(
        self, system: str, messages: list[Message], *, max_tokens: int = DEFAULT_MAX_TOKENS
    ) -> Completion:
        if not self.available:
            return Completion(error="ANTHROPIC_API_KEY is not set")
        try:
            import anthropic
        except ImportError:
            return Completion(error="the anthropic package is not installed")

        try:
            client = anthropic.Anthropic(api_key=self.api_key)
            response = client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=DEFAULT_TEMPERATURE,
                system=system,
                messages=[{"role": m.role, "content": m.content} for m in messages],
            )
        except Exception as exc:  # noqa: BLE001 — provider failures must degrade, not raise
            return Completion(error=f"{type(exc).__name__}: {exc}")

        # `getattr` rather than `block.text`: a response may carry thinking, tool-use or
        # tool-result blocks alongside the text, and none of those have `.text`.
        text = "".join(
            str(getattr(block, "text", ""))
            for block in response.content
            if getattr(block, "type", "") == "text"
        )
        return Completion(
            text=text,
            model=response.model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        )


@dataclass
class OpenAIProvider:
    """The fallback / second-opinion provider named in SPEC §4."""

    model: str = "gpt-4o"
    api_key: str = field(default_factory=lambda: os.environ.get("OPENAI_API_KEY", ""))
    name: str = "openai"

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def complete(
        self, system: str, messages: list[Message], *, max_tokens: int = DEFAULT_MAX_TOKENS
    ) -> Completion:
        if not self.available:
            return Completion(error="OPENAI_API_KEY is not set")
        try:
            import openai
        except ImportError:
            return Completion(error="the openai package is not installed")

        payload: list[Any] = [
            {"role": "system", "content": system},
            *({"role": m.role, "content": m.content} for m in messages),
        ]
        try:
            client = openai.OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=DEFAULT_TEMPERATURE,
                messages=payload,
            )
        except Exception as exc:  # noqa: BLE001
            return Completion(error=f"{type(exc).__name__}: {exc}")

        usage = response.usage
        return Completion(
            text=response.choices[0].message.content or "",
            model=response.model,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
        )


def default_provider() -> LLMProvider:
    """Anthropic if configured, OpenAI if not, `NullProvider` otherwise.

    Never raises for a missing key. A run with no credentials is the *supported* path, not
    an error path — the deterministic model is complete on its own.
    """
    anthropic_provider = AnthropicProvider()
    if anthropic_provider.available:
        return anthropic_provider
    openai_provider = OpenAIProvider()
    if openai_provider.available:
        return openai_provider
    return NullProvider()


__all__ = [
    "DEFAULT_MAX_TOKENS",
    "AnthropicProvider",
    "Completion",
    "LLMProvider",
    "Message",
    "NullProvider",
    "OpenAIProvider",
    "default_provider",
]
