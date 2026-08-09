"""Phase H — the optional layer that answers what determinism could not.

```
deterministic ProtocolModel  →  gaps  →  small contexts  →  LLM  →  validated claims
```

**Optional is the load-bearing word.** The `ProtocolModel` is complete before this package
runs. Enrichment fills fields stage 16 marked as open and adds claims beside the derived
ones; it never removes a deterministic finding, and it never raises — a provider outage is
`DegradedError` territory (P6), not a failed run.

Everything a model produces lands at `Confidence.PROPOSED` and carries `EvidenceKind.MODEL`
evidence naming the exact declarations it was shown. That makes the two runs comparable:
diff a deterministic model against an enriched one and the difference *is* the model's
contribution, measurable rather than assumed.
"""

from __future__ import annotations

from engine.protocol.enrich.apply import MAX_GAPS, enrich
from engine.protocol.enrich.context import GapContext
from engine.protocol.enrich.provider import (
    AnthropicProvider,
    Completion,
    LLMProvider,
    Message,
    NullProvider,
    OpenAIProvider,
    default_provider,
)

__all__ = [
    "MAX_GAPS",
    "AnthropicProvider",
    "Completion",
    "GapContext",
    "LLMProvider",
    "Message",
    "NullProvider",
    "OpenAIProvider",
    "default_provider",
    "enrich",
]
