# llm/ — LLM Provider (SPEC §4)

**The ONLY place in the codebase where an LLM SDK may be imported.** Grep for `anthropic` / `openai`
outside this directory in CI — a hit is a bug (§5 developer note).

| File          | Purpose |
|---------------|---------|
| `provider.py` | `LLMProvider` ABC — **no SDK types may leak past this interface** |
| `anthropic.py`| Claude implementation (**primary**) |
| `openai.py`   | OpenAI implementation (fallback / second opinion) |
| `budget.py`   | token + cost accounting across calls |

## Why this boundary is absolute

P2 (deterministic core, probabilistic edge) only holds if the probabilistic part is *contained*.
Both providers sit behind one interface so that: the rest of the engine is provider-agnostic;
swapping/testing models touches one file; and every call is uniformly logged with a `prompt_hash`
for provenance (G6).

## Model defaults

Primary: **Anthropic Claude** (latest capable model). Fallback / second-opinion: OpenAI. Configure
model IDs and keys via `.env` (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) — never hard-code them.

> The engine must be usable from the CLI with real keys and no frontend. Keep this interface small.
