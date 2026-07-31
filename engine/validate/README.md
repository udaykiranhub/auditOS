# validate/ — Validation (SPEC §8; full spec in Part 4)

`raw Finding[] → validated Finding[]`. Deterministic. **Failure = Fatal.** This is the guardrail
around the probabilistic edge (P2): LLM output is untrusted until it passes through here.

**Pipeline order:** `schema → falsifiability → dedupe → confidence`.

| File               | Stage | Purpose |
|--------------------|-------|---------|
| `schema.py`        | 1 | reject anything that isn't a well-formed `Finding` |
| `falsifiability.py`| 2 | **P5 enforcement** — no `attack_path` (concrete state + actor + consequence) → reject |
| `dedupe.py`        | 3 | collapse duplicate/overlapping findings across agents |
| `confidence.py`    | 4 | **compute** `Finding.confidence` (0..1) — never trust the agent's self-report |

## Why confidence is computed here, not by the agent (§7.7)

Models are systematically overconfident and their self-reported confidence is uncorrelated with
correctness. Confidence is a function of: static corroboration, evidence quality, attack-path
concreteness, cross-agent agreement, etc. — computed deterministically at this layer.

> The confidence formula and dedup heuristics are specified in **Part 4** of the SPEC.
