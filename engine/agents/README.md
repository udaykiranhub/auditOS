# agents/ — Security Agents (SPEC §8; framework in Part 3)

**FAST-MOVING. Hot-loadable. Versioned.** This is the "edge" in P7 — changed constantly. Never let
edge concerns leak into the core.

| Path                  | Purpose |
|-----------------------|---------|
| `framework/base.py`   | `Agent` ABC — the framework does retries, validation, budgeting, logging |
| `framework/registry.py` | agent discovery/registration |
| `framework/lifecycle.py`| agent run lifecycle + state (PENDING/RUNNING/DONE/FAILED) |
| `framework/spec.py`   | `AgentSpec` — the **declarative** record (what context it needs, what schema it emits, what to ignore) |
| `security/`           | one file per agent: `access_control.py`, `business_logic.py`, `math.py`, `oracle.py`, … |
| `prompts/`            | prompt templates, **versioned, NOT in `.py`** |

## P4 — Agents are prompts + contracts, not classes with cleverness

An agent is a declarative record: what context it needs, what schema it emits, what it must ignore.
The framework does everything else. **Agents contain NO orchestration logic. If an agent knows
about another agent, the design is wrong.**

## G4 — Extensibility is the acceptance test for this design

> A new agent is added by dropping **one file + one registry entry**, with **ZERO** changes to the
> orchestrator.

If adding an agent requires touching the orchestrator, the framework has failed its contract.

## What an agent emits

Raw `Finding[]` (see `core/models/findings.py`). Then it is out of the agent's hands:

- The agent does **not** self-report confidence (validation computes it — §7.7).
- Every finding **must** carry an `attack_path` or it is rejected (P5).
- Every finding carries `provenance` (prompt_hash, context_bundle_id, model, tokens) so the engine
  itself is auditable (G6).
