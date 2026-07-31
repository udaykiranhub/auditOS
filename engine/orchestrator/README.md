# orchestrator/ — Execution (SPEC §6; full spec in Part 4)

**SLOW-MOVING core.** Runs the agent DAG with bounded parallelism, retries, and resume.

| File          | Purpose |
|---------------|---------|
| `engine.py`   | DAG execution over registered agents |
| `scheduler.py`| bounded parallelism — `asyncio` + bounded semaphores (agents are IO-bound LLM calls; **no multiprocessing in V1**) |
| `recovery.py` | retries + resume from the on-disk artifact cache |

## Contracts it must honor

- **G4:** adding an agent requires **zero** orchestrator changes. The orchestrator reads the agent
  registry; it never names an agent.
- **P6 (fail soft at the edge):** an agent timeout/failure is degraded-but-survivable — the report
  proceeds, the agent is marked `FAILED`, and the report states the gap explicitly. A report must
  **never** silently omit a subsystem that failed.
- **Anti-goal:** do not optimize for latency. A 20-minute audit that finds a logic bug beats a
  40-second audit that finds 11 reentrancy false positives.

> Scheduling detail, the DAG shape, and recovery semantics are specified in **Part 4** of the SPEC.
