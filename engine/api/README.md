# api/ — HTTP layer (SPEC §6)

FastAPI app. **The frontend is just a client of this API — a human could `curl` every endpoint.**
The engine must remain fully usable from the CLI with no frontend running (§4 hard rule).

| File        | Purpose |
|-------------|---------|
| `routes.py` | upload (ZIP / git URL), status, logs, report download |
| `stream.py` | **SSE** progress stream — the user must see the pipeline working (build logs, agent status) |

## Endpoints (V1 — four screens' worth)

| Method | Path                     | Purpose |
|--------|--------------------------|---------|
| POST   | `/audits`                | start a run: ZIP upload **or** `{git_url, ref?, scope_override?}` → `run_id` |
| GET    | `/audits/{run_id}/status`| pipeline stage + per-agent state |
| GET    | `/audits/{run_id}/stream`| SSE: live progress + logs |
| GET    | `/audits/{run_id}/report`| download `report.md` |

`scope_override: {include: [...], exclude: [...]}` must be accepted at start (§9.3 escape hatch) so
the user can correct a bad scope heuristic without editing code.

## Contract

- No auth, no DB, no job persistence across restarts (V1 non-goals). Runs live under `run/<run_id>/`.
- Errors surface as clean JSON, not stack traces — a `FatalError` is a 4xx/5xx with a clear message.
