# api/ — HTTP layer (SPEC §6)

FastAPI app. **The frontend is just a client of this API — a human could `curl` every endpoint.**
The engine must remain fully usable from the CLI with no frontend running (§4 hard rule).

| File        | Purpose |
|-------------|---------|
| `routes.py` | upload (ZIP / git URL), status, logs, report download |
| `stream.py` | **SSE** progress stream — the user must see the pipeline working (build logs, agent status) |

Run it from the **repository root**, so `engine.*` imports resolve:

```bash
engine/.venv/Scripts/python -m uvicorn engine.api.routes:app --reload --port 8000
```

## Endpoints (V1 — four screens' worth)

| Method | Path                     | Purpose | Status |
|--------|--------------------------|---------|--------|
| POST   | `/audits/upload`         | a `.zip`, or a folder's files + relative paths → `RepoModel` | ✅ |
| POST   | `/audits/remote`         | `{source, ref?, include?, exclude?}` — git URL or local path | ✅ |
| GET    | `/audits/{run_id}/repo`  | re-read a previous run's `RepoModel` | ✅ |
| GET    | `/audits/{run_id}/status`| pipeline stage + per-agent state | ⏳ |
| GET    | `/audits/{run_id}/stream`| SSE: live progress + logs | ⏳ |
| GET    | `/audits/{run_id}/report`| download `report.md` | ⏳ |

**Phase 1 slice.** Ingest is synchronous — there is no job state, no SSE and no report
because there are no stages yet to produce them. `POST /audits` becomes the single async
entry point once the pipeline runs end to end; the ingest routes collapse into it then.

Uploads get the same traversal rules as a ZIP entry: an upload is no more trusted than an
archive.

`scope_override: {include: [...], exclude: [...]}` must be accepted at start (§9.3 escape hatch) so
the user can correct a bad scope heuristic without editing code.

## Contract

- No auth, no DB, no job persistence across restarts (V1 non-goals). Runs live under `run/<run_id>/`.
- Errors surface as clean JSON, not stack traces — a `FatalError` is a 4xx/5xx with a clear message.
