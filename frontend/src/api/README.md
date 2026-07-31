# api/ — backend client (SPEC §4)

Thin Axios/fetch wrappers around the four engine endpoints. The frontend is **only** a client of
the API a human could `curl` — no business logic lives here.

- `POST /audits` — start a run (ZIP upload or `{git_url, ref?, scope_override?}`) → `run_id`
- `GET  /audits/{id}/status` — pipeline stage + per-agent state
- `GET  /audits/{id}/stream` — SSE live progress/logs
- `GET  /audits/{id}/report` — download `report.md`
