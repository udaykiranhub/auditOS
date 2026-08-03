# AuditOS — Frontend

A thin client for the audit engine. **Four screens, and no more:**

| Screen   | Does |
|----------|------|
| Upload   | drop a ZIP, pick a folder, or paste a git URL → `POST /audits` |
| Progress | live pipeline stage + per-agent status, over the SSE stream |
| Logs     | the run's structured log, streamed |
| Download | the finished `report.md` |

## The rule this app exists under

> The backend must be usable entirely from a CLI with no frontend running. The frontend is
> a client of the same API a human could `curl`. — SPEC §4, hard rule

So: **no analysis logic here.** No parsing, no scoring, no severity heuristics, no
re-deriving what the engine already computed. If a screen needs a number the API doesn't
return, the fix goes in the API — not in a `useMemo`.

## Stack

| Concern    | Choice |
|------------|--------|
| Framework  | React 19 |
| Build      | Vite 8 |
| Language   | TypeScript |
| Styling    | Tailwind CSS 4 (via `@tailwindcss/vite`) |
| Routing    | React Router 7 |
| Server state | TanStack Query 5 |
| HTTP       | axios |
| Uploads    | react-dropzone |
| Lint       | oxlint |

## Layout

```
src/
├── pages/       # one file per screen: Upload, Progress, Logs, Download
├── components/  # presentational, screen-agnostic
├── hooks/       # useAudit, useProgressStream (SSE), useLogs
├── api/         # the typed client — the ONLY place axios is imported
└── types/       # mirrors the engine's Pydantic artifacts (Finding, RepoModel, …)
```

`src/types/` is generated from — or hand-mirrored against — the engine's artifact schemas.
When a Pydantic model in `engine/core/models/` changes, this is what changes with it.

## Develop

```bash
npm install
npm run dev        # http://localhost:5173
```

Vite proxies `/audits` → `http://localhost:8000`, so run the backend alongside it — from the
**repository root**, so that `engine.*` imports resolve:

```bash
engine/.venv/Scripts/python -m uvicorn engine.api.routes:app --reload --port 8000
```

```bash
npm run build      # tsc -b && vite build
npm run lint       # oxlint
npm run preview    # serve the production build
```

## Status

🚧 **Pipeline harness.** Not the four screens yet — one screen with a tab per implemented
stage:

```
Upload (zip · folder · git URL, + scope override)
   → POST /audits/upload | /audits/remote
   → RepoPanel:  counts, scope composition, file inventory with per-file reasons,
                 remappings, docs, detection notes, content hash
   → POST /audits/{run_id}/build
   → BuildPanel: builder + status, solc requested vs resolved, compiler settings,
                 per-contract storage layout with packing, selectors, bytecode sizes,
                 diagnostics, AST paths
```

The four-screen app arrives with the pipeline stages that need it — Progress and Logs need
an SSE stream and a job to stream, Download needs a `report.md`.
