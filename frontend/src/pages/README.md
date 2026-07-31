# pages/ — the four screens (SPEC §4)

V1 is exactly four screens. No more.

1. **Upload** — drag-drop ZIP (react-dropzone) or paste a git URL; optional scope override.
2. **Progress** — live pipeline stage + per-agent status, fed by the SSE stream.
3. **Logs** — streamed build/agent logs (the user must see it working — build can take minutes).
4. **Download** — the finished `report.md`.
