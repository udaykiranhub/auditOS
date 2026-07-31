# report/ — Report Generator (SPEC §6; full spec in Part 4)

`validated Finding[] + ProtocolModel → report.md`. Deterministic. Failure = Fatal.

| Path         | Purpose |
|--------------|---------|
| `generate.py`| assembles the final `report.md` from validated findings + protocol summary |
| `templates/` | Markdown templates for the report and its sections |

## Non-negotiable sections

- **Findings** — high-signal only. Each carries its attack path, evidence with line refs, severity,
  confidence, and static corroboration. Business-logic / economic / accounting classes — **not** gas or style.
- **Coverage & Limitations** — states exactly what degraded (§10.2). If the build failed and storage
  layout was lost, say so. *An audit that silently ran without storage layout while a Storage agent
  claimed to check slot collisions is worse than no audit* (P6).

## Anti-metrics — do not chase these

"Number of findings" is an **anti-metric**; it rewards noise. Raw Slither output never appears here
(§11.3). The report is a pipeline output, not a linter dump.
