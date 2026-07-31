/**
 * Phase 1 — Repository Reader results.
 *
 * Everything here comes straight off the `RepoModel` artifact; nothing is re-derived or
 * re-scored in the browser. If a number is missing, the fix belongs in the API.
 */

import { useState } from 'react'
import type { IngestResponse } from '../types/repo'
import FileTable from './FileTable'
import ScopeBar from './ScopeBar'

function Tile({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div
      className="rounded-xl border px-4 py-3"
      style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
    >
      <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
        {label}
      </div>
      <div
        className="mt-1 text-2xl font-semibold"
        style={{ color: accent ?? 'var(--text-primary)' }}
      >
        {value}
      </div>
    </div>
  )
}

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[11px] uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
        {label}
      </span>
      <span className="mono text-xs" style={{ color: 'var(--text-primary)' }}>
        {children}
      </span>
    </div>
  )
}

export default function RepoPanel({ result }: { result: IngestResponse }) {
  const { repo, counts, run_id } = result
  const [showReadme, setShowReadme] = useState(false)
  const remappings = Object.entries(repo.remappings)

  return (
    <div className="flex flex-col gap-4">
      {/* Header ─────────────────────────────────────────────────────────── */}
      <section
        className="rounded-xl border p-5"
        style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
      >
        <div className="flex flex-wrap items-center gap-3">
          <span
            className="mono rounded-md px-2.5 py-1 text-xs font-semibold"
            style={{ background: 'var(--series-1)', color: '#fff' }}
          >
            {repo.kind}
          </span>
          <h2 className="text-lg font-semibold">Repository Reader</h2>
          <span
            className="rounded-full px-2.5 py-0.5 text-[11px] font-medium"
            style={{ background: 'color-mix(in srgb, var(--status-good) 16%, transparent)', color: 'var(--status-good)' }}
          >
            ✓ Phase 1 complete
          </span>
        </div>

        <div className="mt-5 grid grid-cols-2 gap-4 md:grid-cols-4">
          <Meta label="Origin">{repo.origin}</Meta>
          <Meta label="Solidity">
            {repo.solidity_version ?? '—'}
            {repo.solidity_version_source && (
              <span style={{ color: 'var(--text-muted)' }}> · {repo.solidity_version_source}</span>
            )}
          </Meta>
          <Meta label="Run id">{run_id}</Meta>
          <Meta label="Content hash">{repo.content_hash.slice(0, 16)}…</Meta>
        </div>
      </section>

      {/* Counts ─────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Tile label="Solidity files" value={counts.total} />
        <Tile label="In scope" value={counts.in_scope} accent="var(--series-1)" />
        <Tile label="Tests" value={counts.tests} />
        <Tile label="Mocks" value={counts.mocks} />
        <Tile label="Dependencies" value={counts.dependencies} />
        <Tile label="Interfaces" value={counts.interfaces} />
      </div>

      <ScopeBar files={repo.files} />

      <FileTable files={repo.files} />

      {/* Config, docs, notes ────────────────────────────────────────────── */}
      <div className="grid gap-4 lg:grid-cols-2">
        <section
          className="rounded-xl border p-5"
          style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
        >
          <h2 className="text-sm font-semibold">Configuration</h2>
          {remappings.length > 0 ? (
            <table className="mono mt-3 w-full text-left text-xs">
              <tbody>
                {remappings.map(([from, to]) => (
                  <tr key={from} className="border-t" style={{ borderColor: 'var(--gridline)' }}>
                    <td className="py-1.5 pr-3" style={{ color: 'var(--text-primary)' }}>
                      {from}
                    </td>
                    <td className="py-1.5" style={{ color: 'var(--text-secondary)' }}>
                      → {to}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="mt-3 text-xs" style={{ color: 'var(--text-muted)' }}>
              No remappings.
            </p>
          )}

          <h3 className="mt-5 text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
            Documentation ({repo.docs.length})
          </h3>
          <ul className="mono mt-2 flex flex-col gap-1 text-xs">
            {repo.docs.map((doc) => (
              <li key={doc} style={{ color: 'var(--text-secondary)' }}>
                {doc}
              </li>
            ))}
            {repo.docs.length === 0 && <li style={{ color: 'var(--text-muted)' }}>None found.</li>}
          </ul>

          {repo.readme && (
            <>
              <button
                type="button"
                onClick={() => setShowReadme((open) => !open)}
                className="mt-4 text-xs font-medium underline underline-offset-2"
                style={{ color: 'var(--series-1)' }}
              >
                {showReadme ? 'Hide' : 'Show'} README ({repo.readme.length} chars)
              </button>
              {showReadme && (
                <pre
                  className="mono mt-3 max-h-64 overflow-auto rounded-lg p-3 text-[11px] whitespace-pre-wrap"
                  style={{ background: 'var(--plane)', color: 'var(--text-secondary)' }}
                >
                  {repo.readme}
                </pre>
              )}
            </>
          )}
        </section>

        <section
          className="rounded-xl border p-5"
          style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
        >
          <h2 className="text-sm font-semibold">Notes</h2>
          <p className="mt-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
            Detection decisions and degradations. A failed subsystem is stated, never silently
            omitted.
          </p>
          <ul className="mt-3 flex flex-col gap-2 text-xs">
            {repo.notes.map((note) => (
              <li
                key={note}
                className="rounded-lg px-3 py-2"
                style={{ background: 'var(--plane)', color: 'var(--text-secondary)' }}
              >
                {note}
              </li>
            ))}
            {repo.notes.length === 0 && (
              <li style={{ color: 'var(--text-muted)' }}>Nothing to report.</li>
            )}
          </ul>

          <h3 className="mt-5 text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
            Artifact
          </h3>
          <p className="mono mt-2 text-[11px] break-all" style={{ color: 'var(--text-muted)' }}>
            {result.artifact_path}
          </p>
        </section>
      </div>
    </div>
  )
}
