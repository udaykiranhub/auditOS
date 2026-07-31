/**
 * AuditOS — Phase 1 harness.
 *
 * One screen: pick a target, run the Repository Reader, inspect the `RepoModel` it
 * produced. The four-screen app in SPEC §4 arrives with the stages that need it.
 */

import { useMutation } from '@tanstack/react-query'
import { ingestRemote, ingestUpload, toApiError } from './api/client'
import RepoPanel from './components/RepoPanel'
import UploadPanel, { type Source } from './components/UploadPanel'
import type { ApiError, IngestResponse } from './types/repo'
import type { ScopeArgs } from './api/client'

const PIPELINE = [
  { label: 'Repository Reader', artifact: 'RepoModel', done: true },
  { label: 'Build', artifact: 'solc AST', done: false },
  { label: 'Parser', artifact: 'CodeModel', done: false },
  { label: 'Graphs', artifact: 'GraphModel', done: false },
  { label: 'Protocol', artifact: 'ProtocolModel', done: false },
  { label: 'Agents → Report', artifact: 'report.md', done: false },
]

export default function App() {
  const run = useMutation<IngestResponse, ApiError, { source: Source; scope: ScopeArgs }>({
    mutationFn: async ({ source, scope }) => {
      try {
        return source.mode === 'upload'
          ? await ingestUpload(source.files, scope)
          : await ingestRemote(source.source, source.ref, scope)
      } catch (error) {
        throw toApiError(error)
      }
    },
  })

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6 px-5 py-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">AuditOS</h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
            AI smart-contract security engine · Phase 1 harness
          </p>
        </div>

        <ol className="flex flex-wrap items-center gap-1.5 text-[11px]">
          {PIPELINE.map((stage) => (
            <li
              key={stage.label}
              title={stage.artifact}
              className="rounded-md px-2 py-1"
              style={{
                background: stage.done
                  ? 'color-mix(in srgb, var(--series-1) 16%, transparent)'
                  : 'var(--surface-1)',
                color: stage.done ? 'var(--series-1)' : 'var(--text-muted)',
                border: `1px solid ${stage.done ? 'transparent' : 'var(--border)'}`,
              }}
            >
              {stage.done ? '✓ ' : ''}
              {stage.label}
            </li>
          ))}
        </ol>
      </header>

      <UploadPanel
        busy={run.isPending}
        onRun={(source, scope) => run.mutate({ source, scope })}
      />

      {run.isError && (
        <section
          className="rounded-xl border p-5"
          style={{
            background: 'color-mix(in srgb, var(--status-critical) 8%, var(--surface-1))',
            borderColor: 'color-mix(in srgb, var(--status-critical) 40%, transparent)',
          }}
        >
          <div className="flex items-center gap-2">
            <span aria-hidden>⨯</span>
            <h2 className="text-sm font-semibold" style={{ color: 'var(--status-critical)' }}>
              {run.error.code ?? 'Error'}
            </h2>
          </div>
          <p className="mt-2 text-sm">{run.error.message}</p>
          {run.error.hint && (
            <p className="mono mt-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
              {run.error.hint}
            </p>
          )}
        </section>
      )}

      {run.isSuccess && <RepoPanel result={run.data} />}

      {!run.isSuccess && !run.isError && !run.isPending && (
        <p className="py-10 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
          Pick a target above to produce a <span className="mono">RepoModel</span>.
        </p>
      )}
    </div>
  )
}
