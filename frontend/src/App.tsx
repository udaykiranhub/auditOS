/**
 * AuditOS — pipeline harness.
 *
 * One screen per implemented stage: pick a target, run the Repository Reader, then compile
 * it, inspecting each artifact as it is produced. The four-screen app in SPEC §4 arrives
 * with the stages that need it.
 */

import { useMutation } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { ingestRemote, ingestUpload, runBuild, runGraph, runParse, toApiError } from './api/client'
import type { ScopeArgs } from './api/client'
import BuildPanel from './components/BuildPanel'
import GraphPanel from './components/GraphPanel'
import ParsePanel from './components/ParsePanel'
import RepoPanel from './components/RepoPanel'
import UploadPanel, { type Source } from './components/UploadPanel'
import type { ApiError, BuildModel, CodeModel, GraphModel, IngestResponse } from './types/repo'

const PIPELINE = [
  { label: 'Repository Reader', artifact: 'RepoModel', done: true },
  // Optional by design: it enriches, it does not gate. The Parser is tree-sitter-primary
  // and reads code that never compiles (SPEC §10, §12.1).
  { label: 'Compiler enrichment', artifact: 'BuildModel (optional)', done: true },
  { label: 'Parser', artifact: 'CodeModel', done: true },
  { label: 'Graphs', artifact: 'GraphModel', done: true },
  { label: 'Protocol', artifact: 'ProtocolModel', done: false },
  { label: 'Agents → Report', artifact: 'report.md', done: false },
]

type Tab = 'repo' | 'build' | 'parse' | 'graph'

export default function App() {
  const [tab, setTab] = useState<Tab>('repo')

  const ingest = useMutation<IngestResponse, ApiError, { source: Source; scope: ScopeArgs }>({
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

  const [elapsed, setElapsed] = useState(0)

  const build = useMutation<BuildModel, ApiError, string>({
    mutationFn: async (runId) => {
      setElapsed(0)
      try {
        return await runBuild(runId, { onProgress: setElapsed })
      } catch (error) {
        throw toApiError(error)
      }
    },
    onSuccess: () => setTab('build'),
  })

  const parse = useMutation<CodeModel, ApiError, string>({
    mutationFn: async (runId) => {
      try {
        return await runParse(runId)
      } catch (error) {
        throw toApiError(error)
      }
    },
    onSuccess: () => setTab('parse'),
  })

  const graph = useMutation<GraphModel, ApiError, string>({
    mutationFn: async (runId) => {
      try {
        return await runGraph(runId)
      } catch (error) {
        throw toApiError(error)
      }
    },
    onSuccess: () => setTab('graph'),
  })

  // A new ingest invalidates the downstream artifacts: they describe another repository.
  useEffect(() => {
    if (ingest.isPending) {
      build.reset()
      parse.reset()
      graph.reset()
      setTab('repo')
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ingest.isPending])

  const error = ingest.error ?? build.error ?? parse.error ?? graph.error
  const runId = ingest.data?.run_id

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6 px-5 py-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">AuditOS</h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
            AI smart-contract security engine · pipeline harness
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
        busy={ingest.isPending}
        onRun={(source, scope) => ingest.mutate({ source, scope })}
      />

      {error && (
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
              {error.code ?? 'Error'}
            </h2>
          </div>
          <p className="mt-2 text-sm">{error.message}</p>
          {error.hint && (
            <p className="mono mt-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
              {error.hint}
            </p>
          )}
        </section>
      )}

      {ingest.isSuccess && runId && (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex gap-1 rounded-lg p-1" style={{ background: 'var(--surface-1)' }}>
              {(
                [
                  { key: 'repo', label: '1 · Repository Reader', enabled: true },
                  { key: 'build', label: '2 · Compiler enrichment', enabled: build.isSuccess },
                  { key: 'parse', label: '3 · Parser', enabled: parse.isSuccess },
                  { key: 'graph', label: '4 · Graph', enabled: graph.isSuccess },
                ] as const
              ).map((option) => (
                <button
                  key={option.key}
                  type="button"
                  disabled={!option.enabled}
                  onClick={() => setTab(option.key)}
                  className="rounded-md px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-40"
                  style={{
                    background: tab === option.key ? 'var(--plane)' : 'transparent',
                    color: tab === option.key ? 'var(--text-primary)' : 'var(--text-secondary)',
                  }}
                >
                  {option.label}
                </button>
              ))}
            </div>

            <button
              type="button"
              onClick={() => build.mutate(runId)}
              disabled={build.isPending}
              className="rounded-lg px-4 py-2 text-sm font-semibold disabled:opacity-40"
              style={{ background: 'var(--series-1)', color: '#fff' }}
            >
              {build.isPending
                ? `Compiling… ${elapsed.toFixed(0)}s`
                : build.isSuccess
                  ? 'Re-run enrichment'
                  : 'Run compiler enrichment (optional)'}
            </button>

            <button
              type="button"
              onClick={() => parse.mutate(runId)}
              disabled={parse.isPending}
              className="rounded-lg px-4 py-2 text-sm font-semibold disabled:opacity-40"
              style={{ background: 'var(--series-3)', color: '#fff' }}
            >
              {parse.isPending ? 'Parsing…' : parse.isSuccess ? 'Re-run parser' : 'Run parser'}
            </button>

            <button
              type="button"
              onClick={() => graph.mutate(runId)}
              disabled={graph.isPending || !parse.isSuccess}
              title={parse.isSuccess ? undefined : 'Run the parser first — the graph is built from its CodeModel.'}
              className="rounded-lg px-4 py-2 text-sm font-semibold disabled:opacity-40"
              style={{ background: 'var(--series-4)', color: '#fff' }}
            >
              {graph.isPending ? 'Graphing…' : graph.isSuccess ? 'Re-run graph' : 'Build graph'}
            </button>

            {build.isPending && (
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Compiling a large protocol takes minutes. The run is not blocked — this
                stage only adds storage layout, ABI and the compiler AST.
              </span>
            )}
            {parse.isPending && (
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Parsing every file, dependencies included — they are needed for inheritance
                and call-graph completeness.
              </span>
            )}
          </div>

          {tab === 'repo' && <RepoPanel result={ingest.data} />}
          {tab === 'build' && build.data && <BuildPanel build={build.data} />}
          {tab === 'parse' && parse.data && <ParsePanel code={parse.data} />}
          {tab === 'graph' && graph.data && <GraphPanel graph={graph.data} />}
        </>
      )}

      {!ingest.isSuccess && !ingest.isError && !ingest.isPending && (
        <p className="py-10 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
          Pick a target above to produce a <span className="mono">RepoModel</span>.
        </p>
      )}
    </div>
  )
}
