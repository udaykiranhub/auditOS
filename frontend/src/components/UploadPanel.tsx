/**
 * Upload — the only input screen Phase 1 needs.
 *
 * Three origins, matching the reader's three: a `.zip`, a folder, or a git URL. A local
 * folder *path* is also accepted, because the engine is local-first and single-user: the
 * server is the same machine, so it can read the path directly.
 */

import { useCallback, useRef, useState } from 'react'
import { useDropzone } from 'react-dropzone'
import { isRelevantUpload, relativePathOf, type ScopeArgs } from '../api/client'

export type Source =
  | { mode: 'upload'; files: File[]; label: string }
  | { mode: 'remote'; source: string; ref: string }

interface Props {
  onRun: (source: Source, scope: ScopeArgs) => void
  busy: boolean
}

export default function UploadPanel({ onRun, busy }: Props) {
  const [files, setFiles] = useState<File[]>([])
  const [label, setLabel] = useState('')
  const [remote, setRemote] = useState('')
  const [ref, setRef] = useState('')
  const [include, setInclude] = useState('')
  const [exclude, setExclude] = useState('')
  const fileInput = useRef<HTMLInputElement>(null)
  const folderInput = useRef<HTMLInputElement>(null)

  const onDrop = useCallback((accepted: File[]) => {
    if (accepted.length === 0) return

    const isSingleZip = accepted.length === 1 && accepted[0].name.toLowerCase().endsWith('.zip')
    // Send only what the reader opens — a real project is mostly node_modules JavaScript.
    const payload = isSingleZip
      ? accepted
      : accepted.filter((file) => isRelevantUpload(relativePathOf(file)))

    if (payload.length === 0) {
      setFiles([])
      setLabel('No Solidity files in that selection')
      return
    }

    const folder = relativePathOf(payload[0]).split('/')[0]
    setFiles(payload)
    setLabel(
      isSingleZip
        ? accepted[0].name
        : `${folder} — ${payload.length} relevant of ${accepted.length} files`,
    )
    setRemote('')
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: true,
    noClick: true,
  })

  const canRun = files.length > 0 || remote.trim().length > 0

  function run() {
    if (!canRun || busy) return
    const scope: ScopeArgs = { include, exclude }
    if (files.length > 0) onRun({ mode: 'upload', files, label }, scope)
    else onRun({ mode: 'remote', source: remote.trim(), ref: ref.trim() }, scope)
  }

  return (
    <section
      className="rounded-xl border p-5"
      style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
    >
      <h2 className="text-sm font-semibold">Audit target</h2>
      <p className="mt-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
        A ZIP archive, a project folder, or a git URL.
      </p>

      {/* Drop zone ───────────────────────────────────────────────────────── */}
      <div
        {...getRootProps()}
        className="mt-4 flex flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-9 text-center transition-colors"
        style={{
          borderColor: isDragActive ? 'var(--series-1)' : 'var(--baseline)',
          background: isDragActive ? 'color-mix(in srgb, var(--series-1) 8%, transparent)' : 'transparent',
        }}
      >
        <input {...getInputProps()} />
        <p className="text-sm font-medium">
          {label || 'Drop a .sol file, a .zip, or a project folder here'}
        </p>
        <div className="mt-3 flex flex-wrap justify-center gap-2">
          <button
            type="button"
            onClick={() => fileInput.current?.click()}
            className="rounded-lg border px-3 py-1.5 text-xs font-medium"
            style={{ borderColor: 'var(--border)', color: 'var(--text-secondary)' }}
          >
            Choose files…
          </button>
          <button
            type="button"
            onClick={() => folderInput.current?.click()}
            className="rounded-lg border px-3 py-1.5 text-xs font-medium"
            style={{ borderColor: 'var(--border)', color: 'var(--text-secondary)' }}
          >
            Choose folder…
          </button>
          {files.length > 0 && (
            <button
              type="button"
              onClick={() => {
                setFiles([])
                setLabel('')
              }}
              className="rounded-lg px-3 py-1.5 text-xs font-medium"
              style={{ color: 'var(--text-muted)' }}
            >
              Clear
            </button>
          )}
        </div>

        {/* Two inputs, because a directory picker only lists *directories*: opening one to
            look for a single .sol shows an empty window, which reads as a broken upload. */}
        <input
          ref={fileInput}
          type="file"
          hidden
          multiple
          accept=".sol,.zip,.toml,.txt,.json,.md"
          onChange={(event) => onDrop(Array.from(event.target.files ?? []))}
        />

        {/* webkitdirectory is not in React's HTML types; it is how a browser hands over
            a directory, and the relative paths ride along on each File. */}
        <input
          ref={folderInput}
          type="file"
          hidden
          multiple
          {...({ webkitdirectory: '', directory: '' } as Record<string, string>)}
          onChange={(event) => onDrop(Array.from(event.target.files ?? []))}
        />
      </div>

      {/* Remote ──────────────────────────────────────────────────────────── */}
      <div className="mt-4 grid gap-3 sm:grid-cols-[1fr_10rem]">
        <label className="flex flex-col gap-1">
          <span className="text-[11px] uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
            git URL or local folder path
          </span>
          <input
            value={remote}
            onChange={(event) => {
              setRemote(event.target.value)
              if (event.target.value) {
                setFiles([])
                setLabel('')
              }
            }}
            placeholder="https://github.com/org/protocol  ·  x:\path\to\protocol"
            className="mono rounded-lg border px-3 py-2 text-xs outline-none"
            style={{ background: 'var(--plane)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
            ref (optional)
          </span>
          <input
            value={ref}
            onChange={(event) => setRef(event.target.value)}
            placeholder="main"
            className="mono rounded-lg border px-3 py-2 text-xs outline-none"
            style={{ background: 'var(--plane)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
          />
        </label>
      </div>

      {/* Scope override — the escape hatch ───────────────────────────────── */}
      <details className="mt-4">
        <summary className="cursor-pointer text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
          Scope override
        </summary>
        <p className="mt-2 text-xs" style={{ color: 'var(--text-muted)' }}>
          Comma-separated globs over repo-relative paths. The heuristics will be wrong on some
          protocol; exclude wins over include.
        </p>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          {[
            { label: 'include', value: include, set: setInclude, hint: 'src/vendor/*' },
            { label: 'exclude', value: exclude, set: setExclude, hint: 'src/legacy/*' },
          ].map((field) => (
            <label key={field.label} className="flex flex-col gap-1">
              <span className="text-[11px] uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
                {field.label}
              </span>
              <input
                value={field.value}
                onChange={(event) => field.set(event.target.value)}
                placeholder={field.hint}
                className="mono rounded-lg border px-3 py-2 text-xs outline-none"
                style={{ background: 'var(--plane)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
              />
            </label>
          ))}
        </div>
      </details>

      <button
        type="button"
        onClick={run}
        disabled={!canRun || busy}
        className="mt-5 w-full rounded-lg px-4 py-2.5 text-sm font-semibold transition-opacity disabled:cursor-not-allowed disabled:opacity-40"
        style={{ background: 'var(--series-1)', color: '#fff' }}
      >
        {busy ? 'Reading repository…' : 'Run audit'}
      </button>
    </section>
  )
}
