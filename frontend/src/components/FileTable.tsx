/**
 * The file inventory — the table view of what the classifier decided, and why.
 *
 * `scope_reason` is shown for every row on purpose: a wrong heuristic should be visible
 * and correctable (via the include/exclude escape hatch) rather than mysterious.
 */

import { useMemo, useState } from 'react'
import type { SourceFile } from '../types/repo'

type Filter = 'all' | 'in_scope' | 'excluded'

const FILTERS: { key: Filter; label: string }[] = [
  { key: 'all', label: 'All' },
  { key: 'in_scope', label: 'In scope' },
  { key: 'excluded', label: 'Excluded' },
]

function Flag({ label, color }: { label: string; color: string }) {
  return (
    <span
      className="mono rounded px-1.5 py-0.5 text-[10px] font-medium"
      style={{ background: `${color}22`, color }}
    >
      {label}
    </span>
  )
}

export default function FileTable({ files }: { files: SourceFile[] }) {
  const [filter, setFilter] = useState<Filter>('all')
  const [query, setQuery] = useState('')

  const rows = useMemo(() => {
    return files.filter((file) => {
      if (filter === 'in_scope' && !file.in_scope) return false
      if (filter === 'excluded' && file.in_scope) return false
      return !query || file.path.toLowerCase().includes(query.toLowerCase())
    })
  }, [files, filter, query])

  return (
    <section
      className="rounded-xl border"
      style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
    >
      <div className="flex flex-wrap items-center gap-3 border-b p-4" style={{ borderColor: 'var(--border)' }}>
        <h2 className="mr-auto text-sm font-semibold">
          Solidity files{' '}
          <span className="mono font-normal" style={{ color: 'var(--text-muted)' }}>
            {rows.length}/{files.length}
          </span>
        </h2>

        <div className="flex gap-1 rounded-lg p-1" style={{ background: 'var(--plane)' }}>
          {FILTERS.map((option) => (
            <button
              key={option.key}
              type="button"
              onClick={() => setFilter(option.key)}
              className="rounded-md px-3 py-1 text-xs font-medium transition-colors"
              style={{
                background: filter === option.key ? 'var(--surface-1)' : 'transparent',
                color: filter === option.key ? 'var(--text-primary)' : 'var(--text-secondary)',
              }}
            >
              {option.label}
            </button>
          ))}
        </div>

        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Filter by path…"
          className="mono w-56 rounded-lg border px-3 py-1.5 text-xs outline-none"
          style={{
            background: 'var(--plane)',
            borderColor: 'var(--border)',
            color: 'var(--text-primary)',
          }}
        />
      </div>

      <div className="max-h-[28rem] overflow-auto">
        <table className="w-full border-collapse text-left text-xs">
          <thead className="sticky top-0" style={{ background: 'var(--surface-1)' }}>
            <tr style={{ color: 'var(--text-muted)' }}>
              <th className="px-4 py-2 font-medium">Path</th>
              <th className="px-2 py-2 text-right font-medium">LOC</th>
              <th className="px-2 py-2 font-medium">Flags</th>
              <th className="px-4 py-2 font-medium">Scope</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((file) => (
              <tr
                key={file.path}
                className="border-t"
                style={{ borderColor: 'var(--gridline)', opacity: file.in_scope ? 1 : 0.62 }}
              >
                <td className="mono px-4 py-2" style={{ color: 'var(--text-primary)' }}>
                  <span
                    className="mr-2 inline-block h-2 w-2 rounded-full align-middle"
                    style={{
                      background: file.in_scope ? 'var(--series-1)' : 'var(--baseline)',
                    }}
                    aria-hidden
                  />
                  {file.path}
                </td>
                <td
                  className="mono px-2 py-2 text-right tabular-nums"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  {file.loc}
                </td>
                <td className="px-2 py-2">
                  <span className="flex flex-wrap gap-1">
                    {file.is_dependency && <Flag label="dep" color="var(--series-2)" />}
                    {file.is_test && <Flag label="test" color="var(--series-3)" />}
                    {file.is_mock && <Flag label="mock" color="var(--series-4)" />}
                    {file.is_interface_only && <Flag label="iface" color="var(--text-muted)" />}
                  </span>
                </td>
                <td className="px-4 py-2" style={{ color: 'var(--text-secondary)' }}>
                  {file.scope_reason}
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-8 text-center" style={{ color: 'var(--text-muted)' }}>
                  No files match this filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  )
}
