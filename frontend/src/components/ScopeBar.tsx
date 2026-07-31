/**
 * Scope composition — a single 100% stacked bar.
 *
 * The whole thesis of the Repository Reader is that 85–95% of a real protocol's
 * `.sol` files are *not* audit targets, so composition is the thing worth showing.
 *
 * Files can carry more than one flag (a mock inside `test/` is both), which would make
 * a naive stack overlap and overstate the total. Segments are therefore a true
 * partition, assigned by first matching rule: in scope → dependency → test → mock →
 * excluded by override.
 *
 * Colors are categorical slots 1–4 in fixed order, with a 2px surface gap between
 * segments. Every segment is also named and counted in the legend, so identity never
 * rests on hue alone.
 */

import type { SourceFile } from '../types/repo'

interface Segment {
  key: string
  label: string
  color: string
  count: number
}

function partition(files: SourceFile[]): Segment[] {
  let inScope = 0
  let dependency = 0
  let test = 0
  let mock = 0
  let override = 0

  for (const file of files) {
    if (file.in_scope) inScope += 1
    else if (file.is_dependency) dependency += 1
    else if (file.is_test) test += 1
    else if (file.is_mock) mock += 1
    else override += 1
  }

  return [
    { key: 'in_scope', label: 'In scope', color: 'var(--series-1)', count: inScope },
    { key: 'dependency', label: 'Dependencies', color: 'var(--series-2)', count: dependency },
    { key: 'test', label: 'Tests & scripts', color: 'var(--series-3)', count: test },
    { key: 'mock', label: 'Mocks', color: 'var(--series-4)', count: mock },
    { key: 'override', label: 'Excluded by override', color: 'var(--baseline)', count: override },
  ].filter((segment) => segment.count > 0)
}

export default function ScopeBar({ files }: { files: SourceFile[] }) {
  const segments = partition(files)
  const total = files.length || 1

  return (
    <section
      className="rounded-xl border p-5"
      style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
    >
      <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
        Scope composition
      </h2>
      <p className="mt-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
        Out-of-scope files stay in the inventory — the flag propagates, it does not filter.
      </p>

      <div className="mt-4 flex h-7 w-full gap-[2px] overflow-hidden rounded-md">
        {segments.map((segment) => (
          <div
            key={segment.key}
            title={`${segment.label}: ${segment.count}`}
            className="h-full first:rounded-l-md last:rounded-r-md"
            style={{
              width: `${(segment.count / total) * 100}%`,
              background: segment.color,
            }}
          />
        ))}
      </div>

      <ul className="mt-4 flex flex-wrap gap-x-6 gap-y-2">
        {segments.map((segment) => (
          <li key={segment.key} className="flex items-center gap-2 text-xs">
            <span
              className="h-2.5 w-2.5 shrink-0 rounded-sm"
              style={{ background: segment.color }}
              aria-hidden
            />
            <span style={{ color: 'var(--text-secondary)' }}>{segment.label}</span>
            <span className="mono font-semibold" style={{ color: 'var(--text-primary)' }}>
              {segment.count}
            </span>
            <span style={{ color: 'var(--text-muted)' }}>
              {((segment.count / total) * 100).toFixed(0)}%
            </span>
          </li>
        ))}
      </ul>
    </section>
  )
}
