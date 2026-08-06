/**
 * Phase 4 — Graph Engine results (`GraphModel`, SPEC §13).
 *
 * The graph's value is that it answers questions deterministically, so this panel is
 * organised around the answers rather than around a node-and-edge picture: the
 * pre-computed reentrancy candidates, what each function reaches, and — just as important
 * — what the graph could not resolve. A blind spot that is not shown reads as an absence
 * of risk.
 *
 * Nothing is re-derived in the browser. Every number here comes off the artifact.
 */

import { useMemo, useState } from 'react'
import type { Confidence, GraphEdge, GraphModel, GraphNode } from '../types/repo'

const CONFIDENCE_COLOR: Record<Confidence, string> = {
  high: 'var(--status-critical)',
  medium: 'var(--series-2)',
  low: 'var(--text-muted)',
}

/** Only the edge kinds worth colour; the rest read as muted ink. */
const EDGE_COLOR: Record<string, string> = {
  calls: 'var(--series-1)',
  delegatecalls: 'var(--status-critical)',
  staticcalls: 'var(--series-3)',
  creates: 'var(--series-4)',
  writes: 'var(--series-2)',
  reads: 'var(--series-3)',
  modified_by: 'var(--series-4)',
  sends_value: 'var(--status-critical)',
}

const SENTINELS = ['@UNTRUSTED_EXTERNAL', '@UNKNOWN_EXTERNAL']

type Tab = 'candidates' | 'explore' | 'coverage'

function short(id: string): string {
  if (id.startsWith('@')) return id.slice(1)
  const [path, member] = id.split(':')
  return member ? `${path.split('/').pop()}:${member}` : id
}

function Badge({ label, color, title }: { label: string; color: string; title?: string }) {
  return (
    <span
      title={title}
      className="mono rounded px-1.5 py-0.5 text-[10px] font-medium whitespace-nowrap"
      style={{ background: `color-mix(in srgb, ${color} 18%, transparent)`, color }}
    >
      {label}
    </span>
  )
}

function Tile({ label, value, hint }: { label: string; value: number | string; hint?: string }) {
  return (
    <div
      title={hint}
      className="rounded-lg border p-3"
      style={{ background: 'var(--plane)', borderColor: 'var(--border)' }}
    >
      <div className="text-[11px] uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
        {label}
      </div>
      <div className="mono mt-1 text-lg font-semibold">{value}</div>
    </div>
  )
}

export default function GraphPanel({ graph }: { graph: GraphModel }) {
  const [tab, setTab] = useState<Tab>('candidates')

  const index = useMemo(() => {
    const nodes = new Map<string, GraphNode>()
    for (const node of graph.nodes) nodes.set(node.id, node)

    const out = new Map<string, GraphEdge[]>()
    const inbound = new Map<string, GraphEdge[]>()
    for (const edge of graph.edges) {
      if (!out.has(edge.source)) out.set(edge.source, [])
      if (!inbound.has(edge.target)) inbound.set(edge.target, [])
      out.get(edge.source)!.push(edge)
      inbound.get(edge.target)!.push(edge)
    }
    return { nodes, out, inbound }
  }, [graph])

  const counts = useMemo(() => {
    const kinds = new Map<string, number>()
    for (const edge of graph.edges) kinds.set(edge.kind, (kinds.get(edge.kind) ?? 0) + 1)
    return {
      entrypoints: graph.nodes.filter((n) => n.is_entrypoint).length,
      contracts: graph.nodes.filter((n) => n.kind === 'contract').length,
      external: graph.edges.filter((e) => SENTINELS.includes(e.target)).length,
      kinds,
    }
  }, [graph])

  return (
    <section
      className="flex flex-col gap-5 rounded-xl border p-5"
      style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
    >
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">Code property graph</h2>
          <p className="mt-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
            One graph; every "view" below is a projection over edge kind, not a copy.
          </p>
        </div>
        <span className="mono text-[10px]" style={{ color: 'var(--text-muted)' }}>
          {graph.content_hash.slice(0, 12)}
        </span>
      </header>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Tile label="Nodes" value={graph.nodes.length} />
        <Tile label="Edges" value={graph.edges.length} />
        <Tile label="Contracts" value={counts.contracts} />
        <Tile label="Entrypoints" value={counts.entrypoints} hint="Externally callable" />
        <Tile
          label="Leaves repo"
          value={counts.external}
          hint="Calls terminating at a sentinel node"
        />
        <Tile
          label="Reentrancy"
          value={graph.reentrancy_candidates.length}
          hint="Pre-computed entrypoint → external call → state write paths"
        />
      </div>

      <div className="flex gap-1 self-start rounded-lg p-1" style={{ background: 'var(--plane)' }}>
        {(
          [
            { key: 'candidates', label: `Candidates (${graph.reentrancy_candidates.length})` },
            { key: 'explore', label: 'Explore' },
            { key: 'coverage', label: `Coverage (${graph.unresolved.length})` },
          ] as const
        ).map((option) => (
          <button
            key={option.key}
            type="button"
            onClick={() => setTab(option.key)}
            className="rounded-md px-3 py-1.5 text-xs font-medium transition-colors"
            style={{
              background: tab === option.key ? 'var(--surface-1)' : 'transparent',
              color: tab === option.key ? 'var(--text-primary)' : 'var(--text-secondary)',
            }}
          >
            {option.label}
          </button>
        ))}
      </div>

      {tab === 'candidates' && <Candidates graph={graph} />}
      {tab === 'explore' && <Explore graph={graph} index={index} />}
      {tab === 'coverage' && <Coverage graph={graph} />}
    </section>
  )
}

// ── Reentrancy candidates ─────────────────────────────────────────────────────

function Candidates({ graph }: { graph: GraphModel }) {
  if (graph.reentrancy_candidates.length === 0) {
    return (
      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
        No function writes state after handing control to code outside the repository. That
        is the check-effects-interactions order holding across every in-scope entrypoint.
      </p>
    )
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
        A state write ordered <em>after</em> an external call. These are candidates, not
        findings — a guard may already cover the path. Computed here so no model has to
        find them by reading code.
      </p>

      {graph.reentrancy_candidates.map((candidate, position) => (
        <article
          key={`${candidate.function}-${candidate.entrypoint}-${candidate.external_line}-${position}`}
          className="rounded-lg border p-4"
          style={{
            background: 'var(--plane)',
            borderColor: `color-mix(in srgb, ${CONFIDENCE_COLOR[candidate.confidence]} 35%, var(--border))`,
          }}
        >
          <div className="flex flex-wrap items-center gap-2">
            <Badge label={candidate.confidence} color={CONFIDENCE_COLOR[candidate.confidence]} />
            {candidate.guard && (
              <Badge
                label={`guarded: ${candidate.guard}`}
                color="var(--series-3)"
                title="A reentrancy-guard modifier is applied somewhere on this path. Whether it covers this call is the agent's judgement, not the graph's."
              />
            )}
            <span className="mono text-xs font-medium">{short(candidate.function)}</span>
          </div>

          <ol className="mt-3 flex flex-wrap items-center gap-1.5 text-[11px]">
            {candidate.path.map((step, depth) => (
              <li key={step} className="flex items-center gap-1.5">
                {depth > 0 && <span style={{ color: 'var(--text-muted)' }}>→</span>}
                <span
                  className="mono rounded px-1.5 py-0.5"
                  style={{
                    background: 'var(--surface-1)',
                    color: depth === 0 ? 'var(--series-1)' : 'var(--text-secondary)',
                  }}
                >
                  {short(step)}
                </span>
              </li>
            ))}
          </ol>

          <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-[8rem_1fr]">
            <dt style={{ color: 'var(--text-muted)' }}>External call</dt>
            <dd className="mono">
              {candidate.external_call}{' '}
              <span style={{ color: 'var(--text-muted)' }}>
                (line {candidate.external_line} → {short(candidate.external_target)})
              </span>
            </dd>

            <dt style={{ color: 'var(--text-muted)' }}>Then writes</dt>
            <dd className="flex flex-wrap gap-1.5">
              {candidate.writes_after.map((variable) => (
                <span key={variable} className="mono" style={{ color: 'var(--series-2)' }}>
                  {variable.split('#')[1] ?? variable}
                </span>
              ))}
            </dd>
          </dl>
        </article>
      ))}
    </div>
  )
}

// ── Explore ───────────────────────────────────────────────────────────────────

interface Index {
  nodes: Map<string, GraphNode>
  out: Map<string, GraphEdge[]>
  inbound: Map<string, GraphEdge[]>
}

function Explore({ graph, index }: { graph: GraphModel; index: Index }) {
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<string | null>(null)

  const functions = useMemo(
    () =>
      graph.nodes
        .filter((node) => node.kind === 'function' || node.kind === 'modifier')
        .filter((node) => node.in_scope)
        .filter((node) => !search || node.id.toLowerCase().includes(search.toLowerCase()))
        .slice(0, 400),
    [graph, search],
  )

  const node = selected ? index.nodes.get(selected) : null
  const outgoing = selected ? (index.out.get(selected) ?? []) : []
  const incoming = selected ? (index.inbound.get(selected) ?? []) : []

  return (
    <div className="grid gap-4 lg:grid-cols-[20rem_1fr]">
      <div className="flex flex-col gap-2">
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Filter in-scope functions…"
          className="mono rounded-lg border px-3 py-2 text-xs outline-none"
          style={{
            background: 'var(--plane)',
            borderColor: 'var(--border)',
            color: 'var(--text-primary)',
          }}
        />
        <ul
          className="flex max-h-[28rem] flex-col gap-0.5 overflow-y-auto rounded-lg border p-1"
          style={{ background: 'var(--plane)', borderColor: 'var(--border)' }}
        >
          {functions.map((entry) => (
            <li key={entry.id}>
              <button
                type="button"
                onClick={() => setSelected(entry.id)}
                className="mono w-full truncate rounded px-2 py-1 text-left text-[11px]"
                style={{
                  background: selected === entry.id ? 'var(--surface-1)' : 'transparent',
                  color: entry.is_entrypoint ? 'var(--series-1)' : 'var(--text-secondary)',
                }}
                title={entry.id}
              >
                {entry.is_entrypoint ? '● ' : '○ '}
                {short(entry.id)}
              </button>
            </li>
          ))}
          {functions.length === 0 && (
            <li className="px-2 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
              Nothing matches.
            </li>
          )}
        </ul>
      </div>

      <div
        className="rounded-lg border p-4"
        style={{ background: 'var(--plane)', borderColor: 'var(--border)' }}
      >
        {!node && (
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Pick a function to see everything the graph knows it reaches, and everything
            that reaches it.
          </p>
        )}

        {node && (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <span className="mono text-xs font-semibold">{node.name}</span>
              {node.is_entrypoint && <Badge label="entrypoint" color="var(--series-1)" />}
              {node.visibility && <Badge label={node.visibility} color="var(--text-muted)" />}
              {node.mutability && node.mutability !== 'nonpayable' && (
                <Badge label={node.mutability} color="var(--series-3)" />
              )}
              {node.has_assembly && (
                <Badge
                  label="assembly"
                  color="var(--status-critical)"
                  title="Contains inline assembly; storage touched in Yul has no edges in this graph."
                />
              )}
            </div>
            <p className="mono mt-1 text-[10px]" style={{ color: 'var(--text-muted)' }}>
              {node.id}
            </p>

            <EdgeList title="Reaches" edges={outgoing} direction="target" />
            <EdgeList title="Reached by" edges={incoming} direction="source" />
          </>
        )}
      </div>
    </div>
  )
}

function EdgeList({
  title,
  edges,
  direction,
}: {
  title: string
  edges: GraphEdge[]
  direction: 'source' | 'target'
}) {
  const shown = edges.filter((edge) => edge.kind !== 'contains')
  if (shown.length === 0) return null

  return (
    <div className="mt-4">
      <h4 className="text-[11px] uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
        {title} ({shown.length})
      </h4>
      <ul className="mt-2 flex flex-col gap-1">
        {shown.slice(0, 60).map((edge, position) => (
          <li
            key={`${edge.kind}-${edge.source}-${edge.target}-${edge.line}-${position}`}
            className="flex flex-wrap items-center gap-2 text-[11px]"
          >
            <Badge label={edge.kind} color={EDGE_COLOR[edge.kind] ?? 'var(--text-muted)'} />
            <span
              className="mono"
              style={{
                color: SENTINELS.includes(edge[direction])
                  ? 'var(--status-critical)'
                  : 'var(--text-secondary)',
              }}
              title={edge[direction]}
            >
              {short(edge[direction])}
            </span>
            {edge.confidence !== 'high' && (
              <span style={{ color: 'var(--text-muted)' }}>({edge.confidence})</span>
            )}
            {edge.line > 0 && (
              <span className="mono" style={{ color: 'var(--text-muted)' }}>
                :{edge.line}
              </span>
            )}
          </li>
        ))}
        {shown.length > 60 && (
          <li className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
            … and {shown.length - 60} more
          </li>
        )}
      </ul>
    </div>
  )
}

// ── Coverage ──────────────────────────────────────────────────────────────────

function Coverage({ graph }: { graph: GraphModel }) {
  const byReason = useMemo(() => {
    const grouped = new Map<string, { count: number; sample: string[] }>()
    for (const item of graph.unresolved) {
      const entry = grouped.get(item.reason) ?? { count: 0, sample: [] }
      entry.count += 1
      if (entry.sample.length < 3 && item.function) entry.sample.push(item.function)
      grouped.set(item.reason, entry)
    }
    return [...grouped.entries()].sort((a, b) => b[1].count - a[1].count)
  }, [graph])

  return (
    <div className="flex flex-col gap-4">
      <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
        What the graph could not resolve. A blind spot that is not shown reads as an absence
        of risk, so nothing here is dropped silently.
      </p>

      {byReason.length === 0 && (
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
          Every call, parent and storage access resolved.
        </p>
      )}

      {byReason.map(([reason, entry]) => (
        <div
          key={reason}
          className="rounded-lg border p-3"
          style={{ background: 'var(--plane)', borderColor: 'var(--border)' }}
        >
          <div className="flex items-center gap-2">
            <Badge
              label={String(entry.count)}
              color={
                reason === 'UNRESOLVED_DELEGATECALL'
                  ? 'var(--status-critical)'
                  : 'var(--series-2)'
              }
            />
            <span className="mono text-xs font-medium">{reason}</span>
          </div>
          <ul className="mt-2 flex flex-col gap-0.5">
            {entry.sample.map((id) => (
              <li key={id} className="mono text-[10px]" style={{ color: 'var(--text-muted)' }}>
                {short(id)}
              </li>
            ))}
          </ul>
        </div>
      ))}

      <div>
        <h4
          className="text-[11px] uppercase tracking-wide"
          style={{ color: 'var(--text-muted)' }}
        >
          Views
        </h4>
        <div className="mt-2 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {Object.entries(graph.views).map(([name, summary]) => (
            <div
              key={name}
              className="flex items-baseline justify-between rounded-lg border px-3 py-2 text-xs"
              style={{ background: 'var(--plane)', borderColor: 'var(--border)' }}
              title={summary.kinds.join(', ')}
            >
              <span className="mono">{name}</span>
              <span style={{ color: 'var(--text-muted)' }}>
                {summary.edges} edges · {summary.nodes} nodes
              </span>
            </div>
          ))}
        </div>
      </div>

      {graph.notes.length > 0 && (
        <div>
          <h4
            className="text-[11px] uppercase tracking-wide"
            style={{ color: 'var(--text-muted)' }}
          >
            Notes
          </h4>
          <ul className="mt-2 flex flex-col gap-1">
            {graph.notes.map((note) => (
              <li key={note} className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                · {note}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
