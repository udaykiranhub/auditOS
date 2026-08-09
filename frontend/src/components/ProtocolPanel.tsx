/**
 * Phase 5 — Protocol Understanding (`ProtocolModel`, SPEC §7.6).
 *
 * The first artifact in the pipeline that contains *interpretation*, so this panel is
 * organised around one question: **how much of this should you believe?**
 *
 * Three things are therefore never optional here. The confidence mix is shown before any
 * conclusion, because a model built from name-matching and a model built from resolved
 * graph edges look identical once you read only the conclusions. Coverage is shown with
 * denominators, because "4 contracts classified" means nothing without "out of 47". And
 * the blind spots and open questions get their own section, because a limitation that is
 * not displayed reads as an absence of risk.
 *
 * Nothing is re-derived in the browser. Every number comes off the artifact.
 */

import { useState } from 'react'
import type { ClaimConfidence, ProtocolSummary } from '../types/repo'

/** The ladder, weakest first. Colour tracks *how the claim was made*, not how alarming it is. */
const CONFIDENCE: { key: ClaimConfidence; label: string; color: string; hint: string }[] = [
  {
    key: 'refuted',
    label: 'refuted',
    color: 'var(--status-critical)',
    hint: 'An explicit check disagreed. Kept, never deleted.',
  },
  {
    key: 'proposed',
    label: 'proposed',
    color: 'var(--series-4)',
    hint: 'Produced by a model and not yet corroborated.',
  },
  {
    key: 'inferred',
    label: 'inferred',
    color: 'var(--series-2)',
    hint: 'A heuristic over names or signatures. Plausible, falsifiable.',
  },
  {
    key: 'derived',
    label: 'derived',
    color: 'var(--series-1)',
    hint: 'Computed by a documented rule over the CodeModel or GraphModel.',
  },
  {
    key: 'stated',
    label: 'stated',
    color: 'var(--series-3)',
    hint: 'Read literally from the code, the compiler, or a NatSpec tag.',
  },
  {
    key: 'verified',
    label: 'verified',
    color: 'var(--series-3)',
    hint: 'An independent check confirmed it — a build, a static analyser, or a Forge run.',
  },
]

const STATUS_COLOR: Record<string, string> = {
  candidate: 'var(--text-muted)',
  supported: 'var(--series-1)',
  verified: 'var(--series-3)',
  refuted: 'var(--status-critical)',
  unverifiable: 'var(--text-muted)',
}

type Tab = 'overview' | 'invariants' | 'risk' | 'limits'

function short(id: string): string {
  const [path, member] = id.split(':')
  return member ? `${path.split('/').pop()}:${member}` : id
}

function Meter({ value, total, label }: { value: number; total: number; label: string }) {
  const pct = total > 0 ? Math.round((value / total) * 100) : 0
  return (
    <div>
      <div className="flex items-baseline justify-between text-xs">
        <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
        <span className="mono">
          {value}
          <span style={{ color: 'var(--text-muted)' }}>/{total}</span>
        </span>
      </div>
      <div
        className="mt-1 h-1.5 overflow-hidden rounded-full"
        style={{ background: 'var(--surface-1)' }}
        role="meter"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={label}
      >
        <div
          className="h-full rounded-full"
          style={{ width: `${pct}%`, background: 'var(--series-1)' }}
        />
      </div>
    </div>
  )
}

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-lg p-3" style={{ background: 'var(--surface-1)' }}>
      <div className="mono text-lg font-semibold">{value}</div>
      <div className="mt-0.5 text-[11px]" style={{ color: 'var(--text-secondary)' }}>
        {label}
      </div>
    </div>
  )
}

export default function ProtocolPanel({ protocol }: { protocol: ProtocolSummary }) {
  const [tab, setTab] = useState<Tab>('overview')
  const { coverage, counts, confidence } = protocol

  const totalClaims = CONFIDENCE.reduce((sum, level) => sum + (confidence[level.key] ?? 0), 0)
  const grounded = coverage.grounded_claims
  const blocking = protocol.open_questions.filter((q) => q.blocking)

  return (
    <section className="flex flex-col gap-5">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h2 className="text-lg font-semibold">{protocol.identity.name || 'Unnamed protocol'}</h2>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {protocol.archetype.length > 0 ? (
              protocol.archetype.map((archetype) => (
                <span
                  key={archetype}
                  className="mono rounded px-1.5 py-0.5 text-[10px] font-medium"
                  style={{
                    background: 'color-mix(in srgb, var(--series-1) 18%, transparent)',
                    color: 'var(--series-1)',
                  }}
                >
                  {archetype}
                </span>
              ))
            ) : (
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                no archetype matched
              </span>
            )}
          </div>
        </div>

        {/* The confidence mix, before any conclusion. A model built from name-matching and
            one built from resolved graph edges are indistinguishable once you read only
            the conclusions. */}
        <div className="min-w-[260px]">
          <div className="text-[11px]" style={{ color: 'var(--text-secondary)' }}>
            How these {totalClaims} claims were made
          </div>
          <div
            className="mt-1.5 flex h-2 overflow-hidden rounded-full"
            style={{ background: 'var(--surface-1)' }}
          >
            {CONFIDENCE.map((level) => {
              const count = confidence[level.key] ?? 0
              if (count === 0) return null
              return (
                <div
                  key={level.key}
                  title={`${count} ${level.label} — ${level.hint}`}
                  style={{ width: `${(count / totalClaims) * 100}%`, background: level.color }}
                />
              )
            })}
          </div>
          <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-[10px]">
            {CONFIDENCE.filter((level) => (confidence[level.key] ?? 0) > 0).map((level) => (
              <span key={level.key} title={level.hint} style={{ color: level.color }}>
                ● {level.label} {confidence[level.key]}
              </span>
            ))}
          </div>
        </div>
      </header>

      {protocol.summary && (
        <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
          {protocol.summary}
        </p>
      )}

      <div className="flex gap-1 rounded-lg p-1" style={{ background: 'var(--surface-1)' }}>
        {(
          [
            { key: 'overview', label: 'Overview' },
            { key: 'invariants', label: `Invariants (${protocol.invariants.length})` },
            { key: 'risk', label: `Risk surfaces (${protocol.top_risk_surfaces.length})` },
            {
              key: 'limits',
              label: `Limits (${coverage.unmodelled.length + protocol.open_questions.length})`,
            },
          ] as const
        ).map((option) => (
          <button
            key={option.key}
            type="button"
            onClick={() => setTab(option.key)}
            className="rounded-md px-3 py-1.5 text-xs font-medium transition-colors"
            style={{
              background: tab === option.key ? 'var(--plane)' : 'transparent',
              color: tab === option.key ? 'var(--text-primary)' : 'var(--text-secondary)',
            }}
          >
            {option.label}
          </button>
        ))}
      </div>

      {tab === 'overview' && (
        <div className="flex flex-col gap-5">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-6">
            <Stat label="operations" value={counts.operations ?? 0} />
            <Stat label="actors" value={counts.actors ?? 0} />
            <Stat label="assets" value={counts.assets ?? 0} />
            <Stat label="asset flows" value={counts.asset_flows ?? 0} />
            <Stat label="dependencies" value={counts.dependencies ?? 0} />
            <Stat label="trust boundaries" value={counts.trust_boundaries ?? 0} />
          </div>

          {/* Denominators, always. "4 contracts classified" means nothing without "of 47". */}
          <div className="grid gap-3 sm:grid-cols-3">
            <Meter
              label="contracts classified"
              value={coverage.contracts_classified}
              total={coverage.contracts_total}
            />
            <Meter
              label="entrypoints modelled"
              value={coverage.operations_modelled}
              total={coverage.entrypoints_total}
            />
            <Meter
              label="state explained"
              value={coverage.state_vars_explained}
              total={coverage.state_vars_total}
            />
          </div>

          <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
            {grounded} of {totalClaims} claims are grounded — derived or better,{' '}
            <em>and</em> citing something you can open.
          </div>

          {protocol.documentation_conflicts.length > 0 && (
            <div
              className="rounded-lg border p-4"
              style={{
                background: 'color-mix(in srgb, var(--status-critical) 7%, var(--surface-1))',
                borderColor: 'color-mix(in srgb, var(--status-critical) 35%, transparent)',
              }}
            >
              <h3 className="text-sm font-semibold" style={{ color: 'var(--status-critical)' }}>
                {protocol.documentation_conflicts.length} documented promise
                {protocol.documentation_conflicts.length === 1 ? '' : 's'} the code appears to break
              </h3>
              <p className="mt-1 text-[11px]" style={{ color: 'var(--text-secondary)' }}>
                Read these first: the intent is already established, so only the behaviour is
                in question.
              </p>
              <ul className="mt-3 flex flex-col gap-2.5">
                {protocol.documentation_conflicts.map((conflict) => (
                  <li key={conflict.statement} className="text-xs">
                    <div>“{conflict.statement}”</div>
                    <div className="mt-0.5" style={{ color: 'var(--status-critical)' }}>
                      → {conflict.finding}
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {protocol.roles.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold">Contract roles</h3>
              <p className="mt-0.5 text-[11px]" style={{ color: 'var(--text-muted)' }}>
                Ranked by centrality — this order drives context selection.
              </p>
              <div className="mt-2 overflow-x-auto">
                <table className="w-full text-xs">
                  <tbody>
                    {protocol.roles.map((row) => (
                      <tr key={row.contract_id} style={{ borderTop: '1px solid var(--border)' }}>
                        <td className="py-1.5 pr-3 font-medium">{row.name}</td>
                        <td className="py-1.5 pr-3">
                          <span
                            className="mono rounded px-1.5 py-0.5 text-[10px]"
                            style={{
                              background:
                                row.role === 'unknown'
                                  ? 'var(--surface-1)'
                                  : 'color-mix(in srgb, var(--series-1) 16%, transparent)',
                              color:
                                row.role === 'unknown' ? 'var(--text-muted)' : 'var(--series-1)',
                            }}
                          >
                            {row.role}
                          </span>
                        </td>
                        <td
                          className="mono py-1.5 text-[10px]"
                          style={{ color: 'var(--text-muted)' }}
                        >
                          {row.contract_id}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'invariants' && (
        <div className="flex flex-col gap-3">
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Every one of these is a <strong>candidate</strong> until something executes it.
            Nothing deterministic promotes past “supported”; only a Forge run reaches
            “verified”. These are not findings.
          </p>
          {protocol.invariants.length === 0 && (
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
              No candidate invariants were derived. That is a legitimate outcome, not a clean
              bill of health.
            </p>
          )}
          <ul className="flex flex-col gap-2.5">
            {protocol.invariants.map((invariant) => (
              <li
                key={invariant.label}
                className="rounded-lg p-3"
                style={{ background: 'var(--surface-1)' }}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="mono text-[10px] font-semibold">{invariant.label}</span>
                  <span
                    className="mono rounded px-1.5 py-0.5 text-[10px]"
                    style={{
                      background: `color-mix(in srgb, ${STATUS_COLOR[invariant.status]} 18%, transparent)`,
                      color: STATUS_COLOR[invariant.status],
                    }}
                  >
                    {invariant.status}
                  </span>
                  <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
                    {invariant.kind}
                  </span>
                </div>
                <p className="mt-1.5 text-xs">{invariant.statement}</p>
                <div
                  className="mono mt-1.5 text-[10px]"
                  style={{ color: 'var(--text-muted)' }}
                >
                  {invariant.targets.map(short).join(' · ')}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {tab === 'risk' && (
        <div className="flex flex-col gap-3">
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Where to look, not what is wrong. Each surface is phrased as questions on
            purpose — a question survives being wrong; an assertion does not.
          </p>
          <ul className="flex flex-col gap-2.5">
            {protocol.top_risk_surfaces.map((surface) => (
              <li
                key={surface.id}
                className="rounded-lg p-3"
                style={{ background: 'var(--surface-1)' }}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className="mono rounded px-1.5 py-0.5 text-[10px]"
                    style={{
                      background: 'color-mix(in srgb, var(--series-2) 18%, transparent)',
                      color: 'var(--series-2)',
                    }}
                  >
                    {surface.kind}
                  </span>
                  <span className="mono text-[10px]" style={{ color: 'var(--text-muted)' }}>
                    priority {surface.priority.toFixed(2)}
                  </span>
                  {surface.agents.map((agent) => (
                    <span
                      key={agent}
                      className="mono text-[10px]"
                      style={{ color: 'var(--text-muted)' }}
                    >
                      → {agent}
                    </span>
                  ))}
                </div>
                <p className="mt-1.5 text-xs">{surface.title}</p>
                <div className="mono mt-1 text-[10px]" style={{ color: 'var(--text-muted)' }}>
                  {surface.targets.map(short).join(' · ')}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {tab === 'limits' && (
        <div className="flex flex-col gap-5">
          {/* A limitation that is not displayed reads as an absence of risk. */}
          <div>
            <h3 className="text-sm font-semibold">What this model could not see</h3>
            {coverage.unmodelled.length === 0 ? (
              <p className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                No structural blind spots were recorded.
              </p>
            ) : (
              <ul className="mt-2 flex flex-col gap-1.5 text-xs">
                {coverage.unmodelled.map((gap) => (
                  <li key={gap} style={{ color: 'var(--text-secondary)' }}>
                    · {gap}
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div>
            <h3 className="text-sm font-semibold">
              Open questions ({blocking.length} blocking)
            </h3>
            <p className="mt-0.5 text-[11px]" style={{ color: 'var(--text-muted)' }}>
              Questions the deterministic pass could not answer. Each is a small, specific
              prompt the optional enrichment pass can resolve — a blocking one means a field
              downstream is incomplete without it.
            </p>
            <ul className="mt-2 flex flex-col gap-1.5 text-xs">
              {protocol.open_questions.map((question) => (
                <li key={question.id} className="flex gap-2">
                  <span
                    style={{
                      color: question.blocking ? 'var(--status-critical)' : 'var(--text-muted)',
                    }}
                  >
                    {question.blocking ? '!' : '·'}
                  </span>
                  <span style={{ color: 'var(--text-secondary)' }}>{question.question}</span>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <h3 className="text-sm font-semibold">Enrichment</h3>
            <p className="mt-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
              {protocol.enrichment.applied
                ? `${protocol.enrichment.gaps_answered} questions answered by ${protocol.enrichment.provider} (${protocol.enrichment.model}), ${protocol.enrichment.gaps_rejected} rejected by evidence validation.`
                : 'Not applied — this model is entirely deterministic. Every claim above came from the code, not from a language model.'}
            </p>
          </div>

          {protocol.notes.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold">Notes</h3>
              <ul className="mt-2 flex flex-col gap-1.5 text-xs">
                {protocol.notes.map((note) => (
                  <li key={note} style={{ color: 'var(--text-secondary)' }}>
                    · {note}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </section>
  )
}
