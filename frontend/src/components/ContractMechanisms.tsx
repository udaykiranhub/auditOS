/**
 * Per-contract pages: what each function checks, changes, reads and calls.
 *
 * The unit is one contract, because that is the unit an auditor is pointed at. A single
 * summary page can say "49 operations, 10 risk surfaces" about a protocol and leave a
 * reader with nothing to open; this shows the mechanism instead — for every function, the
 * conditions that must hold, the state it moves and in which direction, and the calls that
 * leave the contract.
 *
 * Nothing is computed here. Every field comes off `GET /protocol/mechanisms/{contract}`,
 * which is derived from the semantic graph server-side so the CLI, the API and this screen
 * cannot disagree about what a contract does.
 */

import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { fetchMechanism, fetchMechanisms } from '../api/client'
import type { FunctionMechanism, StateChange } from '../types/repo'

/** Direction of a state change. Colour marks whether value enters or leaves. */
const EFFECT: Record<string, { glyph: string; color: string; label: string }> = {
  increase: { glyph: '↑', color: 'var(--series-2)', label: 'increases' },
  decrease: { glyph: '↓', color: 'var(--series-4)', label: 'decreases' },
  set: { glyph: '=', color: 'var(--text-secondary)', label: 'assigns' },
  scale: { glyph: '×', color: 'var(--text-secondary)', label: 'scales' },
}

function Pill({
  children,
  color,
  title,
}: {
  children: React.ReactNode
  color?: string
  title?: string
}) {
  return (
    <span
      title={title}
      className="mono rounded px-1.5 py-0.5 text-[10px] leading-tight"
      style={{
        background: color
          ? `color-mix(in srgb, ${color} 16%, transparent)`
          : 'var(--surface-1)',
        color: color ?? 'var(--text-secondary)',
      }}
    >
      {children}
    </span>
  )
}

function Change({ change }: { change: StateChange }) {
  const effect = EFFECT[change.effect] ?? EFFECT.set
  return (
    <li className="flex items-baseline gap-2">
      <span
        className="mono w-4 shrink-0 text-center text-xs"
        style={{ color: effect.color }}
        title={`${effect.label} ${change.variable}`}
      >
        {effect.glyph}
      </span>
      <code className="mono min-w-0 break-words text-[11px]">{change.expression}</code>
    </li>
  )
}

function FunctionCard({ fn }: { fn: FunctionMechanism }) {
  const [open, setOpen] = useState(false)
  const risky = fn.writes_after_external_call.length > 0
  const empty =
    !fn.conditions.length &&
    !fn.state_changes.length &&
    !fn.external_calls.length &&
    !fn.internal_calls.length

  return (
    <li
      className="rounded-lg border"
      style={{
        borderColor: 'var(--border)',
        background: 'var(--surface-1)',
      }}
    >
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="flex w-full flex-wrap items-center gap-x-2 gap-y-1.5 px-3 py-2 text-left"
      >
        <span className="mono text-xs font-medium">{fn.name}()</span>
        <Pill>{fn.visibility || '?'}</Pill>
        {fn.mutability && fn.mutability !== 'nonpayable' && <Pill>{fn.mutability}</Pill>}
        {fn.modifier_count > 0 && (
          <Pill color="var(--series-4)" title="modifiers are applied to this function">
            {fn.modifier_count} modifier{fn.modifier_count === 1 ? '' : 's'}
          </Pill>
        )}
        {fn.conditions.length > 0 && (
          <Pill color="var(--series-1)">
            {fn.conditions.length} condition{fn.conditions.length === 1 ? '' : 's'}
          </Pill>
        )}
        {fn.state_changes.length > 0 && (
          <Pill>{fn.state_changes.length} state change{fn.state_changes.length === 1 ? '' : 's'}</Pill>
        )}
        {/* A place to look, never a verdict — a guard may well cover it. */}
        {risky && (
          <Pill
            color="var(--status-critical)"
            title="state written after control left the frame — worth checking, not a finding"
          >
            writes after external call
          </Pill>
        )}
        <span className="ml-auto text-[10px]" style={{ color: 'var(--text-muted)' }}>
          {open ? '−' : '+'}
        </span>
      </button>

      {open && (
        <div className="grid gap-4 border-t px-3 py-3 sm:grid-cols-2" style={{ borderColor: 'var(--border)' }}>
          {empty && (
            <p className="text-[11px] sm:col-span-2" style={{ color: 'var(--text-muted)' }}>
              No conditions, state changes or calls were visible in this body.
            </p>
          )}

          {fn.conditions.length > 0 && (
            <section className="sm:col-span-2">
              <h5 className="text-[11px] font-semibold">Must hold to proceed</h5>
              <ul className="mt-1 flex flex-col gap-1">
                {fn.conditions.map((condition) => (
                  <li key={condition}>
                    <code
                      className="mono block break-words rounded px-2 py-1 text-[11px]"
                      style={{
                        background: 'color-mix(in srgb, var(--series-1) 10%, transparent)',
                        color: 'var(--series-1)',
                      }}
                    >
                      {condition}
                    </code>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {fn.state_changes.length > 0 && (
            <section>
              <h5 className="text-[11px] font-semibold">State changes</h5>
              <ul className="mt-1 flex flex-col gap-1">
                {fn.state_changes.map((change, i) => (
                  <Change key={`${change.expression}-${i}`} change={change} />
                ))}
              </ul>
            </section>
          )}

          {fn.external_calls.length > 0 && (
            <section>
              <h5 className="text-[11px] font-semibold" style={{ color: 'var(--status-critical)' }}>
                Control leaves here
              </h5>
              <ul className="mono mt-1 flex flex-col gap-1 text-[11px]">
                {fn.external_calls.map((call) => (
                  <li key={call} className="break-words">
                    {call}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {fn.reads.length > 0 && (
            <section>
              <h5 className="text-[11px] font-semibold">Reads</h5>
              <p className="mono mt-1 break-words text-[11px]" style={{ color: 'var(--text-secondary)' }}>
                {fn.reads.join(', ')}
              </p>
            </section>
          )}

          {fn.internal_calls.length > 0 && (
            <section>
              <h5 className="text-[11px] font-semibold">Calls in-frame</h5>
              <p className="mono mt-1 break-words text-[11px]" style={{ color: 'var(--text-secondary)' }}>
                {fn.internal_calls.join(', ')}
              </p>
            </section>
          )}
        </div>
      )}
    </li>
  )
}

export default function ContractMechanisms({ runId }: { runId: string }) {
  const [selected, setSelected] = useState<string | null>(null)
  const [showAll, setShowAll] = useState(false)

  const index = useQuery({
    queryKey: ['mechanisms', runId],
    queryFn: () => fetchMechanisms(runId),
  })
  const detail = useQuery({
    queryKey: ['mechanism', runId, selected],
    queryFn: () => fetchMechanism(runId, selected as string),
    enabled: selected !== null,
  })

  if (index.isPending) {
    return (
      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
        Loading contracts…
      </p>
    )
  }
  if (index.isError || !index.data) {
    return (
      <p className="text-xs" style={{ color: 'var(--status-critical)' }}>
        Could not load the contract mechanisms.
      </p>
    )
  }

  const { fidelity, contracts, notes } = index.data
  // Interfaces and libraries with nothing in them crowd out the contracts a reader wants.
  const substantive = contracts.filter((c) => c.functions > 0 && c.state + c.conditions > 0)
  const listed = showAll ? contracts : substantive.length ? substantive : contracts
  const contract = detail.data

  return (
    <div className="flex flex-col gap-4">
      {fidelity !== 'ast' && (
        <div
          className="rounded-lg border px-3 py-2 text-[11px]"
          style={{
            background: 'color-mix(in srgb, var(--status-warning) 8%, var(--surface-1))',
            borderColor: 'color-mix(in srgb, var(--status-warning) 35%, transparent)',
          }}
        >
          <strong>No compiler output.</strong> This view is built from the solc AST, which
          only exists when the repository compiles. Re-run with the build step enabled to
          see conditions and state changes. An empty relation here means “not visible”, not
          “not present”.
          {notes.map((note) => (
            <div key={note} className="mt-1" style={{ color: 'var(--text-secondary)' }}>
              {note}
            </div>
          ))}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,240px)_minmax(0,1fr)]">
        {/* Picker. Scrolls independently on desktop; stacks above the detail on mobile. */}
        <div className="flex flex-col gap-2">
          <ul
            className="flex max-h-[240px] flex-col gap-0.5 overflow-y-auto lg:max-h-[640px]"
            aria-label="Contracts"
          >
            {listed.map((row) => (
              <li key={row.contract_id}>
                <button
                  type="button"
                  onClick={() => setSelected(row.contract_id)}
                  aria-current={selected === row.contract_id}
                  className="w-full rounded-md px-2 py-1.5 text-left transition-colors"
                  style={{
                    background:
                      selected === row.contract_id ? 'var(--surface-1)' : 'transparent',
                  }}
                >
                  <div className="truncate text-xs font-medium">{row.name}</div>
                  <div className="mono text-[10px]" style={{ color: 'var(--text-muted)' }}>
                    {row.entrypoints}/{row.functions} entry · {row.state} state
                    {row.conditions > 0 && ` · ${row.conditions} cond`}
                  </div>
                </button>
              </li>
            ))}
          </ul>
          {substantive.length > 0 && substantive.length < contracts.length && (
            <button
              type="button"
              onClick={() => setShowAll(!showAll)}
              className="self-start text-[10px] underline"
              style={{ color: 'var(--text-muted)' }}
            >
              {showAll
                ? 'Hide interfaces and empty libraries'
                : `Show all ${contracts.length} (incl. interfaces)`}
            </button>
          )}
        </div>

        <div className="min-w-0">
          {contract === undefined ? (
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
              {selected === null
                ? 'Pick a contract to see how each of its functions behaves.'
                : 'Loading…'}
            </p>
          ) : (
            <div className="flex flex-col gap-5">
              <header>
                <h3 className="text-base font-semibold">{contract.name}</h3>
                <p className="mono text-[10px]" style={{ color: 'var(--text-muted)' }}>
                  {contract.kind} · {contract.path}
                  {contract.inherits.length > 0 && ` · is ${contract.inherits.join(', ')}`}
                </p>
              </header>

              {/* The relationships, which is what a summary page cannot show. */}
              {contract.relationships.length > 0 && (
                <section>
                  <h4 className="text-xs font-semibold">How its quantities constrain each other</h4>
                  <p className="mt-0.5 text-[10px]" style={{ color: 'var(--text-muted)' }}>
                    Read out of conditions the protocol enforces on itself — quoted, never
                    inferred from naming.
                  </p>
                  <ul className="mt-2 flex flex-col gap-2">
                    {contract.relationships.map((relation) => (
                      <li
                        key={`${relation.left}-${relation.right}-${relation.rule}`}
                        className="rounded-lg px-3 py-2"
                        style={{ background: 'var(--surface-1)' }}
                      >
                        <div className="mono flex flex-wrap items-center gap-1.5 text-[11px]">
                          <span style={{ color: 'var(--series-2)' }}>{relation.left}</span>
                          <span style={{ color: 'var(--text-muted)' }}>
                            ──{relation.operator}──▶
                          </span>
                          <span style={{ color: 'var(--series-4)' }}>{relation.right}</span>
                        </div>
                        <code
                          className="mono mt-1 block break-words text-[10px]"
                          style={{ color: 'var(--text-secondary)' }}
                        >
                          {relation.rule}
                          {relation.enforced_in && `   · enforced in ${relation.enforced_in}`}
                        </code>
                      </li>
                    ))}
                  </ul>
                </section>
              )}

              {contract.state.length > 0 && (
                <section>
                  <h4 className="text-xs font-semibold">Storage</h4>
                  <div className="mt-1.5 overflow-x-auto">
                    <table className="w-full min-w-[320px] text-[11px]">
                      <tbody>
                        {contract.state.map((item) => (
                          <tr key={item.name} style={{ borderTop: '1px solid var(--border)' }}>
                            <td className="mono py-1 pr-3 font-medium">{item.name}</td>
                            <td
                              className="mono py-1 pr-3"
                              style={{ color: 'var(--text-muted)' }}
                            >
                              {item.type}
                            </td>
                            <td className="py-1" style={{ color: 'var(--text-muted)' }}>
                              {item.visibility}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}

              <section>
                <h4 className="text-xs font-semibold">
                  Functions ({contract.functions.length})
                </h4>
                <p className="mt-0.5 text-[10px]" style={{ color: 'var(--text-muted)' }}>
                  Entry points first. Open one for its conditions, state changes and calls.
                </p>
                <ul className="mt-2 flex flex-col gap-1.5">
                  {contract.functions.map((fn) => (
                    <FunctionCard key={fn.qualified_name + fn.solidity_id} fn={fn} />
                  ))}
                </ul>
              </section>

              {contract.depends_on.length > 0 && (
                <section>
                  <h4 className="text-xs font-semibold">Reaches outside this contract</h4>
                  <p
                    className="mono mt-1 break-words text-[11px]"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    {contract.depends_on.join(', ')}
                  </p>
                </section>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
