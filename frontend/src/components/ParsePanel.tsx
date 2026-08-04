/**
 * Phase 3 — Parser results (`CodeModel`, SPEC §12).
 *
 * Two panes: pick a contract, inspect its functions. The point of the detail view is to
 * make the *derived* facts visible — call kinds, storage reads and writes, the ordering
 * that produces a CEI candidate — because those are what the Graph Engine and the agents
 * will consume, and a wrong one here is invisible everywhere downstream.
 *
 * Nothing is re-derived in the browser; every value comes off the artifact.
 */

import { useMemo, useState } from 'react'
import type {
  CallKind,
  CodeContract,
  CodeFunction,
  CodeModel,
  ContractKind,
} from '../types/repo'

const KIND_COLOR: Record<ContractKind, string> = {
  contract: 'var(--series-1)',
  interface: 'var(--series-3)',
  library: 'var(--series-4)',
  abstract: 'var(--series-2)',
}

/** Only the call kinds a reader needs colour for; the rest stay muted ink. */
const CALL_COLOR: Partial<Record<CallKind, string>> = {
  low_level: 'var(--status-critical)',
  member: 'var(--series-2)',
  super: 'var(--series-7, var(--series-3))',
  internal: 'var(--series-1)',
  new: 'var(--series-4)',
}

type Scope = 'in_scope' | 'all'

/** A state write ordered after an external call — the CEI-violation candidate (§13.3). */
function writesAfterExternalCall(fn: CodeFunction): boolean {
  const external = fn.calls
    .filter((c) => c.kind === 'low_level' || c.kind === 'member')
    .map((c) => c.order)
  if (external.length === 0) return false
  const first = Math.min(...external)
  return fn.accesses.some((a) => a.kind === 'write' && a.order > first)
}

function isEntrypoint(fn: CodeFunction): boolean {
  return (
    fn.visibility === 'public' ||
    fn.visibility === 'external' ||
    fn.kind === 'fallback' ||
    fn.kind === 'receive'
  )
}

function signature(fn: CodeFunction): string {
  const params = fn.params.map((p) => `${p.type}${p.name ? ` ${p.name}` : ''}`).join(', ')
  const returns = fn.returns.map((p) => p.type).join(', ')
  return `${fn.name}(${params})${returns ? ` → (${returns})` : ''}`
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
        {value.toLocaleString()}
      </div>
    </div>
  )
}

// ── Function detail ───────────────────────────────────────────────────────────

function FunctionRow({ fn }: { fn: CodeFunction }) {
  const [open, setOpen] = useState(false)

  const reads = fn.accesses.filter((a) => a.kind === 'read')
  const writes = fn.accesses.filter((a) => a.kind === 'write')
  const cei = writesAfterExternalCall(fn)
  const lowLevel = fn.calls.filter((c) => c.kind === 'low_level')

  return (
    <li className="border-t" style={{ borderColor: 'var(--gridline)' }}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full flex-wrap items-center gap-2 px-4 py-2.5 text-left"
      >
        <span className="mono text-xs" style={{ color: 'var(--text-primary)' }}>
          {signature(fn)}
        </span>
        <span className="mono text-[10px]" style={{ color: 'var(--text-muted)' }}>
          L{fn.line_start}
        </span>

        <span className="ml-auto flex flex-wrap items-center gap-1">
          {isEntrypoint(fn) && <Badge label="entrypoint" color="var(--series-1)" />}
          <Badge label={fn.visibility} color="var(--text-muted)" />
          {fn.mutability !== 'nonpayable' && (
            <Badge label={fn.mutability} color="var(--text-muted)" />
          )}
          {!fn.is_implemented && <Badge label="no body" color="var(--text-muted)" />}
          {lowLevel.length > 0 && (
            <Badge
              label={`${lowLevel.length} low-level`}
              color="var(--status-critical)"
              title="call / delegatecall / staticcall — where reentrancy and untrusted callbacks live"
            />
          )}
          {cei && (
            <Badge
              label="write after call"
              color="var(--status-warning)"
              title="A state write ordered after an external call — a CEI candidate, not a finding"
            />
          )}
          {fn.has_assembly && <Badge label="assembly" color="var(--series-4)" />}
        </span>
      </button>

      {open && (
        <div className="grid gap-4 px-4 pb-4 lg:grid-cols-2">
          <div className="flex flex-col gap-3">
            {fn.modifiers.length > 0 && (
              <Detail label="Modifiers">
                <span className="flex flex-wrap gap-1">
                  {fn.modifiers.map((m) => (
                    <Badge key={m} label={m} color="var(--series-3)" />
                  ))}
                </span>
              </Detail>
            )}

            <Detail label={`Calls (${fn.calls.length}) — in execution order`}>
              {fn.calls.length === 0 ? (
                <Empty />
              ) : (
                <ol className="flex flex-col gap-1">
                  {fn.calls.map((call) => (
                    <li key={`${call.order}-${call.line}`} className="flex items-center gap-2">
                      <span
                        className="mono w-5 text-right text-[10px]"
                        style={{ color: 'var(--text-muted)' }}
                      >
                        {call.order}
                      </span>
                      <Badge
                        label={call.kind}
                        color={CALL_COLOR[call.kind] ?? 'var(--text-muted)'}
                      />
                      <span className="mono text-xs" style={{ color: 'var(--text-primary)' }}>
                        {call.receiver ? `${call.receiver}.` : ''}
                        {call.name}
                      </span>
                      {call.sends_value && <Badge label="value" color="var(--status-warning)" />}
                      {call.is_delegate && (
                        <Badge label="delegate" color="var(--status-critical)" />
                      )}
                      {call.is_try && <Badge label="try" color="var(--text-muted)" />}
                      <span className="mono ml-auto text-[10px]" style={{ color: 'var(--text-muted)' }}>
                        L{call.line}
                      </span>
                    </li>
                  ))}
                </ol>
              )}
            </Detail>

            <div className="grid grid-cols-2 gap-3">
              <Detail label={`Reads (${reads.length})`}>
                <AccessList names={reads.map((a) => a.name)} />
              </Detail>
              <Detail label={`Writes (${writes.length})`}>
                <AccessList names={writes.map((a) => a.name)} />
              </Detail>
            </div>

            {(fn.emits.length > 0 || fn.reverts.length > 0) && (
              <div className="grid grid-cols-2 gap-3">
                <Detail label="Emits">
                  <AccessList names={fn.emits} />
                </Detail>
                <Detail label="Reverts">
                  <AccessList names={fn.reverts} />
                </Detail>
              </div>
            )}
          </div>

          <Detail label={`Source — lines ${fn.line_start}–${fn.line_end}`}>
            <pre
              className="mono max-h-80 overflow-auto rounded-lg p-3 text-[11px] whitespace-pre"
              style={{ background: 'var(--plane)', color: 'var(--text-secondary)' }}
            >
              {fn.raw}
            </pre>
          </Detail>
        </div>
      )}
    </li>
  )
}

function Detail({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div
        className="mb-1.5 text-[11px] uppercase tracking-wide"
        style={{ color: 'var(--text-muted)' }}
      >
        {label}
      </div>
      {children}
    </div>
  )
}

function Empty() {
  return (
    <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
      None.
    </span>
  )
}

function AccessList({ names }: { names: string[] }) {
  const unique = [...new Set(names)]
  if (unique.length === 0) return <Empty />
  return (
    <span className="flex flex-wrap gap-1">
      {unique.map((name) => (
        <span
          key={name}
          className="mono rounded px-1.5 py-0.5 text-[10px]"
          style={{ background: 'var(--plane)', color: 'var(--text-secondary)' }}
        >
          {name}
        </span>
      ))}
    </span>
  )
}

// ── Contract detail ───────────────────────────────────────────────────────────

function ContractDetail({ contract }: { contract: CodeContract }) {
  const callables = [...contract.functions, ...contract.modifiers]

  return (
    <section
      className="rounded-xl border"
      style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
    >
      <div className="border-b p-4" style={{ borderColor: 'var(--border)' }}>
        <div className="flex flex-wrap items-center gap-2">
          <Badge label={contract.kind} color={KIND_COLOR[contract.kind]} />
          <h3 className="text-sm font-semibold">{contract.name}</h3>
          {!contract.in_scope && <Badge label="out of scope" color="var(--text-muted)" />}
          {contract.is_dependency && <Badge label="dependency" color="var(--series-2)" />}
        </div>
        <p className="mono mt-1 text-[11px]" style={{ color: 'var(--text-muted)' }}>
          {contract.path}
        </p>

        {contract.inherits.length > 0 && (
          <p className="mt-3 text-xs" style={{ color: 'var(--text-secondary)' }}>
            inherits{' '}
            {contract.inherits.map((parent, index) => (
              <span key={parent} className="mono">
                {index > 0 && ', '}
                <span
                  style={{
                    color: contract.inherits_ids[index]
                      ? 'var(--text-primary)'
                      : 'var(--status-warning)',
                  }}
                  title={contract.inherits_ids[index] ?? 'not resolved to a file in this repository'}
                >
                  {parent}
                </span>
              </span>
            ))}
          </p>
        )}

        {contract.using_for.length > 0 && (
          <p className="mono mt-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
            {contract.using_for.map((u) => `using ${u.library} for ${u.target_type}`).join(' · ')}
          </p>
        )}
      </div>

      {contract.state_vars.length > 0 && (
        <div className="border-b p-4" style={{ borderColor: 'var(--border)' }}>
          <Detail label={`State variables (${contract.state_vars.length})`}>
            <table className="mono w-full text-left text-xs">
              <thead>
                <tr style={{ color: 'var(--text-muted)' }}>
                  <th className="py-1 pr-3 font-medium">Slot</th>
                  <th className="py-1 pr-3 font-medium">Name</th>
                  <th className="py-1 pr-3 font-medium">Type</th>
                  <th className="py-1 font-medium">Qualifiers</th>
                </tr>
              </thead>
              <tbody>
                {contract.state_vars.map((v) => (
                  <tr key={v.id} className="border-t" style={{ borderColor: 'var(--gridline)' }}>
                    <td
                      className="py-1.5 pr-3 tabular-nums"
                      style={{ color: v.slot === null ? 'var(--text-muted)' : 'var(--series-1)' }}
                      title={v.slot === null ? 'requires a successful build (SPEC §12.1)' : ''}
                    >
                      {v.slot === null ? '—' : `${v.slot}${v.offset ? `+${v.offset}` : ''}`}
                    </td>
                    <td className="py-1.5 pr-3" style={{ color: 'var(--text-primary)' }}>
                      {v.name}
                    </td>
                    <td className="py-1.5 pr-3" style={{ color: 'var(--text-secondary)' }}>
                      {v.type}
                    </td>
                    <td className="py-1.5">
                      <span className="flex flex-wrap gap-1">
                        <Badge label={v.visibility} color="var(--text-muted)" />
                        {v.is_constant && <Badge label="constant" color="var(--series-3)" />}
                        {v.is_immutable && <Badge label="immutable" color="var(--series-3)" />}
                        {v.is_transient && <Badge label="transient" color="var(--series-4)" />}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Detail>
        </div>
      )}

      <ul>
        {callables.length === 0 ? (
          <li className="p-4 text-xs" style={{ color: 'var(--text-muted)' }}>
            This contract declares no functions.
          </li>
        ) : (
          callables.map((fn) => <FunctionRow key={fn.id} fn={fn} />)
        )}
      </ul>
    </section>
  )
}

// ── Panel ─────────────────────────────────────────────────────────────────────

export default function ParsePanel({ code }: { code: CodeModel }) {
  const [scope, setScope] = useState<Scope>('in_scope')
  const [query, setQuery] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const contracts = useMemo(() => {
    return code.contracts.filter((c) => {
      if (scope === 'in_scope' && !c.in_scope) return false
      if (!query) return true
      const needle = query.toLowerCase()
      return c.name.toLowerCase().includes(needle) || c.path.toLowerCase().includes(needle)
    })
  }, [code.contracts, scope, query])

  const selected =
    code.contracts.find((c) => c.id === selectedId) ?? contracts[0] ?? code.contracts[0] ?? null

  const stats = useMemo(() => {
    const inScope = code.contracts.filter((c) => c.in_scope)
    const functions = inScope.flatMap((c) => c.functions)
    return {
      contracts: code.contracts.length,
      inScope: inScope.length,
      functions: code.contracts.reduce((n, c) => n + c.functions.length, 0),
      entrypoints: functions.filter(isEntrypoint).length,
      lowLevel: functions.reduce(
        (n, f) => n + f.calls.filter((c) => c.kind === 'low_level').length,
        0,
      ),
      cei: functions.filter(writesAfterExternalCall).length,
    }
  }, [code.contracts])

  const errors = code.parse_errors.filter((e) => e.severity === 'error')

  return (
    <div className="flex flex-col gap-4">
      <section
        className="rounded-xl border p-5"
        style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
      >
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold">Parser</h2>
          <Badge
            label={code.enriched ? 'solc-enriched' : 'tree-sitter only'}
            color={code.enriched ? 'var(--status-good)' : 'var(--text-muted)'}
            title={
              code.enriched
                ? 'Storage slots and canonical selectors came from the compiler'
                : 'No build was available — structure is complete, storage slots are not'
            }
          />
          <span className="mono ml-auto text-[11px]" style={{ color: 'var(--text-muted)' }}>
            {code.content_hash.slice(0, 16)}…
          </span>
        </div>
        <p className="mt-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
          Tree-sitter is the source of truth for structure; the compiler enriches semantics.
          Nothing here decides whether code is vulnerable — it makes code addressable,
          sliceable and graphable.
        </p>
      </section>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Tile label="Contracts" value={stats.contracts} />
        <Tile label="In scope" value={stats.inScope} accent="var(--series-1)" />
        <Tile label="Functions" value={stats.functions} />
        <Tile label="Entrypoints" value={stats.entrypoints} />
        <Tile label="Low-level calls" value={stats.lowLevel} accent="var(--status-critical)" />
        <Tile label="Write after call" value={stats.cei} accent="var(--status-warning)" />
      </div>

      <div className="grid gap-4 lg:grid-cols-[20rem_1fr]">
        {/* Contract list ─────────────────────────────────────────────────── */}
        <section
          className="flex flex-col rounded-xl border"
          style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
        >
          <div className="flex flex-col gap-2 border-b p-3" style={{ borderColor: 'var(--border)' }}>
            <div className="flex gap-1 rounded-lg p-1" style={{ background: 'var(--plane)' }}>
              {(
                [
                  { key: 'in_scope', label: 'In scope' },
                  { key: 'all', label: 'All' },
                ] as const
              ).map((option) => (
                <button
                  key={option.key}
                  type="button"
                  onClick={() => setScope(option.key)}
                  className="flex-1 rounded-md px-3 py-1 text-xs font-medium"
                  style={{
                    background: scope === option.key ? 'var(--surface-1)' : 'transparent',
                    color: scope === option.key ? 'var(--text-primary)' : 'var(--text-secondary)',
                  }}
                >
                  {option.label}
                </button>
              ))}
            </div>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Filter by name or path…"
              className="mono rounded-lg border px-3 py-1.5 text-xs outline-none"
              style={{
                background: 'var(--plane)',
                borderColor: 'var(--border)',
                color: 'var(--text-primary)',
              }}
            />
          </div>

          <ul className="max-h-[36rem] overflow-auto">
            {contracts.map((contract) => (
              <li key={contract.id}>
                <button
                  type="button"
                  onClick={() => setSelectedId(contract.id)}
                  className="flex w-full flex-col gap-0.5 border-b px-3 py-2 text-left"
                  style={{
                    borderColor: 'var(--gridline)',
                    background:
                      selected?.id === contract.id
                        ? 'color-mix(in srgb, var(--series-1) 10%, transparent)'
                        : 'transparent',
                  }}
                >
                  <span className="flex items-center gap-2">
                    <span
                      className="h-2 w-2 shrink-0 rounded-full"
                      style={{ background: KIND_COLOR[contract.kind] }}
                      aria-hidden
                    />
                    <span className="mono text-xs" style={{ color: 'var(--text-primary)' }}>
                      {contract.name}
                    </span>
                    <span className="mono ml-auto text-[10px]" style={{ color: 'var(--text-muted)' }}>
                      {contract.functions.length}
                    </span>
                  </span>
                  <span className="mono text-[10px]" style={{ color: 'var(--text-muted)' }}>
                    {contract.path}
                  </span>
                </button>
              </li>
            ))}
            {contracts.length === 0 && (
              <li className="p-4 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
                {scope === 'in_scope' && !query && code.contracts.length > 0 ? (
                  <>
                    {/* A lone `Test.sol` or `MockToken.sol` is scored like a real
                        protocol's test suite. Correct, and baffling if the empty list
                        does not say why. */}
                    Nothing is in scope — every contract was classified as a test, mock or
                    dependency.{' '}
                    <button
                      type="button"
                      onClick={() => setScope('all')}
                      className="underline underline-offset-2"
                      style={{ color: 'var(--series-1)' }}
                    >
                      Show all {code.contracts.length}
                    </button>
                    , or re-ingest with a scope override.
                  </>
                ) : (
                  'No contracts match.'
                )}
              </li>
            )}
          </ul>
        </section>

        {selected ? (
          <ContractDetail contract={selected} />
        ) : (
          <section
            className="rounded-xl border p-8 text-center text-sm"
            style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
          >
            <span style={{ color: 'var(--text-muted)' }}>Select a contract.</span>
          </section>
        )}
      </div>

      {/* Parse errors and notes ────────────────────────────────────────────── */}
      <div className="grid gap-4 lg:grid-cols-2">
        <section
          className="rounded-xl border p-5"
          style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
        >
          <h2 className="text-sm font-semibold">
            Parse messages{' '}
            <span className="mono font-normal" style={{ color: 'var(--text-muted)' }}>
              {code.parse_errors.length}
            </span>
          </h2>
          <p className="mt-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
            Non-fatal by design. Tree-sitter is error-tolerant, so a broken file yields a
            partial model rather than an aborted run.
          </p>
          <ul className="mt-3 flex max-h-64 flex-col gap-1.5 overflow-auto text-xs">
            {code.parse_errors.slice(0, 100).map((error, index) => (
              <li
                key={`${error.path}-${error.line}-${index}`}
                className="rounded-lg px-3 py-2"
                style={{ background: 'var(--plane)' }}
              >
                <span
                  className="mono text-[10px]"
                  style={{
                    color:
                      error.severity === 'error'
                        ? 'var(--status-critical)'
                        : 'var(--text-muted)',
                  }}
                >
                  {error.path}
                  {error.line ? `:${error.line}` : ''}
                </span>
                <div style={{ color: 'var(--text-secondary)' }}>{error.message}</div>
              </li>
            ))}
            {code.parse_errors.length === 0 && (
              <li style={{ color: 'var(--text-muted)' }}>Everything parsed cleanly.</li>
            )}
          </ul>
          {errors.length > 0 && (
            <p className="mt-2 text-xs" style={{ color: 'var(--status-critical)' }}>
              {errors.length} of these are errors, not warnings.
            </p>
          )}
        </section>

        <section
          className="rounded-xl border p-5"
          style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
        >
          <h2 className="text-sm font-semibold">Notes</h2>
          <ul className="mt-3 flex flex-col gap-2 text-xs">
            {code.notes.map((note) => (
              <li
                key={note}
                className="rounded-lg px-3 py-2"
                style={{ background: 'var(--plane)', color: 'var(--text-secondary)' }}
              >
                {note}
              </li>
            ))}
            {code.notes.length === 0 && (
              <li style={{ color: 'var(--text-muted)' }}>Nothing to report.</li>
            )}
          </ul>

          <h3 className="mt-5 text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
            Sources
          </h3>
          <p className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
            {code.sources.length} files parsed
            {code.sources.some((s) => s.has_syntax_error) &&
              ` · ${code.sources.filter((s) => s.has_syntax_error).length} with syntax errors`}
            {code.sources.some((s) => s.free_functions.length > 0) &&
              ` · ${code.sources.reduce((n, s) => n + s.free_functions.length, 0)} free functions`}
          </p>
        </section>
      </div>
    </div>
  )
}
