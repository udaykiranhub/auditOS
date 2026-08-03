/**
 * Phase 2 — Build Pipeline results.
 *
 * A failed build is a first-class outcome here, not an error state: the panel shows what
 * the compiler managed and states plainly what was lost. Storage layout and packing are
 * the things only a compiler knows, so they get the most room.
 */

import { useState } from 'react'
import {
  MAX_DEPLOYED_BYTECODE_BYTES,
  type BuildModel,
  type BuildStatus,
  type ContractArtifact,
} from '../types/repo'

const STATUS: Record<BuildStatus, { icon: string; label: string; color: string }> = {
  success: { icon: '✓', label: 'Compiled', color: 'var(--status-good)' },
  partial: { icon: '!', label: 'Partial', color: 'var(--status-warning)' },
  failed: { icon: '⨯', label: 'Failed', color: 'var(--status-critical)' },
  skipped: { icon: '–', label: 'Skipped', color: 'var(--text-muted)' },
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
      <div className="mt-1 text-2xl font-semibold" style={{ color: accent ?? 'var(--text-primary)' }}>
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

function ContractDetail({ contract }: { contract: ContractArtifact }) {
  const selectors = Object.entries(contract.method_identifiers)
  const oversize =
    contract.deployed_bytecode_size !== null &&
    contract.deployed_bytecode_size > MAX_DEPLOYED_BYTECODE_BYTES

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-center gap-3">
        <span className="mono text-sm font-semibold">{contract.name}</span>
        <span className="mono text-xs" style={{ color: 'var(--text-muted)' }}>
          {contract.path}
        </span>
        {!contract.in_scope && (
          <span
            className="mono rounded px-1.5 py-0.5 text-[10px]"
            style={{ background: 'var(--plane)', color: 'var(--text-muted)' }}
          >
            out of scope
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Meta label="Storage slots">{contract.storage.length}</Meta>
        <Meta label="Selectors">{selectors.length}</Meta>
        <Meta label="Creation">{contract.bytecode_size ?? '—'} B</Meta>
        <Meta label="Deployed">
          <span style={{ color: oversize ? 'var(--status-critical)' : undefined }}>
            {contract.deployed_bytecode_size ?? '—'} B{oversize && ' ⨯ over EIP-170'}
          </span>
        </Meta>
      </div>

      {/* Storage layout — the thing only a compiler knows ─────────────────── */}
      <div>
        <h4 className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
          Storage layout
        </h4>
        {contract.storage.length > 0 ? (
          <table className="mono mt-2 w-full text-left text-xs">
            <thead style={{ color: 'var(--text-muted)' }}>
              <tr>
                <th className="py-1 pr-3 font-medium">Slot</th>
                <th className="py-1 pr-3 font-medium">Offset</th>
                <th className="py-1 pr-3 font-medium">Label</th>
                <th className="py-1 pr-3 font-medium">Type</th>
                <th className="py-1 font-medium">Bytes</th>
              </tr>
            </thead>
            <tbody>
              {contract.storage.map((slot) => (
                <tr
                  key={`${slot.slot}-${slot.offset}-${slot.label}`}
                  className="border-t"
                  style={{ borderColor: 'var(--gridline)' }}
                >
                  <td className="py-1.5 pr-3 tabular-nums">{slot.slot}</td>
                  <td className="py-1.5 pr-3 tabular-nums" style={{ color: 'var(--text-secondary)' }}>
                    {slot.offset > 0 ? (
                      <span style={{ color: 'var(--series-2)' }} title="packed with the previous variable">
                        +{slot.offset}
                      </span>
                    ) : (
                      slot.offset
                    )}
                  </td>
                  <td className="py-1.5 pr-3">{slot.label}</td>
                  <td className="py-1.5 pr-3" style={{ color: 'var(--text-secondary)' }}>
                    {slot.type_label}
                  </td>
                  <td className="py-1.5 tabular-nums" style={{ color: 'var(--text-muted)' }}>
                    {slot.bytes_size ?? '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="mt-2 text-xs" style={{ color: 'var(--text-muted)' }}>
            No state variables.
          </p>
        )}
      </div>

      {selectors.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
            External surface
          </h4>
          <ul className="mono mt-2 flex flex-col gap-1 text-xs">
            {selectors.map(([signature, selector]) => (
              <li key={signature} className="flex gap-3">
                <span style={{ color: 'var(--text-muted)' }}>0x{selector}</span>
                <span>{signature}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {contract.abi_omitted && (
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
          ABI omitted: this contract is out of scope, and dependency ABIs add megabytes no agent
          reads.
        </p>
      )}
    </div>
  )
}

export default function BuildPanel({ build }: { build: BuildModel }) {
  const [selected, setSelected] = useState(0)
  const status = STATUS[build.status]
  const errors = build.diagnostics.filter((d) => d.severity === 'error')
  const warnings = build.diagnostics.filter((d) => d.severity === 'warning')
  const contract = build.contracts[selected]

  // The engine already collapses repetitive compiler failures into one sentence each;
  // the bookkeeping notes ("solc: attempted — …") are not reasons.
  const reasons = build.notes.filter(
    (note) => !note.startsWith('BUILD_DEGRADED') && !/: (attempted|unavailable)/.test(note),
  )

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
            {build.builder}
          </span>
          <h2 className="text-lg font-semibold">Build Pipeline</h2>
          <span
            className="rounded-full px-2.5 py-0.5 text-[11px] font-medium"
            style={{
              background: `color-mix(in srgb, ${status.color} 16%, transparent)`,
              color: status.color,
            }}
          >
            {status.icon} {status.label}
          </span>
        </div>

        <div className="mt-5 grid grid-cols-2 gap-4 md:grid-cols-4">
          <Meta label="solc requested">{build.solc_version_requested ?? '—'}</Meta>
          <Meta label="solc resolved">{build.solc_version_resolved ?? '—'}</Meta>
          <Meta label="Optimizer">
            {build.settings.optimizer_enabled === null
              ? '—'
              : build.settings.optimizer_enabled
                ? `on · ${build.settings.optimizer_runs ?? '?'} runs`
                : 'off'}
          </Meta>
          <Meta label="EVM version">{build.settings.evm_version ?? '—'}</Meta>
        </div>

        {!build.build_available && (
          <div
            className="mt-4 rounded-lg px-3 py-2.5 text-xs"
            style={{
              background: 'color-mix(in srgb, var(--status-warning) 12%, transparent)',
              color: 'var(--text-primary)',
            }}
          >
            <p>
              <strong>Degraded, not fatal.</strong> Storage layout and compile-dependent analysis
              (Slither) are unavailable for this run. Parsing and graphs are unaffected —
              tree-sitter reads code that does not compile.
            </p>
            {/* Say *why*, here. Otherwise the banner sends the reader hunting through
                sixty identical compiler errors for the one sentence that matters. */}
            {reasons.length > 0 && (
              <ul className="mt-2 flex flex-col gap-1.5">
                {reasons.map((reason) => (
                  <li key={reason} style={{ color: 'var(--text-secondary)' }}>
                    → {reason}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </section>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Tile label="Sources" value={build.sources.length} />
        <Tile label="With AST" value={build.sources.filter((s) => s.ast_path).length} />
        <Tile label="Contracts" value={build.contracts.length} accent="var(--series-1)" />
        <Tile label="With storage" value={build.contracts.filter((c) => c.storage.length).length} />
        <Tile
          label="Errors"
          value={errors.length}
          accent={errors.length ? 'var(--status-critical)' : undefined}
        />
        <Tile label="Warnings" value={warnings.length} />
      </div>

      {/* Contract explorer ───────────────────────────────────────────────── */}
      {build.contracts.length > 0 && (
        <section
          className="grid gap-0 rounded-xl border lg:grid-cols-[16rem_1fr]"
          style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
        >
          <div
            className="max-h-[30rem] overflow-auto border-b lg:border-r lg:border-b-0"
            style={{ borderColor: 'var(--border)' }}
          >
            {build.contracts.map((item, index) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setSelected(index)}
                className="mono block w-full px-4 py-2.5 text-left text-xs"
                style={{
                  background: index === selected ? 'var(--plane)' : 'transparent',
                  color: item.in_scope ? 'var(--text-primary)' : 'var(--text-muted)',
                  borderLeft: `2px solid ${index === selected ? 'var(--series-1)' : 'transparent'}`,
                }}
              >
                <span className="block font-medium">{item.name}</span>
                <span className="block text-[10px]" style={{ color: 'var(--text-muted)' }}>
                  {item.path}
                </span>
              </button>
            ))}
          </div>
          <div className="p-5">{contract && <ContractDetail contract={contract} />}</div>
        </section>
      )}

      {/* Diagnostics + notes ─────────────────────────────────────────────── */}
      <div className="grid gap-4 lg:grid-cols-2">
        <section
          className="rounded-xl border p-5"
          style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
        >
          <h2 className="text-sm font-semibold">Compiler diagnostics</h2>
          <p className="mt-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
            Evidence, not findings. A warning is context an agent may use, never a report entry on
            its own.
          </p>
          <ul className="mt-3 flex max-h-72 flex-col gap-2 overflow-auto text-xs">
            {[...errors, ...warnings].slice(0, 60).map((diagnostic, index) => (
              <li
                key={`${diagnostic.path}-${diagnostic.line}-${index}`}
                className="rounded-lg px-3 py-2"
                style={{ background: 'var(--plane)' }}
              >
                <span
                  className="mono mr-2 text-[10px] font-semibold uppercase"
                  style={{
                    color:
                      diagnostic.severity === 'error'
                        ? 'var(--status-critical)'
                        : 'var(--status-warning)',
                  }}
                >
                  {diagnostic.severity}
                </span>
                {diagnostic.path && (
                  <span className="mono" style={{ color: 'var(--text-muted)' }}>
                    {diagnostic.path}
                    {diagnostic.line ? `:${diagnostic.line}` : ''}{' '}
                  </span>
                )}
                <span style={{ color: 'var(--text-secondary)' }}>
                  {diagnostic.message.split('\n')[0]}
                </span>
              </li>
            ))}
            {build.diagnostics.length === 0 && (
              <li style={{ color: 'var(--text-muted)' }}>Clean compile.</li>
            )}
          </ul>
        </section>

        <section
          className="rounded-xl border p-5"
          style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
        >
          <h2 className="text-sm font-semibold">Notes</h2>
          <ul className="mt-3 flex flex-col gap-2 text-xs">
            {build.notes.map((note) => (
              <li
                key={note}
                className="rounded-lg px-3 py-2"
                style={{ background: 'var(--plane)', color: 'var(--text-secondary)' }}
              >
                {note}
              </li>
            ))}
            {build.notes.length === 0 && (
              <li style={{ color: 'var(--text-muted)' }}>Nothing to report.</li>
            )}
          </ul>

          <h3 className="mt-5 text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
            ASTs on disk
          </h3>
          <p className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
            Written beside the run rather than embedded — a mid-size contract's AST is megabytes.
          </p>
          <ul className="mono mt-2 flex max-h-40 flex-col gap-1 overflow-auto text-[11px]">
            {build.sources.map((source) => (
              <li key={source.path} style={{ color: 'var(--text-secondary)' }}>
                {source.ast_path ?? source.path}{' '}
                <span style={{ color: 'var(--text-muted)' }}>({source.ast_nodes} nodes)</span>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  )
}
