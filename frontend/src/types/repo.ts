/**
 * Mirrors the engine's Pydantic artifacts in `engine/core/models/repo.py`.
 * When a model there changes, this changes with it.
 */

export type ProjectKind = 'FOUNDRY' | 'HARDHAT' | 'RAW' | 'UNKNOWN'
export type Origin = 'zip' | 'folder' | 'git'

export interface SourceFile {
  path: string
  sha256: string
  loc: number
  is_test: boolean
  is_mock: boolean
  is_dependency: boolean
  is_interface_only: boolean
  in_scope: boolean
  scope_reason: string
}

export interface ScopeOverride {
  include: string[]
  exclude: string[]
}

export interface RepoModel {
  schema_version: string
  content_hash: string
  root: string
  origin: Origin
  kind: ProjectKind
  files: SourceFile[]
  solidity_version: string | null
  solidity_version_source: string | null
  remappings: Record<string, string>
  config_raw: Record<string, unknown>
  readme: string | null
  docs: string[]
  scope_override: ScopeOverride
  notes: string[]
}

export interface IngestResponse {
  run_id: string
  artifact_path: string
  counts: {
    total: number
    in_scope: number
    tests: number
    mocks: number
    dependencies: number
    interfaces: number
  }
  repo: RepoModel
}

/** The shape a `FatalError` takes on the wire (see `engine/api/routes.py`). */
export interface ApiError {
  code?: string
  message: string
  hint?: string | null
}

// ── BuildModel — mirrors engine/core/models/build.py ─────────────────────────

export type Builder = 'foundry' | 'hardhat' | 'solc' | 'none'
export type BuildStatus = 'success' | 'partial' | 'failed' | 'skipped'
export type DiagnosticSeverity = 'error' | 'warning' | 'info'

/** EIP-170: deployed bytecode above this cannot be deployed at all. */
export const MAX_DEPLOYED_BYTECODE_BYTES = 24_576

export interface Diagnostic {
  severity: DiagnosticSeverity
  message: string
  error_code: string | null
  path: string | null
  line: number | null
  column: number | null
}

export interface StorageSlot {
  label: string
  slot: number
  offset: number
  type_label: string
  bytes_size: number | null
  encoding: string | null
}

export interface ContractArtifact {
  id: string
  path: string
  name: string
  in_scope: boolean
  storage: StorageSlot[]
  method_identifiers: Record<string, string>
  abi: Record<string, unknown>[]
  abi_omitted: boolean
  bytecode_size: number | null
  deployed_bytecode_size: number | null
}

export interface SourceUnit {
  path: string
  ast_path: string | null
  ast_sha256: string | null
  ast_nodes: number | null
}

export interface CompilerSettings {
  optimizer_enabled: boolean | null
  optimizer_runs: number | null
  evm_version: string | null
  via_ir: boolean | null
  remappings: string[]
}

export interface BuildModel {
  schema_version: string
  content_hash: string
  repo_content_hash: string
  builder: Builder
  status: BuildStatus
  build_available: boolean
  solc_version_requested: string | null
  solc_version_resolved: string | null
  settings: CompilerSettings
  sources: SourceUnit[]
  contracts: ContractArtifact[]
  diagnostics: Diagnostic[]
  notes: string[]
}
