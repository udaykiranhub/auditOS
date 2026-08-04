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

// ── CodeModel — mirrors engine/core/models/code.py ───────────────────────────

export type ContractKind = 'contract' | 'interface' | 'library' | 'abstract'
export type FunctionKind =
  | 'function'
  | 'constructor'
  | 'fallback'
  | 'receive'
  | 'modifier'
  | 'free'
/** The confidence ladder from SPEC §13.2. `low_level` is where reentrancy lives. */
export type CallKind =
  | 'internal'
  | 'this'
  | 'super'
  | 'member'
  | 'low_level'
  | 'new'
  | 'builtin'
export type AccessKind = 'read' | 'write'
export type Visibility = 'public' | 'external' | 'internal' | 'private'
export type Mutability = 'pure' | 'view' | 'nonpayable' | 'payable'

export interface Param {
  name: string
  type: string
  indexed: boolean
  location: string | null
}

export interface CallSite {
  kind: CallKind
  name: string
  receiver: string | null
  text: string
  line: number
  order: number
  sends_value: boolean
  is_delegate: boolean
  is_static: boolean
  is_try: boolean
}

export interface StateAccess {
  name: string
  /** Empty until the Graph Engine resolves inheritance (SPEC §13.1). */
  state_var_id: string
  kind: AccessKind
  line: number
  order: number
}

export interface CodeFunction {
  id: string
  name: string
  contract_id: string | null
  kind: FunctionKind
  visibility: Visibility
  mutability: Mutability
  is_virtual: boolean
  is_override: boolean
  is_implemented: boolean
  modifiers: string[]
  params: Param[]
  returns: Param[]
  src_start: number
  src_end: number
  line_start: number
  line_end: number
  body_hash: string
  raw: string
  natspec: string | null
  calls: CallSite[]
  accesses: StateAccess[]
  emits: string[]
  reverts: string[]
  has_assembly: boolean
  has_loop: boolean
  has_unchecked: boolean
}

export interface CodeStateVar {
  id: string
  name: string
  type: string
  contract_id: string
  visibility: Visibility
  is_constant: boolean
  is_immutable: boolean
  is_transient: boolean
  slot: number | null
  offset: number | null
  line: number
}

export interface UsingDirective {
  library: string
  target_type: string
  is_global: boolean
}

export interface CodeEvent {
  name: string
  params: Param[]
  is_anonymous: boolean
  line: number
}

export interface CustomError {
  name: string
  params: Param[]
  line: number
}

export interface StructDef {
  name: string
  fields: Param[]
  line: number
}

export interface EnumDef {
  name: string
  values: string[]
  line: number
}

export interface CodeContract {
  id: string
  name: string
  path: string
  kind: ContractKind
  inherits: string[]
  inherits_ids: string[]
  functions: CodeFunction[]
  modifiers: CodeFunction[]
  state_vars: CodeStateVar[]
  events: CodeEvent[]
  errors: CustomError[]
  structs: StructDef[]
  enums: EnumDef[]
  using_for: UsingDirective[]
  natspec: string | null
  is_dependency: boolean
  in_scope: boolean
  line_start: number
  line_end: number
}

export interface CodeImport {
  path: string
  resolved_path: string | null
  symbols: string[]
  line: number
}

export interface CodeSourceUnit {
  path: string
  pragma: string | null
  imports: CodeImport[]
  contract_ids: string[]
  free_functions: CodeFunction[]
  structs: StructDef[]
  enums: EnumDef[]
  errors: CustomError[]
  events: CodeEvent[]
  user_defined_types: string[]
  in_scope: boolean
  has_syntax_error: boolean
}

export interface ParseError {
  path: string
  line: number | null
  message: string
  severity: 'error' | 'warning'
}

export interface CodeModel {
  schema_version: string
  content_hash: string
  repo_content_hash: string
  build_content_hash: string | null
  sources: CodeSourceUnit[]
  contracts: CodeContract[]
  parse_errors: ParseError[]
  notes: string[]
  enriched: boolean
}
