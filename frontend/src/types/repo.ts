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

// ── GraphModel (SPEC §7.5, §13) ──────────────────────────────────────────────
// One code property graph; the "views" are edge-kind projections, not copies.

export type Confidence = 'high' | 'medium' | 'low'

export interface GraphNode {
  id: string
  kind: string
  name: string
  path: string
  contract_id: string | null
  line: number
  visibility: string | null
  mutability: string | null
  type: string | null
  slot: number | null
  in_scope: boolean
  is_dependency: boolean
  is_entrypoint: boolean
  is_implemented: boolean
  has_assembly: boolean
}

export interface GraphEdge {
  source: string
  target: string
  kind: string
  confidence: Confidence
  line: number
  order: number
  via: string | null
  text: string
}

export interface ReentrancyCandidate {
  entrypoint: string
  function: string
  path: string[]
  external_target: string
  external_call: string
  external_line: number
  writes_after: string[]
  guard: string | null
  confidence: Confidence
}

export interface Unresolved {
  reason: string
  function: string | null
  detail: string
  line: number
}

export interface ViewSummary {
  kinds: string[]
  nodes: number
  edges: number
}

export interface GraphModel {
  schema_version: string
  content_hash: string
  code_content_hash: string
  nodes: GraphNode[]
  edges: GraphEdge[]
  linearization: Record<string, string[]>
  override_chains: Record<string, string[]>
  reentrancy_candidates: ReentrancyCandidate[]
  unresolved: Unresolved[]
  import_cycles: string[][]
  views: Record<string, ViewSummary>
  notes: string[]
}

// ── ProtocolModel (SPEC §7.6) ────────────────────────────────────────────────
// The summary view, not the whole artifact. A ProtocolModel for a real repository is
// megabytes and this screen wants a couple of dozen numbers, so the engine serves
// `/protocol/summary` — every field of which is read off the stored artifact rather than
// recomputed, so the two can never disagree.

/** How a claim was arrived at. Ordered weakest-first; `derived` and above are grounded. */
export type ClaimConfidence =
  | 'unknown'
  | 'refuted'
  | 'proposed'
  | 'inferred'
  | 'derived'
  | 'stated'
  | 'verified'

export interface ProtocolIdentity {
  id: string
  name: string
  origin: string
  commit: string | null
  solidity_version: string | null
  description: string
}

export interface ProtocolCoverage {
  contracts_total: number
  contracts_classified: number
  entrypoints_total: number
  operations_modelled: number
  state_vars_total: number
  state_vars_explained: number
  grounded_claims: number
  ungrounded_claims: number
  /** Named blind spots. Silence here would read as completeness. */
  unmodelled: string[]
}

export interface ContractRoleRow {
  contract_id: string
  name: string
  role: string
  secondary_roles: string[]
  score: number
  /** The top two roles are within a whisker of each other — worth checking, not hiding. */
  ambiguous: boolean
}

export interface RiskSurfaceRow {
  id: string
  kind: string
  title: string
  priority: number
  targets: string[]
  /**
   * What kind of reasoning this calls for — replaces the old `agents` field (schema 1.1).
   * The model describes the surface; the Orchestrator picks agents from its own registry.
   */
  domains: string[]
  /** What to actually ask here. A question survives being wrong; an assertion does not. */
  questions: string[]
}

/** A pairing between two economic quantities: `deposits ↕ debt`, `assets ↕ shares`. */
export interface RelationshipRow {
  id: string
  left: string
  right: string
  left_name: string
  right_name: string
  /** How they are coupled: `deposits must cover 2x debt`. Descriptive, never a verdict. */
  nature: string
  status: 'formula' | 'structural' | 'expected_missing'
  /** Verbatim from the source when `status` is `formula`; empty otherwise. */
  formula: string
  open_question: string
}

export interface DocConflictRow {
  statement: string
  finding: string
  subjects: string[]
}

export interface InvariantRow {
  label: string
  statement: string
  kind: string
  /** Starts at `candidate`; only an executed Forge run can reach `verified`. */
  status: 'candidate' | 'supported' | 'verified' | 'refuted' | 'unverifiable'
  targets: string[]
  /** Where this one rule was observed. More than one is coverage, not duplication. */
  supporting_contracts: string[]
  occurrences: number
}

export interface OpenQuestionRow {
  id: string
  question: string
  blocking: boolean
  /** Every entity one answer would resolve. Asked once, applied to all. */
  affected: string[]
  occurrences: number
}

export interface EnrichmentRow {
  applied: boolean
  provider: string
  model: string
  prompt_hash: string
  gaps_answered: number
  gaps_rejected: number
  notes: string[]
}

// ── The semantic graph (schema 1.4) ───────────────────────────────────────────

/** One state write, with its direction. `totalDeposits += amount`, not "writes it". */
export interface StateChange {
  variable: string
  expression: string
  /** increase | decrease | set | scale */
  effect: string
  order: number
}

/** One function, as the questions an auditor asks of it. */
export interface FunctionMechanism {
  name: string
  qualified_name: string
  solidity_id: string
  visibility: string
  mutability: string
  is_entrypoint: boolean
  modifier_count: number
  /**
   * Comparisons that must hold to proceed, normalised — an `if (…) revert` appears as the
   * rule it establishes, not as the condition that triggers the revert.
   */
  conditions: string[]
  state_changes: StateChange[]
  reads: string[]
  internal_calls: string[]
  /** Calls that hand control outside this contract. Where reentrancy questions start. */
  external_calls: string[]
  /** State written after control first left. A candidate to check, not a verdict. */
  writes_after_external_call: string[]
}

/** `deposits ──must cover 2×──▶ debt`, read off a condition the protocol enforces. */
export interface MechanismRelationship {
  left: string
  right: string
  operator: string
  rule: string
  enforced_in: string
}

export interface ContractMechanism {
  name: string
  contract_id: string
  path: string
  kind: string
  inherits: string[]
  state: { name: string; type: string; visibility: string }[]
  functions: FunctionMechanism[]
  relationships: MechanismRelationship[]
  depends_on: string[]
}

/** A row of `GET /protocol/mechanisms` — the contract picker. */
export interface MechanismRow {
  name: string
  contract_id: string
  path: string
  kind: string
  inherits: string[]
  functions: number
  entrypoints: number
  state: number
  relationships: number
  conditions: number
  state_changes: number
}

export interface MechanismIndex {
  /**
   * `ast` when the repository compiled and the graph was read from real expression trees;
   * `text` when it did not, in which case an absent relation means "not visible".
   */
  fidelity: 'ast' | 'text' | 'mixed'
  notes: string[]
  counts: Record<string, number>
  contracts: MechanismRow[]
}

/** One ordered effect in a function body. The order is what reentrancy questions read. */
export interface FunctionStep {
  order: number
  kind:
    | 'check'
    | 'read'
    | 'calculate'
    | 'write'
    | 'internal_call'
    | 'external_call'
    | 'transfer'
    | 'create'
  detail: string
  target: string
  line: number
}

export interface FunctionBehavior {
  id: string
  function_id: string
  contract_id: string
  name: string
  signature: string
  visibility: string
  mutability: string
  operation_id: string | null
  purpose: string
  documented_purpose: string
  inputs: string[]
  outputs: string[]
  modifiers: string[]
  /** The modifiers that actually gate an arbitrary caller — body-checked, not name-matched. */
  caller_requirements: string[]
  preconditions: string[]
  reads: string[]
  writes: string[]
  internal_calls: string[]
  external_calls: string[]
  token_movements: string[]
  emits: string[]
  reverts: string[]
  steps: FunctionStep[]
  /** Non-zero means `steps` is a prefix — read before concluding "nothing happens after". */
  steps_truncated: number
  writes_after_external_call: string[]
  is_entrypoint: boolean
  is_view: boolean
  is_payable: boolean
  is_privileged: boolean
  has_assembly: boolean
  has_loop: boolean
  has_unchecked: boolean
}

export interface Permission {
  id: string
  function_id: string
  contract_id: string
  name: string
  mechanism:
    | 'open'
    | 'owner'
    | 'role'
    | 'governance'
    | 'guardian'
    | 'contract_only'
    | 'self_only'
    | 'signature'
    | 'unknown_guard'
  actor_ids: string[]
  modifiers: string[]
  checks: string[]
  affected_state: string[]
  is_privileged: boolean
}

/**
 * One contract, described end to end.
 *
 * Everything with a `ProtocolID` here is an index into the full `ProtocolModel`; only
 * `functions` and `permissions` are records that live on the profile itself.
 */
export interface ContractProfile {
  id: string
  contract_id: string
  name: string
  path: string
  kind: string
  classification_id: string
  component_id: string | null
  inherits: string[]
  implements: string[]
  libraries: string[]
  purpose: string
  documented_purpose: string
  responsibilities: string[]
  centrality: number
  functions: FunctionBehavior[]
  permissions: Permission[]
  entrypoints: string[]
  operation_ids: string[]
  state_ids: string[]
  actor_ids: string[]
  asset_ids: string[]
  dependency_ids: string[]
  flow_ids: string[]
  quantity_ids: string[]
  relationship_ids: string[]
  invariant_ids: string[]
  surface_ids: string[]
  boundary_ids: string[]
  standard_ids: string[]
  gap_ids: string[]
  depends_on: string[]
  consumed_by: string[]
  edge_ids: string[]
  /** Named blind spots for this contract. Never inferred away. */
  unknowns: string[]
  confidence: ClaimConfidence
}

/** One contract as it appears in the summary — named only, so the payload stays small. */
export interface ProfileRow {
  contract_id: string
  name: string
  purpose: string
  functions: number
  unknowns: number
}

/** A row of `GET /protocol/profiles` — the index a reader picks from. */
export interface ProfileIndexRow extends ProfileRow {
  id: string
  path: string
  kind: string
  centrality: number
  responsibilities: string[]
  implements: string[]
  entrypoints: number
  privileged: number
  /** Functions writing state after control left the frame. Where to look, not a finding. */
  cei_candidates: number
  state: number
}

export interface ProtocolSummary {
  identity: ProtocolIdentity
  summary: string
  archetype: string[]
  counts: Record<string, number>
  coverage: ProtocolCoverage
  confidence: Record<ClaimConfidence, number>
  evidence: Record<string, number>
  core_contracts: string[]
  roles: ContractRoleRow[]
  top_risk_surfaces: RiskSurfaceRow[]
  documentation_conflicts: DocConflictRow[]
  invariants: InvariantRow[]
  open_questions: OpenQuestionRow[]
  /** The contract-level view (schema 1.2), ranked by centrality. */
  profiles: ProfileRow[]
  /** How the protocol's quantities constrain each other (schema 1.3). */
  relationships: RelationshipRow[]
  enrichment: EnrichmentRow
  notes: string[]
}
