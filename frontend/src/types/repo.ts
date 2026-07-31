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
