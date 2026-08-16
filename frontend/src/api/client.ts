/**
 * The typed API client — the only place axios is imported.
 *
 * Vite proxies `/audits` to the FastAPI server on :8000, so these are same-origin
 * in development. Every call here is something a human could `curl`.
 */

import axios, { AxiosError } from 'axios'
import type {
  ApiError,
  BuildModel,
  CodeModel,
  ContractMechanism,
  ContractProfile,
  GraphModel,
  IngestResponse,
  MechanismIndex,
  ProfileIndexRow,
  ProtocolSummary,
} from '../types/repo'

const http = axios.create({
  // Ingest is synchronous and a large repo takes a while; there is no job queue yet.
  timeout: 5 * 60 * 1000,
})

export interface ScopeArgs {
  include: string
  exclude: string
}

/**
 * The relative path a browser gives us for a file inside a folder.
 *
 * A folder picked through `<input webkitdirectory>` carries `webkitRelativePath`; a folder
 * *dragged* onto the dropzone carries nothing there — react-dropzone puts the path on a
 * non-standard `path` property instead. Missing this makes a dropped folder arrive as a
 * flat pile of basenames, which destroys every path-based scope heuristic.
 */
export function relativePathOf(file: File): string {
  const dropped = (file as File & { path?: string }).path
  return file.webkitRelativePath || dropped?.replace(/^\.?[\\/]/, '') || file.name
}

const DOC_EXTENSIONS = ['.md', '.markdown', '.rst', '.pdf']

/**
 * Build config that must survive **at any depth**, including inside `lib/`.
 *
 * A Foundry dependency carries its own `remappings.txt` / `foundry.toml`, and the compiler
 * needs them to resolve that dependency's imports — `lib/v4-periphery/remappings.txt` is
 * what maps `@uniswap/v4-core/` to `lib/v4-periphery/lib/v4-core/`. Dropping these as
 * "dependency files" strips a few kilobytes and breaks compilation of the whole project.
 */
const NESTED_CONFIG_NAMES = ['foundry.toml', 'remappings.txt', '.gitmodules']

/** Config that is only meaningful at the project root — node_modules has thousands. */
const ROOT_CONFIG_NAMES = [
  'package.json',
  'hardhat.config.js',
  'hardhat.config.ts',
  'hardhat.config.cjs',
  'hardhat.config.mjs',
]

/**
 * Keep only what the engine actually opens.
 *
 * The Reader enumerates `*.sol` and reads config + docs; the Build stage additionally
 * needs every `remappings.txt` / `foundry.toml` in the tree. Nothing else can change a
 * `RepoModel` or a `BuildModel`. A real Hardhat project is mostly `node_modules`
 * JavaScript, so sending everything means tens of thousands of multipart parts and a
 * minutes-long upload for no added signal.
 *
 * Dependency `.sol` files are kept — they are what dependency classification is about, and
 * the compiler needs them to resolve imports — but their READMEs and per-package
 * `package.json` files are not.
 */
export function isRelevantUpload(relativePath: string): boolean {
  const parts = relativePath.split('/').filter(Boolean)
  // Drop the dropped-folder's own name, exactly as the server does.
  const path = (parts.length > 1 ? parts.slice(1) : parts).join('/')
  const lower = path.toLowerCase()
  if (!path || parts.some((part) => part === '.git')) return false

  if (lower.endsWith('.sol')) return true

  const name = lower.split('/').pop() ?? ''
  if (NESTED_CONFIG_NAMES.includes(name)) return true

  const underDependency = /(^|\/)(lib|node_modules|vendor|external)\//.test(lower)
  if (underDependency) return false

  if (ROOT_CONFIG_NAMES.includes(name)) return true
  return DOC_EXTENSIONS.some((extension) => lower.endsWith(extension))
}

/** Upload a `.zip`, or a whole folder's files with their relative paths. */
export async function ingestUpload(files: File[], scope: ScopeArgs): Promise<IngestResponse> {
  const form = new FormData()
  for (const file of files) {
    form.append('files', file, relativePathOf(file))
  }
  form.append('include', scope.include)
  form.append('exclude', scope.exclude)

  const { data } = await http.post<IngestResponse>('/audits/upload', form)
  return data
}

/** Ingest a git URL, or a folder path on the machine running the engine. */
export async function ingestRemote(
  source: string,
  ref: string,
  scope: ScopeArgs,
): Promise<IngestResponse> {
  const { data } = await http.post<IngestResponse>('/audits/remote', {
    source,
    ref: ref || null,
    include: splitGlobs(scope.include),
    exclude: splitGlobs(scope.exclude),
  })
  return data
}

export interface BuildJobStatus {
  run_id: string
  state: 'running' | 'done' | 'error'
  elapsed_seconds: number
  model: BuildModel | null
  error: string | null
}

/**
 * Start a build and poll it to completion.
 *
 * Compiling a real protocol takes minutes — longer than any reasonable HTTP timeout, so
 * holding a single request open turned a slow build into `timeout of 300000ms exceeded`,
 * which reads as a failure when the compiler was still working. Each poll is a fast
 * request instead, and `onProgress` lets the UI show that something is happening.
 */
export async function runBuild(
  runId: string,
  options: { allowHardhat?: boolean; onProgress?: (elapsedSeconds: number) => void } = {},
): Promise<BuildModel> {
  await http.post<BuildJobStatus>(`/audits/${runId}/build`, {
    allow_hardhat: options.allowHardhat ?? false,
  })

  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, BUILD_POLL_INTERVAL_MS))
    const { data } = await http.get<BuildJobStatus>(`/audits/${runId}/build/status`)

    if (data.state === 'done' && data.model) return data.model
    if (data.state === 'error') throw new Error(data.error ?? 'The build worker crashed.')
    options.onProgress?.(data.elapsed_seconds)
  }
}

const BUILD_POLL_INTERVAL_MS = 1500

function splitGlobs(value: string): string[] {
  return value
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean)
}

const BACKEND_DOWN = 'Could not reach the engine on http://localhost:8000.'
const START_COMMAND =
  'Start it from the repository root:  ' +
  'engine/.venv/Scripts/python -m uvicorn engine.api.routes:app --reload --port 8000'

/** Turn any failure into the `{code, message, hint}` shape the UI renders. */
export function toApiError(error: unknown): ApiError {
  if (error instanceof AxiosError) {
    const detail = error.response?.data?.detail
    if (detail && typeof detail === 'object') return detail as ApiError
    if (typeof detail === 'string') return { message: detail }
    if (error.code === 'ERR_NETWORK') {
      return { code: 'BACKEND_UNREACHABLE', message: BACKEND_DOWN, hint: START_COMMAND }
    }
    if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
      // A bare "timeout of 300000ms exceeded" says nothing about which of the two very
      // different causes applied, and the five-minute wait makes a dead server look
      // identical to a slow one.
      return {
        code: 'REQUEST_TIMED_OUT',
        message:
          'The engine did not answer within 5 minutes. It is either still working on a ' +
          'very large protocol, or it has stopped.',
        hint: `Check it is alive:  curl http://localhost:8000/audits/health\n${START_COMMAND}`,
      }
    }
    return { message: error.message }
  }
  return { message: String(error) }
}

/**
 * Parse a run's repository into a `CodeModel` (SPEC §12).
 *
 * Synchronous, unlike the build: parsing cannot be skipped, so there is no partial result
 * worth streaming. The engine uses the run's `BuildModel` when one exists — storage slots
 * and canonical selectors are enrichment, never a precondition.
 */
export async function runParse(runId: string): Promise<CodeModel> {
  const { data } = await http.post<CodeModel>(`/audits/${runId}/parse`)
  return data
}

/**
 * Build the code property graph from a run's `CodeModel` (SPEC §13).
 *
 * Fast — pure computation over an artifact already on disk — so no polling. Requires a
 * parse first; the engine answers 409 rather than silently re-parsing, because redoing an
 * expensive stage implicitly hides which artifact you are looking at.
 */
export async function runGraph(runId: string): Promise<GraphModel> {
  const { data } = await http.post<GraphModel>(`/audits/${runId}/graph`)
  return data
}

/** One SPEC §13.5 query. `target` is a SolidityID for the queries that need one. */
export async function graphQuery<T>(runId: string, q: string, target = ''): Promise<T> {
  const { data } = await http.get<{ result: T }>(`/audits/${runId}/graph/query`, {
    params: { q, target },
  })
  return data.result
}

/**
 * Interpret a run's `CodeModel` + `GraphModel` into a `ProtocolModel` (SPEC §7.6, §8).
 *
 * Synchronous like the graph: the deterministic pass is pure computation over artifacts
 * already on disk. Requires a graph first; the engine answers 409 rather than silently
 * re-running an upstream stage.
 *
 * `enrich` is off by default and stays that way unless a caller asks. Turning it on makes
 * the call network-bound and spends an API budget — and, more importantly, makes the
 * artifact non-comparable to the deterministic run before it, which is the comparison the
 * whole architecture exists to enable.
 */
export async function runProtocol(
  runId: string,
  options: { enrich?: boolean; verify?: boolean } = {},
): Promise<ProtocolSummary> {
  await http.post(`/audits/${runId}/protocol`, {
    enrich: options.enrich ?? false,
    verify: options.verify ?? false,
  })
  // The model itself is megabytes; this screen wants the summary the engine derives from
  // the artifact it just wrote.
  const { data } = await http.get<ProtocolSummary>(`/audits/${runId}/protocol/summary`)
  return data
}

/**
 * The contract-level index (schema 1.2).
 *
 * Separate from the summary because the two are read at different times: the summary
 * answers "what is this protocol", this answers "which contract do I open". Neither
 * carries the function bodies — `fetchProfile` is the only call that does.
 */
export async function fetchProfiles(runId: string): Promise<ProfileIndexRow[]> {
  const { data } = await http.get<{ profiles: ProfileIndexRow[] }>(
    `/audits/${runId}/protocol/profiles`,
  )
  return data.profiles
}

/**
 * The per-contract mechanism index (schema 1.4).
 *
 * Derived from the semantic graph server-side, so the CLI, the API and this screen cannot
 * disagree about what a contract does.
 */
export async function fetchMechanisms(runId: string): Promise<MechanismIndex> {
  const { data } = await http.get<MechanismIndex>(`/audits/${runId}/protocol/mechanisms`)
  return data
}

/** One contract's mechanism in full: every function's conditions, changes and calls. */
export async function fetchMechanism(
  runId: string,
  contract: string,
): Promise<ContractMechanism> {
  const addressed = contract.split('/').map(encodeURIComponent).join('/')
  const { data } = await http.get<ContractMechanism>(
    `/audits/${runId}/protocol/mechanisms/${addressed}`,
  )
  return data
}

/**
 * One contract in full. `contract` may be a `SolidityID` or a bare contract name.
 *
 * The segments are encoded individually: a `SolidityID` is `src/Vault.sol:Vault`, and
 * percent-encoding its separators would stop the server's `:path` parameter matching.
 */
export async function fetchProfile(runId: string, contract: string): Promise<ContractProfile> {
  const addressed = contract.split('/').map(encodeURIComponent).join('/')
  const { data } = await http.get<ContractProfile>(
    `/audits/${runId}/protocol/profiles/${addressed}`,
  )
  return data
}
