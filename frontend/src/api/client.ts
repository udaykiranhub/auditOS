/**
 * The typed API client — the only place axios is imported.
 *
 * Vite proxies `/audits` to the FastAPI server on :8000, so these are same-origin
 * in development. Every call here is something a human could `curl`.
 */

import axios, { AxiosError } from 'axios'
import type { ApiError, IngestResponse } from '../types/repo'

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
const CONFIG_NAMES = [
  'foundry.toml',
  'remappings.txt',
  'package.json',
  'hardhat.config.js',
  'hardhat.config.ts',
  'hardhat.config.cjs',
  'hardhat.config.mjs',
]

/**
 * Keep only what the Repository Reader actually opens.
 *
 * It enumerates `*.sol` and reads config + docs; nothing else can change the `RepoModel`.
 * A real Hardhat project is mostly `node_modules` JavaScript, so sending everything means
 * tens of thousands of multipart parts and a minutes-long upload for no added signal.
 * `.sol` files under dependency roots are kept — they are what dependency classification
 * is about — but their READMEs and per-package `package.json` files are not.
 */
export function isRelevantUpload(relativePath: string): boolean {
  const parts = relativePath.split('/').filter(Boolean)
  // Drop the dropped-folder's own name, exactly as the server does.
  const path = (parts.length > 1 ? parts.slice(1) : parts).join('/')
  const lower = path.toLowerCase()
  if (!path || parts.some((part) => part === '.git')) return false

  if (lower.endsWith('.sol')) return true

  const underDependency = /(^|\/)(lib|node_modules|vendor|external)\//.test(lower)
  if (underDependency) return false

  const name = lower.split('/').pop() ?? ''
  if (CONFIG_NAMES.includes(name)) return true
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

function splitGlobs(value: string): string[] {
  return value
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean)
}

/** Turn any failure into the `{code, message, hint}` shape the UI renders. */
export function toApiError(error: unknown): ApiError {
  if (error instanceof AxiosError) {
    const detail = error.response?.data?.detail
    if (detail && typeof detail === 'object') return detail as ApiError
    if (typeof detail === 'string') return { message: detail }
    if (error.code === 'ERR_NETWORK') {
      return {
        code: 'BACKEND_UNREACHABLE',
        message: 'Could not reach the engine on http://localhost:8000.',
        hint:
          'From the repository root:  ' +
          'engine/.venv/Scripts/python -m uvicorn engine.api.routes:app --reload --port 8000',
      }
    }
    return { message: error.message }
  }
  return { message: String(error) }
}
