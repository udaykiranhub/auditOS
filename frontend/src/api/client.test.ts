/**
 * The upload filter decides what the engine is allowed to see.
 *
 * These tests exist because of a real bug: the filter dropped every non-`.sol` file under
 * `lib/`, which silently removed `lib/v4-periphery/remappings.txt`. The upload looked
 * complete — 3,143 dependency sources arrived — but the compiler could no longer resolve
 * `@uniswap/v4-core/`, and 58 "Source not found" errors made it look like the audit target
 * was broken. It wasn't. A few kilobytes of remapping config had been thrown away.
 */

import { describe, expect, it } from 'vitest'
import { isRelevantUpload, relativePathOf } from './client'

describe('isRelevantUpload', () => {
  it('keeps Solidity anywhere, including dependency roots', () => {
    expect(isRelevantUpload('protocol/src/Vault.sol')).toBe(true)
    expect(isRelevantUpload('protocol/lib/openzeppelin/contracts/ERC20.sol')).toBe(true)
    expect(isRelevantUpload('protocol/node_modules/@oz/token/ERC20.sol')).toBe(true)
  })

  it('keeps nested build config — the compiler needs it to resolve imports', () => {
    expect(isRelevantUpload('protocol/lib/v4-periphery/remappings.txt')).toBe(true)
    expect(isRelevantUpload('protocol/lib/v4-periphery/foundry.toml')).toBe(true)
    expect(isRelevantUpload('protocol/lib/v4-periphery/lib/v4-core/remappings.txt')).toBe(true)
    expect(isRelevantUpload('protocol/.gitmodules')).toBe(true)
  })

  it('keeps root config and docs', () => {
    expect(isRelevantUpload('protocol/foundry.toml')).toBe(true)
    expect(isRelevantUpload('protocol/remappings.txt')).toBe(true)
    expect(isRelevantUpload('protocol/package.json')).toBe(true)
    expect(isRelevantUpload('protocol/hardhat.config.ts')).toBe(true)
    expect(isRelevantUpload('protocol/README.md')).toBe(true)
    expect(isRelevantUpload('protocol/docs/architecture.md')).toBe(true)
  })

  it('drops dependency bulk that cannot change any artifact', () => {
    expect(isRelevantUpload('protocol/node_modules/hardhat/package.json')).toBe(false)
    expect(isRelevantUpload('protocol/lib/openzeppelin/README.md')).toBe(false)
    expect(isRelevantUpload('protocol/node_modules/.bin/tsc')).toBe(false)
    expect(isRelevantUpload('protocol/.git/objects/ab/cdef')).toBe(false)
  })

  it('drops the dropped folder name before matching, as the server does', () => {
    // "protocol" is the wrapper; "foundry.toml" is at the repo root, not one level down.
    expect(isRelevantUpload('protocol/foundry.toml')).toBe(true)
    expect(isRelevantUpload('foundry.toml')).toBe(true)
  })
})

describe('relativePathOf', () => {
  it('prefers webkitRelativePath, as set by the folder picker', () => {
    const file = Object.assign(new File([''], 'Vault.sol'), {
      webkitRelativePath: 'protocol/src/Vault.sol',
    })
    expect(relativePathOf(file)).toBe('protocol/src/Vault.sol')
  })

  it('falls back to react-dropzone\'s `path` for a dragged folder', () => {
    // A dragged folder sets no webkitRelativePath; without this fallback every file
    // arrives as a bare basename and all path-based scope heuristics collapse.
    const file = Object.assign(new File([''], 'Vault.sol'), { path: '/protocol/src/Vault.sol' })
    expect(relativePathOf(file)).toBe('protocol/src/Vault.sol')
  })

  it('falls back to the bare name for a single dropped file', () => {
    expect(relativePathOf(new File([''], 'protocol.zip'))).toBe('protocol.zip')
  })
})
