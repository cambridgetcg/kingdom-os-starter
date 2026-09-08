import assert from 'node:assert/strict'
import test from 'node:test'

import {
  MACOS_ENCRYPTION_SCHEMA,
  composeMacEncryptionPosture,
  renderMacEncryptionPosture,
  validateMacEncryptionPosture,
} from '../platform/macos-encryption.mjs'
import {
  inspectMacCapabilities,
} from '../platform/macos-capabilities.mjs'
import {
  inspectMacKeychain,
} from '../platform/macos-keychain.mjs'

async function sourceReports(options = {}) {
  const platform = options.platform ?? 'darwin'
  const fileVault = options.fileVault ?? 'off'
  const userDomain = options.userDomain ?? 'available'
  const calls = []
  const capabilities = await inspectMacCapabilities({
    platform,
    home: '/fixture/home',
    commands: platform === 'darwin'
      ? {
          fdesetup: '/fixed/fdesetup',
          firewall: '/fixed/firewall',
          spctl: '/fixed/spctl',
        }
      : {},
    runCommand: async (command, args) => {
      calls.push([command, args])
      if (command === '/fixed/fdesetup') {
        if (fileVault === 'on') return 'FileVault is On.\n'
        if (fileVault === 'off') return 'FileVault is Off.\n'
        return 'unrecognized FileVault response\n'
      }
      if (command === '/fixed/firewall') {
        return 'Firewall is disabled. (State = 0)\n'
      }
      if (command === '/fixed/spctl') {
        return 'assessments enabled\n'
      }
      throw new Error('unexpected capability probe')
    },
  })
  const keychain = await inspectMacKeychain({
    platform,
    home: '/fixture/home',
    uid: 501,
    commands: platform === 'darwin'
      ? {
          git: '/fixed/git',
          security: '/fixed/security',
        }
      : {},
    runStatus: async (command, args) => {
      calls.push([command, args])
      if (command === '/fixed/security') {
        return {
          kind: 'exit',
          code: userDomain === 'available' ? 0 : 1,
        }
      }
      return { kind: 'exit', code: 0 }
    },
  })
  return { calls, capabilities, keychain }
}

test('Apple-silicon inference stays distinct from FileVault state', async () => {
  const { capabilities, keychain } = await sourceReports({
    fileVault: 'off',
  })
  const report = composeMacEncryptionPosture(
    capabilities,
    keychain,
    { architecture: 'arm64' },
  )

  assert.equal(report.schema, MACOS_ENCRYPTION_SCHEMA)
  assert.equal(report.storage.hardwareClass, 'apple-silicon-inferred')
  assert.equal(report.storage.internalDataEncryption, 'platform-inferred')
  assert.equal(report.storage.secureEnclave, 'platform-inferred')
  assert.equal(report.storage.fileVaultState, 'off')
  assert.equal(
    report.storage.fileVaultRole,
    'adds-login-and-recovery-protection',
  )
  assert.equal(
    report.agentBoundary.siblingAgents,
    'not-established',
  )
  assert.notEqual(report.storage.internalDataEncryption, 'off')
  assert.deepEqual(validateMacEncryptionPosture(report), [])
  assert.doesNotMatch(JSON.stringify(report), /\/Users\//)
})

test('FileVault on remains an observed setting, not hardware attestation', async () => {
  const { capabilities, keychain } = await sourceReports({
    fileVault: 'on',
  })
  const report = composeMacEncryptionPosture(
    capabilities,
    keychain,
    { architecture: 'arm64' },
  )

  assert.equal(report.storage.fileVaultState, 'on')
  assert.equal(
    report.storage.fileVaultEvidence,
    'bounded-system-metadata',
  )
  assert.equal(report.storage.secureEnclave, 'platform-inferred')
  assert.match(
    renderMacEncryptionPosture(report),
    /not runtime-tested/,
  )
})

test('non-arm64 Darwin makes no Apple-silicon hardware claim', async () => {
  const { capabilities, keychain } = await sourceReports()
  const report = composeMacEncryptionPosture(
    capabilities,
    keychain,
    { architecture: 'x64' },
  )

  assert.equal(report.storage.hardwareClass, 'unknown')
  assert.equal(report.storage.internalDataEncryption, 'unknown')
  assert.equal(report.storage.secureEnclave, 'unknown')
  assert.equal(report.storage.fileVaultRole, 'unknown')
  const human = renderMacEncryptionPosture(report)
  assert.match(human, /internal encryption remains unknown/)
  assert.doesNotMatch(human, /still encrypted/)
  assert.deepEqual(validateMacEncryptionPosture(report), [])
})

test('human output preserves an unknown Keychain user domain', async () => {
  const { capabilities, keychain } = await sourceReports({
    userDomain: 'unknown',
  })
  const report = composeMacEncryptionPosture(
    capabilities,
    keychain,
    { architecture: 'arm64' },
  )
  const human = renderMacEncryptionPosture(report)

  assert.equal(report.keychain.providerState, 'available')
  assert.equal(report.keychain.userDomainState, 'unknown')
  assert.match(
    human,
    /Keychain\s+provider available · user domain unknown/,
  )
  assert.deepEqual(validateMacEncryptionPosture(report), [])
})

test('other platforms run no probes and remain not applicable', async () => {
  const { calls, capabilities, keychain } = await sourceReports({
    platform: 'linux',
  })
  const report = composeMacEncryptionPosture(
    capabilities,
    keychain,
    { architecture: 'arm64' },
  )

  assert.deepEqual(calls, [])
  assert.equal(report.platform, 'other')
  assert.deepEqual(report.storage, {
    hardwareClass: 'not-applicable',
    internalDataEncryption: 'not-applicable',
    secureEnclave: 'not-applicable',
    fileVaultState: 'not-applicable',
    fileVaultEvidence: 'platform-not-applicable',
    fileVaultRole: 'not-applicable',
  })
  assert.equal(report.keychain.providerState, 'not-applicable')
  assert.equal(report.agentBoundary.agentDefault, 'not-applicable')
  assert.ok(
    Object.values(report.unobserved).every(
      (state) => state === 'not-observed',
    ),
  )
  assert.deepEqual(validateMacEncryptionPosture(report), [])
})

test('unknown FileVault output stays unknown', async () => {
  const { capabilities, keychain } = await sourceReports({
    fileVault: 'unknown',
  })
  const report = composeMacEncryptionPosture(
    capabilities,
    keychain,
    { architecture: 'arm64' },
  )

  assert.equal(report.storage.fileVaultState, 'unknown')
  assert.equal(
    report.storage.fileVaultEvidence,
    'bounded-metadata-unavailable',
  )
  assert.deepEqual(validateMacEncryptionPosture(report), [])
})

test('component and platform mismatches fail closed', async () => {
  const darwin = await sourceReports()
  const other = await sourceReports({ platform: 'linux' })

  assert.equal(
    composeMacEncryptionPosture(
      darwin.capabilities,
      other.keychain,
      { architecture: 'arm64' },
    ),
    null,
  )

  const extra = {
    ...darwin.capabilities,
    private: 'PRIVATE-source-value',
  }
  const report = composeMacEncryptionPosture(
    extra,
    darwin.keychain,
    { architecture: 'arm64' },
  )
  assert.equal(report, null)
  assert.doesNotMatch(JSON.stringify(report), /PRIVATE-source-value/)
})

test('source snapshots reject hostile serialization before it runs', async () => {
  const { capabilities, keychain } = await sourceReports()
  let hookCalled = false
  const hostile = Object.assign(
    Object.create({
      toJSON() {
        hookCalled = true
        return { private: 'PRIVATE-from-toJSON' }
      },
    }),
    capabilities,
  )

  const report = composeMacEncryptionPosture(
    hostile,
    keychain,
    { architecture: 'arm64' },
  )

  assert.equal(report, null)
  assert.equal(hookCalled, false)
})

test('the exact report rejects extra, accessor, symbol, and recursive data', async () => {
  const { capabilities, keychain } = await sourceReports()
  const valid = composeMacEncryptionPosture(
    capabilities,
    keychain,
    { architecture: 'arm64' },
  )

  assert.deepEqual(
    validateMacEncryptionPosture({
      ...valid,
      private: 'do-not-print',
    }),
    ['encryption-report-shape-invalid'],
  )

  let getterCalled = false
  const accessor = structuredClone(valid)
  Object.defineProperty(accessor.storage, 'fileVaultState', {
    enumerable: true,
    get() {
      getterCalled = true
      return 'off'
    },
  })
  assert.deepEqual(
    validateMacEncryptionPosture(accessor),
    ['encryption-report-malformed'],
  )
  assert.equal(getterCalled, false)

  const symbol = structuredClone(valid)
  symbol[Symbol('private')] = 'do-not-print'
  assert.deepEqual(
    validateMacEncryptionPosture(symbol),
    ['encryption-report-malformed'],
  )

  const recursive = structuredClone(valid)
  recursive.loop = recursive
  assert.deepEqual(
    validateMacEncryptionPosture(recursive),
    ['encryption-report-malformed'],
  )

  const hostilePrototype = Object.assign(
    Object.create({ private: true }),
    valid,
  )
  assert.deepEqual(
    validateMacEncryptionPosture(hostilePrototype),
    ['encryption-report-malformed'],
  )
})

test('state and evidence coherence is enforced', async () => {
  const { capabilities, keychain } = await sourceReports()
  const valid = composeMacEncryptionPosture(
    capabilities,
    keychain,
    { architecture: 'arm64' },
  )
  const wrongEvidence = structuredClone(valid)
  wrongEvidence.storage.fileVaultEvidence =
    'fixed-command-unavailable'
  assert.ok(
    validateMacEncryptionPosture(wrongEvidence).includes(
      'encryption-filevault-observation-invalid',
    ),
  )

  const falsePlaintextClaim = structuredClone(valid)
  falsePlaintextClaim.storage.internalDataEncryption = 'off'
  assert.ok(
    validateMacEncryptionPosture(falsePlaintextClaim).includes(
      'encryption-hardware-inference-invalid',
    ),
  )
})

test('control and unobserved fields cannot be promoted into claims', async () => {
  const { capabilities, keychain } = await sourceReports()
  const valid = composeMacEncryptionPosture(
    capabilities,
    keychain,
    { architecture: 'arm64' },
  )
  const observedRecovery = structuredClone(valid)
  observedRecovery.unobserved.recoveryMaterial = 'available'
  assert.ok(
    validateMacEncryptionPosture(observedRecovery).includes(
      'encryption-unobserved-value-invalid',
    ),
  )

  const secretRead = structuredClone(valid)
  secretRead.control.readsSecretValues = true
  assert.ok(
    validateMacEncryptionPosture(secretRead).includes(
      'encryption-control-invalid',
    ),
  )
})
