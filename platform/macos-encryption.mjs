import {
  checkMacCapabilities,
} from './macos-capabilities.mjs'
import {
  validateMacKeychainReport,
} from './macos-keychain.mjs'

const MACOS_ENCRYPTION_SCHEMA =
  'kingdom.macos-encryption-posture/0.1'
const MEANING =
  'This report separates internal-storage encryption, FileVault, Keychain protection, and agent isolation; platform inference and documentation are not runtime cryptographic attestation.'

const ROOT_FIELDS = Object.freeze([
  'schema',
  'mode',
  'consistency',
  'platform',
  'storage',
  'keychain',
  'agentBoundary',
  'unobserved',
  'control',
  'meaning',
])
const STORAGE_FIELDS = Object.freeze([
  'hardwareClass',
  'internalDataEncryption',
  'secureEnclave',
  'fileVaultState',
  'fileVaultEvidence',
  'fileVaultRole',
])
const KEYCHAIN_FIELDS = Object.freeze([
  'providerState',
  'userDomainState',
  'protectionModel',
  'secretActionEvidence',
])
const AGENT_BOUNDARY_FIELDS = Object.freeze([
  'boundary',
  'siblingAgents',
  'kingdomWalls',
  'agentDefault',
])
const UNOBSERVED_FIELDS = Object.freeze([
  'keyMaterial',
  'recoveryMaterial',
  'backupEncryption',
  'transportEncryption',
])
const CONTROL = Object.freeze({
  writes: false,
  networkRequests: false,
  readsCoarseMetadata: true,
  readsPrivateContent: false,
  returnsPrivateContent: false,
  readsSecretValues: false,
  listsSecretNames: false,
  readsKeyMaterial: false,
  readsRecoveryMaterial: false,
  listsBackupDestinations: false,
  requestsPermission: false,
  opensApplications: false,
  changesSettings: false,
  changesServices: false,
})

function record(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false
  }
  try {
    const prototype = Object.getPrototypeOf(value)
    return prototype === Object.prototype || prototype === null
  } catch {
    return false
  }
}

function exactDataRecord(value, expected) {
  if (!record(value)) return false
  try {
    const keys = Reflect.ownKeys(value)
    if (
      keys.length !== expected.length
      || keys.some(
        (key) => typeof key !== 'string' || !expected.includes(key),
      )
    ) {
      return false
    }
    return keys.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key)
      return Boolean(
        descriptor
        && descriptor.enumerable
        && Object.hasOwn(descriptor, 'value'),
      )
    })
  } catch {
    return false
  }
}

function plainData(value, seen = new WeakSet()) {
  if (
    value === null
    || typeof value === 'string'
    || typeof value === 'boolean'
    || (typeof value === 'number' && Number.isFinite(value))
  ) {
    return true
  }
  if (typeof value !== 'object' || seen.has(value)) return false

  try {
    seen.add(value)
    if (Array.isArray(value)) {
      if (
        Object.getPrototypeOf(value) !== Array.prototype
        || value.length > 4_096
      ) {
        return false
      }
      const expected = [
        ...Array.from({ length: value.length }, (_, index) => `${index}`),
        'length',
      ]
      const keys = Reflect.ownKeys(value)
      if (
        keys.length !== expected.length
        || keys.some(
          (key) => typeof key !== 'string' || !expected.includes(key),
        )
      ) {
        return false
      }
      return keys.every((key) => {
        const descriptor = Object.getOwnPropertyDescriptor(value, key)
        if (
          !descriptor
          || !Object.hasOwn(descriptor, 'value')
          || (key !== 'length' && !descriptor.enumerable)
        ) {
          return false
        }
        return key === 'length' || plainData(descriptor.value, seen)
      })
    }
    if (!record(value)) return false
    const keys = Reflect.ownKeys(value)
    if (
      keys.length > 4_096
      || keys.some((key) => typeof key !== 'string')
    ) {
      return false
    }
    return keys.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key)
      return Boolean(
        descriptor
        && descriptor.enumerable
        && Object.hasOwn(descriptor, 'value')
        && plainData(descriptor.value, seen),
      )
    })
  } catch {
    return false
  }
}

function passes(check, value) {
  try {
    const issues = check(value)
    return Array.isArray(issues) && issues.length === 0
  } catch {
    return false
  }
}

function validatedSnapshot(check, value) {
  if (!plainData(value) || !passes(check, value)) return null
  try {
    const snapshot = JSON.parse(JSON.stringify(value))
    return plainData(snapshot) && passes(check, snapshot)
      ? snapshot
      : null
  } catch {
    return null
  }
}

function composeMacEncryptionPosture(
  capabilities,
  keychain,
  options = {},
) {
  const capabilitySnapshot = validatedSnapshot(
    options.checkCapabilities ?? checkMacCapabilities,
    capabilities,
  )
  const keychainSnapshot = validatedSnapshot(
    options.validateKeychain ?? validateMacKeychainReport,
    keychain,
  )
  if (
    !capabilitySnapshot
    || !keychainSnapshot
    || capabilitySnapshot.platform !== keychainSnapshot.platform
  ) {
    return null
  }

  const platform = capabilitySnapshot.platform
  const darwin = platform === 'darwin'
  const appleSilicon =
    darwin
    && (options.architecture ?? process.arch) === 'arm64'
  const report = {
    schema: MACOS_ENCRYPTION_SCHEMA,
    mode: 'observation-only',
    consistency: 'non-atomic',
    platform,
    storage: {
      hardwareClass: darwin
        ? appleSilicon
          ? 'apple-silicon-inferred'
          : 'unknown'
        : 'not-applicable',
      internalDataEncryption: darwin
        ? appleSilicon
          ? 'platform-inferred'
          : 'unknown'
        : 'not-applicable',
      secureEnclave: darwin
        ? appleSilicon
          ? 'platform-inferred'
          : 'unknown'
        : 'not-applicable',
      fileVaultState: capabilitySnapshot.safety.fileVault.state,
      fileVaultEvidence:
        capabilitySnapshot.safety.fileVault.evidence,
      fileVaultRole: darwin
        ? appleSilicon
          ? 'adds-login-and-recovery-protection'
          : 'unknown'
        : 'not-applicable',
    },
    keychain: {
      providerState: keychainSnapshot.provider.toolState,
      userDomainState: keychainSnapshot.provider.userDomainState,
      protectionModel: darwin
        ? 'documented-metadata-and-secret-key-separation'
        : 'not-applicable',
      secretActionEvidence: 'not-tested',
    },
    agentBoundary: {
      boundary: keychainSnapshot.isolation.boundary,
      siblingAgents: darwin
        ? 'not-established'
        : 'not-applicable',
      kingdomWalls: keychainSnapshot.isolation.kingdomWalls,
      agentDefault: darwin
        ? 'opaque-broker-required'
        : 'not-applicable',
    },
    unobserved: {
      keyMaterial: 'not-observed',
      recoveryMaterial: 'not-observed',
      backupEncryption: 'not-observed',
      transportEncryption: 'not-observed',
    },
    control: { ...CONTROL },
    meaning: MEANING,
  }
  return validateMacEncryptionPosture(report).length === 0
    ? report
    : null
}

function fileVaultEvidenceMatches(state, evidence) {
  if (['on', 'off'].includes(state)) {
    return evidence === 'bounded-system-metadata'
  }
  if (state === 'unknown') {
    return [
      'bounded-metadata-unavailable',
      'fixed-command-unavailable',
    ].includes(evidence)
  }
  return (
    state === 'not-applicable'
    && evidence === 'platform-not-applicable'
  )
}

function controlMatches(value) {
  return (
    exactDataRecord(value, Object.keys(CONTROL))
    && Object.entries(CONTROL).every(
      ([key, expected]) => value[key] === expected,
    )
  )
}

function validateMacEncryptionPosture(report) {
  const issues = []
  if (!plainData(report)) return ['encryption-report-malformed']
  if (!exactDataRecord(report, ROOT_FIELDS)) {
    return ['encryption-report-shape-invalid']
  }
  if (
    report.schema !== MACOS_ENCRYPTION_SCHEMA
    || report.mode !== 'observation-only'
    || report.consistency !== 'non-atomic'
    || !['darwin', 'other'].includes(report.platform)
    || report.meaning !== MEANING
  ) {
    issues.push('encryption-report-static-value-invalid')
  }

  const darwin = report.platform === 'darwin'
  if (!exactDataRecord(report.storage, STORAGE_FIELDS)) {
    issues.push('encryption-storage-shape-invalid')
  } else {
    const inferred =
      report.storage.hardwareClass === 'apple-silicon-inferred'
    if (
      darwin
      && !['apple-silicon-inferred', 'unknown'].includes(
        report.storage.hardwareClass,
      )
    ) {
      issues.push('encryption-hardware-value-invalid')
    }
    if (
      !darwin
      && report.storage.hardwareClass !== 'not-applicable'
    ) {
      issues.push('encryption-hardware-value-invalid')
    }
    const expectedHardwareState = darwin
      ? inferred
        ? 'platform-inferred'
        : 'unknown'
      : 'not-applicable'
    if (
      report.storage.internalDataEncryption !== expectedHardwareState
      || report.storage.secureEnclave !== expectedHardwareState
    ) {
      issues.push('encryption-hardware-inference-invalid')
    }
    if (
      ![
        'on',
        'off',
        'unknown',
        'not-applicable',
      ].includes(report.storage.fileVaultState)
      || !fileVaultEvidenceMatches(
        report.storage.fileVaultState,
        report.storage.fileVaultEvidence,
      )
      || (
        darwin
          ? report.storage.fileVaultState === 'not-applicable'
          : report.storage.fileVaultState !== 'not-applicable'
      )
    ) {
      issues.push('encryption-filevault-observation-invalid')
    }
    if (
      report.storage.fileVaultRole
      !== (
        darwin
          ? inferred
            ? 'adds-login-and-recovery-protection'
            : 'unknown'
          : 'not-applicable'
      )
    ) {
      issues.push('encryption-filevault-role-invalid')
    }
  }

  if (!exactDataRecord(report.keychain, KEYCHAIN_FIELDS)) {
    issues.push('encryption-keychain-shape-invalid')
  } else if (darwin) {
    if (
      !['available', 'unavailable'].includes(
        report.keychain.providerState,
      )
      || !['available', 'unknown'].includes(
        report.keychain.userDomainState,
      )
      || (
        report.keychain.providerState === 'unavailable'
        && report.keychain.userDomainState !== 'unknown'
      )
      || report.keychain.protectionModel
        !== 'documented-metadata-and-secret-key-separation'
      || report.keychain.secretActionEvidence !== 'not-tested'
    ) {
      issues.push('encryption-keychain-value-invalid')
    }
  } else if (
    report.keychain.providerState !== 'not-applicable'
    || report.keychain.userDomainState !== 'not-applicable'
    || report.keychain.protectionModel !== 'not-applicable'
    || report.keychain.secretActionEvidence !== 'not-tested'
  ) {
    issues.push('encryption-keychain-value-invalid')
  }

  if (
    !exactDataRecord(
      report.agentBoundary,
      AGENT_BOUNDARY_FIELDS,
    )
  ) {
    issues.push('encryption-agent-boundary-shape-invalid')
  } else if (
    report.agentBoundary.boundary
      !== (darwin ? 'login-user' : 'not-applicable')
    || report.agentBoundary.siblingAgents
      !== (darwin ? 'not-established' : 'not-applicable')
    || report.agentBoundary.kingdomWalls
      !== 'not-operating-system-enforced'
    || report.agentBoundary.agentDefault
      !== (darwin ? 'opaque-broker-required' : 'not-applicable')
  ) {
    issues.push('encryption-agent-boundary-value-invalid')
  }

  if (!exactDataRecord(report.unobserved, UNOBSERVED_FIELDS)) {
    issues.push('encryption-unobserved-shape-invalid')
  } else if (
    Object.values(report.unobserved).some(
      (value) => value !== 'not-observed',
    )
  ) {
    issues.push('encryption-unobserved-value-invalid')
  }
  if (!controlMatches(report.control)) {
    issues.push('encryption-control-invalid')
  }
  return [...new Set(issues)]
}

function renderMacEncryptionPosture(report) {
  const internalState = report.storage?.internalDataEncryption
  const fileVaultState = report.storage?.fileVaultState
  const internal = {
    'platform-inferred': 'encrypted by platform (inferred)',
    unknown: 'unknown',
    'not-applicable': 'not applicable',
  }[report.storage?.internalDataEncryption] ?? 'unknown'
  const hardware = {
    'apple-silicon-inferred': 'Apple silicon inferred',
    unknown: 'hardware class unknown',
    'not-applicable': 'not applicable',
  }[report.storage?.hardwareClass] ?? 'hardware class unknown'
  const enclave = {
    'platform-inferred': 'present by platform inference',
    unknown: 'unknown',
    'not-applicable': 'not applicable',
  }[report.storage?.secureEnclave] ?? 'unknown'
  const fileVault =
    fileVaultState === 'on'
      ? internalState === 'platform-inferred'
        ? 'extra login/recovery protection enabled'
        : 'enabled; hardware-specific role not inferred'
      : fileVaultState === 'off'
        ? internalState === 'platform-inferred'
          ? 'internal data still encrypted; extra login/recovery gate off'
          : 'off; internal encryption remains unknown'
        : fileVaultState === 'not-applicable'
          ? 'not applicable'
          : 'state unknown'
  const keychainProtection = {
    'documented-metadata-and-secret-key-separation':
      'documented metadata/secret-key separation',
    'not-applicable': 'not applicable',
  }[report.keychain?.protectionModel] ?? 'protection model unknown'
  const keychainProvider =
    report.keychain?.providerState ?? 'unknown'
  const keychainUserDomain =
    report.keychain?.userDomainState ?? 'unknown'
  const boundary =
    report.agentBoundary?.boundary === 'login-user'
      ? 'same login user'
      : 'not applicable'
  const siblingBoundary =
    report.agentBoundary?.siblingAgents === 'not-established'
      ? 'sibling-agent isolation not established'
      : 'sibling-agent boundary not applicable'
  return [
    'KINGDOM OS macOS encryption — observation only',
    `  internal     ${internal} · ${hardware}`,
    `  enclave      ${enclave} · not runtime-tested`,
    `  FileVault    ${fileVaultState ?? 'unknown'} · ${fileVault}`,
    `  Keychain     provider ${keychainProvider} · user domain ${keychainUserDomain} · ${keychainProtection}`,
    `  boundary     ${boundary} · ${siblingBoundary}`,
    '  unobserved   key material, recovery material, backup encryption, and transport encryption',
    '  control      no private, secret, key, or recovery reads; no writes, prompts, or settings changes',
  ].join('\n')
}

export {
  MACOS_ENCRYPTION_SCHEMA,
  composeMacEncryptionPosture,
  renderMacEncryptionPosture,
  validateMacEncryptionPosture,
}
