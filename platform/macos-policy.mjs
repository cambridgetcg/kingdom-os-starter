import { types as utilTypes } from 'node:util'

import {
  MAC_CAPABILITY_IDS,
  checkMacCapabilities,
  explainMacCapability,
} from './macos-capabilities.mjs'
import {
  composeMacEncryptionPosture,
  validateMacEncryptionPosture,
} from './macos-encryption.mjs'
import {
  validateMacKeychainReport,
} from './macos-keychain.mjs'

const MACOS_POLICY_SCHEMA =
  'kingdom.macos-capability-policy/0.2'
const CAPABILITY_SOURCE_SCHEMA =
  'kingdom.macos-agent-capabilities/0.1'
const KEYCHAIN_SOURCE_SCHEMA =
  'kingdom.macos-keychain-posture/0.1'
const ENCRYPTION_SOURCE_SCHEMA =
  'kingdom.macos-encryption-posture/0.1'
// Static registration only: do not import or invoke the action from this observer.
const POWER_ADAPTER_EVIDENCE =
  'static-code:platform/macos-awake.mjs:/usr/bin/caffeinate -i -t N -w PID'
const MEANING =
  'This preflight names unmet requirements for one capability. Static adapter registration is code evidence only, not tested execution or authenticated authority. It does not supply task authority, validate a filesystem or private-data scope, authorize an action, invoke one, or turn encryption context into permission.'

const ROOT_FIELDS = Object.freeze([
  'schema',
  'mode',
  'consistency',
  'platform',
  'capabilityId',
  'sourceSchemas',
  'capability',
  'requirements',
  'decision',
  'semanticBoundary',
  'control',
  'meaning',
])
const SOURCE_FIELDS = Object.freeze([
  'capabilities',
  'keychain',
  'encryption',
])
const CAPABILITY_FIELDS = Object.freeze([
  'nativeEdgeState',
  'nativeEdgeEvidence',
  'recommendedHandling',
  'risk',
  'executionEvidenceState',
])
const REQUIREMENT_FIELDS = Object.freeze([
  'macosAuthorization',
  'taskAuthority',
  'filesystemScope',
  'privateDataScope',
  'opaqueBroker',
  'fixedAdapter',
])
const MACOS_AUTHORIZATION_FIELDS = Object.freeze([
  'requirement',
  'state',
  'actorIdentity',
  'actorScope',
])
const TASK_AUTHORITY_FIELDS = Object.freeze([
  'requirement',
  'state',
  'grantedByReport',
])
const SCOPE_FIELDS = Object.freeze(['requirement', 'state'])
const OPAQUE_BROKER_FIELDS = Object.freeze([
  'requirement',
  'state',
  'providerState',
  'siblingAgentIsolation',
])
const FIXED_ADAPTER_FIELDS = Object.freeze([
  'requirement',
  'state',
  'evidence',
  'executionEvidenceState',
])
const DECISION_FIELDS = Object.freeze([
  'state',
  'reasons',
  'authorizesAction',
])
const SEMANTIC_BOUNDARY = Object.freeze({
  authorizesExecution: false,
  enforcesExecution: false,
  isBearerCredential: false,
  isActionReceipt: false,
  establishesSessionEnforcement: false,
  sourceInstanceBinding: 'not-provided',
  observationFreshness: 'not-established',
})

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
  invokesActions: false,
  invokesAdapters: false,
  invokesGeneralShell: false,
  grantsAuthority: false,
  requestsPermission: false,
  opensApplications: false,
  changesSettings: false,
  changesServices: false,
})

const CAPABILITY_REQUIREMENTS = Object.freeze({
  'keychain-reference': Object.freeze({
    filesystemScope: 'not-applicable',
    privateDataScope: 'declared-scope-required',
    opaqueBroker: 'required',
  }),
  'shortcuts-run': Object.freeze({
    filesystemScope: 'action-plan-dependent',
    privateDataScope: 'action-input-dependent',
    opaqueBroker: 'not-applicable',
  }),
  'notifications-send': Object.freeze({
    filesystemScope: 'not-applicable',
    privateDataScope: 'action-input-dependent',
    opaqueBroker: 'not-applicable',
  }),
  'speech-speak': Object.freeze({
    filesystemScope: 'not-applicable',
    privateDataScope: 'action-input-dependent',
    opaqueBroker: 'not-applicable',
  }),
  'apps-open': Object.freeze({
    filesystemScope: 'action-plan-dependent',
    privateDataScope: 'action-input-dependent',
    opaqueBroker: 'not-applicable',
  }),
  'clipboard-read': Object.freeze({
    filesystemScope: 'not-applicable',
    privateDataScope: 'declared-scope-required',
    opaqueBroker: 'not-applicable',
  }),
  'clipboard-write': Object.freeze({
    filesystemScope: 'not-applicable',
    privateDataScope: 'action-input-dependent',
    opaqueBroker: 'not-applicable',
  }),
  'files-search-metadata': Object.freeze({
    filesystemScope: 'declared-roots-required',
    privateDataScope: 'declared-scope-required',
    opaqueBroker: 'not-applicable',
  }),
  'documents-transform': Object.freeze({
    filesystemScope: 'declared-roots-required',
    privateDataScope: 'declared-scope-required',
    opaqueBroker: 'not-applicable',
  }),
  'power-hold-awake': Object.freeze({
    filesystemScope: 'not-applicable',
    privateDataScope: 'not-applicable',
    opaqueBroker: 'not-applicable',
  }),
  'automation-control': Object.freeze({
    filesystemScope: 'action-plan-dependent',
    privateDataScope: 'action-input-dependent',
    opaqueBroker: 'not-applicable',
  }),
  'accessibility-control': Object.freeze({
    filesystemScope: 'not-applicable',
    privateDataScope: 'action-input-dependent',
    opaqueBroker: 'not-applicable',
  }),
  'screen-capture': Object.freeze({
    filesystemScope: 'action-plan-dependent',
    privateDataScope: 'declared-scope-required',
    opaqueBroker: 'not-applicable',
  }),
  'input-monitor': Object.freeze({
    filesystemScope: 'not-applicable',
    privateDataScope: 'declared-scope-required',
    opaqueBroker: 'not-applicable',
  }),
  'full-disk-read': Object.freeze({
    filesystemScope: 'declared-roots-required',
    privateDataScope: 'declared-scope-required',
    opaqueBroker: 'not-applicable',
  }),
  'microphone-capture': Object.freeze({
    filesystemScope: 'action-plan-dependent',
    privateDataScope: 'declared-scope-required',
    opaqueBroker: 'not-applicable',
  }),
  'camera-capture': Object.freeze({
    filesystemScope: 'action-plan-dependent',
    privateDataScope: 'declared-scope-required',
    opaqueBroker: 'not-applicable',
  }),
  'local-network': Object.freeze({
    filesystemScope: 'not-applicable',
    privateDataScope: 'action-input-dependent',
    opaqueBroker: 'not-applicable',
  }),
})

const POLICY_REASON_ORDER = Object.freeze([
  'capability-not-applicable',
  'native-edge-unavailable',
  'fixed-action-adapter-missing',
  'macos-authorization-unknown',
  'macos-authorization-not-tested',
  'opaque-broker-missing',
  'task-authority-not-provided',
  'filesystem-scope-not-provided',
  'filesystem-classification-not-observed',
  'private-data-scope-not-provided',
  'private-data-classification-not-observed',
])

function record(value) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || utilTypes.isProxy(value)
  ) {
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
  if (
    typeof value !== 'object'
    || seen.has(value)
    || utilTypes.isProxy(value)
  ) {
    return false
  }

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

function dataEqual(left, right) {
  if (left === right) return true
  if (
    left === null
    || right === null
    || typeof left !== 'object'
    || typeof right !== 'object'
  ) {
    return false
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return (
      Array.isArray(left)
      && Array.isArray(right)
      && left.length === right.length
      && left.every((value, index) => dataEqual(value, right[index]))
    )
  }
  const leftKeys = Object.keys(left)
  const rightKeys = Object.keys(right)
  return (
    leftKeys.length === rightKeys.length
    && leftKeys.every(
      (key) => Object.hasOwn(right, key)
        && dataEqual(left[key], right[key]),
    )
  )
}

function authorizationState(requirement) {
  if (requirement === 'not-required') return 'not-required'
  if (
    [
      'per-item-at-use',
      'per-shortcut-at-use',
      'per-target-at-use',
    ].includes(requirement)
  ) {
    return 'not-tested'
  }
  if (requirement === 'unknown') return 'unknown'
  return 'not-applicable'
}

function recommendedHandling(agentDefault) {
  return {
    'allow-scoped': 'declared-roots-only',
    'ask-before-effect': 'task-authority-before-effect',
    'deny-private-read-until-task':
      'private-data-scope-required',
    'deny-until-explicit-grant':
      'explicit-macos-grant-required',
    'not-applicable': 'not-applicable',
  }[agentDefault] ?? null
}

function scopeState(requirement, privateData = false) {
  if (requirement === 'not-applicable') return 'not-applicable'
  if (
    requirement
    === (
      privateData
        ? 'declared-scope-required'
        : 'declared-roots-required'
    )
  ) {
    return 'not-provided'
  }
  return 'not-observed'
}

function buildRequirements({
  capability,
  capabilityId,
  encryption,
  platform,
}) {
  if (platform !== 'darwin') {
    return {
      macosAuthorization: {
        requirement: 'not-applicable',
        state: 'not-applicable',
        actorIdentity: 'unresolved',
        actorScope: 'responsible-process-specific',
      },
      taskAuthority: {
        requirement: 'not-applicable',
        state: 'not-applicable',
        grantedByReport: false,
      },
      filesystemScope: {
        requirement: 'not-applicable',
        state: 'not-applicable',
      },
      privateDataScope: {
        requirement: 'not-applicable',
        state: 'not-applicable',
      },
      opaqueBroker: {
        requirement: 'not-applicable',
        state: 'not-applicable',
        providerState: 'not-applicable',
        siblingAgentIsolation: 'not-applicable',
      },
      fixedAdapter: {
        requirement: 'not-applicable',
        state: 'not-applicable',
        evidence: 'not-applicable',
        executionEvidenceState: 'not-observed',
      },
    }
  }

  const policy = CAPABILITY_REQUIREMENTS[capabilityId]
  const brokerRequired = policy.opaqueBroker === 'required'
  return {
    macosAuthorization: {
      requirement: capability.authorization,
      state: authorizationState(capability.authorization),
      actorIdentity: 'unresolved',
      actorScope: 'responsible-process-specific',
    },
    taskAuthority: {
      requirement: 'current-task-required',
      state: 'not-provided',
      grantedByReport: false,
    },
    filesystemScope: {
      requirement: policy.filesystemScope,
      state: scopeState(policy.filesystemScope),
    },
    privateDataScope: {
      requirement: policy.privateDataScope,
      state: scopeState(policy.privateDataScope, true),
    },
    opaqueBroker: {
      requirement: policy.opaqueBroker,
      state: brokerRequired ? 'missing' : 'not-applicable',
      providerState: brokerRequired
        ? encryption.keychain.providerState
        : 'not-applicable',
      siblingAgentIsolation: brokerRequired
        ? encryption.agentBoundary.siblingAgents
        : 'not-applicable',
    },
    fixedAdapter: {
      requirement: 'required',
      state: capabilityId === 'power-hold-awake' ? 'implemented' : 'missing',
      evidence: capabilityId === 'power-hold-awake'
        ? POWER_ADAPTER_EVIDENCE
        : 'no-registered-fixed-action-adapter',
      executionEvidenceState: 'not-observed',
    },
  }
}

function decisionReasons(platform, capability, requirements) {
  const predicates = {
    'capability-not-applicable': platform !== 'darwin',
    'native-edge-unavailable': [
      'fixed-command-unavailable',
      'fixed-command-unavailable-adapter-required',
    ].includes(capability.nativeEdgeEvidence),
    'fixed-action-adapter-missing':
      requirements.fixedAdapter.state === 'missing',
    'macos-authorization-unknown':
      requirements.macosAuthorization.state === 'unknown',
    'macos-authorization-not-tested':
      requirements.macosAuthorization.state === 'not-tested',
    'opaque-broker-missing':
      requirements.opaqueBroker.state === 'missing',
    'task-authority-not-provided':
      requirements.taskAuthority.state === 'not-provided',
    'filesystem-scope-not-provided':
      requirements.filesystemScope.state === 'not-provided',
    'filesystem-classification-not-observed':
      requirements.filesystemScope.state === 'not-observed',
    'private-data-scope-not-provided':
      requirements.privateDataScope.state === 'not-provided',
    'private-data-classification-not-observed':
      requirements.privateDataScope.state === 'not-observed',
  }
  return POLICY_REASON_ORDER.filter((reason) => predicates[reason])
}

function composeMacCapabilityPolicy(
  capabilityId,
  capabilities,
  keychain,
  options = {},
) {
  if (
    typeof capabilityId !== 'string'
    || !MAC_CAPABILITY_IDS.includes(capabilityId)
  ) {
    return null
  }

  const checkCapabilities =
    options.checkCapabilities ?? checkMacCapabilities
  const validateKeychain =
    options.validateKeychain ?? validateMacKeychainReport
  const validateEncryption =
    options.validateEncryption ?? validateMacEncryptionPosture
  const capabilitySnapshot = validatedSnapshot(
    checkCapabilities,
    capabilities,
  )
  const keychainSnapshot = validatedSnapshot(
    validateKeychain,
    keychain,
  )
  if (
    !capabilitySnapshot
    || !keychainSnapshot
    || capabilitySnapshot.platform !== keychainSnapshot.platform
  ) {
    return null
  }

  const encryption = composeMacEncryptionPosture(
    capabilitySnapshot,
    keychainSnapshot,
    {
      architecture: options.architecture ?? process.arch,
      checkCapabilities,
      validateKeychain,
    },
  )
  const encryptionSnapshot = validatedSnapshot(
    validateEncryption,
    encryption,
  )
  if (
    !encryptionSnapshot
    || encryptionSnapshot.platform !== capabilitySnapshot.platform
  ) {
    return null
  }

  const sourceCapability =
    capabilitySnapshot.capabilities[capabilityId]
  if (!record(sourceCapability)) return null
  const capability = {
    nativeEdgeState: sourceCapability.toolState,
    nativeEdgeEvidence: sourceCapability.evidence,
    recommendedHandling:
      capabilitySnapshot.platform === 'darwin'
        ? recommendedHandling(sourceCapability.agentDefault)
        : 'not-applicable',
    risk: sourceCapability.risk,
    executionEvidenceState: 'not-observed',
  }
  const requirements = buildRequirements({
    capability: sourceCapability,
    capabilityId,
    encryption: encryptionSnapshot,
    platform: capabilitySnapshot.platform,
  })
  const report = {
    schema: MACOS_POLICY_SCHEMA,
    mode: 'preflight-only',
    consistency: 'non-atomic',
    platform: capabilitySnapshot.platform,
    capabilityId,
    sourceSchemas: {
      capabilities: CAPABILITY_SOURCE_SCHEMA,
      keychain: KEYCHAIN_SOURCE_SCHEMA,
      encryption: ENCRYPTION_SOURCE_SCHEMA,
    },
    capability,
    requirements,
    decision: {
      state: 'stop',
      reasons: decisionReasons(
        capabilitySnapshot.platform,
        capability,
        requirements,
      ),
      authorizesAction: false,
    },
    semanticBoundary: { ...SEMANTIC_BOUNDARY },
    control: { ...CONTROL },
    meaning: MEANING,
  }
  return validateMacCapabilityPolicy(report).length === 0
    ? report
    : null
}

function capabilityObservationMatches(report) {
  const explanation = explainMacCapability(
    report.capabilityId,
    {
      platform: report.platform === 'darwin' ? 'darwin' : 'other',
    },
  )
  if (!explanation) return false
  const capability = report.capability
  const expectedHandling =
    report.platform === 'darwin'
      ? recommendedHandling(
        explanation.capability.agentDefault,
      )
      : 'not-applicable'
  if (
    capability.recommendedHandling
      !== expectedHandling
    || capability.risk !== explanation.capability.risk
    || capability.executionEvidenceState !== 'not-observed'
  ) {
    return false
  }
  if (report.platform !== 'darwin') {
    return (
      capability.nativeEdgeState === 'not-applicable'
      && capability.nativeEdgeEvidence === 'platform-not-applicable'
    )
  }
  if (explanation.capability.toolState === 'adapter-required') {
    return (
      capability.nativeEdgeState === 'adapter-required'
      && [
        'fixed-command-present-adapter-required',
        'fixed-command-unavailable-adapter-required',
        'static-public-catalog',
      ].includes(capability.nativeEdgeEvidence)
    )
  }
  return (
    (
      capability.nativeEdgeState === 'available'
      && capability.nativeEdgeEvidence === 'fixed-command-presence'
    )
    || (
      capability.nativeEdgeState === 'unavailable'
      && capability.nativeEdgeEvidence === 'fixed-command-unavailable'
    )
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

function semanticBoundaryMatches(value) {
  return (
    exactDataRecord(
      value,
      Object.keys(SEMANTIC_BOUNDARY),
    )
    && Object.entries(SEMANTIC_BOUNDARY).every(
      ([key, expected]) => value[key] === expected,
    )
  )
}

function requirementsHaveExactShape(requirements) {
  return (
    exactDataRecord(requirements, REQUIREMENT_FIELDS)
    && exactDataRecord(
      requirements.macosAuthorization,
      MACOS_AUTHORIZATION_FIELDS,
    )
    && exactDataRecord(
      requirements.taskAuthority,
      TASK_AUTHORITY_FIELDS,
    )
    && exactDataRecord(
      requirements.filesystemScope,
      SCOPE_FIELDS,
    )
    && exactDataRecord(
      requirements.privateDataScope,
      SCOPE_FIELDS,
    )
    && exactDataRecord(
      requirements.opaqueBroker,
      OPAQUE_BROKER_FIELDS,
    )
    && exactDataRecord(
      requirements.fixedAdapter,
      FIXED_ADAPTER_FIELDS,
    )
  )
}

function validateMacCapabilityPolicy(report) {
  const issues = []
  if (!plainData(report)) return ['policy-report-malformed']
  if (!exactDataRecord(report, ROOT_FIELDS)) {
    return ['policy-report-shape-invalid']
  }
  if (
    report.schema !== MACOS_POLICY_SCHEMA
    || report.mode !== 'preflight-only'
    || report.consistency !== 'non-atomic'
    || !['darwin', 'other'].includes(report.platform)
    || report.meaning !== MEANING
    || !MAC_CAPABILITY_IDS.includes(report.capabilityId)
  ) {
    issues.push('policy-report-static-value-invalid')
  }

  if (
    !exactDataRecord(report.sourceSchemas, SOURCE_FIELDS)
    || report.sourceSchemas.capabilities !== CAPABILITY_SOURCE_SCHEMA
    || report.sourceSchemas.keychain !== KEYCHAIN_SOURCE_SCHEMA
    || report.sourceSchemas.encryption !== ENCRYPTION_SOURCE_SCHEMA
  ) {
    issues.push('policy-source-schema-invalid')
  }
  if (
    !exactDataRecord(report.capability, CAPABILITY_FIELDS)
    || !capabilityObservationMatches(report)
  ) {
    issues.push('policy-capability-observation-invalid')
  }
  if (!requirementsHaveExactShape(report.requirements)) {
    issues.push('policy-requirement-shape-invalid')
  } else {
    const explanation = explainMacCapability(
      report.capabilityId,
      {
        platform: report.platform === 'darwin' ? 'darwin' : 'other',
      },
    )
    if (
      !explanation
      || !Object.hasOwn(
        CAPABILITY_REQUIREMENTS,
        report.capabilityId,
      )
      || !['darwin', 'other'].includes(report.platform)
    ) {
      issues.push('policy-requirement-value-invalid')
    } else {
      const providerState =
        report.requirements.opaqueBroker.providerState
      if (
        report.platform === 'darwin'
        && report.capabilityId === 'keychain-reference'
        && !['available', 'unavailable'].includes(providerState)
      ) {
        issues.push('policy-keychain-context-invalid')
      }
      const expectedEncryption = {
        keychain: { providerState },
        agentBoundary: {
          siblingAgents:
            report.platform === 'darwin'
              ? 'not-established'
              : 'not-applicable',
        },
      }
      const expected = buildRequirements({
        capability: {
          authorization:
            report.platform === 'darwin'
              ? explanation.capability.authorization
              : 'not-applicable',
        },
        capabilityId: report.capabilityId,
        encryption: expectedEncryption,
        platform: report.platform,
      })
      if (!dataEqual(report.requirements, expected)) {
        issues.push('policy-requirement-value-invalid')
      }
    }
  }

  if (!exactDataRecord(report.decision, DECISION_FIELDS)) {
    issues.push('policy-decision-shape-invalid')
  } else {
    const expectedReasons = (
      requirementsHaveExactShape(report.requirements)
      && exactDataRecord(report.capability, CAPABILITY_FIELDS)
    )
      ? decisionReasons(
        report.platform,
        report.capability,
        report.requirements,
      )
      : []
    if (
      report.decision.state !== 'stop'
      || report.decision.authorizesAction !== false
      || !dataEqual(report.decision.reasons, expectedReasons)
    ) {
      issues.push('policy-decision-invalid')
    }
  }
  if (!controlMatches(report.control)) {
    issues.push('policy-control-invalid')
  }
  if (!semanticBoundaryMatches(report.semanticBoundary)) {
    issues.push('policy-semantic-boundary-invalid')
  }
  return [...new Set(issues)]
}

function renderMacCapabilityPolicy(report) {
  const reasons = report.decision?.reasons?.length > 0
    ? report.decision.reasons.join(', ')
    : 'observer-cannot-authorize'
  const adapterBoundary =
    report.requirements?.fixedAdapter?.state === 'missing'
      ? 'fixed adapter missing; general-shell and session enforcement are not established here'
      : report.requirements?.fixedAdapter?.state
        === 'not-applicable'
        ? 'macOS adapter not applicable; this report establishes no session enforcement'
        : report.requirements?.fixedAdapter?.state === 'implemented'
          ? 'fixed power adapter implemented (static code only); execution not observed; this report establishes no session enforcement'
          : 'fixed adapter state unknown; this report establishes no session enforcement'
  return [
    'KINGDOM OS macOS policy preflight — observation only',
    `  capability   ${report.capabilityId ?? 'unknown'}`,
    `  native edge  ${report.capability?.nativeEdgeState ?? 'unknown'} · ${report.capability?.nativeEdgeEvidence ?? 'unknown'}`,
    `  handling     ${report.capability?.recommendedHandling ?? 'unknown'} · risk ${report.capability?.risk ?? 'unknown'}`,
    `  decision     stop · ${reasons}`,
    '  authority    this report grants none and is not an action receipt',
    `  boundary     ${adapterBoundary}`,
    '  encryption   validated context only; never permission',
    '  control      no action, adapter, general shell, private read, secret read, prompt, setting, or service change',
  ].join('\n')
}

export {
  CAPABILITY_REQUIREMENTS,
  MACOS_POLICY_SCHEMA,
  POLICY_REASON_ORDER,
  composeMacCapabilityPolicy,
  renderMacCapabilityPolicy,
  validateMacCapabilityPolicy,
}
