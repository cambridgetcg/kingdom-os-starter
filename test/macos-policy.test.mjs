import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

import {
  MAC_CAPABILITY_IDS,
  inspectMacCapabilities,
} from '../platform/macos-capabilities.mjs'
import {
  inspectMacKeychain,
} from '../platform/macos-keychain.mjs'
import {
  CAPABILITY_REQUIREMENTS,
  MACOS_POLICY_SCHEMA,
  POLICY_REASON_ORDER,
  composeMacCapabilityPolicy,
  renderMacCapabilityPolicy,
  validateMacCapabilityPolicy,
} from '../platform/macos-policy.mjs'

const COMMAND_KEYS = Object.freeze([
  'caffeinate',
  'fdesetup',
  'firewall',
  'mdfind',
  'open',
  'osascript',
  'pbcopy',
  'pbpaste',
  'plutil',
  'qlmanage',
  'say',
  'screencapture',
  'security',
  'shortcuts',
  'sips',
  'spctl',
  'textutil',
])

const EXPECTED_REQUIREMENT_ROWS = Object.freeze([
  ['keychain-reference', 'not-applicable', 'declared-scope-required', 'required'],
  ['shortcuts-run', 'action-plan-dependent', 'action-input-dependent', 'not-applicable'],
  ['notifications-send', 'not-applicable', 'action-input-dependent', 'not-applicable'],
  ['speech-speak', 'not-applicable', 'action-input-dependent', 'not-applicable'],
  ['apps-open', 'action-plan-dependent', 'action-input-dependent', 'not-applicable'],
  ['clipboard-read', 'not-applicable', 'declared-scope-required', 'not-applicable'],
  ['clipboard-write', 'not-applicable', 'action-input-dependent', 'not-applicable'],
  ['files-search-metadata', 'declared-roots-required', 'declared-scope-required', 'not-applicable'],
  ['documents-transform', 'declared-roots-required', 'declared-scope-required', 'not-applicable'],
  ['power-hold-awake', 'not-applicable', 'not-applicable', 'not-applicable'],
  ['automation-control', 'action-plan-dependent', 'action-input-dependent', 'not-applicable'],
  ['accessibility-control', 'not-applicable', 'action-input-dependent', 'not-applicable'],
  ['screen-capture', 'action-plan-dependent', 'declared-scope-required', 'not-applicable'],
  ['input-monitor', 'not-applicable', 'declared-scope-required', 'not-applicable'],
  ['full-disk-read', 'declared-roots-required', 'declared-scope-required', 'not-applicable'],
  ['microphone-capture', 'action-plan-dependent', 'declared-scope-required', 'not-applicable'],
  ['camera-capture', 'action-plan-dependent', 'declared-scope-required', 'not-applicable'],
  ['local-network', 'not-applicable', 'action-input-dependent', 'not-applicable'],
])

const EXPECTED_REASON_ORDER = Object.freeze([
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

function clone(value) {
  return JSON.parse(JSON.stringify(value))
}

function keychainReport({
  platform = 'darwin',
  providerState = 'available',
} = {}) {
  if (platform !== 'darwin') {
    return {
      schema: 'kingdom.macos-keychain-posture/0.1',
      mode: 'observation-only',
      platform: 'other',
      provider: {
        kind: 'macos-keychain',
        toolState: 'not-applicable',
        userDomainState: 'not-applicable',
      },
      gate: {
        kind: 'keep',
        toolState: 'not-applicable',
        evidenceState: 'not-applicable',
        authorization: 'not-applicable',
        actionEvidence: 'not-tested',
        agentDefault: 'not-applicable',
      },
      gitCredentialHelper: {
        kind: 'osxkeychain',
        state: 'not-applicable',
      },
      isolation: {
        boundary: 'not-applicable',
        siblingAgents: 'not-applicable',
        kingdomWalls: 'not-operating-system-enforced',
      },
      evidence: [],
      control: {
        writes: false,
        networkRequests: false,
        readsCoarseMetadata: true,
        returnsPrivateContent: false,
        readsSecretValues: false,
        listsSecretNames: false,
        requestsPermission: false,
        opensApplications: false,
        changesSettings: false,
        changesServices: false,
      },
      meaning:
        'The macOS Keychain posture is not applicable on this host.',
    }
  }
  return {
    schema: 'kingdom.macos-keychain-posture/0.1',
    mode: 'observation-only',
    platform: 'darwin',
    provider: {
      kind: 'macos-keychain',
      toolState: providerState,
      userDomainState:
        providerState === 'available' ? 'available' : 'unknown',
    },
    gate: {
      kind: 'keep',
      toolState: 'available',
      evidenceState: 'owner-mode-path-match',
      authorization: 'per-item-at-use',
      actionEvidence: 'not-tested',
      agentDefault: 'deny-private-read-until-task',
    },
    gitCredentialHelper: {
      kind: 'osxkeychain',
      state: 'configured',
    },
    isolation: {
      boundary: 'login-user',
      siblingAgents: 'not-isolated',
      kingdomWalls: 'not-operating-system-enforced',
    },
    evidence: [
      'fixed-native-tool-presence',
      'user-domain-exit-status-only',
      'final-gate-source-owner-mode-path-metadata',
      'git-helper-exact-match-exit-status-only',
    ],
    control: {
      writes: false,
      networkRequests: false,
      readsCoarseMetadata: true,
      returnsPrivateContent: false,
      readsSecretValues: false,
      listsSecretNames: false,
      requestsPermission: false,
      opensApplications: false,
      changesSettings: false,
      changesServices: false,
    },
    meaning:
      'Keychain protects the login user, not sibling agents under that user. Gate metadata does not prove behavior, Keychain ACLs, or ancestor-directory safety. Evidence is not authority or consent.',
  }
}

async function capabilityReport({
  fileVault = 'off',
  toolsPresent = true,
} = {}) {
  const commands = Object.fromEntries(
    COMMAND_KEYS.map((key) => [
      key,
      toolsPresent ? `/fixed/${key}` : null,
    ]),
  )
  return inspectMacCapabilities({
    platform: 'darwin',
    home: '/fixture/home',
    commands,
    runCommand: async (command) => {
      if (command === '/fixed/fdesetup') {
        return `FileVault is ${fileVault}.`
      }
      if (command === '/fixed/firewall') {
        return 'Firewall is disabled. (State = 0)'
      }
      if (command === '/fixed/spctl') {
        return 'assessments enabled'
      }
      assert.fail(`unexpected fixture command: ${command}`)
    },
  })
}

async function darwinSources(options = {}) {
  return {
    capabilities: await capabilityReport(options),
    keychain: keychainReport(options),
  }
}

async function policyFor(id, options = {}) {
  const { capabilities, keychain } = await darwinSources(options)
  return composeMacCapabilityPolicy(
    id,
    capabilities,
    keychain,
    { architecture: options.architecture ?? 'arm64' },
  )
}

test('the policy table covers every capability exactly once', () => {
  assert.deepEqual(
    Object.keys(CAPABILITY_REQUIREMENTS),
    MAC_CAPABILITY_IDS,
  )
  assert.deepEqual(
    Object.entries(CAPABILITY_REQUIREMENTS).map(
      ([id, requirements]) => [
        id,
        requirements.filesystemScope,
        requirements.privateDataScope,
        requirements.opaqueBroker,
      ],
    ),
    EXPECTED_REQUIREMENT_ROWS,
  )
  assert.deepEqual(POLICY_REASON_ORDER, EXPECTED_REASON_ORDER)
})

test('every known capability produces only a stop preflight', async () => {
  const { capabilities, keychain } = await darwinSources()
  for (const id of MAC_CAPABILITY_IDS) {
    const report = composeMacCapabilityPolicy(
      id,
      capabilities,
      keychain,
      { architecture: 'arm64' },
    )
    assert.ok(report, id)
    assert.equal(report.schema, MACOS_POLICY_SCHEMA)
    assert.deepEqual(validateMacCapabilityPolicy(report), [])
    assert.equal(report.capabilityId, id)
    assert.equal(report.decision.state, 'stop')
    assert.equal(report.decision.authorizesAction, false)
    assert.deepEqual(report.requirements.fixedAdapter, {
      requirement: 'required',
      state: id === 'power-hold-awake' ? 'implemented' : 'missing',
      evidence: id === 'power-hold-awake'
        ? 'static-code:platform/macos-awake.mjs:/usr/bin/caffeinate -i -t N -w PID'
        : 'no-registered-fixed-action-adapter',
      executionEvidenceState: 'not-observed',
    })
    assert.equal(
      report.decision.reasons.includes('fixed-action-adapter-missing'),
      id !== 'power-hold-awake',
    )
    assert.deepEqual(report.requirements.taskAuthority, {
      requirement: 'current-task-required',
      state: 'not-provided',
      grantedByReport: false,
    })
    assert.equal(report.capability.executionEvidenceState, 'not-observed')
    assert.equal(report.control.invokesActions, false)
    assert.equal(report.control.invokesAdapters, false)
    assert.equal(report.control.invokesGeneralShell, false)
    assert.equal(report.control.grantsAuthority, false)
    assert.equal(
      report.semanticBoundary.authorizesExecution,
      false,
    )
    assert.equal(
      report.semanticBoundary.establishesSessionEnforcement,
      false,
    )
    assert.equal(
      report.semanticBoundary.sourceInstanceBinding,
      'not-provided',
    )
    assert.equal(
      report.semanticBoundary.observationFreshness,
      'not-established',
    )
    assert.doesNotMatch(
      JSON.stringify(report),
      /"allow"|"ready"|"authorized"/,
    )
  }
})

test('power registration is static code evidence, independent of native availability', async () => {
  assert.equal(MACOS_POLICY_SCHEMA, 'kingdom.macos-capability-policy/0.2')
  for (const toolsPresent of [true, false]) {
    const report = await policyFor('power-hold-awake', { toolsPresent })
    assert.ok(report)
    assert.deepEqual(validateMacCapabilityPolicy(report), [])
    assert.equal(report.requirements.fixedAdapter.state, 'implemented')
    assert.equal(
      report.requirements.fixedAdapter.evidence,
      'static-code:platform/macos-awake.mjs:/usr/bin/caffeinate -i -t N -w PID',
    )
    assert.equal(
      report.requirements.fixedAdapter.executionEvidenceState,
      'not-observed',
    )
    assert.equal(report.capability.executionEvidenceState, 'not-observed')
    assert.equal(
      report.capability.nativeEdgeState,
      toolsPresent ? 'available' : 'unavailable',
    )
    assert.equal(report.requirements.macosAuthorization.state, 'not-required')
    assert.deepEqual(report.decision, {
      state: 'stop',
      reasons: toolsPresent
        ? ['task-authority-not-provided']
        : ['native-edge-unavailable', 'task-authority-not-provided'],
      authorizesAction: false,
    })
    assert.equal(report.semanticBoundary.isActionReceipt, false)
    assert.equal(report.semanticBoundary.isBearerCredential, false)
    assert.equal(report.semanticBoundary.enforcesExecution, false)
    const text = renderMacCapabilityPolicy(report)
    assert.match(text, /fixed power adapter implemented \(static code only\)/)
    assert.match(text, /execution not observed/)
    assert.match(text, /decision\s+stop/)
    assert.match(text, /grants none/)
    assert.match(text, /no session enforcement/)
    assert.doesNotMatch(text, /fixed adapter missing|state unknown/)
  }
})

test('observation modules do not import the awake action module', () => {
  for (const name of [
    'macos-policy',
    'macos-capabilities',
    'macos-encryption',
    'macos-keychain',
  ]) {
    const source = readFileSync(
      new URL(`../platform/${name}.mjs`, import.meta.url),
      'utf8',
    )
    assert.doesNotMatch(
      source,
      /(?:\bfrom\s*|\bimport\s*(?:\(\s*)?|\brequire\s*\(\s*)['"][^'"]*macos-awake\.mjs['"]/,
      name,
    )
  }
})

test('the exact contract rejects power registration and authority promotions', async () => {
  const valid = await policyFor('power-hold-awake')
  const attacks = [
    (report) => { report.schema = 'kingdom.macos-capability-policy/0.1' },
    (report) => { report.requirements.fixedAdapter.state = 'tested' },
    (report) => { report.requirements.fixedAdapter.evidence = 'on-host-tested' },
    (report) => { report.requirements.fixedAdapter.evidence = 'authenticated' },
    (report) => { report.requirements.fixedAdapter.executionEvidenceState = 'passed' },
    (report) => { report.capability.executionEvidenceState = 'passed' },
    (report) => { report.requirements.taskAuthority.state = 'provided' },
    (report) => { report.requirements.taskAuthority.grantedByReport = true },
    (report) => { report.decision.state = 'allow' },
    (report) => { report.decision.authorizesAction = true },
    (report) => { report.decision.reasons = [] },
    (report) => { report.decision.reasons.unshift('fixed-action-adapter-missing') },
    (report) => { report.control.invokesActions = true },
    (report) => { report.control.invokesAdapters = true },
    (report) => { report.semanticBoundary.isActionReceipt = true },
    (report) => { report.semanticBoundary.establishesSessionEnforcement = true },
    (report) => {
      report.requirements.fixedAdapter.state = 'missing'
      report.requirements.fixedAdapter.evidence = 'no-registered-fixed-action-adapter'
      report.decision.reasons.unshift('fixed-action-adapter-missing')
    },
  ]
  for (const mutate of attacks) {
    const report = clone(valid)
    mutate(report)
    assert.notDeepEqual(validateMacCapabilityPolicy(report), [])
  }

  for (const id of MAC_CAPABILITY_IDS.filter((id) => id !== 'power-hold-awake')) {
    const report = await policyFor(id)
    report.requirements.fixedAdapter = clone(valid.requirements.fixedAdapter)
    report.decision.reasons = report.decision.reasons.filter(
      (reason) => reason !== 'fixed-action-adapter-missing',
    )
    assert.ok(
      validateMacCapabilityPolicy(report).includes('policy-requirement-value-invalid'),
      id,
    )
  }
})

test('raw tool presence never becomes a fixed adapter', async () => {
  const report = await policyFor('speech-speak')

  assert.equal(report.capability.nativeEdgeState, 'available')
  assert.equal(
    report.capability.recommendedHandling,
    'task-authority-before-effect',
  )
  assert.equal(
    report.requirements.fixedAdapter.evidence,
    'no-registered-fixed-action-adapter',
  )
  assert.ok(
    report.decision.reasons.includes(
      'fixed-action-adapter-missing',
    ),
  )
  assert.ok(
    report.decision.reasons.includes(
      'task-authority-not-provided',
    ),
  )
})

test('filesystem and private-data requirements stay separate', async () => {
  const search = await policyFor('files-search-metadata')
  const documents = await policyFor('documents-transform')
  const fullDisk = await policyFor('full-disk-read')
  const clipboard = await policyFor('clipboard-read')
  const power = await policyFor('power-hold-awake')

  for (const report of [search, documents, fullDisk]) {
    assert.equal(
      report.requirements.filesystemScope.requirement,
      'declared-roots-required',
    )
    assert.equal(
      report.requirements.privateDataScope.requirement,
      'declared-scope-required',
    )
  }
  assert.equal(
    clipboard.requirements.filesystemScope.requirement,
    'not-applicable',
  )
  assert.equal(
    clipboard.requirements.privateDataScope.requirement,
    'declared-scope-required',
  )
  assert.equal(
    power.requirements.filesystemScope.requirement,
    'not-applicable',
  )
  assert.equal(
    power.requirements.privateDataScope.requirement,
    'not-applicable',
  )
})

test('Keychain availability still requires a missing opaque broker', async () => {
  const report = await policyFor('keychain-reference')

  assert.equal(
    report.sourceSchemas.encryption,
    'kingdom.macos-encryption-posture/0.1',
  )
  assert.deepEqual(report.requirements.opaqueBroker, {
    requirement: 'required',
    state: 'missing',
    providerState: 'available',
    siblingAgentIsolation: 'not-established',
  })
  assert.ok(
    report.decision.reasons.includes('opaque-broker-missing'),
  )
  assert.equal(report.control.readsSecretValues, false)
  assert.equal(report.control.listsSecretNames, false)
})

test('encryption and provider permutations never authorize', async () => {
  const reports = await Promise.all([
    policyFor('keychain-reference', {
      fileVault: 'off',
      providerState: 'available',
    }),
    policyFor('keychain-reference', {
      fileVault: 'on',
      providerState: 'available',
    }),
    policyFor('keychain-reference', {
      fileVault: 'off',
      providerState: 'unavailable',
    }),
  ])

  for (const report of reports) {
    assert.equal(report.decision.state, 'stop')
    assert.equal(report.decision.authorizesAction, false)
    assert.equal(report.requirements.opaqueBroker.state, 'missing')
  }
  assert.deepEqual(
    reports.map((report) => report.decision.reasons),
    [
      reports[0].decision.reasons,
      reports[0].decision.reasons,
      reports[0].decision.reasons,
    ],
  )
})

test('other platforms run no probes and normalize every requirement', async () => {
  const capabilities = await inspectMacCapabilities({
    platform: 'linux',
    home: '/fixture/home',
    runCommand: async () => {
      assert.fail('non-Darwin policy fixture must not run a probe')
    },
  })
  const keychain = await inspectMacKeychain({
    platform: 'linux',
    home: '/fixture/home',
    uid: 1000,
    runStatus: async () => {
      assert.fail('non-Darwin policy fixture must not run a probe')
    },
  })
  const report = composeMacCapabilityPolicy(
    'screen-capture',
    capabilities,
    keychain,
    { architecture: 'x64' },
  )

  assert.ok(report)
  assert.equal(report.platform, 'other')
  assert.equal(
    report.capability.nativeEdgeState,
    'not-applicable',
  )
  assert.equal(
    report.capability.recommendedHandling,
    'not-applicable',
  )
  assert.deepEqual(report.decision.reasons, [
    'capability-not-applicable',
  ])
  assert.equal(
    report.requirements.fixedAdapter.state,
    'not-applicable',
  )
  assert.equal(
    report.requirements.privateDataScope.state,
    'not-applicable',
  )
  const text = renderMacCapabilityPolicy(report)
  assert.match(text, /macOS adapter not applicable/)
  assert.doesNotMatch(text, /fixed adapter missing/)

  for (const id of MAC_CAPABILITY_IDS) {
    const policy = composeMacCapabilityPolicy(id, capabilities, keychain)
    assert.deepEqual(validateMacCapabilityPolicy(policy), [], id)
    assert.deepEqual(policy.requirements.fixedAdapter, {
      requirement: 'not-applicable',
      state: 'not-applicable',
      evidence: 'not-applicable',
      executionEvidenceState: 'not-observed',
    }, id)
    assert.deepEqual(policy.decision, {
      state: 'stop',
      reasons: ['capability-not-applicable'],
      authorizesAction: false,
    }, id)
  }
})

test('unknown capabilities and mismatched sources fail closed', async () => {
  const { capabilities, keychain } = await darwinSources()
  const otherKeychain = keychainReport({ platform: 'other' })

  assert.equal(
    composeMacCapabilityPolicy(
      'private-looking-capability',
      capabilities,
      keychain,
    ),
    null,
  )
  assert.equal(
    composeMacCapabilityPolicy(
      'speech-speak',
      capabilities,
      otherKeychain,
    ),
    null,
  )
})

test('sources are snapshotted and hostile serialization never runs', async () => {
  const { capabilities, keychain } = await darwinSources()
  const privateText = 'PRIVATE-SOURCE-MUST-NOT-SURVIVE'
  assert.equal(
    composeMacCapabilityPolicy(
      'speech-speak',
      { ...capabilities, privateText },
      keychain,
    ),
    null,
  )

  let toJSONCalls = 0
  const withHook = clone(capabilities)
  withHook.toJSON = () => {
    toJSONCalls += 1
    return capabilities
  }
  assert.equal(
    composeMacCapabilityPolicy(
      'speech-speak',
      withHook,
      keychain,
    ),
    null,
  )
  assert.equal(toJSONCalls, 0)

  let getterCalls = 0
  const withGetter = clone(capabilities)
  Object.defineProperty(withGetter, 'secret', {
    enumerable: true,
    get() {
      getterCalls += 1
      return privateText
    },
  })
  assert.equal(
    composeMacCapabilityPolicy(
      'speech-speak',
      withGetter,
      keychain,
    ),
    null,
  )
  assert.equal(getterCalls, 0)

  const recursive = clone(capabilities)
  recursive.loop = recursive
  assert.equal(
    composeMacCapabilityPolicy(
      'speech-speak',
      recursive,
      keychain,
    ),
    null,
  )
  assert.equal(
    composeMacCapabilityPolicy(
      'speech-speak',
      new Proxy(clone(capabilities), {}),
      keychain,
    ),
    null,
  )

  const report = composeMacCapabilityPolicy(
    'speech-speak',
    capabilities,
    keychain,
    { architecture: 'arm64' },
  )
  capabilities.capabilities['speech-speak'].toolState =
    'unavailable'
  keychain.provider.toolState = 'unavailable'
  assert.equal(report.capability.nativeEdgeState, 'available')
  assert.equal(report.decision.state, 'stop')
})

test('the exact output rejects structural and promotion attacks', async () => {
  const valid = await policyFor('keychain-reference')
  const attacks = []

  attacks.push({ ...valid, private: 'do-not-print' })

  const symbol = clone(valid)
  symbol[Symbol('hidden')] = true
  attacks.push(symbol)

  const accessor = clone(valid)
  Object.defineProperty(accessor, 'secret', {
    enumerable: true,
    get() {
      return 'do-not-print'
    },
  })
  attacks.push(accessor)

  const recursive = clone(valid)
  recursive.loop = recursive
  attacks.push(recursive)

  attacks.push(Object.create(valid))
  attacks.push(new Proxy(clone(valid), {}))

  const nullCapability = clone(valid)
  nullCapability.capability = null
  attacks.push(nullCapability)

  const allow = clone(valid)
  allow.decision.state = 'allow'
  attacks.push(allow)

  const authority = clone(valid)
  authority.decision.authorizesAction = true
  attacks.push(authority)

  const task = clone(valid)
  task.requirements.taskAuthority.state = 'provided'
  attacks.push(task)

  const adapter = clone(valid)
  adapter.requirements.fixedAdapter.state = 'available'
  attacks.push(adapter)

  const broker = clone(valid)
  broker.requirements.opaqueBroker.state = 'available'
  attacks.push(broker)

  const evidence = clone(valid)
  evidence.capability.executionEvidenceState = 'passed'
  attacks.push(evidence)

  const control = clone(valid)
  control.control.invokesActions = true
  attacks.push(control)

  const receipt = clone(valid)
  receipt.semanticBoundary.isActionReceipt = true
  attacks.push(receipt)

  const binding = clone(valid)
  binding.semanticBoundary.sourceInstanceBinding = 'provided'
  attacks.push(binding)

  for (const attack of attacks) {
    assert.notDeepEqual(validateMacCapabilityPolicy(attack), [])
  }
})

test('decision reasons are exact, ordered, and unique', async () => {
  const valid = await policyFor('files-search-metadata')
  const missing = clone(valid)
  missing.decision.reasons.pop()
  const extra = clone(valid)
  extra.decision.reasons.push('made-up-reason')
  const duplicate = clone(valid)
  duplicate.decision.reasons.push(
    duplicate.decision.reasons.at(-1),
  )
  const reordered = clone(valid)
  reordered.decision.reasons.reverse()

  for (const report of [missing, extra, duplicate, reordered]) {
    assert.ok(
      validateMacCapabilityPolicy(report).includes(
        'policy-decision-invalid',
      ),
    )
  }
})

test('malformed public input returns fixed issues without throwing', async () => {
  const valid = await policyFor('speech-speak')
  const invalidId = clone(valid)
  invalidId.capabilityId = 'private-looking-capability'
  const invalidPlatform = clone(valid)
  invalidPlatform.platform = 'private-looking-platform'
  const nullCapability = clone(valid)
  nullCapability.capability = null
  const proxy = new Proxy({}, {
    getPrototypeOf() {
      throw new Error('prototype trap')
    },
  })

  for (const value of [
    invalidId,
    invalidPlatform,
    nullCapability,
    proxy,
  ]) {
    let issues
    assert.doesNotThrow(() => {
      issues = validateMacCapabilityPolicy(value)
    })
    assert.notDeepEqual(issues, [])
    assert.doesNotMatch(
      JSON.stringify(issues),
      /private-looking|prototype trap/,
    )
  }
})

test('human rendering says stop and names the non-enforcement boundary', async () => {
  const report = await policyFor('documents-transform')
  const text = renderMacCapabilityPolicy(report)

  assert.match(text, /policy preflight — observation only/)
  assert.match(text, /decision\s+stop/)
  assert.match(text, /grants none/)
  assert.match(text, /fixed adapter missing/)
  assert.match(text, /general-shell and session enforcement/)
  assert.match(text, /encryption\s+validated context only/)
  assert.doesNotMatch(text, /PRIVATE|secret value|item name/)
})
