import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'

import {
  COMPOSITE_SCHEMA,
  checkMacReport,
  composeReport,
  parseArguments,
  runCli,
} from '../bin/mac.mjs'
import {
  checkMacCapabilities,
  checkMacCapabilityExplanation,
  explainMacCapability,
  inspectMacCapabilities,
} from '../platform/macos-capabilities.mjs'
import {
  inspectMacKeychain,
  validateMacKeychainReport,
} from '../platform/macos-keychain.mjs'
import {
  MACOS_ENCRYPTION_SCHEMA,
} from '../platform/macos-encryption.mjs'
import {
  MACOS_POLICY_SCHEMA,
} from '../platform/macos-policy.mjs'

function capabilityReport() {
  return {
    schema: 'kingdom.macos-agent-capabilities/0.1',
    mode: 'observation-only',
    platform: 'darwin',
    actor: {
      identityState: 'unresolved',
      scope: 'responsible-process-specific',
    },
    capabilities: {
      'accessibility-control': {
        title: 'Control the user interface',
        summary: 'Actor-specific UI control.',
        nativeEdge: 'Accessibility APIs',
        toolState: 'adapter-required',
        authorization: 'unknown',
        actionEvidence: 'not-tested',
        agentDefault: 'deny-until-explicit-grant',
        risk: 'high',
        settingId: 'accessibility',
        evidence: 'static-public-catalog',
      },
    },
    settings: {
      accessibility: {
        location: 'Privacy & Security > Accessibility',
        state: 'not-observed',
        evidence: 'static-public-catalog',
      },
    },
    safety: {
      fileVault: {
        state: 'off',
        evidence: 'bounded-system-metadata',
      },
      firewall: {
        state: 'off',
        evidence: 'bounded-system-metadata',
      },
      gatekeeper: {
        state: 'on',
        evidence: 'bounded-system-metadata',
      },
    },
    control: {
      writes: false,
      networkRequests: false,
      readsCoarseSystemMetadata: true,
      readsPrivateContent: false,
      returnsPrivateContent: false,
      readsSecretValues: false,
      listsSecretNames: false,
      requestsPermission: false,
      opensApplications: false,
      changesSettings: false,
      changesServices: false,
    },
    meaning: 'Observation is not permission.',
  }
}

function keychainReport() {
  return {
    schema: 'kingdom.macos-keychain-posture/0.1',
    mode: 'observation-only',
    platform: 'darwin',
    provider: {
      kind: 'macos-keychain',
      toolState: 'available',
      userDomainState: 'available',
    },
    gate: {
      kind: 'keep',
      toolState: 'available',
      evidenceState: 'owner-mode-path-match',
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
  }
}

function capture(overrides = {}) {
  const stdout = []
  const stderr = []
  return {
    stdout,
    stderr,
    options: {
      writeOut: (text) => stdout.push(text),
      writeError: (text) => stderr.push(text),
      checkCapabilities: () => [],
      checkExplanation: () => [],
      validateKeychain: () => [],
      ...overrides,
    },
  }
}

test('existing observation verbs retain their argument contract', () => {
  assert.deepEqual(parseArguments([]), {
    command: 'doctor',
    json: false,
  })
  assert.deepEqual(parseArguments(['status', '--json']), {
    command: 'doctor',
    json: true,
  })
  assert.deepEqual(parseArguments(['encryption', '--json']), {
    command: 'encryption',
    json: true,
  })
  assert.deepEqual(
    parseArguments([
      'policy',
      'documents-transform',
      '--json',
    ]),
    {
      command: 'policy',
      id: 'documents-transform',
      json: true,
    },
  )
  assert.deepEqual(parseArguments(['explain', 'screen-capture']), {
    command: 'explain',
    id: 'screen-capture',
    json: false,
  })
  for (const args of [
    ['grant', 'accessibility-control'],
    ['open-settings'],
    ['keychain', 'list'],
    ['policy'],
    ['policy', 'screen-capture', 'run'],
    ['encrypt'],
    ['decrypt'],
    ['enable'],
    ['rotate'],
    ['recover'],
    ['export'],
    ['doctor', '--json', '--json'],
  ]) {
    assert.equal(parseArguments(args), null)
  }
})

test('doctor composes capability and Keychain posture without an action', async () => {
  let capabilityCalls = 0
  let keychainCalls = 0
  const io = capture({
    inspectCapabilities: async () => {
      capabilityCalls += 1
      return capabilityReport()
    },
    inspectKeychain: async () => {
      keychainCalls += 1
      return keychainReport()
    },
  })

  const code = await runCli(['doctor', '--json'], io.options)
  const report = JSON.parse(io.stdout.join(''))

  assert.equal(code, 0)
  assert.equal(capabilityCalls, 1)
  assert.equal(keychainCalls, 1)
  assert.equal(report.schema, COMPOSITE_SCHEMA)
  assert.equal(report.consistency, 'non-atomic')
  assert.equal(
    report.keychainPosture.schema,
    'kingdom.macos-keychain-posture/0.1',
  )
  assert.equal(
    report.macosCapabilities.actor.identityState,
    'unresolved',
  )
  assert.equal(report.control.writes, false)
  assert.equal(Object.hasOwn(report, 'encryptionPosture'), false)
  assert.equal(
    report.keychainPosture.control.readsSecretValues,
    false,
  )
  assert.deepEqual(io.stderr, [])
})

test('encryption view derives a separate exact posture without a new probe', async () => {
  let capabilityCalls = 0
  let keychainCalls = 0
  const io = capture({
    architecture: 'arm64',
    inspectCapabilities: async () => {
      capabilityCalls += 1
      return capabilityReport()
    },
    inspectKeychain: async () => {
      keychainCalls += 1
      return keychainReport()
    },
  })

  const code = await runCli(['encryption', '--json'], io.options)
  const report = JSON.parse(io.stdout.join(''))

  assert.equal(code, 0)
  assert.equal(capabilityCalls, 1)
  assert.equal(keychainCalls, 1)
  assert.equal(report.schema, MACOS_ENCRYPTION_SCHEMA)
  assert.equal(report.storage.internalDataEncryption, 'platform-inferred')
  assert.equal(report.storage.fileVaultState, 'off')
  assert.equal(report.keychain.providerState, 'available')
  assert.equal(report.agentBoundary.siblingAgents, 'not-established')
  assert.equal(report.unobserved.recoveryMaterial, 'not-observed')
  assert.equal(report.control.readsKeyMaterial, false)
  assert.deepEqual(io.stderr, [])
})

test('policy preflight composes exact schemas and always stops', async () => {
  let capabilityCalls = 0
  let keychainCalls = 0
  const io = capture({
    architecture: 'arm64',
    inspectCapabilities: async () => {
      capabilityCalls += 1
      return capabilityReport()
    },
    inspectKeychain: async () => {
      keychainCalls += 1
      return keychainReport()
    },
  })

  const code = await runCli(
    ['policy', 'accessibility-control', '--json'],
    io.options,
  )
  const report = JSON.parse(io.stdout.join(''))

  assert.equal(code, 0)
  assert.equal(capabilityCalls, 1)
  assert.equal(keychainCalls, 1)
  assert.equal(report.schema, MACOS_POLICY_SCHEMA)
  assert.equal(report.capabilityId, 'accessibility-control')
  assert.equal(
    report.sourceSchemas.encryption,
    MACOS_ENCRYPTION_SCHEMA,
  )
  assert.equal(report.decision.state, 'stop')
  assert.equal(report.decision.authorizesAction, false)
  assert.equal(report.semanticBoundary.isBearerCredential, false)
  assert.equal(report.requirements.fixedAdapter.state, 'missing')
  assert.equal(report.control.invokesGeneralShell, false)
  assert.deepEqual(io.stderr, [])
})

test('Keychain view does not inspect another capability', async () => {
  const io = capture({
    inspectCapabilities: async () => {
      assert.fail('capability observer must not run')
    },
    inspectKeychain: async () => keychainReport(),
  })

  const code = await runCli(['keychain'], io.options)

  assert.equal(code, 0)
  assert.match(
    io.stdout.join(''),
    /no item names, values, private payloads/,
  )
  assert.deepEqual(io.stderr, [])
})

test('one capability explanation is bounded and explicit', async () => {
  const report = capabilityReport()
  const io = capture({
    inspectCapabilities: async () => {
      assert.fail('static explanation must not run the live observer')
    },
    inspectKeychain: async () => {
      assert.fail('Keychain observer must not run')
    },
    explainCapability: async (id) => {
      assert.equal(id, 'accessibility-control')
      return {
        schema:
          'kingdom.macos-agent-capability-explanation/0.1',
        mode: 'observation-only',
        platform: 'darwin',
        actor: report.actor,
        id,
        capability: report.capabilities[id],
        setting: report.settings.accessibility,
        control: report.control,
      }
    },
  })

  const code = await runCli(
    ['explain', 'accessibility-control'],
    io.options,
  )

  assert.equal(code, 0)
  assert.match(io.stdout.join(''), /permission\s+unknown/)
  assert.match(io.stdout.join(''), /Privacy & Security > Accessibility/)
  assert.match(io.stdout.join(''), /no action was tested/)
  assert.deepEqual(io.stderr, [])
})

test('unknown and action-like input fails without reflection or probes', async () => {
  const privateText = 'PRIVATE-secret-capability'
  let calls = 0
  const io = capture({
    inspectCapabilities: async () => {
      calls += 1
      return capabilityReport()
    },
    inspectKeychain: async () => {
      calls += 1
      return keychainReport()
    },
    explainCapability: async () => null,
  })

  const unknown = await runCli(
    ['explain', privateText],
    io.options,
  )
  const policy = await runCli(
    ['policy', privateText],
    io.options,
  )
  const action = await runCli(
    ['capture', privateText],
    io.options,
  )
  const text = `${io.stdout.join('\n')}\n${io.stderr.join('\n')}`

  assert.equal(unknown, 64)
  assert.equal(policy, 64)
  assert.equal(action, 64)
  assert.equal(calls, 0)
  assert.doesNotMatch(text, new RegExp(privateText))
  assert.match(text, /unknown capability/)
  assert.match(text, /unknown command/)
})

test('reports are validated immediately before output and fail closed', async () => {
  const privateText = 'TOP-SECRET-DO-NOT-PRINT'
  const validKeychain = await inspectMacKeychain({
    platform: 'linux',
    home: '/fixture/home',
    uid: 1000,
    runStatus: async () => {
      assert.fail('non-macOS Keychain fixture must not run a probe')
    },
  })
  const validCapabilities = await inspectMacCapabilities({
    platform: 'linux',
    home: '/fixture/home',
    runCommand: async () => {
      assert.fail('non-macOS capability fixture must not run a probe')
    },
  })
  const validExplanation = explainMacCapability(
    'accessibility-control',
    { platform: 'linux' },
  )

  const keychainIo = capture({
    inspectKeychain: async () => ({
      ...validKeychain,
      secret: privateText,
    }),
    validateKeychain: validateMacKeychainReport,
  })
  const keychainCode = await runCli(
    ['keychain', '--json'],
    keychainIo.options,
  )

  const capabilityIo = capture({
    inspectCapabilities: async () => ({
      ...validCapabilities,
      secret: privateText,
    }),
    inspectKeychain: async () => validKeychain,
    checkCapabilities: checkMacCapabilities,
  })
  const capabilityCode = await runCli(
    ['doctor', '--json'],
    capabilityIo.options,
  )

  const encryptionIo = capture({
    inspectCapabilities: async () => ({
      ...validCapabilities,
      secret: privateText,
    }),
    inspectKeychain: async () => validKeychain,
    checkCapabilities: checkMacCapabilities,
    validateKeychain: validateMacKeychainReport,
  })
  const encryptionCode = await runCli(
    ['encryption', '--json'],
    encryptionIo.options,
  )

  const policyIo = capture({
    inspectCapabilities: async () => ({
      ...validCapabilities,
      secret: privateText,
    }),
    inspectKeychain: async () => validKeychain,
    checkCapabilities: checkMacCapabilities,
    validateKeychain: validateMacKeychainReport,
  })
  const policyCode = await runCli(
    ['policy', 'screen-capture', '--json'],
    policyIo.options,
  )

  const explanationIo = capture({
    explainCapability: async () => ({
      ...validExplanation,
      secret: privateText,
    }),
    checkExplanation: checkMacCapabilityExplanation,
  })
  const explanationCode = await runCli(
    ['explain', 'accessibility-control', '--json'],
    explanationIo.options,
  )

  const text = [
    ...keychainIo.stdout,
    ...keychainIo.stderr,
    ...capabilityIo.stdout,
    ...capabilityIo.stderr,
    ...encryptionIo.stdout,
    ...encryptionIo.stderr,
    ...policyIo.stdout,
    ...policyIo.stderr,
    ...explanationIo.stdout,
    ...explanationIo.stderr,
  ].join('\n')
  assert.equal(keychainCode, 1)
  assert.equal(capabilityCode, 1)
  assert.equal(encryptionCode, 1)
  assert.equal(policyCode, 1)
  assert.equal(explanationCode, 1)
  assert.doesNotMatch(text, new RegExp(privateText))
  assert.equal(
    (text.match(/unsafe observation refused/g) ?? []).length,
    5,
  )
})

test('the doctor document has one exact composite schema', async () => {
  const capabilities = await inspectMacCapabilities({
    platform: 'linux',
    home: '/fixture/home',
    runCommand: async () => {
      assert.fail('non-macOS capability fixture must not run a probe')
    },
  })
  const keychain = await inspectMacKeychain({
    platform: 'linux',
    home: '/fixture/home',
    uid: 1000,
    runStatus: async () => {
      assert.fail('non-macOS Keychain fixture must not run a probe')
    },
  })
  const report = composeReport(capabilities, keychain)

  assert.equal(report.schema, COMPOSITE_SCHEMA)
  assert.deepEqual(checkMacReport(report), [])

  const extra = { ...report, private: 'do-not-print' }
  assert.deepEqual(checkMacReport(extra), ['composite-shape-invalid'])

  const mismatch = {
    ...report,
    keychainPosture: {
      ...keychain,
      platform: 'darwin',
    },
  }
  assert.ok(
    checkMacReport(mismatch).includes('keychain-posture-invalid'),
  )
  assert.ok(
    checkMacReport(mismatch).includes('composite-platform-mismatch'),
  )
})

test('hostile prototype serialization is validated before bytes are printed', async () => {
  const privateText = 'TOP-SECRET-PROTOTYPE'
  let serializationHookCalled = false
  const capabilities = await inspectMacCapabilities({
    platform: 'linux',
    home: '/fixture/home',
    runCommand: async () => {
      assert.fail('non-macOS capability fixture must not run a probe')
    },
  })
  const keychain = await inspectMacKeychain({
    platform: 'linux',
    home: '/fixture/home',
    uid: 1000,
    runStatus: async () => {
      assert.fail('non-macOS Keychain fixture must not run a probe')
    },
  })
  const hostile = Object.assign(
    Object.create({
      toJSON() {
        serializationHookCalled = true
        return {
          ...capabilities,
          private: privateText,
        }
      },
    }),
    capabilities,
  )
  const io = capture({
    inspectCapabilities: async () => hostile,
    inspectKeychain: async () => keychain,
    checkCapabilities: checkMacCapabilities,
    validateKeychain: validateMacKeychainReport,
  })

  const code = await runCli(['doctor', '--json'], io.options)
  const text = [...io.stdout, ...io.stderr].join('\n')

  assert.equal(code, 1)
  assert.equal(serializationHookCalled, false)
  assert.deepEqual(io.stdout, [])
  assert.match(text, /unsafe observation refused/)
  assert.doesNotMatch(text, new RegExp(privateText))
})

function awakeReport(overrides = {}) {
  return {
    schema: 'kingdom.macos-awake/0.1',
    request: { pid: 42, seconds: 1 },
    scope: 'host-wide-idle-system-sleep',
    spawn: { attempted: true, observed: true, childPid: 4321 },
    child: { exitObserved: true, code: 0, signal: null },
    stop: { reason: 'deadline', cancellation: null },
    cleanup: { signals: [], exitConfirmed: true },
    targetBinding: 'non-atomic',
    macosAuthorization: 'not-required',
    assertionInstallation: 'not-observed',
    actualWakefulness: 'not-observed',
    ...overrides,
  }
}

const awakeArgs = ['awake', '--pid', '42', '--seconds', '1', '--json']

test('awake requires a canonical PID and finite duration without a utility operand', () => {
  assert.deepEqual(parseArguments(awakeArgs), {
    command: 'awake', pid: 42, seconds: 1, json: true,
  })
  assert.deepEqual(parseArguments(['awake', '--seconds', '3600', '--pid', '2147483647']), {
    command: 'awake', pid: 2147483647, seconds: 3600, json: false,
  })
  for (const args of [
    ['awake'], ['awake', '--pid', '42'], ['awake', '--seconds', '1'],
    [...awakeArgs, '/bin/sleep'], [...awakeArgs, '--'],
    [...awakeArgs, '--pid', '43'], [...awakeArgs, '--json'],
    ['awake', '--pid', '42', '--pid', '42'],
    ['awake', '--pid', '42', '--authorized', 'yes'],
    ['awake', '--pid', '42', '--detach', '1'],
  ]) assert.equal(parseArguments(args), null, JSON.stringify(args))
  for (const pid of ['0', '-1', '+1', '01', '1.5', '1e3', '2147483648', '12345678901', '42\n', String(process.pid)]) {
    assert.equal(parseArguments(['awake', '--pid', pid, '--seconds', '1']), null, pid)
  }
  for (const seconds of ['0', '-1', '01', '3601', 'Infinity', '1.5', '1e3', '1\n']) {
    assert.equal(parseArguments(['awake', '--pid', '42', '--seconds', seconds]), null, seconds)
  }
})

test('awake is dispatched separately with a real cancellation signal and validated output', async () => {
  const signals = new EventEmitter()
  let calls = 0
  const io = capture({
    signalSource: signals,
    inspectCapabilities: () => assert.fail('awake must not inspect capabilities'),
    inspectKeychain: () => assert.fail('awake must not inspect Keychain'),
    runAwake: async (request, { signal }) => {
      calls += 1
      assert.deepEqual(request, { pid: 42, seconds: 1 })
      assert.ok(signal instanceof AbortSignal)
      assert.equal(signal.aborted, false)
      for (const name of ['SIGINT', 'SIGTERM', 'SIGHUP']) assert.equal(signals.listenerCount(name), 1)
      return awakeReport()
    },
  })
  assert.equal(await runCli(awakeArgs, io.options), 0)
  assert.equal(calls, 1)
  assert.deepEqual(JSON.parse(io.stdout.join('')), awakeReport())
  assert.deepEqual(io.stderr, [])
  assert.deepEqual(signals.eventNames(), [])
})

test('malformed awake input never reaches any observer or action', async () => {
  const io = capture({
    runAwake: () => assert.fail('invalid request reached action'),
    inspectCapabilities: () => assert.fail('invalid request reached observer'),
    inspectKeychain: () => assert.fail('invalid request reached Keychain'),
  })
  assert.equal(await runCli([...awakeArgs, 'PRIVATE-command'], io.options), 64)
  assert.deepEqual(io.stdout, [])
  assert.doesNotMatch(io.stderr.join(''), /PRIVATE-command/)
})

test('handled signals cancel only this invocation and retain existing listeners', async () => {
  for (const [name, code] of [['SIGINT', 130], ['SIGTERM', 143], ['SIGHUP', 129]]) {
    const signals = new EventEmitter()
    let existingCalls = 0
    const existing = () => { existingCalls += 1 }
    signals.on(name, existing)
    const io = capture({
      signalSource: signals,
      runAwake: async (_request, { signal }) => {
        signals.emit(name)
        assert.equal(signal.aborted, true)
        assert.equal(signal.reason, name)
        return awakeReport({ stop: { reason: 'cancelled', cancellation: name } })
      },
    })
    assert.equal(await runCli(awakeArgs, io.options), code)
    assert.equal(existingCalls, 1)
    assert.deepEqual(signals.listeners(name), [existing])
    for (const other of ['SIGINT', 'SIGTERM', 'SIGHUP'].filter((value) => value !== name)) {
      assert.equal(signals.listenerCount(other), 0)
    }
  }
})

test('caller cancellation is connected before dispatch', async () => {
  const controller = new AbortController()
  controller.abort('SIGHUP')
  const signals = new EventEmitter()
  const io = capture({
    signal: controller.signal,
    signalSource: signals,
    runAwake: async (_request, { signal }) => {
      assert.equal(signal.aborted, true)
      assert.equal(signal.reason, 'SIGHUP')
      return awakeReport({
        spawn: { attempted: false, observed: false, childPid: null },
        child: { exitObserved: false, code: null, signal: null },
        cleanup: { signals: [], exitConfirmed: false },
        stop: { reason: 'cancelled', cancellation: 'SIGHUP' },
      })
    },
  })
  assert.equal(await runCli(awakeArgs, io.options), 129)
  assert.deepEqual(signals.eventNames(), [])
})

test('awake failures and unsafe reports release handlers without reflecting payloads', async () => {
  const privateText = 'PRIVATE-action-error'
  let serialized = false
  for (const runAwake of [
    async () => { throw new Error(privateText) },
    async () => ({ ...awakeReport(), secret: privateText }),
    async () => Object.assign(Object.create({
      toJSON() { serialized = true; return { secret: privateText } },
    }), awakeReport()),
    async () => null,
  ]) {
    const signals = new EventEmitter()
    const io = capture({ runAwake, signalSource: signals })
    assert.equal(await runCli(awakeArgs, io.options), 1)
    assert.deepEqual(io.stdout, [])
    assert.doesNotMatch(io.stderr.join(''), new RegExp(privateText))
    assert.deepEqual(signals.eventNames(), [])
  }
  assert.equal(serialized, false)
})

test('awake human output describes a request rather than claiming wakefulness', async () => {
  const io = capture({ runAwake: async () => awakeReport(), signalSource: new EventEmitter() })
  assert.equal(await runCli(awakeArgs.filter((arg) => arg !== '--json'), io.options), 0)
  assert.match(io.stderr.join(''), /requesting at most 1s for PID 42; Ctrl-C cancels/)
  assert.match(io.stdout.join(''), /actual wakefulness not observed/)
  assert.match(io.stdout.join(''), /child exit confirmed/)
})
