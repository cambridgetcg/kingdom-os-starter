import assert from 'node:assert/strict'
import test from 'node:test'

import {
  MAC_CAPABILITY_IDS,
  checkMacCapabilityExplanation,
  checkMacCapabilities,
  explainMacCapability,
  inspectMacCapabilities,
  renderMacCapabilities,
  renderMacCapabilityExplanation,
} from '../platform/macos-capabilities.mjs'

const COMMAND_KEYS = [
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
]

function commands(overrides = {}) {
  return {
    ...Object.fromEntries(COMMAND_KEYS.map((key) => [key, null])),
    ...overrides,
  }
}

function allCommands() {
  return commands({
    caffeinate: '/usr/bin/caffeinate',
    fdesetup: '/usr/bin/fdesetup',
    firewall: '/usr/libexec/ApplicationFirewall/socketfilterfw',
    mdfind: '/usr/bin/mdfind',
    open: '/usr/bin/open',
    osascript: '/usr/bin/osascript',
    pbcopy: '/usr/bin/pbcopy',
    pbpaste: '/usr/bin/pbpaste',
    plutil: '/usr/bin/plutil',
    qlmanage: '/usr/bin/qlmanage',
    say: '/usr/bin/say',
    screencapture: '/usr/sbin/screencapture',
    security: '/usr/bin/security',
    shortcuts: '/usr/bin/shortcuts',
    sips: '/usr/bin/sips',
    spctl: '/usr/sbin/spctl',
    textutil: '/usr/bin/textutil',
  })
}

function safetyRunner(calls = []) {
  return async (command, args, options) => {
    calls.push({ command, args, options })
    if (command === '/usr/bin/fdesetup') return 'FileVault is Off.\n'
    if (command.endsWith('/socketfilterfw')) {
      return 'Firewall is disabled. (State = 0)\n'
    }
    if (command === '/usr/sbin/spctl') return 'assessments enabled\n'
    return null
  }
}

test('fixed native tools report presence without claiming permission', async () => {
  const report = await inspectMacCapabilities({
    platform: 'darwin',
    home: '/trusted/home',
    commands: allCommands(),
    runCommand: safetyRunner(),
  })

  assert.equal(report.schema, 'kingdom.macos-agent-capabilities/0.1')
  assert.equal(report.mode, 'observation-only')
  assert.equal(report.platform, 'darwin')
  assert.equal(
    report.capabilities['keychain-reference'].toolState,
    'adapter-required',
  )
  assert.equal(
    report.capabilities['keychain-reference'].evidence,
    'fixed-command-present-adapter-required',
  )
  assert.equal(report.capabilities['shortcuts-run'].toolState, 'available')
  assert.equal(
    report.capabilities['notifications-send'].toolState,
    'adapter-required',
  )
  assert.equal(report.capabilities['documents-transform'].toolState, 'available')
  assert.equal(
    report.capabilities['documents-transform'].authorization,
    'per-target-at-use',
  )
  assert.equal(
    report.capabilities['accessibility-control'].toolState,
    'adapter-required',
  )
  assert.ok(
    Object.values(report.capabilities).every(
      (capability) => capability.actionEvidence === 'not-tested',
    ),
  )
  assert.equal(report.control.readsCoarseSystemMetadata, true)
  assert.equal(report.control.readsPrivateContent, false)
  assert.equal(report.control.returnsPrivateContent, false)
  assert.deepEqual(checkMacCapabilities(report, {
    home: '/trusted/home',
  }), [])
})

test('privacy-controlled capabilities remain unknown for an unresolved actor', async () => {
  const report = await inspectMacCapabilities({
    platform: 'darwin',
    home: '/trusted/home',
    commands: allCommands(),
    runCommand: safetyRunner(),
  })
  const ids = [
    'notifications-send',
    'automation-control',
    'accessibility-control',
    'screen-capture',
    'input-monitor',
    'full-disk-read',
    'microphone-capture',
    'camera-capture',
    'local-network',
  ]

  assert.deepEqual(report.actor, {
    identityState: 'unresolved',
    scope: 'responsible-process-specific',
  })
  for (const id of ids) {
    assert.equal(report.capabilities[id].authorization, 'unknown')
  }
})

test('safety metadata uses only fixed bounded commands and a narrow environment', async () => {
  const calls = []
  const report = await inspectMacCapabilities({
    platform: 'darwin',
    home: '/trusted/home',
    commands: allCommands(),
    detachedCommands: false,
    environment: {
      HOME: '/hostile/home',
      PATH: '/hostile/bin',
      NODE_OPTIONS: '--import=/hostile/inject.mjs',
      KINGDOM_MAC_FIXTURE: '/hostile/fixture',
    },
    runCommand: safetyRunner(calls),
  })

  assert.deepEqual(report.safety, {
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
  })
  assert.deepEqual(
    calls.map(({ command, args }) => [command, args]),
    [
      ['/usr/bin/fdesetup', ['status']],
      [
        '/usr/libexec/ApplicationFirewall/socketfilterfw',
        ['--getglobalstate'],
      ],
      ['/usr/sbin/spctl', ['--status']],
    ],
  )
  for (const call of calls) {
    assert.equal(call.options.detached, false)
    assert.equal(call.options.home, '/trusted/home')
    assert.equal(call.options.maxBytes, 4 * 1024)
    assert.equal(call.options.timeoutMs, 3_000)
    assert.equal(call.options.env.HOME, '/trusted/home')
    assert.equal(call.options.env.PATH, '/usr/bin:/bin:/usr/sbin:/sbin')
    assert.equal(call.options.env.LANG, 'C')
    assert.equal(call.options.env.LC_ALL, 'C')
    assert.equal(call.options.env.NODE_OPTIONS, undefined)
    assert.equal(call.options.env.KINGDOM_MAC_FIXTURE, undefined)
  }
})

test('missing and malformed safety observations become unknown without raw output', async () => {
  const privateOutput =
    'PRIVATE /Users/someone keychain-item clipboard window process'
  const report = await inspectMacCapabilities({
    platform: 'darwin',
    home: '/trusted/home',
    commands: allCommands(),
    runCommand: async (command) => {
      if (command === '/usr/bin/fdesetup') return null
      if (command.endsWith('/socketfilterfw')) return privateOutput
      return 'unexpected assessments format'
    },
  })
  const text = JSON.stringify(report)

  assert.equal(report.safety.fileVault.state, 'unknown')
  assert.equal(report.safety.firewall.state, 'unknown')
  assert.equal(report.safety.gatekeeper.state, 'unknown')
  assert.doesNotMatch(text, /PRIVATE|Users|somebody|keychain-item|clipboard window/)
  assert.deepEqual(checkMacCapabilities(report, {
    home: '/trusted/home',
  }), [])
})

test('firewall parsing accepts only complete consistent native forms', async () => {
  const cases = [
    ['Firewall is disabled. (State = 0)\n', 'off'],
    ['Firewall is enabled. (State = 1)\n', 'on'],
    ['Firewall is enabled. (State = 2)\n', 'on'],
    ['Firewall is enabled. (State = 0)\n', 'unknown'],
    ['Firewall is disabled. (State = 1)\n', 'unknown'],
    ['prefix Firewall is disabled. (State = 0)\n', 'unknown'],
    ['Firewall is disabled. (State = 0) suffix\n', 'unknown'],
  ]

  for (const [firewallOutput, expected] of cases) {
    const report = await inspectMacCapabilities({
      platform: 'darwin',
      home: '/trusted/home',
      commands: allCommands(),
      runCommand: async (command) => {
        if (command === '/usr/bin/fdesetup') return 'FileVault is Off.\n'
        if (command.endsWith('/socketfilterfw')) return firewallOutput
        return 'assessments enabled\n'
      },
    })
    assert.equal(report.safety.firewall.state, expected)
    assert.deepEqual(checkMacCapabilities(report), [])
  }
})

test('missing safety tools are unknown and are never invoked', async () => {
  let calls = 0
  const report = await inspectMacCapabilities({
    platform: 'darwin',
    home: '/trusted/home',
    commands: commands(),
    runCommand: async () => {
      calls += 1
      return ''
    },
  })

  assert.equal(calls, 0)
  assert.equal(report.safety.fileVault.state, 'unknown')
  assert.equal(report.safety.firewall.state, 'unknown')
  assert.equal(report.safety.gatekeeper.state, 'unknown')
  assert.equal(
    report.capabilities['keychain-reference'].toolState,
    'adapter-required',
  )
  assert.equal(
    report.capabilities['keychain-reference'].evidence,
    'fixed-command-unavailable-adapter-required',
  )
})

test('non-Darwin hosts perform no command and make no macOS claim', async () => {
  let called = false
  const report = await inspectMacCapabilities({
    platform: 'linux',
    commands: allCommands(),
    runCommand: async () => {
      called = true
      return ''
    },
  })

  assert.equal(called, false)
  assert.equal(report.platform, 'other')
  assert.ok(
    Object.values(report.capabilities).every(
      (capability) => capability.toolState === 'not-applicable',
    ),
  )
  assert.ok(
    Object.values(report.safety).every(
      (setting) => setting.state === 'not-applicable',
    ),
  )
})

test('the public catalog is complete, static, and contains no private material', async () => {
  const report = await inspectMacCapabilities({
    platform: 'darwin',
    home: '/Users/private-account',
    commands: allCommands(),
    runCommand: safetyRunner(),
  })
  const text = JSON.stringify(report)

  assert.equal(new Set(MAC_CAPABILITY_IDS).size, MAC_CAPABILITY_IDS.length)
  assert.deepEqual(
    Object.keys(report.capabilities),
    [...MAC_CAPABILITY_IDS],
  )
  assert.doesNotMatch(text, /private-account|\/Users\/|commandPath|stdout|stderr/)
  assert.doesNotMatch(
    text,
    /shortcutNames|clipboardContent|keychainItemNames|secretValue|windowNames/,
  )
  assert.deepEqual(checkMacCapabilities(report, {
    home: '/Users/private-account',
  }), [])
})

test('one-capability explanation is static and unknown IDs are not reflected', () => {
  let called = false
  const options = {
    platform: 'darwin',
    runCommand: async () => {
      called = true
      return 'PRIVATE COMMAND OUTPUT'
    },
  }
  const explanation = explainMacCapability(
    'accessibility-control',
    options,
  )
  const commandBacked = explainMacCapability('apps-open', options)
  const unknown = explainMacCapability(
    'PRIVATE /Users/person --grant',
    options,
  )

  assert.equal(called, false)
  assert.equal(
    explanation.schema,
    'kingdom.macos-agent-capability-explanation/0.1',
  )
  assert.equal(explanation.id, 'accessibility-control')
  assert.equal(explanation.capability.authorization, 'unknown')
  assert.equal(
    explanation.setting.location,
    'Privacy & Security > Accessibility',
  )
  assert.equal(commandBacked.capability.toolState, 'unknown')
  assert.equal(commandBacked.capability.evidence, 'static-public-catalog')
  assert.deepEqual(checkMacCapabilityExplanation(explanation), [])
  assert.deepEqual(checkMacCapabilityExplanation(commandBacked), [])
  assert.equal(unknown, null)
  assert.doesNotMatch(JSON.stringify(explanation), /PRIVATE|Users|--grant/)
})

test('public-safety checks reject recursive extras, private strings, and contradictions', async () => {
  const report = await inspectMacCapabilities({
    platform: 'darwin',
    home: '/trusted/home',
    commands: allCommands(),
    runCommand: safetyRunner(),
  })
  const hostile = structuredClone(report)
  hostile.capabilities['screen-capture'].privatePayload =
    '/Users/private/window-content'
  hostile.settings.accessibility.privatePayload = 'PRIVATE APP NAME'
  hostile.safety.firewall.privatePayload = 'PRIVATE PROCESS'
  hostile.control.extraPermission = false

  const hostileIssues = checkMacCapabilities(hostile, {
    home: '/Users/private',
  })
  assert.ok(hostileIssues.includes('capability-shape-invalid'))
  assert.ok(hostileIssues.includes('setting-shape-invalid'))
  assert.ok(hostileIssues.includes('safety-observation-invalid'))
  assert.ok(hostileIssues.includes('control-contract-invalid'))
  assert.ok(hostileIssues.includes('public-string-allowlist-failed'))
  assert.ok(hostileIssues.includes('account-home-leak'))

  const contradiction = structuredClone(report)
  contradiction.settings.firewall.state = 'on'
  assert.ok(
    checkMacCapabilities(contradiction)
      .includes('safety-mirror-mismatch'),
  )

  const claimed = structuredClone(report)
  claimed.capabilities['screen-capture'].authorization = 'authorized'
  claimed.capabilities['apps-open'].actionEvidence = 'succeeded'
  assert.ok(
    checkMacCapabilities(claimed)
      .includes('capability-static-mismatch'),
  )
})

test('explanation validator rejects extras and static contradictions', () => {
  const explanation = explainMacCapability(
    'notifications-send',
    { platform: 'darwin' },
  )
  assert.equal(explanation.capability.toolState, 'adapter-required')
  assert.deepEqual(checkMacCapabilityExplanation(explanation), [])

  const hostile = structuredClone(explanation)
  hostile.capability.rawSender = '/Users/private/Notifier.app'
  hostile.control.extraPermission = false
  assert.ok(
    checkMacCapabilityExplanation(hostile)
      .includes('capability-shape-invalid'),
  )
  assert.ok(
    checkMacCapabilityExplanation(hostile)
      .includes('control-contract-invalid'),
  )
  assert.ok(
    checkMacCapabilityExplanation(hostile)
      .includes('public-string-allowlist-failed'),
  )

  const contradiction = structuredClone(explanation)
  contradiction.setting.location = 'Privacy & Security > Camera'
  assert.ok(
    checkMacCapabilityExplanation(contradiction)
      .includes('setting-static-mismatch'),
  )
})

test('report validator rejects prototype and hidden-key serialization attacks', async () => {
  const report = await inspectMacCapabilities({
    platform: 'darwin',
    home: '/trusted/home',
    commands: allCommands(),
    runCommand: safetyRunner(),
  })
  let reflected = false

  const hostilePrototype = Object.assign(
    Object.create({ inheritedPrivateValue: '/Users/private/prototype' }),
    report,
  )
  assert.deepEqual(
    checkMacCapabilities(hostilePrototype),
    ['invalid-report'],
  )

  const inheritedToJSON = Object.assign(
    Object.create({
      toJSON() {
        reflected = true
        return { privateValue: '/Users/private/reflected' }
      },
    }),
    report,
  )
  assert.deepEqual(
    checkMacCapabilities(inheritedToJSON),
    ['invalid-report'],
  )

  const ownHidden = structuredClone(report)
  Object.defineProperty(ownHidden, 'toJSON', {
    enumerable: false,
    value() {
      reflected = true
      return { privateValue: '/Users/private/reflected' }
    },
  })
  assert.deepEqual(
    checkMacCapabilities(ownHidden),
    ['report-shape-invalid'],
  )

  const ownSymbol = structuredClone(report)
  ownSymbol[Symbol('private')] = '/Users/private/symbol'
  assert.deepEqual(
    checkMacCapabilities(ownSymbol),
    ['report-shape-invalid'],
  )

  const nestedHiddenAndSymbol = structuredClone(report)
  Object.defineProperty(
    nestedHiddenAndSymbol.capabilities['apps-open'],
    'privateValue',
    {
      enumerable: false,
      value: '/Users/private/hidden',
    },
  )
  nestedHiddenAndSymbol.settings.accessibility[
    Symbol('private')
  ] = '/Users/private/symbol'
  const nestedIssues = checkMacCapabilities(nestedHiddenAndSymbol)
  assert.ok(nestedIssues.includes('capability-shape-invalid'))
  assert.ok(nestedIssues.includes('setting-shape-invalid'))
  assert.ok(nestedIssues.includes('public-string-allowlist-failed'))

  assert.equal(reflected, false)
  assert.doesNotMatch(
    [
      ...checkMacCapabilities(hostilePrototype),
      ...checkMacCapabilities(inheritedToJSON),
      ...checkMacCapabilities(ownHidden),
      ...checkMacCapabilities(ownSymbol),
      ...nestedIssues,
    ].join(' '),
    /Users|private|prototype|reflected|symbol|hidden/,
  )
})

test('explanation validator rejects prototype and hidden-key serialization attacks', () => {
  const explanation = explainMacCapability(
    'screen-capture',
    { platform: 'darwin' },
  )
  let reflected = false

  const hostilePrototype = Object.assign(
    Object.create({ inheritedPrivateValue: '/Users/private/prototype' }),
    explanation,
  )
  assert.deepEqual(
    checkMacCapabilityExplanation(hostilePrototype),
    ['invalid-explanation'],
  )

  const inheritedToJSON = Object.assign(
    Object.create({
      toJSON() {
        reflected = true
        return { privateValue: '/Users/private/reflected' }
      },
    }),
    explanation,
  )
  assert.deepEqual(
    checkMacCapabilityExplanation(inheritedToJSON),
    ['invalid-explanation'],
  )

  const ownHidden = structuredClone(explanation)
  Object.defineProperty(ownHidden, 'toJSON', {
    enumerable: false,
    value() {
      reflected = true
      return { privateValue: '/Users/private/reflected' }
    },
  })
  assert.deepEqual(
    checkMacCapabilityExplanation(ownHidden),
    ['explanation-shape-invalid'],
  )

  const ownSymbol = structuredClone(explanation)
  ownSymbol[Symbol('private')] = '/Users/private/symbol'
  assert.deepEqual(
    checkMacCapabilityExplanation(ownSymbol),
    ['explanation-shape-invalid'],
  )

  const nestedHiddenAndSymbol = structuredClone(explanation)
  Object.defineProperty(
    nestedHiddenAndSymbol.capability,
    'privateValue',
    {
      enumerable: false,
      value: '/Users/private/hidden',
    },
  )
  nestedHiddenAndSymbol.setting[
    Symbol('private')
  ] = '/Users/private/symbol'
  const nestedIssues = checkMacCapabilityExplanation(
    nestedHiddenAndSymbol,
  )
  assert.ok(nestedIssues.includes('capability-shape-invalid'))
  assert.ok(nestedIssues.includes('setting-shape-invalid'))
  assert.ok(nestedIssues.includes('public-string-allowlist-failed'))

  assert.equal(reflected, false)
  assert.doesNotMatch(
    [
      ...checkMacCapabilityExplanation(hostilePrototype),
      ...checkMacCapabilityExplanation(inheritedToJSON),
      ...checkMacCapabilityExplanation(ownHidden),
      ...checkMacCapabilityExplanation(ownSymbol),
      ...nestedIssues,
    ].join(' '),
    /Users|private|prototype|reflected|symbol|hidden/,
  )
})

test('human rendering states limits and contains no command output', async () => {
  const report = await inspectMacCapabilities({
    platform: 'darwin',
    home: '/trusted/home',
    commands: allCommands(),
    runCommand: safetyRunner(),
  })
  const summary = renderMacCapabilities(report)
  const explanation = renderMacCapabilityExplanation(
    await explainMacCapability('keychain-reference', { report }),
  )

  assert.match(summary, /observation only/)
  assert.match(summary, /permissions remain actor-specific/)
  assert.match(summary, /bounded coarse metadata only/)
  assert.match(summary, /no private payloads, prompts, actions, writes/)
  assert.match(explanation, /per-item-at-use/)
  assert.match(explanation, /no action was tested/)
  assert.doesNotMatch(`${summary}\n${explanation}`, /\/usr\/|trusted\/home/)
})
