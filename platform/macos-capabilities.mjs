import {
  accessSync,
  constants,
  statSync,
} from 'node:fs'
import { trustedAccount } from './account.mjs'

import {
  boundedCommand,
  narrowEnvironment,
} from './command.mjs'

const SCHEMA = 'kingdom.macos-agent-capabilities/0.1'
const EXPLANATION_SCHEMA =
  'kingdom.macos-agent-capability-explanation/0.1'
const METADATA_TIMEOUT_MS = 3_000
const METADATA_MAX_BYTES = 4 * 1024
const MEANING =
  'Tool presence, permission, successful action, and authority are separate facts; this report performs no action.'

const FIXED_COMMAND_PATHS = Object.freeze({
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

const SETTINGS_CATALOG = Object.freeze({
  accessibility: {
    location: 'Privacy & Security > Accessibility',
  },
  automation: {
    location: 'Privacy & Security > Automation',
  },
  camera: {
    location: 'Privacy & Security > Camera',
  },
  'effect-only': {
    location: 'The explicit action is the consent boundary',
  },
  'file-authority': {
    location:
      'Task-declared roots; Privacy & Security > Files & Folders where applicable',
  },
  'full-disk-access': {
    location: 'Privacy & Security > Full Disk Access',
  },
  'input-monitoring': {
    location: 'Privacy & Security > Input Monitoring',
  },
  keychain: {
    location: 'Keychain Access or Passwords; access is per item',
  },
  'local-network': {
    location: 'Privacy & Security > Local Network',
  },
  microphone: {
    location: 'Privacy & Security > Microphone',
  },
  notifications: {
    location: 'Notifications > sender',
  },
  power: {
    location: 'Energy or Lock Screen',
  },
  'screen-recording': {
    location: 'Privacy & Security > Screen & System Audio Recording',
  },
  shortcuts: {
    location: 'Shortcuts; each action may have its own consent surface',
  },
})

const CAPABILITY_CATALOG = Object.freeze({
  'keychain-reference': {
    title: 'Keychain reference',
    summary:
      'Refer to one declared Keychain capability without returning its value.',
    nativeEdge: 'macOS Keychain',
    toolKeys: ['security'],
    requiresAdapter: true,
    authorization: 'per-item-at-use',
    agentDefault: 'deny-private-read-until-task',
    risk: 'high',
    settingId: 'keychain',
  },
  'shortcuts-run': {
    title: 'Run a Shortcut',
    summary:
      'Run one named, user-curated Shortcut only after its effect is chosen.',
    nativeEdge: 'Shortcuts',
    toolKeys: ['shortcuts'],
    authorization: 'per-shortcut-at-use',
    agentDefault: 'ask-before-effect',
    risk: 'high',
    settingId: 'shortcuts',
  },
  'notifications-send': {
    title: 'Send a notification',
    summary:
      'Offer a visible message through a stable sender; delivery is not proof it was seen.',
    nativeEdge: 'Notification Center',
    toolKeys: ['osascript'],
    requiresAdapter: true,
    authorization: 'unknown',
    agentDefault: 'ask-before-effect',
    risk: 'medium',
    settingId: 'notifications',
  },
  'speech-speak': {
    title: 'Speak text',
    summary: 'Produce local audible speech as an explicit effect.',
    nativeEdge: 'macOS speech synthesis',
    toolKeys: ['say'],
    authorization: 'not-required',
    agentDefault: 'ask-before-effect',
    risk: 'medium',
    settingId: 'effect-only',
  },
  'apps-open': {
    title: 'Open an app, file, or URL',
    summary: 'Hand one declared target to LaunchServices.',
    nativeEdge: 'LaunchServices',
    toolKeys: ['open'],
    authorization: 'not-required',
    agentDefault: 'ask-before-effect',
    risk: 'medium',
    settingId: 'effect-only',
  },
  'clipboard-read': {
    title: 'Read the clipboard',
    summary:
      'Read transient user content only when the current task names that need.',
    nativeEdge: 'macOS pasteboard',
    toolKeys: ['pbpaste'],
    authorization: 'not-required',
    agentDefault: 'deny-private-read-until-task',
    risk: 'high',
    settingId: 'effect-only',
  },
  'clipboard-write': {
    title: 'Write the clipboard',
    summary: 'Replace transient user state only as an explicit effect.',
    nativeEdge: 'macOS pasteboard',
    toolKeys: ['pbcopy'],
    authorization: 'not-required',
    agentDefault: 'ask-before-effect',
    risk: 'medium',
    settingId: 'effect-only',
  },
  'files-search-metadata': {
    title: 'Search file metadata',
    summary:
      'Search only declared roots because names and paths can be private.',
    nativeEdge: 'Spotlight metadata',
    toolKeys: ['mdfind'],
    authorization: 'unknown',
    agentDefault: 'deny-private-read-until-task',
    risk: 'high',
    settingId: 'file-authority',
  },
  'documents-transform': {
    title: 'Transform documents',
    summary:
      'Use native text, image, property-list, and preview tools only inside declared roots.',
    nativeEdge: 'native document tools',
    toolKeys: ['textutil', 'sips', 'plutil', 'qlmanage'],
    authorization: 'per-target-at-use',
    agentDefault: 'allow-scoped',
    risk: 'medium',
    settingId: 'file-authority',
  },
  'power-hold-awake': {
    title: 'Hold the Mac awake',
    summary:
      'Request a host-wide idle-system-sleep assertion with mac awake for an existing same-user PID and explicit 1..3600 seconds; may consume battery, changes no permanent settings, and requires no new privacy grant.',
    nativeEdge: 'power assertion',
    toolKeys: ['caffeinate'],
    authorization: 'not-required',
    agentDefault: 'ask-before-effect',
    risk: 'medium',
    settingId: 'power',
  },
  'automation-control': {
    title: 'Control another app',
    summary:
      'Apple Events permission belongs to the exact actor-target pair.',
    nativeEdge: 'Apple Events',
    toolKeys: ['osascript'],
    authorization: 'unknown',
    agentDefault: 'deny-until-explicit-grant',
    risk: 'high',
    settingId: 'automation',
  },
  'accessibility-control': {
    title: 'Control the user interface',
    summary:
      'Accessibility permission belongs to one stable responsible process.',
    nativeEdge: 'Accessibility APIs',
    toolKeys: [],
    authorization: 'unknown',
    agentDefault: 'deny-until-explicit-grant',
    risk: 'high',
    settingId: 'accessibility',
  },
  'screen-capture': {
    title: 'Capture the screen',
    summary:
      'Capture private visual content only for an explicitly scoped task.',
    nativeEdge: 'screen capture',
    toolKeys: ['screencapture'],
    authorization: 'unknown',
    agentDefault: 'deny-until-explicit-grant',
    risk: 'high',
    settingId: 'screen-recording',
  },
  'input-monitor': {
    title: 'Monitor input',
    summary:
      'Global keyboard and pointer observation is outside the first bridge.',
    nativeEdge: 'input event APIs',
    toolKeys: [],
    authorization: 'unknown',
    agentDefault: 'deny-until-explicit-grant',
    risk: 'critical',
    settingId: 'input-monitoring',
  },
  'full-disk-read': {
    title: 'Read protected app data',
    summary: 'Full Disk Access is outside the first bridge.',
    nativeEdge: 'protected file access',
    toolKeys: [],
    authorization: 'unknown',
    agentDefault: 'deny-until-explicit-grant',
    risk: 'critical',
    settingId: 'full-disk-access',
  },
  'microphone-capture': {
    title: 'Capture microphone audio',
    summary: 'Ambient audio capture requires a separate current choice.',
    nativeEdge: 'AVFoundation audio capture',
    toolKeys: [],
    authorization: 'unknown',
    agentDefault: 'deny-until-explicit-grant',
    risk: 'critical',
    settingId: 'microphone',
  },
  'camera-capture': {
    title: 'Capture camera video',
    summary: 'Ambient video capture requires a separate current choice.',
    nativeEdge: 'AVFoundation video capture',
    toolKeys: [],
    authorization: 'unknown',
    agentDefault: 'deny-until-explicit-grant',
    risk: 'critical',
    settingId: 'camera',
  },
  'local-network': {
    title: 'Use the local network',
    summary:
      'Local discovery or listeners require a stable actor and separate scope.',
    nativeEdge: 'local-network APIs',
    toolKeys: [],
    authorization: 'unknown',
    agentDefault: 'deny-until-explicit-grant',
    risk: 'critical',
    settingId: 'local-network',
  },
})

const MAC_CAPABILITY_IDS = Object.freeze(Object.keys(CAPABILITY_CATALOG))

const CONTROL = Object.freeze({
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
})

const EXPLANATION_CONTROL = Object.freeze({
  ...CONTROL,
  readsCoarseSystemMetadata: false,
})

const REPORT_KEYS = Object.freeze([
  'schema',
  'mode',
  'platform',
  'actor',
  'capabilities',
  'settings',
  'safety',
  'control',
  'meaning',
])
const ACTOR_KEYS = Object.freeze(['identityState', 'scope'])
const CAPABILITY_KEYS = Object.freeze([
  'title',
  'summary',
  'nativeEdge',
  'authorization',
  'agentDefault',
  'risk',
  'settingId',
  'toolState',
  'actionEvidence',
  'evidence',
])
const SETTING_KEYS = Object.freeze(['location', 'state', 'evidence'])
const SAFETY_KEYS = Object.freeze(['fileVault', 'firewall', 'gatekeeper'])
const SAFETY_SETTING_IDS = Object.freeze({
  fileVault: 'file-vault',
  firewall: 'firewall',
  gatekeeper: 'gatekeeper',
})
const SAFETY_LOCATIONS = Object.freeze({
  fileVault: 'Privacy & Security > FileVault',
  firewall: 'Network > Firewall',
  gatekeeper: 'Privacy & Security > Allow applications from',
})
const EXPLANATION_KEYS = Object.freeze([
  'schema',
  'mode',
  'platform',
  'actor',
  'id',
  'capability',
  'setting',
  'control',
])

const PUBLIC_STRING_ALLOWLIST = (() => {
  const strings = new Set([
    SCHEMA,
    EXPLANATION_SCHEMA,
    MEANING,
    'observation-only',
    'darwin',
    'other',
    'unresolved',
    'responsible-process-specific',
    'available',
    'unavailable',
    'adapter-required',
    'unknown',
    'not-applicable',
    'not-tested',
    'not-observed',
    'on',
    'off',
    'fixed-command-presence',
    'fixed-command-unavailable',
    'fixed-command-present-adapter-required',
    'fixed-command-unavailable-adapter-required',
    'fixed-command-unavailable',
    'static-public-catalog',
    'platform-not-applicable',
    'bounded-system-metadata',
    'bounded-metadata-unavailable',
    'fixed-command-unavailable',
  ])
  for (const id of MAC_CAPABILITY_IDS) strings.add(id)
  for (const definition of Object.values(CAPABILITY_CATALOG)) {
    for (const value of Object.values(definition)) {
      if (typeof value === 'string') strings.add(value)
    }
  }
  for (const setting of Object.values(SETTINGS_CATALOG)) {
    strings.add(setting.location)
  }
  for (const location of Object.values(SAFETY_LOCATIONS)) {
    strings.add(location)
  }
  return strings
})()

function executable(path) {
  try {
    accessSync(path, constants.X_OK)
    return statSync(path).isFile()
  } catch {
    return false
  }
}

function resolveCommands(platform, overrides = {}) {
  const commands = {}
  for (const [key, path] of Object.entries(FIXED_COMMAND_PATHS)) {
    commands[key] = platform === 'darwin' && executable(path)
      ? path
      : null
  }
  for (const key of Object.keys(FIXED_COMMAND_PATHS)) {
    if (!Object.hasOwn(overrides, key)) continue
    const value = overrides[key]
    commands[key] =
      typeof value === 'string' && value.startsWith('/')
        ? value
        : null
  }
  return commands
}

function parseFileVault(output) {
  if (typeof output !== 'string') return 'unknown'
  const value = output.trim().toLowerCase()
  if (/^filevault is on\.?$/.test(value)) return 'on'
  if (/^filevault is off\.?$/.test(value)) return 'off'
  return 'unknown'
}

function parseFirewall(output) {
  if (typeof output !== 'string') return 'unknown'
  const value = output.trim()
  if (/^Firewall is disabled\. \(State = 0\)$/.test(value)) return 'off'
  if (/^Firewall is enabled\. \(State = [12]\)$/.test(value)) return 'on'
  return 'unknown'
}

function parseGatekeeper(output) {
  if (typeof output !== 'string') return 'unknown'
  const value = output.trim().toLowerCase()
  if (/^assessments enabled\.?$/.test(value)) return 'on'
  if (/^assessments disabled\.?$/.test(value)) return 'off'
  return 'unknown'
}

async function observeSafety({
  commands,
  detached,
  home,
  platform,
  runCommand,
}) {
  if (platform !== 'darwin') {
    return {
      fileVault: {
        state: 'not-applicable',
        evidence: 'platform-not-applicable',
      },
      firewall: {
        state: 'not-applicable',
        evidence: 'platform-not-applicable',
      },
      gatekeeper: {
        state: 'not-applicable',
        evidence: 'platform-not-applicable',
      },
    }
  }

  const specs = {
    fileVault: {
      command: commands.fdesetup,
      args: ['status'],
      parse: parseFileVault,
    },
    firewall: {
      command: commands.firewall,
      args: ['--getglobalstate'],
      parse: parseFirewall,
    },
    gatekeeper: {
      command: commands.spctl,
      args: ['--status'],
      parse: parseGatekeeper,
    },
  }
  const environment = narrowEnvironment({}, home)
  const entries = await Promise.all(
    Object.entries(specs).map(async ([id, spec]) => {
      if (!spec.command) {
        return [id, {
          state: 'unknown',
          evidence: 'fixed-command-unavailable',
        }]
      }
      const output = await runCommand(spec.command, spec.args, {
        detached,
        env: environment,
        home,
        maxBytes: METADATA_MAX_BYTES,
        timeoutMs: METADATA_TIMEOUT_MS,
      })
      const state = spec.parse(output)
      return [id, {
        state,
        evidence: state === 'unknown'
          ? 'bounded-metadata-unavailable'
          : 'bounded-system-metadata',
      }]
    }),
  )
  return Object.fromEntries(entries)
}

function capabilityReport(platform, commands) {
  return Object.fromEntries(
    Object.entries(CAPABILITY_CATALOG).map(([id, definition]) => {
      let toolState
      const rawEdgeAvailable =
        definition.toolKeys.length > 0
        && definition.toolKeys.every((key) => commands[key])
      if (platform !== 'darwin') {
        toolState = 'not-applicable'
      } else if (
        definition.requiresAdapter
        || definition.toolKeys.length === 0
      ) {
        toolState = 'adapter-required'
      } else {
        toolState = rawEdgeAvailable
          ? 'available'
          : 'unavailable'
      }
      const {
        requiresAdapter: _requiresAdapter,
        toolKeys: _toolKeys,
        ...publicDefinition
      } = definition
      let evidence
      if (platform !== 'darwin') {
        evidence = 'platform-not-applicable'
      } else if (definition.requiresAdapter) {
        evidence = rawEdgeAvailable
          ? 'fixed-command-present-adapter-required'
          : 'fixed-command-unavailable-adapter-required'
      } else if (definition.toolKeys.length === 0) {
        evidence = 'static-public-catalog'
      } else {
        evidence = rawEdgeAvailable
          ? 'fixed-command-presence'
          : 'fixed-command-unavailable'
      }
      return [id, {
        ...publicDefinition,
        toolState,
        actionEvidence: 'not-tested',
        evidence,
      }]
    }),
  )
}

function settingsReport(safety) {
  const settings = Object.fromEntries(
    Object.entries(SETTINGS_CATALOG).map(([id, setting]) => [
      id,
      {
        ...setting,
        state: 'not-observed',
        evidence: 'static-public-catalog',
      },
    ]),
  )
  settings['file-vault'] = {
    location: SAFETY_LOCATIONS.fileVault,
    ...safety.fileVault,
  }
  settings.firewall = {
    location: SAFETY_LOCATIONS.firewall,
    ...safety.firewall,
  }
  settings.gatekeeper = {
    location: SAFETY_LOCATIONS.gatekeeper,
    ...safety.gatekeeper,
  }
  return settings
}

async function inspectMacCapabilities(options = {}) {
  const platform = options.platform ?? process.platform
  const publicPlatform = platform === 'darwin' ? 'darwin' : 'other'
  const home = platform === 'darwin'
    ? options.home ?? trustedAccount().home
    : '/'
  const commands = resolveCommands(platform, options.commands)
  const safety = await observeSafety({
    commands,
    detached: options.detachedCommands ?? true,
    home,
    platform,
    runCommand: options.runCommand ?? boundedCommand,
  })

  return {
    schema: SCHEMA,
    mode: 'observation-only',
    platform: publicPlatform,
    actor: {
      identityState: 'unresolved',
      scope: 'responsible-process-specific',
    },
    capabilities: capabilityReport(platform, commands),
    settings: settingsReport(safety),
    safety,
    control: { ...CONTROL },
    meaning: MEANING,
  }
}

function explainMacCapability(id, options = {}) {
  if (
    typeof id !== 'string'
    || !Object.hasOwn(CAPABILITY_CATALOG, id)
  ) {
    return null
  }
  const platform = (options.platform ?? process.platform) === 'darwin'
    ? 'darwin'
    : 'other'
  const definition = CAPABILITY_CATALOG[id]
  const {
    requiresAdapter: _requiresAdapter,
    toolKeys: _toolKeys,
    ...publicDefinition
  } = definition
  const toolState = platform !== 'darwin'
    ? 'not-applicable'
    : definition.requiresAdapter || definition.toolKeys.length === 0
      ? 'adapter-required'
      : 'unknown'
  const capability = {
    ...publicDefinition,
    toolState,
    actionEvidence: 'not-tested',
    evidence: platform === 'darwin'
      ? 'static-public-catalog'
      : 'platform-not-applicable',
  }
  const setting = SETTINGS_CATALOG[definition.settingId]
  return {
    schema: EXPLANATION_SCHEMA,
    mode: 'observation-only',
    platform,
    actor: {
      identityState: 'unresolved',
      scope: 'responsible-process-specific',
    },
    id,
    capability,
    setting: {
      ...setting,
      state: 'not-observed',
      evidence: 'static-public-catalog',
    },
    control: { ...EXPLANATION_CONTROL },
  }
}

function record(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false
  }
  try {
    const prototype = Object.getPrototypeOf(value)
    return prototype === Object.prototype || prototype === null
  } catch {
    return false
  }
}

function exactKeys(value, expected) {
  if (!record(value)) return false
  try {
    const actual = Reflect.ownKeys(value)
    if (
      actual.length !== expected.length
      || actual.some((key) => typeof key !== 'string')
      || !expected.every((key) => actual.includes(key))
    ) {
      return false
    }
    return actual.every((key) => {
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

function publicDefinition(definition) {
  const {
    requiresAdapter: _requiresAdapter,
    toolKeys: _toolKeys,
    ...result
  } = definition
  return result
}

function staticFieldsMatch(capability, definition) {
  const expected = publicDefinition(definition)
  return Object.entries(expected).every(
    ([key, value]) => capability?.[key] === value,
  )
}

function reportObservationMatches(capability, definition, platform) {
  if (platform === 'other') {
    return (
      capability.toolState === 'not-applicable'
      && capability.evidence === 'platform-not-applicable'
    )
  }
  if (definition.requiresAdapter) {
    return (
      capability.toolState === 'adapter-required'
      && [
        'fixed-command-present-adapter-required',
        'fixed-command-unavailable-adapter-required',
      ].includes(capability.evidence)
    )
  }
  if (definition.toolKeys.length === 0) {
    return (
      capability.toolState === 'adapter-required'
      && capability.evidence === 'static-public-catalog'
    )
  }
  return (
    (
      capability.toolState === 'available'
      && capability.evidence === 'fixed-command-presence'
    )
    || (
      capability.toolState === 'unavailable'
      && capability.evidence === 'fixed-command-unavailable'
    )
  )
}

function explanationObservationMatches(capability, definition, platform) {
  if (platform === 'other') {
    return (
      capability.toolState === 'not-applicable'
      && capability.evidence === 'platform-not-applicable'
    )
  }
  return (
    capability.evidence === 'static-public-catalog'
    && capability.toolState === (
      definition.requiresAdapter || definition.toolKeys.length === 0
        ? 'adapter-required'
        : 'unknown'
    )
  )
}

function controlMatches(control, expected) {
  return (
    exactKeys(control, Object.keys(expected))
    && Object.entries(expected).every(
      ([key, value]) => control[key] === value,
    )
  )
}

function safetyObservationMatches(observation, platform) {
  if (!exactKeys(observation, ['state', 'evidence'])) return false
  if (platform === 'other') {
    return (
      observation.state === 'not-applicable'
      && observation.evidence === 'platform-not-applicable'
    )
  }
  if (['on', 'off'].includes(observation.state)) {
    return observation.evidence === 'bounded-system-metadata'
  }
  return (
    observation.state === 'unknown'
    && [
      'fixed-command-unavailable',
      'bounded-metadata-unavailable',
    ].includes(observation.evidence)
  )
}

function stringsArePublic(value, seen = new WeakSet()) {
  if (typeof value === 'string') {
    return PUBLIC_STRING_ALLOWLIST.has(value)
  }
  if (typeof value === 'boolean') return true
  if (!record(value) || seen.has(value)) return false
  seen.add(value)
  try {
    return Reflect.ownKeys(value).every((key) => {
      if (typeof key !== 'string') return false
      const descriptor = Object.getOwnPropertyDescriptor(value, key)
      return Boolean(
        descriptor
        && descriptor.enumerable
        && Object.hasOwn(descriptor, 'value')
        && stringsArePublic(descriptor.value, seen),
      )
    })
  } catch {
    return false
  }
}

function containsPrivateHome(value, home, seen = new WeakSet()) {
  if (typeof home !== 'string' || home.length <= 1) return false
  if (typeof value === 'string') return value.includes(home)
  if (typeof value === 'boolean') return false
  if (!record(value) || seen.has(value)) return false
  seen.add(value)
  try {
    return Reflect.ownKeys(value).some((key) => {
      if (typeof key !== 'string') return false
      const descriptor = Object.getOwnPropertyDescriptor(value, key)
      return Boolean(
        descriptor
        && descriptor.enumerable
        && Object.hasOwn(descriptor, 'value')
        && containsPrivateHome(descriptor.value, home, seen),
      )
    })
  } catch {
    return false
  }
}

function checkMacCapabilities(report, { home } = {}) {
  const issues = []
  if (!record(report)) return ['invalid-report']

  if (!exactKeys(report, REPORT_KEYS)) {
    return ['report-shape-invalid']
  }
  if (
    report.schema !== SCHEMA
    || report.mode !== 'observation-only'
    || !['darwin', 'other'].includes(report.platform)
    || report.meaning !== MEANING
  ) {
    issues.push('report-static-value-invalid')
  }
  if (
    !exactKeys(report.actor, ACTOR_KEYS)
    || report.actor.identityState !== 'unresolved'
    || report.actor.scope !== 'responsible-process-specific'
  ) {
    issues.push('actor-scope-claim')
  }

  const capabilitiesHaveExactKeys = exactKeys(
    report.capabilities,
    MAC_CAPABILITY_IDS,
  )
  if (!capabilitiesHaveExactKeys) {
    issues.push('capability-set-mismatch')
  }
  for (const id of capabilitiesHaveExactKeys ? MAC_CAPABILITY_IDS : []) {
    const capability = report.capabilities?.[id]
    const definition = CAPABILITY_CATALOG[id]
    if (!exactKeys(capability, CAPABILITY_KEYS)) {
      issues.push('capability-shape-invalid')
      continue
    }
    if (
      !staticFieldsMatch(capability, definition)
      || capability.actionEvidence !== 'not-tested'
    ) {
      issues.push('capability-static-mismatch')
    }
    if (
      !reportObservationMatches(
        capability,
        definition,
        report.platform,
      )
    ) {
      issues.push('capability-observation-invalid')
    }
  }

  const expectedSettingIds = [
    ...Object.keys(SETTINGS_CATALOG),
    ...Object.values(SAFETY_SETTING_IDS),
  ]
  const settingsHaveExactKeys = exactKeys(
    report.settings,
    expectedSettingIds,
  )
  if (!settingsHaveExactKeys) {
    issues.push('settings-set-mismatch')
  }
  for (
    const [id, expected] of settingsHaveExactKeys
      ? Object.entries(SETTINGS_CATALOG)
      : []
  ) {
    const setting = report.settings?.[id]
    if (!exactKeys(setting, SETTING_KEYS)) {
      issues.push('setting-shape-invalid')
      continue
    }
    if (
      setting.location !== expected.location
      || setting.state !== 'not-observed'
      || setting.evidence !== 'static-public-catalog'
    ) {
      issues.push('setting-static-mismatch')
    }
  }

  const safetyHasExactKeys = exactKeys(report.safety, SAFETY_KEYS)
  if (!safetyHasExactKeys) {
    issues.push('safety-shape-invalid')
  }
  for (const id of safetyHasExactKeys ? SAFETY_KEYS : []) {
    const observation = report.safety?.[id]
    if (!safetyObservationMatches(observation, report.platform)) {
      issues.push('safety-observation-invalid')
    }
    const mirror = report.settings?.[SAFETY_SETTING_IDS[id]]
    if (
      !exactKeys(mirror, SETTING_KEYS)
      || mirror.location !== SAFETY_LOCATIONS[id]
      || mirror.state !== observation?.state
      || mirror.evidence !== observation?.evidence
    ) {
      issues.push('safety-mirror-mismatch')
    }
  }

  if (!controlMatches(report.control, CONTROL)) {
    issues.push('control-contract-invalid')
  }
  if (!stringsArePublic(report)) {
    issues.push('public-string-allowlist-failed')
  }
  if (containsPrivateHome(report, home)) {
    issues.push('account-home-leak')
  }
  return [...new Set(issues)]
}

function checkMacCapabilityExplanation(explanation) {
  const issues = []
  if (!record(explanation)) return ['invalid-explanation']

  if (!exactKeys(explanation, EXPLANATION_KEYS)) {
    return ['explanation-shape-invalid']
  }
  if (
    explanation.schema !== EXPLANATION_SCHEMA
    || explanation.mode !== 'observation-only'
    || !['darwin', 'other'].includes(explanation.platform)
  ) {
    issues.push('explanation-static-value-invalid')
  }
  if (
    !exactKeys(explanation.actor, ACTOR_KEYS)
    || explanation.actor.identityState !== 'unresolved'
    || explanation.actor.scope !== 'responsible-process-specific'
  ) {
    issues.push('actor-scope-claim')
  }
  if (
    typeof explanation.id !== 'string'
    || !Object.hasOwn(CAPABILITY_CATALOG, explanation.id)
  ) {
    issues.push('capability-id-invalid')
  } else {
    const definition = CAPABILITY_CATALOG[explanation.id]
    const capability = explanation.capability
    if (!exactKeys(capability, CAPABILITY_KEYS)) {
      issues.push('capability-shape-invalid')
    } else {
      if (
        !staticFieldsMatch(capability, definition)
        || capability.actionEvidence !== 'not-tested'
      ) {
        issues.push('capability-static-mismatch')
      }
      if (
        !explanationObservationMatches(
          capability,
          definition,
          explanation.platform,
        )
      ) {
        issues.push('capability-observation-invalid')
      }
    }
    const expectedSetting = SETTINGS_CATALOG[definition.settingId]
    if (!exactKeys(explanation.setting, SETTING_KEYS)) {
      issues.push('setting-shape-invalid')
    } else if (
      explanation.setting.location !== expectedSetting.location
      || explanation.setting.state !== 'not-observed'
      || explanation.setting.evidence !== 'static-public-catalog'
    ) {
      issues.push('setting-static-mismatch')
    }
  }
  if (!controlMatches(explanation.control, EXPLANATION_CONTROL)) {
    issues.push('control-contract-invalid')
  }
  if (!stringsArePublic(explanation)) {
    issues.push('public-string-allowlist-failed')
  }
  return [...new Set(issues)]
}

function renderMacCapabilities(report) {
  const states = Object.values(report.capabilities ?? {})
    .map((capability) => capability.toolState)
  const available = states.filter((state) => state === 'available').length
  const adapterRequired = states
    .filter((state) => state === 'adapter-required')
    .length
  const unavailable = states
    .filter((state) => state === 'unavailable')
    .length
  return [
    'KINGDOM OS macOS edge — observation only',
    `  actor       ${report.actor?.identityState ?? 'unknown'} · permissions remain actor-specific`,
    `  capability  ${available} available · ${adapterRequired} adapter-required · ${unavailable} unavailable`,
    `  FileVault   ${report.safety?.fileVault?.state ?? 'unknown'}`,
    `  firewall    ${report.safety?.firewall?.state ?? 'unknown'}`,
    `  Gatekeeper  ${report.safety?.gatekeeper?.state ?? 'unknown'}`,
    '  control     bounded coarse metadata only; no private payloads, prompts, actions, writes, or settings changes',
  ].join('\n')
}

function renderMacCapabilityExplanation(explanation) {
  if (!explanation) return null
  const capability = explanation.capability
  return [
    `${explanation.id} — ${capability.title}`,
    `  ${capability.summary}`,
    `  native edge   ${capability.nativeEdge} · ${capability.toolState}`,
    `  permission    ${capability.authorization}`,
    `  agent default ${capability.agentDefault}`,
    `  risk          ${capability.risk}`,
    `  setting       ${explanation.setting?.location ?? 'not applicable'}`,
    '  evidence      no action was tested',
  ].join('\n')
}

export {
  MAC_CAPABILITY_IDS,
  checkMacCapabilityExplanation,
  checkMacCapabilities,
  explainMacCapability,
  inspectMacCapabilities,
  renderMacCapabilities,
  renderMacCapabilityExplanation,
}
