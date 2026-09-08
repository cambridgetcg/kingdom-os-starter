#!/usr/bin/env node

// macOS observations and the separately requested finite keep-awake action.
// Observation verbs never dispatch an action or grant task authority.

import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  MAC_CAPABILITY_IDS,
  checkMacCapabilities,
  checkMacCapabilityExplanation,
  explainMacCapability,
  inspectMacCapabilities,
  renderMacCapabilities,
  renderMacCapabilityExplanation,
} from '../platform/macos-capabilities.mjs'
import {
  inspectMacKeychain,
  validateMacKeychainReport,
} from '../platform/macos-keychain.mjs'
import {
  composeMacEncryptionPosture,
  renderMacEncryptionPosture,
  validateMacEncryptionPosture,
} from '../platform/macos-encryption.mjs'
import {
  composeMacCapabilityPolicy,
  renderMacCapabilityPolicy,
  validateMacCapabilityPolicy,
} from '../platform/macos-policy.mjs'
import {
  MAX_AWAKE_PID,
  MAX_AWAKE_SECONDS,
  macAwakeExitCode,
  renderMacAwakeReport,
  runMacAwake,
  validateMacAwakeReport,
} from '../platform/macos-awake.mjs'

const VALID_COMMANDS = new Set([
  'awake',
  'doctor',
  'encryption',
  'explain',
  'keychain',
  'policy',
  'status',
])
const COMPOSITE_SCHEMA = 'kingdom.macos-agent-native/0.1'
const COMPOSITE_MEANING =
  'This non-atomic document composes two read-only observations; capability evidence is not permission or authority.'
const COMPOSITE_CONTROL = Object.freeze({
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
})
const COMPOSITE_KEYS = Object.freeze([
  'schema',
  'mode',
  'consistency',
  'platform',
  'macosCapabilities',
  'keychainPosture',
  'control',
  'meaning',
])

function usage() {
  return [
    'usage: node bin/mac.mjs [doctor|encryption|keychain|policy CAPABILITY|explain CAPABILITY] [--json]',
    '       node bin/mac.mjs awake --pid PID --seconds N [--json]',
    '',
    'Observation verbs read coarse metadata, return no private payload,',
    'and neither request permission nor perform an action.',
    '',
    'awake: explicitly request host-wide idle-sleep prevention for one existing',
    `same-user process, for 1..${MAX_AWAKE_SECONDS} seconds. No command operand.`,
    'May use battery; no permanent power setting or privacy grant changes.',
    'Ctrl-C cancels this foreground lease. Caller task authority is required.',
  ].join('\n')
}

function parseArguments(args) {
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string')) {
    return null
  }
  const json = args.filter((arg) => arg === '--json').length
  const words = args.filter((arg) => arg !== '--json')
  if (json > 1) return null
  if (words.length === 0) {
    return { command: 'doctor', json: json === 1 }
  }
  if (
    words.length === 1
    && ['help', '-h', '--help'].includes(words[0])
  ) {
    return { command: 'help', json: false }
  }
  const command = words[0]
  if (!VALID_COMMANDS.has(command)) return null
  if (command === 'awake') {
    if (words.length !== 5) return null
    const values = new Map()
    for (let index = 1; index < words.length; index += 2) {
      const flag = words[index]
      const value = words[index + 1]
      if (
        !['--pid', '--seconds'].includes(flag)
        || values.has(flag)
        || !/^[1-9][0-9]{0,9}$/.test(value)
        || String(Number(value)) !== value
      ) return null
      values.set(flag, Number(value))
    }
    const pid = values.get('--pid')
    const seconds = values.get('--seconds')
    if (
      !Number.isInteger(pid) || pid > MAX_AWAKE_PID
      || !Number.isInteger(seconds) || seconds > MAX_AWAKE_SECONDS
      || pid === process.pid
    ) return null
    return { command, pid, seconds, json: json === 1 }
  }
  if (['explain', 'policy'].includes(command)) {
    if (words.length !== 2) return null
    return {
      command,
      id: words[1],
      json: json === 1,
    }
  }
  if (words.length !== 1) return null
  return {
    command: command === 'status' ? 'doctor' : command,
    json: json === 1,
  }
}

function composeReport(capabilities, keychain) {
  return {
    schema: COMPOSITE_SCHEMA,
    mode: 'observation-only',
    consistency: 'non-atomic',
    platform: capabilities?.platform,
    macosCapabilities: capabilities,
    keychainPosture: keychain,
    control: { ...COMPOSITE_CONTROL },
    meaning: COMPOSITE_MEANING,
  }
}

function plainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false
  }
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function exactKeys(value, expected) {
  if (!plainRecord(value)) return false
  const actual = Reflect.ownKeys(value)
  return (
    actual.length === expected.length
    && actual.every(
      (key) => typeof key === 'string' && expected.includes(key),
    )
  )
}

function checkMacReport(report, options = {}) {
  const issues = []
  if (!exactKeys(report, COMPOSITE_KEYS)) {
    return ['composite-shape-invalid']
  }
  if (
    report.schema !== COMPOSITE_SCHEMA
    || report.mode !== 'observation-only'
    || report.consistency !== 'non-atomic'
    || !['darwin', 'other'].includes(report.platform)
    || report.meaning !== COMPOSITE_MEANING
  ) {
    issues.push('composite-static-value-invalid')
  }
  if (
    !exactKeys(report.control, Object.keys(COMPOSITE_CONTROL))
    || Object.entries(COMPOSITE_CONTROL).some(
      ([key, value]) => report.control[key] !== value,
    )
  ) {
    issues.push('composite-control-invalid')
  }

  const checkCapabilities =
    options.checkCapabilities ?? checkMacCapabilities
  const validateKeychain =
    options.validateKeychain ?? validateMacKeychainReport
  if (!passes(checkCapabilities, report.macosCapabilities)) {
    issues.push('capability-ledger-invalid')
  }
  if (!passes(validateKeychain, report.keychainPosture)) {
    issues.push('keychain-posture-invalid')
  }
  if (
    report.macosCapabilities?.platform !== report.platform
    || report.keychainPosture?.platform !== report.platform
  ) {
    issues.push('composite-platform-mismatch')
  }
  return [...new Set(issues)]
}

function renderKeychain(report) {
  return [
    'KINGDOM OS macOS Keychain edge — observation only',
    `  provider    ${report.provider?.toolState ?? 'unknown'} · user domain ${report.provider?.userDomainState ?? 'unknown'}`,
    `  keep gate   ${report.gate?.toolState ?? 'unknown'} · ${report.gate?.evidenceState ?? 'unknown'}`,
    `  Git helper  ${report.gitCredentialHelper?.state ?? 'unknown'}`,
    `  isolation   ${report.isolation?.boundary ?? 'unknown'} · sibling agents ${report.isolation?.siblingAgents ?? 'unknown'}`,
    '  control     coarse metadata only; no item names, values, private payloads, writes, or permission requests',
  ].join('\n')
}

function renderDoctor(report) {
  return [
    renderMacCapabilities(report.macosCapabilities),
    '',
    renderKeychain(report.keychainPosture),
    '',
    'From the source directory, use `node bin/mac.mjs explain CAPABILITY` for one setting and boundary.',
    'Use `node bin/mac.mjs encryption` for the layered encryption posture.',
  ].join('\n')
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
  try {
    if (!passes(check, value)) return null
    const text = JSON.stringify(value, null, 2)
    const snapshot = JSON.parse(text)
    if (!passes(check, snapshot)) return null
    return { snapshot, text }
  } catch {
    return null
  }
}

async function runAwakeCommand(parsed, options) {
  const controller = new AbortController()
  const signalSource = options.signalSource ?? process
  const handlers = new Map(
    ['SIGINT', 'SIGTERM', 'SIGHUP'].map((name) => [
      name, () => controller.abort(name),
    ]),
  )
  const writeOut = options.writeOut ?? ((text) => console.log(text))
  const writeError = options.writeError ?? ((text) => console.error(text))
  try {
    for (const [name, handler] of handlers) signalSource.on(name, handler)
    const signal = options.signal
      ? AbortSignal.any([controller.signal, options.signal])
      : controller.signal
    const runAwake = options.runAwake ?? runMacAwake
    if (!parsed.json) {
      writeError(`macOS awake: requesting at most ${parsed.seconds}s for PID ${parsed.pid}; Ctrl-C cancels`)
    }
    const report = await runAwake(
      { pid: parsed.pid, seconds: parsed.seconds },
      { signal },
    )
    const validated = validatedSnapshot(
      options.validateAwake ?? validateMacAwakeReport,
      report,
    )
    if (!validated) {
      writeError('macOS awake: unsafe result refused')
      return 1
    }
    writeOut(
      parsed.json
        ? validated.text
        : renderMacAwakeReport(validated.snapshot),
    )
    return macAwakeExitCode(validated.snapshot)
  } catch {
    writeError('macOS awake: action failed')
    return 1
  } finally {
    for (const [name, handler] of handlers) {
      signalSource.removeListener(name, handler)
    }
  }
}

async function runCli(args = process.argv.slice(2), options = {}) {
  const parsed = parseArguments(args)
  const writeOut = options.writeOut ?? ((text) => console.log(text))
  const writeError = options.writeError ?? ((text) => console.error(text))
  const inspectCapabilities =
    options.inspectCapabilities ?? inspectMacCapabilities
  const inspectKeychain = options.inspectKeychain ?? inspectMacKeychain
  const explainCapability =
    options.explainCapability ?? explainMacCapability
  const checkCapabilities =
    options.checkCapabilities ?? checkMacCapabilities
  const checkExplanation =
    options.checkExplanation ?? checkMacCapabilityExplanation
  const validateKeychain =
    options.validateKeychain ?? validateMacKeychainReport
  const validateEncryption =
    options.validateEncryption ?? validateMacEncryptionPosture
  const validatePolicy =
    options.validatePolicy ?? validateMacCapabilityPolicy
  const checkComposite =
    options.checkComposite
    ?? ((report) => checkMacReport(report, {
      checkCapabilities,
      validateKeychain,
    }))

  if (!parsed) {
    writeError('macOS edge: unknown command')
    writeError(usage())
    return 64
  }
  if (parsed.command === 'help') {
    writeOut(usage())
    return 0
  }
  if (parsed.command === 'awake') {
    return runAwakeCommand(parsed, options)
  }
  if (parsed.command === 'keychain') {
    const report = await inspectKeychain()
    const validated = validatedSnapshot(validateKeychain, report)
    if (!validated) {
      writeError('macOS edge: unsafe observation refused')
      return 1
    }
    writeOut(
      parsed.json
        ? validated.text
        : renderKeychain(validated.snapshot),
    )
    return 0
  }
  if (parsed.command === 'encryption') {
    const [capabilities, keychain] = await Promise.all([
      inspectCapabilities(),
      inspectKeychain(),
    ])
    const report = composeMacEncryptionPosture(
      capabilities,
      keychain,
      {
        architecture: options.architecture ?? process.arch,
        checkCapabilities,
        validateKeychain,
      },
    )
    const validated = validatedSnapshot(validateEncryption, report)
    if (!validated) {
      writeError('macOS edge: unsafe observation refused')
      return 1
    }
    writeOut(
      parsed.json
        ? validated.text
        : renderMacEncryptionPosture(validated.snapshot),
    )
    return 0
  }
  if (parsed.command === 'policy') {
    if (!MAC_CAPABILITY_IDS.includes(parsed.id)) {
      writeError('macOS edge: unknown capability')
      return 64
    }
    const [capabilities, keychain] = await Promise.all([
      inspectCapabilities(),
      inspectKeychain(),
    ])
    const report = composeMacCapabilityPolicy(
      parsed.id,
      capabilities,
      keychain,
      {
        architecture: options.architecture ?? process.arch,
        checkCapabilities,
        validateKeychain,
        validateEncryption,
      },
    )
    const validated = validatedSnapshot(validatePolicy, report)
    if (!validated) {
      writeError('macOS edge: unsafe observation refused')
      return 1
    }
    writeOut(
      parsed.json
        ? validated.text
        : renderMacCapabilityPolicy(validated.snapshot),
    )
    return 0
  }
  if (parsed.command === 'explain') {
    const explanation = await explainCapability(parsed.id)
    if (!explanation) {
      writeError('macOS edge: unknown capability')
      return 64
    }
    const validated = validatedSnapshot(checkExplanation, explanation)
    if (!validated) {
      writeError('macOS edge: unsafe observation refused')
      return 1
    }
    writeOut(
      parsed.json
        ? validated.text
        : renderMacCapabilityExplanation(validated.snapshot),
    )
    return 0
  }

  const [capabilities, keychain] = await Promise.all([
    inspectCapabilities(),
    inspectKeychain(),
  ])
  const report = composeReport(capabilities, keychain)
  const validated = validatedSnapshot(checkComposite, report)
  if (!validated) {
    writeError('macOS edge: unsafe observation refused')
    return 1
  }
  writeOut(
    parsed.json
      ? validated.text
      : renderDoctor(validated.snapshot),
  )
  return 0
}

if (
  process.argv[1]
  && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
) {
  try {
    process.exitCode = await runCli()
  } catch {
    console.error('macOS edge: command failed')
    process.exitCode = 1
  }
}

export {
  COMPOSITE_SCHEMA,
  checkMacReport,
  composeReport,
  parseArguments,
  renderDoctor,
  renderKeychain,
  runCli,
  usage,
}
