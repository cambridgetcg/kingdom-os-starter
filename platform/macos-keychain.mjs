import { spawn } from 'node:child_process'
import {
  accessSync,
  constants,
  lstatSync,
  realpathSync,
  statSync,
} from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'

import { trustedAccount } from './account.mjs'
const MACOS_KEYCHAIN_SCHEMA = 'kingdom.macos-keychain-posture/0.1'
const STATUS_TIMEOUT_MS = 3_000

function executable(candidates) {
  for (const candidate of candidates) {
    try {
      accessSync(candidate, constants.X_OK)
      if (statSync(candidate).isFile()) return candidate
    } catch {
      // Try the next fixed path.
    }
  }
  return null
}

function narrowEnvironment(home) {
  return {
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
    HOME: home,
    LANG: 'C',
    LC_ALL: 'C',
    NO_COLOR: '1',
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    TERM: 'dumb',
  }
}

function boundedStatus(command, args, options = {}) {
  return new Promise((resolveStatus) => {
    if (
      typeof command !== 'string'
      || !isAbsolute(command)
      || !Array.isArray(args)
      || args.some((arg) => typeof arg !== 'string' || arg.includes('\0'))
    ) {
      resolveStatus({ kind: 'invalid' })
      return
    }

    let child
    let timer
    let settled = false

    const finish = (value) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      resolveStatus(value)
    }

    const killGroup = () => {
      if (!child?.pid) return
      try {
        process.kill(-child.pid, 'SIGKILL')
        return
      } catch {
        // Fall back to the child if no process group was established.
      }
      try {
        child.kill('SIGKILL')
      } catch {
        // The child already exited.
      }
    }

    try {
      child = spawn(command, args, {
        cwd: options.cwd ?? '/',
        detached: true,
        env: options.env,
        stdio: ['ignore', 'ignore', 'ignore'],
      })
    } catch {
      finish({ kind: 'error' })
      return
    }

    timer = setTimeout(() => {
      killGroup()
      finish({ kind: 'timeout' })
    }, options.timeoutMs ?? STATUS_TIMEOUT_MS)

    child.on('error', () => {
      killGroup()
      finish({ kind: 'error' })
    })
    child.on('close', (code, signal) => {
      killGroup()
      if (Number.isInteger(code)) {
        finish({ kind: 'exit', code })
      } else if (typeof signal === 'string') {
        finish({ kind: 'signal', signal })
      } else {
        finish({ kind: 'error' })
      }
    })
  })
}

function commandOverride(value, fallback) {
  if (value === null) return null
  if (value === undefined) return fallback
  return typeof value === 'string' && isAbsolute(value)
    ? value
    : null
}

function keepGateEvidenceState(home, uid) {
  const gate = join(home, '.local', 'bin', 'keep')
  const source = join(home, 'keep', 'keep')

  try {
    const gateEntry = lstatSync(gate)
    const sourceEntry = lstatSync(source)

    if (
      !gateEntry.isSymbolicLink()
      || !sourceEntry.isFile()
      || sourceEntry.isSymbolicLink()
    ) {
      return 'owner-mode-path-mismatch'
    }

    if (gateEntry.uid !== uid || sourceEntry.uid !== uid) {
      return 'owner-mode-path-mismatch'
    }
    if (
      (sourceEntry.mode & 0o022) !== 0
      || (sourceEntry.mode & 0o100) === 0
    ) {
      return 'owner-mode-path-mismatch'
    }
    if (realpathSync(gate) !== realpathSync(source)) {
      return 'owner-mode-path-mismatch'
    }
    return 'owner-mode-path-match'
  } catch (error) {
    return error?.code === 'ENOENT'
      ? 'unavailable'
      : 'unknown'
  }
}

function exactKeys(value, keys) {
  if (!record(value)) return false
  const actual = Reflect.ownKeys(value)
  return (
    actual.length === keys.length
    && actual.every(
      (key) => typeof key === 'string' && keys.includes(key),
    )
  )
}

function normalizeStatus(value) {
  if (!exactKeys(value, value?.kind === 'exit'
    ? ['kind', 'code']
    : value?.kind === 'signal'
      ? ['kind', 'signal']
      : ['kind'])) {
    return { kind: 'invalid' }
  }
  if (
    value.kind === 'exit'
    && Number.isInteger(value.code)
    && value.code >= 0
  ) {
    return { kind: 'exit', code: value.code }
  }
  if (value.kind === 'signal' && typeof value.signal === 'string') {
    return { kind: 'signal', signal: value.signal }
  }
  if (['timeout', 'error', 'invalid'].includes(value.kind)) {
    return { kind: value.kind }
  }
  return { kind: 'invalid' }
}

async function runStatusSafely(runStatus, command, args, options) {
  try {
    return normalizeStatus(await runStatus(command, args, options))
  } catch {
    return { kind: 'error' }
  }
}

function confirmed(outcome) {
  return outcome.kind === 'exit' && outcome.code === 0
}

function gitHelperState(outcome) {
  if (outcome.kind !== 'exit') return 'unknown'
  if (outcome.code === 0) return 'configured'
  if (outcome.code === 1) return 'not-configured'
  return 'unknown'
}

async function inspectMacKeychain(options = {}) {
  const platform = options.platform ?? process.platform
  if (platform !== 'darwin') {
    return {
      schema: MACOS_KEYCHAIN_SCHEMA,
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
      meaning: OTHER_MEANING,
    }
  }
  const account = options.home === undefined || options.uid === undefined
    ? trustedAccount()
    : null
  const home = resolve(options.home ?? account.home)
  const uid = options.uid ?? account.uid
  if (!Number.isInteger(uid) || uid < 0) {
    throw new TypeError('Keychain observer uid must be a non-negative integer')
  }
  const runStatus = options.runStatus ?? boundedStatus
  const timeoutMs = Number.isInteger(options.timeoutMs)
    && options.timeoutMs >= 25
    && options.timeoutMs <= STATUS_TIMEOUT_MS
    ? options.timeoutMs
    : STATUS_TIMEOUT_MS
  const fixedCommands = {
    git: executable(['/usr/bin/git', '/bin/git']),
    security: platform === 'darwin'
      ? executable(['/usr/bin/security'])
      : null,
  }
  const commands = {
    git: commandOverride(options.commands?.git, fixedCommands.git),
    security: commandOverride(
      options.commands?.security,
      fixedCommands.security,
    ),
  }

  const environment = narrowEnvironment(home)
  const [userDomainStatus, gitHelperStatus] = await Promise.all([
    commands.security
      ? runStatusSafely(
          runStatus,
          commands.security,
          ['default-keychain', '-d', 'user'],
          { cwd: '/', env: environment, timeoutMs },
        )
      : { kind: 'unavailable' },
    commands.git
      ? runStatusSafely(
          runStatus,
          commands.git,
          [
            'config',
            '--global',
            '--no-includes',
            '--get-all',
            'credential.helper',
            '^osxkeychain$',
          ],
          { cwd: '/', env: environment, timeoutMs },
        )
      : { kind: 'unavailable' },
  ])
  const gateEvidenceState = keepGateEvidenceState(home, uid)

  return {
    schema: MACOS_KEYCHAIN_SCHEMA,
    mode: 'observation-only',
    platform: 'darwin',
    provider: {
      kind: 'macos-keychain',
      toolState: commands.security ? 'available' : 'unavailable',
      userDomainState: confirmed(userDomainStatus)
        ? 'available'
        : 'unknown',
    },
    gate: {
      kind: 'keep',
      toolState: [
        'owner-mode-path-match',
        'owner-mode-path-mismatch',
      ].includes(gateEvidenceState)
        ? 'available'
        : 'unavailable',
      evidenceState: gateEvidenceState,
      authorization: 'per-item-at-use',
      actionEvidence: 'not-tested',
      agentDefault: 'deny-private-read-until-task',
    },
    gitCredentialHelper: {
      kind: 'osxkeychain',
      state: gitHelperState(gitHelperStatus),
    },
    isolation: {
      boundary: 'login-user',
      siblingAgents: 'not-isolated',
      kingdomWalls: 'not-operating-system-enforced',
    },
    evidence: [...DARWIN_EVIDENCE],
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
    meaning: DARWIN_MEANING,
  }
}

const ROOT_FIELDS = [
  'schema',
  'mode',
  'platform',
  'provider',
  'gate',
  'gitCredentialHelper',
  'isolation',
  'evidence',
  'control',
  'meaning',
]
const PROVIDER_FIELDS = ['kind', 'toolState', 'userDomainState']
const GATE_FIELDS = [
  'kind',
  'toolState',
  'evidenceState',
  'authorization',
  'actionEvidence',
  'agentDefault',
]
const GIT_FIELDS = ['kind', 'state']
const ISOLATION_FIELDS = [
  'boundary',
  'siblingAgents',
  'kingdomWalls',
]
const CONTROL_FIELDS = [
  'writes',
  'networkRequests',
  'readsCoarseMetadata',
  'returnsPrivateContent',
  'readsSecretValues',
  'listsSecretNames',
  'requestsPermission',
  'opensApplications',
  'changesSettings',
  'changesServices',
]
const DARWIN_EVIDENCE = [
  'fixed-native-tool-presence',
  'user-domain-exit-status-only',
  'final-gate-source-owner-mode-path-metadata',
  'git-helper-exact-match-exit-status-only',
]
const DARWIN_MEANING = 'Keychain protects the login user, not sibling agents under that user. Gate metadata does not prove behavior, Keychain ACLs, or ancestor-directory safety. Evidence is not authority or consent.'
const OTHER_MEANING = 'The macOS Keychain posture is not applicable on this host.'

function record(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false
  }
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function validateFields(value, expected, issues) {
  if (!record(value)) {
    issues.push('keychain-schema-invalid-type')
    return false
  }
  const actual = Reflect.ownKeys(value)
  if (
    actual.some(
      (key) => typeof key !== 'string' || !expected.includes(key),
    )
  ) {
    issues.push('keychain-schema-extra-field')
  }
  if (expected.some((key) => !actual.includes(key))) {
    issues.push('keychain-schema-missing-field')
  }
  return true
}

function validateEnum(value, allowed, issues) {
  if (!allowed.includes(value)) {
    issues.push('keychain-schema-invalid-value')
  }
}

function validateStaticArray(value, expected, issues) {
  if (
    !Array.isArray(value)
    || value.length !== expected.length
    || value.some((item, index) => item !== expected[index])
  ) {
    issues.push('keychain-schema-invalid-value')
  }
}

function validateControl(control, issues) {
  if (!validateFields(control, CONTROL_FIELDS, issues)) return
  const expected = {
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
  }
  for (const [key, value] of Object.entries(expected)) {
    if (control[key] !== value) {
      issues.push('keychain-schema-invalid-value')
    }
  }
}

function validateMacKeychainReport(report, options = {}) {
  const issues = []
  if (!validateFields(report, ROOT_FIELDS, issues)) {
    return [...new Set(issues)]
  }

  let text
  try {
    text = JSON.stringify(report)
  } catch {
    return ['keychain-report-malformed']
  }
  const home = options.home
  if (typeof home === 'string' && home.length > 1 && text.includes(home)) {
    issues.push('account-home-leak')
  }
  if (
    text.includes('/Users/')
    || text.includes('/home/')
    || text.includes('file://')
  ) {
    issues.push('absolute-path-leak')
  }

  validateEnum(report.schema, [MACOS_KEYCHAIN_SCHEMA], issues)
  validateEnum(report.mode, ['observation-only'], issues)
  validateEnum(report.platform, ['darwin', 'other'], issues)
  const darwin = report.platform === 'darwin'

  if (validateFields(report.provider, PROVIDER_FIELDS, issues)) {
    validateEnum(report.provider.kind, ['macos-keychain'], issues)
    validateEnum(
      report.provider.toolState,
      darwin
        ? ['available', 'unavailable']
        : ['not-applicable'],
      issues,
    )
    validateEnum(
      report.provider.userDomainState,
      darwin
        ? ['available', 'unknown']
        : ['not-applicable'],
      issues,
    )
  }

  if (validateFields(report.gate, GATE_FIELDS, issues)) {
    validateEnum(report.gate.kind, ['keep'], issues)
    validateEnum(
      report.gate.toolState,
      darwin
        ? ['available', 'unavailable']
        : ['not-applicable'],
      issues,
    )
    validateEnum(
      report.gate.evidenceState,
      darwin
        ? [
            'owner-mode-path-match',
            'owner-mode-path-mismatch',
            'unavailable',
            'unknown',
          ]
        : ['not-applicable'],
      issues,
    )
    validateEnum(
      report.gate.authorization,
      darwin ? ['per-item-at-use'] : ['not-applicable'],
      issues,
    )
    validateEnum(report.gate.actionEvidence, ['not-tested'], issues)
    validateEnum(
      report.gate.agentDefault,
      darwin
        ? ['deny-private-read-until-task']
        : ['not-applicable'],
      issues,
    )
  }

  if (
    validateFields(
      report.gitCredentialHelper,
      GIT_FIELDS,
      issues,
    )
  ) {
    validateEnum(
      report.gitCredentialHelper.kind,
      ['osxkeychain'],
      issues,
    )
    validateEnum(
      report.gitCredentialHelper.state,
      darwin
        ? ['configured', 'not-configured', 'unknown']
        : ['not-applicable'],
      issues,
    )
  }

  if (validateFields(report.isolation, ISOLATION_FIELDS, issues)) {
    validateEnum(
      report.isolation.boundary,
      darwin ? ['login-user'] : ['not-applicable'],
      issues,
    )
    validateEnum(
      report.isolation.siblingAgents,
      darwin ? ['not-isolated'] : ['not-applicable'],
      issues,
    )
    validateEnum(
      report.isolation.kingdomWalls,
      ['not-operating-system-enforced'],
      issues,
    )
  }

  validateStaticArray(
    report.evidence,
    darwin ? DARWIN_EVIDENCE : [],
    issues,
  )
  validateControl(report.control, issues)
  validateEnum(
    report.meaning,
    [darwin ? DARWIN_MEANING : OTHER_MEANING],
    issues,
  )

  return [...new Set(issues)]
}

function checkMacKeychainReport(report, options = {}) {
  const issues = validateMacKeychainReport(report, options)
  if (issues.length > 0 || report.platform !== 'darwin') {
    return issues
  }

  if (report.provider.toolState !== 'available') {
    issues.push('macos-security-unavailable')
  }
  if (report.provider.userDomainState !== 'available') {
    issues.push('keychain-user-domain-unknown')
  }
  if (report.gate.evidenceState === 'owner-mode-path-mismatch') {
    issues.push('keep-gate-metadata-mismatch')
  } else if (report.gate.evidenceState === 'unavailable') {
    issues.push('keep-gate-unavailable')
  } else if (report.gate.evidenceState === 'unknown') {
    issues.push('keep-gate-unknown')
  }
  if (report.gitCredentialHelper.state === 'not-configured') {
    issues.push('git-osxkeychain-not-configured')
  } else if (report.gitCredentialHelper.state === 'unknown') {
    issues.push('git-osxkeychain-unknown')
  }

  return issues
}

export {
  MACOS_KEYCHAIN_SCHEMA,
  checkMacKeychainReport,
  inspectMacKeychain,
  validateMacKeychainReport,
}
