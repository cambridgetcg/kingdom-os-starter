import assert from 'node:assert/strict'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'

import {
  MACOS_KEYCHAIN_SCHEMA,
  checkMacKeychainReport,
  inspectMacKeychain,
  validateMacKeychainReport,
} from '../platform/macos-keychain.mjs'

function temporaryHome(context) {
  const home = mkdtempSync(join(tmpdir(), 'kingdom-macos-keychain-'))
  context.after(() => rmSync(home, { recursive: true, force: true }))
  return home
}

function installMatchingKeepGate(home) {
  const sourceDirectory = join(home, 'keep')
  const gateDirectory = join(home, '.local', 'bin')
  mkdirSync(sourceDirectory, { mode: 0o700 })
  mkdirSync(gateDirectory, { mode: 0o700, recursive: true })
  const source = join(sourceDirectory, 'keep')
  writeFileSync(source, '#!/bin/zsh\nexit 0\n', { mode: 0o700 })
  chmodSync(sourceDirectory, 0o700)
  chmodSync(gateDirectory, 0o700)
  symlinkSync(source, join(gateDirectory, 'keep'))
}

const EXIT_ZERO = { kind: 'exit', code: 0 }

function fixedCommands(overrides = {}) {
  return {
    git: '/usr/bin/git',
    security: '/usr/bin/security',
    ...overrides,
  }
}

async function processExited(pid) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      process.kill(pid, 0)
    } catch (error) {
      if (error?.code === 'ESRCH') return true
      throw error
    }
    await delay(20)
  }
  return false
}

test('Keychain posture uses status-only fixed commands and returns no private material', async (context) => {
  const home = temporaryHome(context)
  installMatchingKeepGate(home)
  const calls = []
  const runStatus = async (command, args, options) => {
    calls.push({ command, args, options })
    return EXIT_ZERO
  }

  const report = await inspectMacKeychain({
    platform: 'darwin',
    home,
    uid: process.getuid(),
    commands: fixedCommands(),
    runStatus,
  })

  assert.equal(report.schema, MACOS_KEYCHAIN_SCHEMA)
  assert.equal(report.provider.toolState, 'available')
  assert.equal(report.provider.userDomainState, 'available')
  assert.equal(report.gate.evidenceState, 'owner-mode-path-match')
  assert.equal(report.gitCredentialHelper.state, 'configured')
  assert.equal(report.isolation.siblingAgents, 'not-isolated')
  assert.equal(
    report.isolation.kingdomWalls,
    'not-operating-system-enforced',
  )
  assert.deepEqual(checkMacKeychainReport(report, { home }), [])

  assert.deepEqual(
    calls.map(({ command, args }) => ({ command, args })),
    [
      {
        command: '/usr/bin/security',
        args: ['default-keychain', '-d', 'user'],
      },
      {
        command: '/usr/bin/git',
        args: [
          'config',
          '--global',
          '--no-includes',
          '--get-all',
          'credential.helper',
          '^osxkeychain$',
        ],
      },
    ],
  )
  for (const call of calls) {
    assert.equal(call.options.env.HOME, home)
    assert.equal(call.options.cwd, '/')
    assert.equal(
      call.options.env.PATH,
      '/usr/bin:/bin:/usr/sbin:/sbin',
    )
    assert.equal(
      Object.hasOwn(call.options.env, 'NODE_OPTIONS'),
      false,
    )
    assert.equal(
      call.args.some((arg) =>
        [
          '-g',
          '-w',
          'add-generic-password',
          'delete-generic-password',
          'dump-keychain',
          'find-generic-password',
        ].includes(arg)
      ),
      false,
    )
  }

  const text = JSON.stringify(report)
  assert.doesNotMatch(text, new RegExp(home))
  assert.doesNotMatch(text, /\/Users\/|\/home\//)
  assert.doesNotMatch(
    text,
    /Claude Code-credentials|dev\.agenttool\/|keep\./,
  )
  assert.equal(report.control.readsSecretValues, false)
  assert.equal(report.control.listsSecretNames, false)
  assert.equal(report.control.readsCoarseMetadata, true)
  assert.equal(report.control.returnsPrivateContent, false)
  assert.equal(report.control.writes, false)
  assert.equal(report.control.networkRequests, false)
})

test('hostile ambient variables cannot choose commands or enter the report', async (context) => {
  const home = temporaryHome(context)
  installMatchingKeepGate(home)
  const original = {
    HOME: process.env.HOME,
    KINGDOM_MAC_COMMAND: process.env.KINGDOM_MAC_COMMAND,
    NODE_OPTIONS: process.env.NODE_OPTIONS,
    PATH: process.env.PATH,
  }
  context.after(() => {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  })
  process.env.HOME = '/hostile/home'
  process.env.PATH = '/hostile/bin'
  process.env.NODE_OPTIONS = '--require=/hostile/inject.cjs'
  process.env.KINGDOM_MAC_COMMAND = '/hostile/security'

  const calls = []
  const report = await inspectMacKeychain({
    platform: 'darwin',
    home,
    uid: process.getuid(),
    runStatus: async (command, args, options) => {
      calls.push({ command, args, options })
      return EXIT_ZERO
    },
  })

  assert.ok(
    calls.every(({ command }) =>
      ['/usr/bin/security', '/usr/bin/git', '/bin/git'].includes(command)
    ),
  )
  assert.ok(
    calls.every(({ options }) => options.env.HOME === home),
  )
  assert.doesNotMatch(JSON.stringify(report), /hostile/)
})

test('typed status outcomes distinguish an absent Git declaration from uncertainty', async (context) => {
  const home = temporaryHome(context)
  installMatchingKeepGate(home)

  const notConfigured = await inspectMacKeychain({
    platform: 'darwin',
    home,
    uid: process.getuid(),
    commands: fixedCommands(),
    runStatus: async () => ({ kind: 'exit', code: 1 }),
  })
  assert.equal(notConfigured.provider.userDomainState, 'unknown')
  assert.equal(
    notConfigured.gitCredentialHelper.state,
    'not-configured',
  )
  assert.deepEqual(validateMacKeychainReport(notConfigured, { home }), [])
  assert.deepEqual(
    checkMacKeychainReport(notConfigured, { home }),
    [
      'keychain-user-domain-unknown',
      'git-osxkeychain-not-configured',
    ],
  )

  const uncertainOutcomes = [
    { kind: 'exit', code: 2 },
    { kind: 'signal', signal: 'SIGTERM' },
    { kind: 'timeout' },
    { kind: 'error' },
    { kind: 'invalid', extra: true },
    'PRIVATE OUTPUT',
  ]
  for (const outcome of uncertainOutcomes) {
    const report = await inspectMacKeychain({
      platform: 'darwin',
      home,
      uid: process.getuid(),
      commands: fixedCommands(),
      runStatus: async () => outcome,
    })
    assert.equal(report.provider.userDomainState, 'unknown')
    assert.equal(report.gitCredentialHelper.state, 'unknown')
    assert.deepEqual(validateMacKeychainReport(report, { home }), [])
  }

  const missing = await inspectMacKeychain({
    platform: 'darwin',
    home,
    uid: process.getuid(),
    commands: {
      git: null,
      security: null,
    },
    runStatus: async () => {
      assert.fail('no command should run when fixed tools are unavailable')
    },
  })
  assert.equal(missing.provider.toolState, 'unavailable')
  assert.equal(missing.provider.userDomainState, 'unknown')
  assert.equal(missing.gitCredentialHelper.state, 'unknown')
  assert.deepEqual(validateMacKeychainReport(missing, { home }), [])
  assert.ok(
    checkMacKeychainReport(missing, { home })
      .includes('macos-security-unavailable'),
  )
})

test('the bounded status runner removes descendant processes on timeout and close', async (context) => {
  const home = temporaryHome(context)
  installMatchingKeepGate(home)
  const probe = join(home, 'slow-status-probe')
  const pidFile = join(home, 'slow-child.pid')
  writeFileSync(
    probe,
    [
      '#!/bin/sh',
      'pid_file="${0%/*}/slow-child.pid"',
      '/bin/sleep 30 &',
      'child_pid=$!',
      'printf "%s\\n" "$child_pid" > "$pid_file"',
      'wait "$child_pid"',
      '',
    ].join('\n'),
    { mode: 0o700 },
  )
  const childPids = []
  context.after(() => {
    for (const childPid of childPids) {
      try {
        process.kill(childPid, 'SIGKILL')
      } catch {
        // The bounded runner already removed it.
      }
    }
  })

  const report = await inspectMacKeychain({
    platform: 'darwin',
    home,
    uid: process.getuid(),
    timeoutMs: 500,
    commands: {
      git: null,
      security: probe,
    },
  })
  assert.equal(report.provider.userDomainState, 'unknown')
  assert.equal(existsSync(pidFile), true)
  const childPid = Number.parseInt(
    readFileSync(pidFile, 'utf8').trim(),
    10,
  )
  childPids.push(childPid)
  assert.equal(Number.isInteger(childPid), true)
  assert.equal(await processExited(childPid), true)

  const exitProbe = join(home, 'exit-status-probe')
  const exitPidFile = join(home, 'exit-child.pid')
  writeFileSync(
    exitProbe,
    [
      '#!/bin/sh',
      'pid_file="${0%/*}/exit-child.pid"',
      '/bin/sleep 30 &',
      'child_pid=$!',
      'printf "%s\\n" "$child_pid" > "$pid_file"',
      'exit 0',
      '',
    ].join('\n'),
    { mode: 0o700 },
  )
  const exitedReport = await inspectMacKeychain({
    platform: 'darwin',
    home,
    uid: process.getuid(),
    timeoutMs: 500,
    commands: {
      git: null,
      security: exitProbe,
    },
  })
  assert.equal(exitedReport.provider.userDomainState, 'available')
  assert.equal(existsSync(exitPidFile), true)
  const exitChildPid = Number.parseInt(
    readFileSync(exitPidFile, 'utf8').trim(),
    10,
  )
  childPids.push(exitChildPid)
  assert.equal(Number.isInteger(exitChildPid), true)
  assert.equal(await processExited(exitChildPid), true)
})

test('the keep gate reports only final owner, mode, and path-match evidence', async (context) => {
  const home = temporaryHome(context)
  const sourceDirectory = join(home, 'keep')
  const gateDirectory = join(home, '.local', 'bin')
  mkdirSync(sourceDirectory, { mode: 0o700 })
  mkdirSync(gateDirectory, { mode: 0o700, recursive: true })
  const source = join(sourceDirectory, 'keep')
  const substitute = join(sourceDirectory, 'substitute')
  const gate = join(gateDirectory, 'keep')
  writeFileSync(source, '#!/bin/zsh\n', { mode: 0o700 })
  writeFileSync(substitute, '#!/bin/zsh\n', { mode: 0o700 })
  symlinkSync(substitute, gate)

  const baseOptions = {
    platform: 'darwin',
    home,
    uid: process.getuid(),
    commands: fixedCommands(),
    runStatus: async () => EXIT_ZERO,
  }
  const substituted = await inspectMacKeychain(baseOptions)
  assert.equal(
    substituted.gate.evidenceState,
    'owner-mode-path-mismatch',
  )
  assert.ok(
    checkMacKeychainReport(substituted, { home })
      .includes('keep-gate-metadata-mismatch'),
  )
  assert.deepEqual(validateMacKeychainReport(substituted, { home }), [])
  assert.doesNotMatch(JSON.stringify(substituted), new RegExp(home))

  rmSync(gate)
  symlinkSync(source, gate)
  chmodSync(source, 0o722)
  const writable = await inspectMacKeychain(baseOptions)
  assert.equal(
    writable.gate.evidenceState,
    'owner-mode-path-mismatch',
  )

  chmodSync(source, 0o700)
  const wrongUid = await inspectMacKeychain({
    ...baseOptions,
    uid: process.getuid() + 1,
  })
  assert.equal(
    wrongUid.gate.evidenceState,
    'owner-mode-path-mismatch',
  )

  rmSync(gate)
  const missing = await inspectMacKeychain(baseOptions)
  assert.equal(missing.gate.evidenceState, 'unavailable')
  assert.equal(missing.gate.toolState, 'unavailable')
  assert.ok(
    checkMacKeychainReport(missing, { home })
      .includes('keep-gate-unavailable'),
  )
})

test('non-macOS hosts are not applicable and execute no probes', async () => {
  const report = await inspectMacKeychain({
    platform: 'linux',
    commands: fixedCommands(),
    runStatus: async () => {
      assert.fail('macOS probes must not run on another platform')
    },
  })

  assert.equal(report.platform, 'other')
  assert.equal(report.provider.toolState, 'not-applicable')
  assert.equal(report.gate.evidenceState, 'not-applicable')
  assert.equal(report.gitCredentialHelper.state, 'not-applicable')
  assert.deepEqual(
    validateMacKeychainReport(report, { home: '/fixture/home' }),
    [],
  )
  assert.deepEqual(
    checkMacKeychainReport(report, { home: '/fixture/home' }),
    [],
  )
  await assert.rejects(
    inspectMacKeychain({
      platform: 'darwin',
      home: '/fixture/home',
      uid: '--help',
      commands: fixedCommands(),
      runStatus: async () => EXIT_ZERO,
    }),
    /non-negative integer/,
  )
})

test('exact schema validation rejects arbitrary content and extra controls', async (context) => {
  const home = temporaryHome(context)
  installMatchingKeepGate(home)
  const valid = await inspectMacKeychain({
    platform: 'darwin',
    home,
    uid: process.getuid(),
    commands: fixedCommands(),
    runStatus: async () => EXIT_ZERO,
  })
  assert.deepEqual(validateMacKeychainReport(valid, { home }), [])

  const privateText = 'do-not-reflect-this-private-value'
  const cases = [
    {
      mutate: (report) => {
        report[privateText] = privateText
      },
      issue: 'keychain-schema-extra-field',
    },
    {
      mutate: (report) => {
        report[Symbol(privateText)] = privateText
      },
      issue: 'keychain-schema-extra-field',
    },
    {
      mutate: (report) => {
        report.provider[privateText] = privateText
      },
      issue: 'keychain-schema-extra-field',
    },
    {
      mutate: (report) => {
        report.meaning = privateText
      },
      issue: 'keychain-schema-invalid-value',
    },
    {
      mutate: (report) => {
        report.control[privateText] = true
      },
      issue: 'keychain-schema-extra-field',
    },
    {
      mutate: (report) => {
        Object.defineProperty(report.control, privateText, {
          enumerable: false,
          value: true,
        })
      },
      issue: 'keychain-schema-extra-field',
    },
    {
      mutate: (report) => {
        report.control.writes = true
      },
      issue: 'keychain-schema-invalid-value',
    },
    {
      mutate: (report) => {
        report.control.readsCoarseMetadata = false
      },
      issue: 'keychain-schema-invalid-value',
    },
    {
      mutate: (report) => {
        report.evidence.push(privateText)
      },
      issue: 'keychain-schema-invalid-value',
    },
    {
      mutate: (report) => {
        delete report.gate.kind
      },
      issue: 'keychain-schema-missing-field',
    },
  ]

  for (const { mutate, issue } of cases) {
    const report = JSON.parse(JSON.stringify(valid))
    mutate(report)
    const validation = validateMacKeychainReport(report, { home })
    assert.ok(validation.includes(issue))
    assert.deepEqual(
      checkMacKeychainReport(report, { home }),
      validation,
    )
    assert.doesNotMatch(JSON.stringify(validation), new RegExp(privateText))
  }

  const homeLeak = JSON.parse(JSON.stringify(valid))
  homeLeak.meaning = '/Users/private/private'
  const leakIssues = validateMacKeychainReport(homeLeak, {
    home: '/Users/private',
  })
  assert.ok(leakIssues.includes('account-home-leak'))
  assert.ok(leakIssues.includes('absolute-path-leak'))
  assert.ok(leakIssues.includes('keychain-schema-invalid-value'))
})
