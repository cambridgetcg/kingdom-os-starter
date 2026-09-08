import { spawn } from 'node:child_process'
import { accessSync, constants, statSync } from 'node:fs'
import { constants as osConstants } from 'node:os'
import { types } from 'node:util'

import { boundedCommand, narrowEnvironment } from './command.mjs'

const MAX_AWAKE_SECONDS = 3600
const MAX_AWAKE_PID = 2147483647
const EXECUTABLE = '/usr/bin/caffeinate'
const SCHEMA = 'kingdom.macos-awake/0.1'
const CANCELLATION_SIGNALS = ['SIGINT', 'SIGTERM', 'SIGHUP']
const EXIT_SIGNALS = new Set(Object.keys(osConstants.signals))
const REASONS = [
  'unsupported-platform', 'privileged-caller', 'invalid-control',
  'self-target', 'target-unavailable', 'target-uncertain', 'target-other-user',
  'executable-unavailable', 'cancelled', 'deadline', 'target-exit-observed',
  'target-identity-uncertain', 'spawn-error', 'child-exit-unclassified',
  'internal-error', 'cleanup-unconfirmed',
]
const CANCELLED = Symbol('cancelled')

function dataRecord(value, keys) {
  if (!value || typeof value !== 'object' || types.isProxy(value)) return false
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return false
  const actual = Reflect.ownKeys(value)
  return actual.length === keys.length && actual.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    return keys.includes(key) && descriptor.enumerable
      && Object.hasOwn(descriptor, 'value')
  })
}

function validPid(value) {
  return Number.isInteger(value) && value > 0 && value <= MAX_AWAKE_PID
}

function validRequest(request) {
  return dataRecord(request, ['pid', 'seconds'])
    && validPid(request.pid) && Number.isInteger(request.seconds)
    && request.seconds >= 1 && request.seconds <= MAX_AWAKE_SECONDS
}

function newReport(request) {
  return {
    schema: SCHEMA,
    request: { ...request },
    scope: 'host-wide-idle-system-sleep',
    spawn: { attempted: false, observed: false, childPid: null },
    child: { exitObserved: false, code: null, signal: null },
    stop: { reason: 'internal-error', cancellation: null },
    cleanup: { signals: [], exitConfirmed: false },
    targetBinding: 'non-atomic',
    macosAuthorization: 'not-required',
    assertionInstallation: 'not-observed',
    actualWakefulness: 'not-observed',
  }
}

function executableAvailable() {
  try {
    accessSync(EXECUTABLE, constants.X_OK)
    return statSync(EXECUTABLE).isFile()
  } catch {
    return false
  }
}

async function observeTarget(pid) {
  const output = await boundedCommand('/bin/ps', [
    '-p', String(pid), '-o', 'pid=,uid=,lstart=,stat=',
  ], {
    timeoutMs: 500, maxBytes: 1024, detached: false,
    cwd: '/', env: narrowEnvironment({}, '/'),
  })
  if (output === null || output.trim() === '') {
    try {
      // Signal zero queries existence; it delivers no signal to the target.
      process.kill(pid, 0)
    } catch (error) {
      if (error.code === 'ESRCH') return { state: 'absent' }
    }
    return { state: 'uncertain' }
  }
  const match = /^\s*(\d+)\s+(\d+)\s+([A-Za-z]{3} [A-Za-z]{3} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4})\s+([RSDTIUZ][A-Za-z+<>=-]*)\s*$/.exec(output)
  if (!match || Number(match[1]) !== pid) return { state: 'uncertain' }
  if (match[4].startsWith('Z')) return { state: 'absent' }
  return {
    state: 'present', pid, uid: Number(match[2]), startedAt: match[3],
  }
}

function presentTarget(target, pid) {
  return dataRecord(target, ['state', 'pid', 'uid', 'startedAt'])
    && target.state === 'present' && target.pid === pid
    && Number.isInteger(target.uid) && target.uid >= 0
    && typeof target.startedAt === 'string'
    && target.startedAt.length > 0 && target.startedAt.length <= 64
}

async function runMacAwake(request, options = {}) {
  if (!validRequest(request)) return null
  request = { ...request }
  const report = newReport(request)
  const signal = options.signal
  const refuse = (reason) => {
    report.stop.reason = reason
    if (reason === 'cancelled') {
      report.stop.cancellation = CANCELLATION_SIGNALS.includes(signal?.reason)
        ? signal.reason : 'caller'
    }
    return report
  }
  if (types.isProxy(signal) || !(signal instanceof AbortSignal)) {
    return refuse('invalid-control')
  }
  const inspect = options.observeTarget ?? observeTarget
  let stopActive
  let cancelResolve
  const cancelled = new Promise((resolve) => { cancelResolve = resolve })
  const onAbort = () => {
    cancelResolve(CANCELLED)
    stopActive?.('cancelled')
  }
  signal.addEventListener('abort', onAbort, { once: true })
  const observe = async () => {
    let timer
    try {
      return await Promise.race([
        Promise.resolve().then(() => inspect(request.pid)),
        new Promise((resolve) => {
          timer = setTimeout(() => resolve({ state: 'uncertain' }), 600)
        }),
        cancelled,
      ])
    } catch {
      return { state: 'uncertain' }
    } finally {
      clearTimeout(timer)
    }
  }
  try {
    if (signal.aborted) return refuse('cancelled')
    if ((options.platform ?? process.platform) !== 'darwin') {
      return refuse('unsupported-platform')
    }
    const uid = options.uid ?? process.getuid?.()
    const euid = options.euid ?? process.geteuid?.()
    if (!Number.isInteger(uid) || uid <= 0 || euid !== uid) {
      return refuse('privileged-caller')
    }
    if (request.pid === (options.selfPid ?? process.pid)) {
      return refuse('self-target')
    }
    const initial = await observe()
    if (signal.aborted || initial === CANCELLED) return refuse('cancelled')
    if (initial?.state === 'absent') return refuse('target-unavailable')
    if (!presentTarget(initial, request.pid)) return refuse('target-uncertain')
    if (initial.uid !== uid) return refuse('target-other-user')
    if (!(options.executableAvailable ?? executableAvailable)()) {
      return refuse('executable-unavailable')
    }
    if (signal.aborted) return refuse('cancelled')

    return await new Promise((resolveLease) => {
      const startChild = options.spawn ?? spawn
      const now = options.now ?? (() => performance.now())
      const deadline = now() + request.seconds * 1000
      const timers = new Set()
      let child
      let settled = false
      let stopReason = null
      let exitObserved = false
      let polling = false
      const schedule = (fn, milliseconds) => {
        const timer = setTimeout(() => {
          timers.delete(timer)
          fn()
        }, milliseconds)
        timers.add(timer)
        return timer
      }
      const finish = (reason) => {
        if (settled) return
        settled = true
        stopActive = undefined
        for (const timer of timers) clearTimeout(timer)
        timers.clear()
        child?.removeListener('spawn', onSpawn)
        child?.removeListener('error', onError)
        child?.removeListener('exit', onExit)
        if (reason === 'cleanup-unconfirmed') child?.unref?.()
        refuse(reason)
        report.cleanup.exitConfirmed = exitObserved
        resolveLease(report)
      }
      const killChild = (name) => {
        if (settled || exitObserved || !child?.pid) return
        report.cleanup.signals.push(name)
        try { child.kill(name) } catch { /* Exit must still be observed. */ }
      }
      const stop = (reason) => {
        if (settled || stopReason !== null) return
        stopReason = reason
        if (exitObserved) {
          finish(reason)
          return
        }
        killChild('SIGTERM')
        if (settled) return
        schedule(() => killChild('SIGKILL'), options.killGraceMs ?? 250)
        schedule(() => finish('cleanup-unconfirmed'), options.cleanupMs ?? 1250)
      }
      const inspectActive = async () => {
        if (settled || stopReason || exitObserved || polling) return
        polling = true
        const current = await observe()
        polling = false
        if (settled || stopReason || exitObserved) return
        if (signal.aborted || current === CANCELLED) stop('cancelled')
        else if (current?.state === 'absent') stop('target-exit-observed')
        else if (!presentTarget(current, request.pid)
          || current.uid !== initial.uid
          || current.startedAt !== initial.startedAt) {
          stop('target-identity-uncertain')
        } else {
          schedule(() => { void inspectActive() }, options.pollMs ?? 250)
        }
      }
      const onSpawn = () => {
        report.spawn.observed = true
        report.spawn.childPid = child.pid
        if (stopReason) {
          if (report.cleanup.signals.length === 0) killChild('SIGTERM')
          return
        }
        if (signal.aborted) stop('cancelled')
        else if (now() >= deadline) stop('deadline')
        else void inspectActive()
      }
      const onError = () => {
        if (settled) return
        if (!child?.pid) finish('spawn-error')
        else stop('spawn-error')
      }
      const onExit = (code, name) => {
        if (settled || exitObserved) return
        exitObserved = true
        report.child = { exitObserved: true, code, signal: name }
        for (const timer of timers) clearTimeout(timer)
        timers.clear()
        if (stopReason) {
          finish(stopReason)
        } else if (now() >= deadline) {
          finish('deadline')
        } else {
          void observe().then((current) => {
            if (settled) return
            if (signal.aborted || current === CANCELLED) finish('cancelled')
            else if (current?.state === 'absent') finish('target-exit-observed')
            else if (!presentTarget(current, request.pid)
              || current.uid !== initial.uid
              || current.startedAt !== initial.startedAt) {
              finish('target-identity-uncertain')
            } else finish('child-exit-unclassified')
          })
        }
      }
      stopActive = stop
      try {
        if (signal.aborted) {
          finish('cancelled')
          return
        }
        report.spawn.attempted = true
        child = startChild(EXECUTABLE, [
          '-i', '-t', String(request.seconds), '-w', String(request.pid),
        ], {
          shell: false, detached: false, cwd: '/',
          stdio: 'ignore', env: narrowEnvironment({}, '/'),
        })
        child.once('spawn', onSpawn)
        child.once('error', onError)
        child.once('exit', onExit)
        schedule(() => stop('deadline'), Math.max(0, deadline - now()))
        if (signal.aborted) stop('cancelled')
      } catch {
        if (child?.pid) stop('internal-error')
        else finish('spawn-error')
      }
    })
  } catch {
    return refuse('internal-error')
  } finally {
    signal.removeEventListener('abort', onAbort)
  }
}

function validateMacAwakeReport(report) {
  const fields = [
    'schema', 'request', 'scope', 'spawn', 'child', 'stop', 'cleanup',
    'targetBinding', 'macosAuthorization', 'assertionInstallation',
    'actualWakefulness',
  ]
  if (!dataRecord(report, fields)
    || !validRequest(report.request)
    || !dataRecord(report.spawn, ['attempted', 'observed', 'childPid'])
    || !dataRecord(report.child, ['exitObserved', 'code', 'signal'])
    || !dataRecord(report.stop, ['reason', 'cancellation'])
    || !dataRecord(report.cleanup, ['signals', 'exitConfirmed'])) {
    return ['awake-report-shape-invalid']
  }
  const { child, spawn: started, stop, cleanup } = report
  const signals = cleanup.signals
  if (!Array.isArray(signals) || types.isProxy(signals)
    || Object.getPrototypeOf(signals) !== Array.prototype
    || signals.length > 2
    || Reflect.ownKeys(signals).length !== signals.length + 1
    || !Array.from({ length: signals.length }, (_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(signals, String(index))
      return descriptor && Object.hasOwn(descriptor, 'value')
        && descriptor.enumerable && descriptor.value === ['SIGTERM', 'SIGKILL'][index]
    }).every(Boolean)) return ['awake-cleanup-invalid']
  if (report.schema !== SCHEMA
    || report.scope !== 'host-wide-idle-system-sleep'
    || report.targetBinding !== 'non-atomic'
    || report.macosAuthorization !== 'not-required'
    || report.assertionInstallation !== 'not-observed'
    || report.actualWakefulness !== 'not-observed'
    || !REASONS.includes(stop.reason)
    || ![true, false].includes(started.attempted)
    || ![true, false].includes(started.observed)
    || ![true, false].includes(child.exitObserved)
    || ![true, false].includes(cleanup.exitConfirmed)
    || (started.childPid !== null && !validPid(started.childPid))
    || (child.code !== null && (!Number.isInteger(child.code) || child.code < 0 || child.code > 255))
    || (child.signal !== null && !EXIT_SIGNALS.has(child.signal))
    || (child.code !== null && child.signal !== null)
    || (stop.reason === 'cancelled'
      ? !['SIGINT', 'SIGTERM', 'SIGHUP', 'caller'].includes(stop.cancellation)
      : stop.cancellation !== null)) return ['awake-report-value-invalid']
  if (cleanup.exitConfirmed !== child.exitObserved
    || (started.observed && (!started.attempted || !validPid(started.childPid)))
    || (!started.observed && started.childPid !== null)
    || (child.exitObserved && !started.observed)
    || (!child.exitObserved && (child.code !== null || child.signal !== null))
    || (child.exitObserved && child.code === null && child.signal === null)
    || (signals.length > 0 && !started.attempted)
    || (stop.reason === 'cleanup-unconfirmed' && cleanup.exitConfirmed)
    || (['deadline', 'target-exit-observed'].includes(stop.reason)
      && !cleanup.exitConfirmed)) return ['awake-report-evidence-invalid']
  return []
}

function macAwakeExitCode(report) {
  if (validateMacAwakeReport(report).length) return 1
  if (report.stop.reason === 'cancelled') {
    if (report.spawn.observed && !report.cleanup.exitConfirmed) return 1
    return { SIGINT: 130, SIGTERM: 143, SIGHUP: 129 }[report.stop.cancellation] ?? 1
  }
  const expectedExit = report.child.code === 0
    || report.cleanup.signals.includes(report.child.signal)
  return ['deadline', 'target-exit-observed'].includes(report.stop.reason)
    && report.cleanup.exitConfirmed && expectedExit ? 0 : 1
}

function renderMacAwakeReport(report) {
  return [
    'KINGDOM OS macOS awake — finite idle-sleep request',
    `  target       PID ${report.request.pid} · maximum ${report.request.seconds}s · non-atomic binding`,
    `  command      ${report.spawn.observed ? 'spawn observed' : 'not observed'} · child ${report.spawn.childPid ?? 'none'}`,
    `  stop         ${report.stop.reason}${report.stop.cancellation ? ` · ${report.stop.cancellation}` : ''}`,
    `  cleanup      ${report.cleanup.exitConfirmed ? 'child exit confirmed' : 'no child exit confirmed'}`,
    '  scope        host-wide idle system sleep only; may use battery; no permanent setting change',
    '  evidence     assertion installation and actual wakefulness not observed',
  ].join('\n')
}

export {
  MAX_AWAKE_PID,
  MAX_AWAKE_SECONDS,
  macAwakeExitCode,
  observeTarget,
  renderMacAwakeReport,
  runMacAwake,
  validateMacAwakeReport,
}
