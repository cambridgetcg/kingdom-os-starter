import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { EventEmitter, getEventListeners, once } from 'node:events'
import test from 'node:test'

import {
  MAX_AWAKE_PID,
  MAX_AWAKE_SECONDS,
  macAwakeExitCode,
  renderMacAwakeReport,
  runMacAwake,
  validateMacAwakeReport,
} from '../platform/macos-awake.mjs'

const request = { pid: 42, seconds: 1 }
const target = { state: 'present', pid: 42, uid: 1000, startedAt: 'fixture-start' }

class Child extends EventEmitter {
  pid = 4321
  calls = []
  respondsTo = new Set(['SIGTERM', 'SIGKILL'])

  kill(name) {
    this.calls.push(name)
    if (this.respondsTo.has(name)) {
      queueMicrotask(() => this.emit('exit', null, name))
    }
    return true
  }
}

function fixture(overrides = {}) {
  const child = new Child()
  const controller = new AbortController()
  const calls = []
  return {
    child, controller, calls,
    options: {
      platform: 'darwin', uid: 1000, euid: 1000, selfPid: 1234,
      signal: controller.signal,
      executableAvailable: () => true,
      observeTarget: async () => ({ ...target }),
      pollMs: 5, killGraceMs: 10, cleanupMs: 80,
      spawn: (...args) => {
        calls.push(args)
        queueMicrotask(() => child.emit('spawn'))
        return child
      },
      ...overrides,
    },
  }
}

function valid(report, code) {
  assert.deepEqual(validateMacAwakeReport(report), [])
  assert.equal(macAwakeExitCode(report), code)
  assert.equal(report.assertionInstallation, 'not-observed')
  assert.equal(report.actualWakefulness, 'not-observed')
  assert.equal(report.targetBinding, 'non-atomic')
}

async function cancelledReport(name = 'SIGINT') {
  const f = fixture()
  const result = runMacAwake(request, f.options)
  await once(f.child, 'spawn')
  f.controller.abort(name)
  return result
}

test('requests are exact bounded numeric records before any probe', async () => {
  let probes = 0
  const f = fixture({ observeTarget: async () => { probes += 1; return target } })
  for (const value of [
    null, {}, [], { ...request, extra: true },
    { pid: '42', seconds: 1 }, { pid: 0, seconds: 1 },
    { pid: -1, seconds: 1 }, { pid: MAX_AWAKE_PID + 1, seconds: 1 },
    { pid: 1.5, seconds: 1 }, { pid: 42, seconds: 0 },
    { pid: 42, seconds: MAX_AWAKE_SECONDS + 1 },
    { pid: 42, seconds: Infinity }, { pid: 42, seconds: 1.5 },
    Object.assign(Object.create({}), request), new Proxy(request, {}),
    { get pid() { assert.fail('request getter ran') }, seconds: 1 },
  ]) assert.equal(await runMacAwake(value, f.options), null)
  assert.equal(probes, 0)
  assert.equal(f.calls.length, 0)
})

test('platform, caller, target, executable, and control refusals never spawn', async () => {
  const cases = [
    [{ signal: undefined }, 'invalid-control'],
    [{ signal: { aborted: false } }, 'invalid-control'],
    [{ platform: 'linux' }, 'unsupported-platform'],
    [{ uid: 0, euid: 0 }, 'privileged-caller'],
    [{ euid: 0 }, 'privileged-caller'],
    [{ selfPid: 42 }, 'self-target'],
    [{ observeTarget: async () => ({ state: 'absent' }) }, 'target-unavailable'],
    [{ observeTarget: async () => ({ state: 'uncertain' }) }, 'target-uncertain'],
    [{ observeTarget: async () => ({ ...target, uid: 1001 }) }, 'target-other-user'],
    [{ observeTarget: async () => ({ ...target, pid: 43 }) }, 'target-uncertain'],
    [{ executableAvailable: () => false }, 'executable-unavailable'],
  ]
  for (const [overrides, reason] of cases) {
    const f = fixture(overrides)
    const report = await runMacAwake(request, f.options)
    valid(report, 1)
    assert.equal(report.stop.reason, reason)
    assert.equal(f.calls.length, 0)
    assert.equal(getEventListeners(f.controller.signal, 'abort').length, 0)
  }
})

test('native invocation has fixed args, no utility operand, and no inherited environment', async () => {
  const previous = process.env.KINGDOM_AWAKE_TEST_SECRET
  process.env.KINGDOM_AWAKE_TEST_SECRET = 'do-not-forward'
  try {
    const f = fixture()
    const result = runMacAwake(request, f.options)
    await once(f.child, 'spawn')
    f.controller.abort('SIGINT')
    const report = await result
    valid(report, 130)
    assert.deepEqual(f.calls, [[
      '/usr/bin/caffeinate', ['-i', '-t', '1', '-w', '42'],
      {
        shell: false, detached: false, cwd: '/', stdio: 'ignore',
        env: {
          HOME: '/', PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
          LANG: 'C', LC_ALL: 'C', NO_COLOR: '1', TERM: 'dumb',
        },
      },
    ]])
    assert.equal(report.scope, 'host-wide-idle-system-sleep')
    assert.equal(report.macosAuthorization, 'not-required')
    assert.doesNotMatch(JSON.stringify(report), /do-not-forward|fixture-start/)
  } finally {
    if (previous === undefined) delete process.env.KINGDOM_AWAKE_TEST_SECRET
    else process.env.KINGDOM_AWAKE_TEST_SECRET = previous
  }
})

test('pre-spawn cancellation and cancellation during preflight return without action', async () => {
  for (const when of ['before', 'during', 'last-check']) {
    const f = fixture()
    if (when === 'before') f.controller.abort('SIGTERM')
    if (when === 'during') {
      f.options.observeTarget = async () => {
        f.controller.abort('SIGTERM')
        return target
      }
    }
    if (when === 'last-check') {
      f.options.executableAvailable = () => {
        f.controller.abort('SIGTERM')
        return true
      }
    }
    const report = await runMacAwake(request, f.options)
    valid(report, 143)
    assert.equal(report.stop.reason, 'cancelled')
    assert.equal(report.spawn.attempted, false)
    assert.equal(f.calls.length, 0)
    assert.equal(getEventListeners(f.controller.signal, 'abort').length, 0)
  }
})

test('cancellation does not wait for a hung preflight or active target observation', async () => {
  for (const active of [false, true]) {
    let observations = 0
    const f = fixture({
      observeTarget: async () => {
        observations += 1
        if (active && observations === 1) return target
        return new Promise(() => {})
      },
    })
    const result = runMacAwake(request, f.options)
    if (active) await once(f.child, 'spawn')
    else await new Promise((resolve) => setImmediate(resolve))
    f.controller.abort('SIGHUP')
    const report = await result
    valid(report, 129)
    assert.equal(report.spawn.observed, active)
    assert.equal(report.cleanup.exitConfirmed, active)
    assert.equal(getEventListeners(f.controller.signal, 'abort').length, 0)
  }
})

test('unresponsive preflight is bounded and fails to rest', { timeout: 2000 }, async () => {
  const f = fixture({ observeTarget: () => new Promise(() => {}) })
  const report = await runMacAwake(request, f.options)
  valid(report, 1)
  assert.equal(report.stop.reason, 'target-uncertain')
  assert.equal(f.calls.length, 0)
})

test('target loss, changed identity, and failed observations stop only the owned child', async () => {
  for (const current of [
    { state: 'absent' }, { ...target, startedAt: 'replacement' },
    { ...target, uid: 1001 }, { state: 'uncertain' }, null,
  ]) {
    let calls = 0
    const f = fixture({ observeTarget: async () => ++calls === 1 ? target : current })
    const report = await runMacAwake(request, f.options)
    valid(report, current?.state === 'absent' ? 0 : 1)
    assert.equal(report.stop.reason, current?.state === 'absent'
      ? 'target-exit-observed' : 'target-identity-uncertain')
    assert.deepEqual(f.child.calls, ['SIGTERM'])
    assert.equal(report.spawn.childPid, 4321)
    assert.equal(report.request.pid, 42)
  }
})

test('deadline stops the owned child and awaits its observed exit', { timeout: 3000 }, async () => {
  const f = fixture()
  const report = await runMacAwake(request, f.options)
  valid(report, 0)
  assert.equal(report.stop.reason, 'deadline')
  assert.deepEqual(report.cleanup, { signals: ['SIGTERM'], exitConfirmed: true })
  assert.equal(getEventListeners(f.controller.signal, 'abort').length, 0)
})

test('native exit can confirm target absence but cannot invent completion', async () => {
  for (const absent of [true, false]) {
    let gone = false
    const f = fixture({ observeTarget: async () => gone ? { state: 'absent' } : target })
    const result = runMacAwake(request, f.options)
    await once(f.child, 'spawn')
    gone = absent
    f.child.emit('exit', 0, null)
    const report = await result
    valid(report, absent ? 0 : 1)
    assert.equal(report.stop.reason, absent ? 'target-exit-observed' : 'child-exit-unclassified')
    assert.deepEqual(f.child.calls, [])
    assert.equal(report.child.exitObserved, true)
  }
})

test('spawn failure and post-spawn errors do not reflect child errors', async () => {
  const privateText = 'PRIVATE-error-payload'
  const thrown = fixture({ spawn: () => { throw new Error(privateText) } })
  const noChild = await runMacAwake(request, thrown.options)
  valid(noChild, 1)
  assert.equal(noChild.stop.reason, 'spawn-error')
  assert.equal(noChild.spawn.attempted, true)
  assert.equal(noChild.spawn.observed, false)
  const f = fixture()
  const result = runMacAwake(request, f.options)
  await once(f.child, 'spawn')
  f.child.emit('error', new Error(privateText))
  const report = await result
  valid(report, 1)
  assert.equal(report.stop.reason, 'spawn-error')
  assert.equal(report.cleanup.exitConfirmed, true)
  assert.doesNotMatch(JSON.stringify([noChild, report]), new RegExp(privateText))
})

test('TERM resistance escalates to KILL without claiming kill means exit', async () => {
  const f = fixture()
  f.child.respondsTo = new Set(['SIGKILL'])
  const result = runMacAwake(request, f.options)
  await once(f.child, 'spawn')
  f.controller.abort('SIGINT')
  const report = await result
  valid(report, 130)
  assert.deepEqual(f.child.calls, ['SIGTERM', 'SIGKILL'])
  assert.equal(report.child.signal, 'SIGKILL')
  assert.equal(report.cleanup.exitConfirmed, true)
})

test('unconfirmed cleanup settles as failure within a bound', { timeout: 1000 }, async () => {
  const f = fixture()
  f.child.respondsTo.clear()
  const result = runMacAwake(request, f.options)
  await once(f.child, 'spawn')
  f.controller.abort('SIGINT')
  const report = await result
  valid(report, 1)
  assert.equal(report.stop.reason, 'cleanup-unconfirmed')
  assert.equal(report.cleanup.exitConfirmed, false)
  assert.deepEqual(f.child.calls, ['SIGTERM', 'SIGKILL'])
})

test('settlement removes timers and listeners and never sends a late signal', async () => {
  const f = fixture()
  const result = runMacAwake(request, f.options)
  await once(f.child, 'spawn')
  f.controller.abort('SIGINT')
  f.child.emit('exit', null, 'SIGTERM')
  const report = await result
  valid(report, 130)
  const snapshot = JSON.stringify(report)
  await new Promise((resolve) => setTimeout(resolve, 100))
  assert.deepEqual(f.child.calls, ['SIGTERM'])
  assert.equal(f.child.eventNames().length, 0)
  assert.equal(getEventListeners(f.controller.signal, 'abort').length, 0)
  assert.equal(JSON.stringify(report), snapshot)
})

test('signal exit codes and caller cancellation remain distinct', async () => {
  for (const [name, code] of [['SIGINT', 130], ['SIGTERM', 143], ['SIGHUP', 129], ['private-reason', 1]]) {
    const report = await cancelledReport(name)
    valid(report, code)
    assert.equal(report.stop.cancellation, name === 'private-reason' ? 'caller' : name)
    assert.doesNotMatch(JSON.stringify(report), /private-reason/)
    assert.match(renderMacAwakeReport(report), /actual wakefulness not observed/)
  }
})

test('cancellation during spawn still terminates the eventual owned child', async () => {
  const f = fixture()
  const original = f.options.spawn
  f.options.spawn = (...args) => {
    f.controller.abort('SIGTERM')
    return original(...args)
  }
  const report = await runMacAwake(request, f.options)
  valid(report, 143)
  assert.deepEqual(f.child.calls, ['SIGTERM'])
  assert.equal(report.cleanup.exitConfirmed, true)
})

test('spawn errors before the spawn event settle without an owned process', async () => {
  const f = fixture()
  f.child.pid = undefined
  f.options.spawn = () => {
    queueMicrotask(() => f.child.emit('error', new Error('PRIVATE-spawn-error')))
    return f.child
  }
  const report = await runMacAwake(request, f.options)
  valid(report, 1)
  assert.equal(report.spawn.observed, false)
  assert.equal(report.stop.reason, 'spawn-error')
  assert.deepEqual(f.child.calls, [])
})

test('an owned self-expiring process confirms TERM-to-KILL cleanup without caffeinate', { timeout: 4000 }, async (t) => {
  let actualChild
  let ready
  const started = new Promise((resolve) => { ready = resolve })
  const f = fixture({
    spawn: (command, args, options) => {
      assert.equal(command, '/usr/bin/caffeinate')
      assert.deepEqual(args, ['-i', '-t', '1', '-w', '42'])
      actualChild = spawn(process.execPath, ['-e',
        "process.on('SIGTERM', () => {}); process.stdout.write('ready'); setTimeout(() => process.exit(0), 2000)",
      ], { ...options, stdio: ['ignore', 'pipe', 'ignore'] })
      actualChild.stdout.once('data', ready)
      return actualChild
    },
  })
  t.after(async () => {
    if (actualChild?.pid && actualChild.exitCode === null && actualChild.signalCode === null) {
      const closed = once(actualChild, 'close')
      actualChild.kill('SIGKILL')
      await closed
    }
  })
  const result = runMacAwake(request, f.options)
  await started
  f.controller.abort('SIGTERM')
  const report = await result
  valid(report, 143)
  assert.deepEqual(report.cleanup.signals, ['SIGTERM', 'SIGKILL'])
  assert.equal(report.child.signal, 'SIGKILL')
  assert.equal(actualChild.signalCode, 'SIGKILL')
})

test('the validated request is snapshotted before asynchronous preflight', async () => {
  const mutable = { ...request }
  const inspected = []
  const f = fixture({
    observeTarget: async (pid) => {
      inspected.push(pid)
      return { ...target, pid }
    },
  })
  const result = runMacAwake(mutable, f.options)
  mutable.pid = 1234
  mutable.seconds = 3601
  await once(f.child, 'spawn')
  f.controller.abort('SIGINT')
  const report = await result
  valid(report, 130)
  assert.deepEqual(report.request, request)
  assert.deepEqual(f.calls[0][1], ['-i', '-t', '1', '-w', '42'])
  assert.ok(inspected.every((pid) => pid === 42))
})

test('unconfirmed cleanup releases the child event-loop reference', async () => {
  const f = fixture()
  let unrefs = 0
  f.child.unref = () => { unrefs += 1 }
  f.child.respondsTo.clear()
  const result = runMacAwake(request, f.options)
  await once(f.child, 'spawn')
  f.controller.abort('SIGINT')
  const report = await result
  valid(report, 1)
  assert.equal(report.stop.reason, 'cleanup-unconfirmed')
  assert.equal(unrefs, 1)
})

test('unconfirmed cleanup lets a real foreground caller exit before its expiring fixture child', { timeout: 4000 }, async (t) => {
  const moduleUrl = new URL('../platform/macos-awake.mjs', import.meta.url).href
  const code = `
    import { spawn } from 'node:child_process'
    import { runMacAwake } from ${JSON.stringify(moduleUrl)}
    const controller = new AbortController()
    const report = await runMacAwake({ pid: 42, seconds: 1 }, {
      platform: 'darwin', uid: 1000, euid: 1000, selfPid: 1234,
      signal: controller.signal,
      executableAvailable: () => true,
      observeTarget: async () => ({ state: 'present', pid: 42, uid: 1000, startedAt: 'fixture' }),
      killGraceMs: 10, cleanupMs: 50,
      spawn: (_command, _args, options) => {
        const child = spawn(process.execPath, ['-e', 'setTimeout(() => process.exit(0), 5000)'], options)
        child.kill = () => false
        child.once('spawn', () => {
          console.log(JSON.stringify({ ownedChild: child.pid }))
          controller.abort('SIGINT')
        })
        return child
      },
    })
    console.log(JSON.stringify(report))
    process.exitCode = 1
  `
  const parent = spawn(process.execPath, ['--input-type=module', '-e', code], {
    cwd: '/', stdio: ['ignore', 'pipe', 'ignore'],
    env: { HOME: '/', PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' },
  })
  let output = ''
  let timer
  parent.stdout.on('data', (chunk) => { output += chunk.toString('utf8') })
  t.after(() => {
    clearTimeout(timer)
    if (parent.exitCode === null && parent.signalCode === null) parent.kill('SIGKILL')
    const match = /"ownedChild":(\d+)/.exec(output)
    if (match) {
      try { process.kill(Number(match[1]), 'SIGKILL') } catch (error) {
        if (error.code !== 'ESRCH') throw error
      }
    }
  })
  const exit = await Promise.race([
    once(parent, 'close').then(([code]) => code),
    new Promise((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error('foreground caller retained its child handle')), 2000)
    }),
  ])
  clearTimeout(timer)
  assert.equal(exit, 1)
  const [owned, report] = output.trim().split('\n').map((line) => JSON.parse(line))
  valid(report, 1)
  assert.equal(report.stop.reason, 'cleanup-unconfirmed')
  assert.equal(report.cleanup.exitConfirmed, false)
  assert.equal(report.spawn.childPid, owned.ownedChild)
  assert.doesNotThrow(() => process.kill(owned.ownedChild, 0))
})

test('unexpected native termination signals produce valid failure results', async () => {
  for (const name of ['SIGABRT', 'SIGSEGV', 'SIGQUIT']) {
    const f = fixture()
    const result = runMacAwake(request, f.options)
    await once(f.child, 'spawn')
    f.child.emit('exit', null, name)
    const report = await result
    valid(report, 1)
    assert.equal(report.stop.reason, 'child-exit-unclassified')
    assert.equal(report.child.signal, name)
    assert.equal(report.cleanup.exitConfirmed, true)
    assert.deepEqual(f.child.calls, [])
  }
})

test('result validation rejects extra data, accessors, and promoted evidence', async () => {
  const report = await cancelledReport()
  for (const mutate of [
    (r) => { r.secret = 'PRIVATE' },
    (r) => { r.assertionInstallation = 'confirmed' },
    (r) => { r.actualWakefulness = 'confirmed' },
    (r) => { r.targetBinding = 'atomic' },
    (r) => { r.request.seconds = 0 },
    (r) => { r.child.exitObserved = false },
    (r) => { r.child.signal = 'PRIVATE' },
    (r) => { r.stop.cancellation = 'PRIVATE' },
    (r) => { r.cleanup.signals = ['SIGKILL', 'SIGTERM'] },
    (r) => { r.cleanup.signals[2] = 'SIGKILL' },
    (r) => { r.cleanup.signals = new Array(1) },
    (r) => { r.cleanup.signals.private = 'PRIVATE' },
    (r) => { r.child = { ...r.child, private: 'PRIVATE' } },
    (r) => { Object.defineProperty(r, 'scope', { get() { assert.fail('getter ran') } }) },
    (r) => { Object.defineProperty(r.cleanup.signals, '0', { get() { assert.fail('getter ran') } }) },
  ]) {
    const bad = structuredClone(report)
    mutate(bad)
    assert.notDeepEqual(validateMacAwakeReport(bad), [])
    assert.equal(macAwakeExitCode(bad), 1)
  }
  assert.notDeepEqual(validateMacAwakeReport(new Proxy(report, {})), [])
})
