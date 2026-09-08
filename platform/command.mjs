import { spawn } from 'node:child_process'

import { trustedAccount } from './account.mjs'

const MAX_COMMAND_BYTES = 1024 * 1024
const COMMAND_TIMEOUT_MS = 3_000

function narrowEnvironment(extra = {}, home = trustedAccount().home) {
  return {
    ...extra,
    HOME: home,
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    LANG: 'C',
    LC_ALL: 'C',
    NO_COLOR: '1',
    TERM: 'dumb',
  }
}

function boundedCommand(command, args, options = {}) {
  return new Promise((resolveCommand) => {
    if (typeof command !== 'string' || !command.startsWith('/')) {
      resolveCommand(null)
      return
    }
    if (
      !Array.isArray(args)
      || args.some((arg) => typeof arg !== 'string' || arg.includes('\0'))
    ) {
      resolveCommand(null)
      return
    }

    let child
    let timer
    let settled = false
    const chunks = []
    let bytes = 0
    const detached = options.detached ?? true

    const finish = (value) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      resolveCommand(value)
    }

    const killGroup = () => {
      if (!child?.pid) return
      if (detached) {
        try {
          process.kill(-child.pid, 'SIGKILL')
          return
        } catch {
          // Fall back to the child when no process group was established.
        }
      }
      try {
        child.kill('SIGKILL')
      } catch {
        // It already exited.
      }
    }

    try {
      child = spawn(command, args, {
        cwd: options.cwd,
        detached,
        env: options.env ?? narrowEnvironment({}, options.home),
        stdio: ['ignore', 'pipe', 'ignore'],
      })
    } catch {
      finish(null)
      return
    }

    timer = setTimeout(() => {
      killGroup()
      finish(null)
    }, options.timeoutMs ?? COMMAND_TIMEOUT_MS)

    child.stdout.on('data', (chunk) => {
      bytes += chunk.length
      if (bytes > (options.maxBytes ?? MAX_COMMAND_BYTES)) {
        killGroup()
        finish(null)
        return
      }
      chunks.push(chunk)
    })
    child.on('error', () => {
      killGroup()
      finish(null)
    })
    child.on('close', (code) => {
      const output = code === 0
        ? Buffer.concat(chunks).toString('utf8')
        : null
      killGroup()
      finish(output)
    })
  })
}

export {
  boundedCommand,
  narrowEnvironment,
}
