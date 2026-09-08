import { execFileSync } from 'node:child_process'
import {
  accessSync,
  constants,
  lstatSync,
  realpathSync,
  statSync,
} from 'node:fs'
import { isAbsolute } from 'node:path'
import { TextDecoder } from 'node:util'

const ACCOUNT_RECORD_MAX_BYTES = 64 * 1024
const ACCOUNT_LOOKUP_TIMEOUT_MS = 3_000
const ACCOUNT_ENVIRONMENT = Object.freeze({
  HOME: '/',
  LANG: 'C',
  LC_ALL: 'C',
  NO_COLOR: '1',
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
  TERM: 'dumb',
})

function executable(candidates) {
  for (const candidate of candidates) {
    try {
      accessSync(candidate, constants.X_OK)
      if (statSync(candidate).isFile()) return candidate
    } catch {
      // Try the next fixed system path.
    }
  }
  return null
}

function accountCommand(command, args) {
  try {
    const output = execFileSync(command, args, {
      cwd: '/',
      env: ACCOUNT_ENVIRONMENT,
      maxBuffer: ACCOUNT_RECORD_MAX_BYTES,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: ACCOUNT_LOOKUP_TIMEOUT_MS,
    })
    return new TextDecoder('utf-8', { fatal: true }).decode(output)
  } catch {
    throw new Error('operating-system account record is unavailable')
  }
}

function numericUid(value) {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) return null
  const uid = Number(value)
  return Number.isSafeInteger(uid) ? uid : null
}

function validHome(value) {
  return (
    typeof value === 'string'
    && isAbsolute(value)
    && !/[\u0000-\u001f\u007f]/.test(value)
  )
}

function darwinAccountHome(uid) {
  const command = executable(['/usr/bin/dscacheutil'])
  if (!command) throw new Error('operating-system account record is unavailable')
  const output = accountCommand(command, ['-q', 'user', '-a', 'uid', String(uid)])
  const uids = output
    .split(/\r?\n/)
    .flatMap((line) => {
      const match = /^uid: ([0-9]+)$/.exec(line)
      return match ? [numericUid(match[1])] : []
    })
  const homes = output
    .split(/\r?\n/)
    .flatMap((line) => {
      const match = /^dir: (.+)$/.exec(line)
      return match ? [match[1]] : []
    })
  if (
    uids.length !== 1
    || uids[0] !== uid
    || homes.length !== 1
    || !validHome(homes[0])
  ) {
    throw new Error('operating-system account home is unavailable')
  }
  return homes[0]
}

function linuxAccountHome(uid) {
  const command = executable(['/usr/bin/getent', '/bin/getent'])
  if (!command) throw new Error('operating-system account record is unavailable')
  const output = accountCommand(command, ['passwd', String(uid)])
  const records = output.split(/\r?\n/).filter(Boolean)
  if (records.length !== 1) {
    throw new Error('operating-system account home is unavailable')
  }
  const fields = records[0].split(':')
  const home = fields[5]
  const recordedUid = numericUid(fields[2] ?? '')
  if (
    fields.length !== 7
    || recordedUid !== uid
    || !validHome(home)
  ) {
    throw new Error('operating-system account home is unavailable')
  }
  return home
}

function trustedAccount() {
  const platform = process.platform
  if (!['darwin', 'linux'].includes(platform)) {
    throw new Error('operating-system account lookup is unsupported')
  }
  const uid = typeof process.getuid === 'function' ? process.getuid() : null
  if (!Number.isInteger(uid) || uid < 0) {
    throw new Error('operating-system account uid is unavailable')
  }

  const recordedHome = platform === 'darwin'
    ? darwinAccountHome(uid)
    : linuxAccountHome(uid)
  if (!validHome(recordedHome)) {
    throw new Error('operating-system account home is unavailable')
  }

  let home
  let entry
  try {
    home = realpathSync(recordedHome)
    entry = lstatSync(home)
  } catch {
    throw new Error('account home is not one owned real directory')
  }
  if (
    !entry.isDirectory()
    || entry.isSymbolicLink()
    || (Number.isInteger(entry.uid) && entry.uid !== uid)
  ) {
    throw new Error('account home is not one owned real directory')
  }
  return { home, uid }
}

export {
  trustedAccount,
}
