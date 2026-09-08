# KINGDOM OS · macOS starter

A small set of readable local tools, with room to choose what you use.

This **0.1.0 preview** exports the macOS edge of KINGDOM OS: local capability and encryption explanations, bounded diagnostic observations, and one explicit keep-awake action. It is not the full OS, a hosted service, an agent identity, or a membership.

Reading, downloading, and extracting this source run nothing. Using a command is a separate choice. The optional [Foundation reference](foundation/FOUNDATION.md) supplies chosen commitments, not permission to operate someone else's machine.

## Requirements

- **Node.js 22 or newer**, supplied by you. No npm packages or package-manager installation is needed.
- macOS and its required native tools for the macOS commands. The live acceptance environment is **macOS 26.3.1 on Apple Silicon**; other releases and architectures are not claimed tested.
- An ordinary, unprivileged account for `awake`. It refuses root/elevated execution and other-user targets.

No Node binary, installer, shell integration, service, scheduler, or agent configuration is included.

## Inspect before use

The [release list](https://github.com/cambridgetcg/kingdom-os-starter/releases) holds published preview archives and their `SHA256SUMS`. The repository's [current release descriptor](https://raw.githubusercontent.com/cambridgetcg/kingdom-os-starter/main/release.json) names the exact source commit, artifact hash, requirements, and limits.

Check the named archive against the published checksum before extraction:

```sh
shasum -a 256 -c SHA256SUMS
```

A matching checksum establishes matching bytes, not that the code is safe or that you have authority to run it. The archive includes the complete selected source and tests; review them rather than relying on a private upstream link.

Extract into a directory you control. From the extracted `kingdom-os-starter-0.1.0` directory, the first two commands are static and make no host probe:

```sh
node bin/mac.mjs --help
node bin/mac.mjs explain power-hold-awake --json
```

No `sudo`, PATH change, global installation, or configuration edit is required. The broader Kingdom shell launcher is deliberately not included.

## Choose a command

| Command | What happens |
|---|---|
| `--help` | Prints usage; no host observation. |
| `explain CAPABILITY` | Reads the built-in capability description; no host observation. |
| `doctor` | Makes bounded observations of fixed native tools, coarse security settings, and Keychain posture. |
| `encryption` | Interprets the bounded capability and Keychain observations; it does not encrypt, decrypt, or attest hardware. |
| `keychain` | Observes provider/status and fixed gate metadata; it does not retrieve secret values or Keychain item names. |
| `policy CAPABILITY` | Names unmet requirements; its decision always remains `stop` and grants no authority. |
| `awake --pid PID --seconds N` | Requests one finite, host-wide idle-system-sleep assertion for an existing same-user process. |

Commands support `--json`. Invoking the CLI without arguments selects `doctor`, so use `--help` for a no-probe first look. These tools make no network requests and install no persistent state. Diagnostic observations can still query coarse information on the host; do not call them merely because this page was read.

### One finite awake request

Choose the PID of an already-running job and an explicit duration:

```sh
node bin/mac.mjs awake --pid 12345 --seconds 300
```

Replace `12345` with that job's actual PID. Both arguments are required; the duration is **1–3600 seconds**. There is no executable operand, general shell runner, automatic renewal, or detached mode.

The adapter uses only `/usr/bin/caffeinate -i -t N -w PID` for the power effect. It prevents **idle system sleep across the host** and may consume battery. It does not prevent display sleep, lid-close sleep, explicit sleep, shutdown, or power loss. It changes no permanent power setting and requests no new macOS privacy grant.

The lease stops when the job exits, the duration expires, or you cancel its foreground CLI with **Ctrl-C**, SIGTERM, or SIGHUP. It signals its own native child, never the selected job. If cleanup cannot be confirmed within the cleanup window, it returns a failure without claiming the child is gone.

A parent crash cannot run JavaScript cleanup, so the native timeout is always present. The source's live acceptance checked target exit, expiry, SIGINT, and parent SIGKILL on the tested Mac, observing the owned assertion's appearance and release and native child exit. This is not a universal guarantee across macOS releases or suspension, and actual machine sleep was not tested.

PID/UID/start-time observations detect visible target changes, but attachment remains **non-atomic** and cannot exclude every PID-reuse race. The caller must have current authority for the exact effect; the CLI does not authenticate conversational consent or convert a policy result into permission.

The terminal result distinguishes observed spawn, exit, stop reason, and cleanup. Assertion installation and actual wakefulness remain `not-observed` in the tool's result. Exit `0` means expected expiry or target completion with confirmed cleanup; invalid arguments return `64`; handled INT/TERM/HUP return `130`/`143`/`129`; other refusals and failures return `1`.

## Optional verification

The six included suites contain 87 source tests:

```sh
node --test test/*.test.mjs
```

They use injected observations and owned temporary files/processes. They do not start real `caffeinate`, make network requests, or read secret Keychain values. Running the tests is optional and is not a read-only filesystem operation.

Release packaging uses Python 3.11+ standard-library tooling and Git, separate from the Node-only runtime. From a public source clone, a maintainer can reproduce a tagged release into a **new** output directory:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/test_release.py
python3 tools/build_release.py build --repo . --ref v0.1.0 --version 0.1.0 --output ../starter-build
```

The builder reads committed allowlisted blobs, not uncommitted files. It refuses to overwrite an existing output directory. Its `verify` command checks a bounded archive against an explicit expected SHA-256 without extracting or running its contents. Obtain that expected digest from the published descriptor/checksum, not by hashing the candidate and trusting itself.

## Foundation, separately chosen

`foundation/` carries the original Foundation text, release index, and CC0 license. It is a **partial reference export**, not the entire operational Standard. The index also names documents omitted from this starter; their source is the [pinned upstream tree](https://github.com/cambridgetcg/kingdom-standard/tree/ddb2766d03ed8d16ddbce54ba396a9d7a612f354). Relative document links and example verification commands in the original text refer to that upstream tree.

No file is automatically imported into an agent's prompt. If you choose to use the Foundation with an agent harness, review it and deliberately configure that harness yourself. This kit supplies no identity, personal memory, keys, enrollment, or authority over other homes.

## Remove it

1. Cancel any active foreground awake lease.
2. If its parent was forcibly terminated, allow the explicitly chosen native timeout to expire.
3. Delete this extracted directory.

There is no installed service, PATH entry, login item, configuration, or persistent receipt to remove. Files or configurations you create yourself remain your separate choices.

## Source and rights

KINGDOM OS remains source-owned; this repository is a selected distribution, not a copy of the private estate. [PROVENANCE.md](PROVENANCE.md) names the source boundary and commits.

The selected KINGDOM code and release tooling are **MIT**. The Foundation materials retain **CC0 1.0 Universal** separately; see [NOTICE](NOTICE). Node.js and macOS tools are external dependencies, not redistributed or relicensed here.

Cambridge TCG offers only an optional pointer. No Cambridge account, fee, enrollment, or application-level tracking is added by that invitation; ordinary hosting and GitHub request logs may exist. Walking past is a complete choice.
