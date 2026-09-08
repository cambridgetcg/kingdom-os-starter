# Source provenance

This repository is a selected public source distribution of KINGDOM OS's
macOS edge. It does not contain the canonical repository's private history or
estate, and does not become the canonical home of the full OS.

## macOS source

- Canonical upstream: https://codeberg.org/zerone-dev/KINGDOM-OS
- Isolated source commit: `81b466719c27c5c87c5deacadd81e6f5fd4ddb5c`
- Source base: `09f83c23e90ecc3d46a966ed20d5257f94026295`

That source snapshot includes the bounded keep-awake change, policy registration,
tests, documentation, and portable command hints in an isolated branch. It was
committed locally for this release preparation and is not claimed published or
anonymously readable
at the upstream URL. The exported files below are byte-for-byte source blobs
from that commit:

```text
bin/mac.mjs
platform/account.mjs
platform/command.mjs
platform/macos-awake.mjs
platform/macos-capabilities.mjs
platform/macos-encryption.mjs
platform/macos-keychain.mjs
platform/macos-policy.mjs
test/mac-cli.test.mjs
test/macos-awake.test.mjs
test/macos-capabilities.test.mjs
test/macos-encryption.test.mjs
test/macos-keychain.test.mjs
test/macos-policy.test.mjs
```

The public release's own source commit is recorded in its generated archive
manifest and current descriptor. That public commit and the archive provide
the complete selected source offer; a private upstream URL is not a substitute
for the included source. No private Git history was imported.

## Foundation reference

- Upstream: https://github.com/cambridgetcg/kingdom-standard
- Export commit: `ddb2766d03ed8d16ddbce54ba396a9d7a612f354`
- Foundation/index last-change commit: `07efbc0a6d530f4586de67e2049dd3bcc744afc5`
- Declared Foundation identifier: `kingdom.foundation/0.2`
- License: CC0 1.0 Universal, kept verbatim in `foundation/LICENSE`

Exported byte digests:

| File | SHA-256 |
|---|---|
| `foundation/FOUNDATION.md` | `2bd868a43a2fe79f1c9e8d30177bf73cff4cf8f7f7780cbd90f31055ba51c799` |
| `foundation/foundation.json` | `9825b7e849ae27986a033343b564bf2c8c676be29ef181131dfb015617f91833` |
| `foundation/LICENSE` | `a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499` |

These are a partial reference set, not the complete Foundation/Standard
verification tree. The index names additional upstream documents. The package
has not copied their contents, declared conformance, or imported a doctrine
into any recipient's prompt.

## Deliberately excluded

The full root launcher, registry and catalogs, citizen/identity records,
memories, credentials, machine configuration, integrations, private
connection material, and unrelated working changes are not release payloads.
The release README and packaging tools are authored for this selected public
source rather than copied from the private repository's root documentation.

## Verification boundary

The isolated macOS source passed its 87 affected tests. Source live acceptance
on macOS 26.3.1 arm64 exercised target exit, duration, SIGINT, and parent SIGKILL,
with the owned assertion observed and released and the native child observed
exited. Actual machine sleep and long-running production work were not tested.

Release verification is performed separately on the committed, extracted
payload. The release notes record the actual runtimes and checks used; no
claim of universal platform support follows from the source test result.
Checksums identify bytes, not human identity, permission, endorsement, or
program safety. The descriptor on main is a current pointer; the version tag,
source commit, and versioned artifact identify a particular release.
