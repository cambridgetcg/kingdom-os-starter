#!/usr/bin/env python3
"""Deterministic source release. Requires Python >=3.11, POSIX, and Git for build.

Verify is bounded, read-only, offline, and never extracts or executes payloads.
A matching digest establishes matching bytes, not safe code or authorization.
"""

import sys

# Even a cold standard-library import must not create bytecode during verify.
sys.dont_write_bytecode = True

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import tarfile
import time
import zlib

REPOSITORY = "https://github.com/cambridgetcg/kingdom-os-starter"
CANONICAL_URL = "https://raw.githubusercontent.com/cambridgetcg/kingdom-os-starter/main/release.json"
PAYLOAD = tuple(sorted((
    "bin/mac.mjs",
    "platform/macos-awake.mjs", "platform/macos-capabilities.mjs",
    "platform/macos-encryption.mjs", "platform/macos-keychain.mjs",
    "platform/macos-policy.mjs", "platform/command.mjs", "platform/account.mjs",
    "test/mac-cli.test.mjs", "test/macos-awake.test.mjs",
    "test/macos-capabilities.test.mjs", "test/macos-encryption.test.mjs",
    "test/macos-keychain.test.mjs", "test/macos-policy.test.mjs",
    "foundation/FOUNDATION.md", "foundation/foundation.json", "foundation/LICENSE",
    "README.md", "LICENSE", "NOTICE", "PROVENANCE.md",
    "tools/build_release.py", "tools/test_release.py",
)))
MAX_FILE = 1024 * 1024
MAX_PAYLOAD = 4 * 1024 * 1024
MAX_COMPRESSED = 4 * 1024 * 1024
MAX_EXPANDED = 8 * 1024 * 1024
MAX_MANIFEST = 64 * 1024
MAX_TREE = 64 * 1024
MAX_PATH = 100  # Deliberately avoid USTAR prefix/long-name extensions.
MAX_ENTRIES = len(PAYLOAD) + 1
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})")
OID_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


class ReleaseError(ValueError):
    """Refuse an input without printing its possibly private contents."""


def require(condition, message):
    if not condition:
        raise ReleaseError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def mode_for(path):
    return 0o755 if path == "bin/mac.mjs" else 0o644


def validate_version(version):
    require(isinstance(version, str) and VERSION_RE.fullmatch(version), "version must be bounded numeric MAJOR.MINOR.PATCH")
    return "kingdom-os-starter-" + version


def git_environment():
    # No inherited credentials, GIT_DIR, object alternates, config injection,
    # loader variables, agent sockets, proxy settings, or caller PATH.
    return {
        "PATH": os.defpath, "LC_ALL": "C", "HOME": os.devnull,
        "XDG_CONFIG_HOME": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_COUNT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
        "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
    }


def git_read(repo, args, limit=MAX_TREE):
    executable = shutil.which("git", path=os.defpath)
    require(executable is not None, "Git is required for build")
    # protocol.allow also blocks fetch on older Git without GIT_NO_LAZY_FETCH.
    command = [executable, "--no-replace-objects", "-c", "protocol.allow=never",
               "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args]
    chunks = bytearray()
    deadline = time.monotonic() + 30
    with subprocess.Popen(command, env=git_environment(), stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as child:
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    require(remaining > 0 and ready.select(remaining), "Git inspection timed out")
                    part = os.read(child.stdout.fileno(), min(65536, limit + 1 - len(chunks)))
                    if not part:
                        break
                    chunks.extend(part)
                    require(len(chunks) <= limit, "Git inspection exceeds size bound")
            require(child.wait(timeout=max(0.01, deadline - time.monotonic())) == 0,
                    "Git object inspection failed (missing object, ref, or unsupported repository)")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
    return bytes(chunks)


# These are heuristics, not a secret-free certification. Only exact fake home
# names in the two existing regression fixtures are exempt, never entire tests.
FIXTURE_HOMES = {
    "test/macos-capabilities.test.mjs": {"someone", "private-account", "person", "private"},
    "test/macos-keychain.test.mjs": {"private"},
}
CREDENTIAL_PATTERNS = tuple(re.compile(pattern) for pattern in (
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----",
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
    r"\bgithub_pat_[A-Za-z0-9_]{70,255}\b",
    r"\bxox[baprs]-[A-Za-z0-9-]{20,255}\b",
    r"\bsk_(?:live|proj)_[A-Za-z0-9_-]{20,255}\b",
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b",
    r"https?://[^/\s:@]+:[^/\s@]+@",
))
HOME_RE = re.compile(r"/(?:Users|home)/([A-Za-z0-9_.-]+)")
ASSIGNMENT_RE = re.compile(
    r'''(?i)\b(?:[a-z][a-z0-9_]*_)?(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|password|secret_access_key)\b["']?\s*[:=]\s*["']([A-Za-z0-9_+/=.\-]{24,})["']'''
)


def check_public_data(path, data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReleaseError("non-UTF-8 source: " + path) from error
    require("\x00" not in text, "binary source: " + path)
    for pattern in CREDENTIAL_PATTERNS:
        require(not pattern.search(text), "credential-shaped content: " + path)
    for match in ASSIGNMENT_RE.finditer(text):
        value = match.group(1)
        require(not (len(set(value)) >= 10 and any(c.isalpha() for c in value)
                     and any(c.isdigit() for c in value)), "credential-shaped assignment: " + path)
    for match in HOME_RE.finditer(text):
        require(match.group(1) in FIXTURE_HOMES.get(path, ()), "operator-home-shaped path: " + path)


def read_source(repo, ref):
    require(bool(ref) and len(ref) <= 200 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", ref)
            and ".." not in ref, "ref must be a commit ID or a single ref name")
    commit = git_read(repo, ["rev-parse", "--verify", "--end-of-options", ref + "^{commit}"], 100).decode("ascii").strip()
    require(OID_RE.fullmatch(commit), "ref did not resolve to one commit")
    tree = git_read(repo, ["rev-parse", "--verify", "--end-of-options", commit + "^{tree}"], 100).decode("ascii").strip()
    require(OID_RE.fullmatch(tree) and len(tree) == len(commit), "invalid source tree")
    inventory = git_read(repo, ["ls-tree", "-r", "-l", "-z", "--full-tree", tree])
    entries = {}
    for entry in inventory.split(b"\x00"):
        if not entry:
            continue
        try:
            metadata, raw_path = entry.split(b"\t", 1)
            mode, kind, oid, size = metadata.split()
            path = raw_path.decode("ascii")
        except (ValueError, UnicodeDecodeError) as error:
            raise ReleaseError("invalid or unexpected tracked source path") from error
        require(path in PAYLOAD or path == "release.json", "unexpected tracked source file; review the export inventory")
        require(path not in entries, "duplicate Git tree entry")
        require(mode in (b"100644", b"100755") and kind == b"blob", "unsupported Git mode or object: " + path)
        require(OID_RE.fullmatch(oid.decode("ascii")), "invalid blob ID")
        require(size.isdigit() and int(size) <= MAX_FILE, "source file exceeds size bound: " + path)
        entries[path] = (oid.decode("ascii"), int(size))
    require(set(entries) - {"release.json"} == set(PAYLOAD), "missing allowlisted source file")
    require(sum(entries[path][1] for path in PAYLOAD) <= MAX_PAYLOAD, "source payload exceeds size bound")
    payload = {}
    for path in PAYLOAD:
        oid, size = entries[path]
        data = git_read(repo, ["cat-file", "blob", oid], size)
        require(len(data) == size, "Git blob size mismatch: " + path)
        check_public_data(path, data)
        payload[path] = data
    return {"repository": REPOSITORY, "commit": commit, "tree": tree}, payload


def file_records(payload):
    return [{"path": path, "size": len(payload[path]), "mode": format(mode_for(path), "04o"),
             "sha256": digest(payload[path])} for path in PAYLOAD]


def tar_header(name, size, mode):
    require(len(name.encode("ascii")) <= MAX_PATH, "archive path exceeds bound")
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = mode
    info.uid = info.gid = info.mtime = 0
    info.uname = info.gname = ""
    info.type = tarfile.REGTYPE
    return info.tobuf(format=tarfile.USTAR_FORMAT, encoding="ascii", errors="strict")


def make_archive(version, source, payload):
    root = validate_version(version)
    manifest = {"schema": "kingdom.os-starter-manifest/0.1", "version": version,
                "source": source, "files": file_records(payload)}
    contents = dict(payload, **{"manifest.json": json_bytes(manifest)})
    require(len(contents["manifest.json"]) <= MAX_MANIFEST, "manifest exceeds size bound")
    raw = bytearray()
    for path in sorted(contents):
        data = contents[path]
        raw.extend(tar_header(root + "/" + path, len(data), mode_for(path)))
        raw.extend(data)
        raw.extend(b"\x00" * (-len(data) % 512))
    raw.extend(b"\x00" * 1024)
    raw.extend(b"\x00" * (-len(raw) % tarfile.RECORDSIZE))
    require(len(raw) <= MAX_EXPANDED, "expanded archive exceeds size bound")
    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, mode="wb", filename="", mtime=0, compresslevel=9) as zipped:
        zipped.write(raw)
    archive = stream.getvalue()
    require(len(archive) <= MAX_COMPRESSED, "compressed archive exceeds size bound")
    return archive


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ReleaseError("non-finite JSON value")

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError) as error:
        raise ReleaseError("malformed manifest JSON") from error


def check_manifest(data, version, payload):
    manifest = strict_json(data)
    require(type(manifest) is dict and set(manifest) == {"schema", "version", "source", "files"}, "unknown or missing manifest keys")
    require(manifest["schema"] == "kingdom.os-starter-manifest/0.1" and manifest["version"] == version,
            "manifest schema or version mismatch")
    source = manifest["source"]
    require(type(source) is dict and set(source) == {"repository", "commit", "tree"}, "invalid manifest source keys")
    require(source["repository"] == REPOSITORY and all(isinstance(source[key], str) and OID_RE.fullmatch(source[key])
            for key in ("commit", "tree")) and len(source["commit"]) == len(source["tree"]), "invalid source identity")
    records = manifest["files"]
    require(type(records) is list and len(records) == len(PAYLOAD), "invalid manifest file inventory")
    for record in records:
        require(type(record) is dict and set(record) == {"path", "size", "mode", "sha256"}, "invalid manifest file keys")
        require(type(record["size"]) is int, "manifest size must be an integer")
    require(records == file_records(payload), "manifest file inventory, mode, size, or hash mismatch")
    return source


def verify_bytes(archive, expected_sha256):
    require(isinstance(expected_sha256, str) and re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256), "expected SHA-256 must contain exactly 64 hex characters")
    require(len(archive) <= MAX_COMPRESSED, "compressed archive exceeds size bound")
    sha256 = digest(archive)
    require(sha256 == expected_sha256.lower(), "archive SHA-256 mismatch")
    require(archive[:10] == b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff", "non-canonical gzip header")
    try:
        decoder = zlib.decompressobj(wbits=31)
        raw = decoder.decompress(archive, MAX_EXPANDED + 1)
    except zlib.error as error:
        raise ReleaseError("invalid gzip stream") from error
    require(len(raw) <= MAX_EXPANDED, "expanded archive exceeds size bound")
    require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail, "truncated or trailing gzip data")
    # Inspect fixed headers ourselves: no tar parser may interpret PAX, GNU,
    # sparse files, links, or hidden records before they have been rejected.
    offset = 0
    entries = {}
    root = None
    version = None
    total = 0
    while offset + 512 <= len(raw) and raw[offset:offset + 512] != b"\x00" * 512:
        require(len(entries) < MAX_ENTRIES, "archive has too many entries")
        header = raw[offset:offset + 512]
        try:
            name = header[:100].split(b"\x00", 1)[0].decode("ascii")
            entry_root, path = name.split("/", 1)
            size_field = header[124:136]
            require(re.fullmatch(rb"[0-7]{11}\x00", size_field), "non-canonical tar size")
            size = int(size_field[:-1], 8)
        except (ValueError, UnicodeDecodeError) as error:
            raise ReleaseError("invalid archive path or size") from error
        require(entry_root.startswith("kingdom-os-starter-"), "invalid archive root")
        entry_version = entry_root.removeprefix("kingdom-os-starter-")
        require(validate_version(entry_version) == entry_root, "invalid archive root")
        if root is None:
            root, version = entry_root, entry_version
        require(entry_root == root, "mixed archive roots")
        require(path in PAYLOAD or path == "manifest.json", "unexpected or unsafe archive path")
        require(path not in entries, "duplicate archive entry")
        require(size <= (MAX_MANIFEST if path == "manifest.json" else MAX_FILE), "archive entry exceeds size bound")
        require(header == tar_header(name, size, mode_for(path)), "non-canonical or unsafe USTAR header")
        start = offset + 512
        end = start + size
        offset = end + (-size % 512)
        require(offset <= len(raw), "truncated archive entry")
        require(not any(raw[end:offset]), "non-zero archive entry padding")
        entries[path] = raw[start:end]
        if path != "manifest.json":
            total += size
            require(total <= MAX_PAYLOAD, "archive payload exceeds size bound")
    expected_end = ((offset + 1024 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
    require(len(raw) == expected_end and not any(raw[offset:]), "invalid tar terminator or trailing data")
    require(set(entries) == set(PAYLOAD) | {"manifest.json"}, "missing archive entries")
    require(list(entries) == sorted(entries), "archive entries are not sorted")
    manifest = entries.pop("manifest.json")
    source = check_manifest(manifest, version, entries)
    for path, data in entries.items():
        check_public_data(path, data)
    return {"version": version, "sha256": sha256, "size": len(archive),
            "source_commit": source["commit"], "source_tree": source["tree"],
            "payload_files": len(PAYLOAD)}


def verify_archive(path, expected_sha256):
    # Reject links, devices and FIFOs without opening a blocking stream.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), "archive must be a regular file")
        require(info.st_size <= MAX_COMPRESSED, "compressed archive exceeds size bound")
        archive = stream.read(MAX_COMPRESSED + 1)
    return verify_bytes(archive, expected_sha256)


def release_descriptor(version, source, archive):
    filename = validate_version(version) + ".tar.gz"
    tag = "v" + version
    base = REPOSITORY + "/releases/download/" + tag + "/"
    return {
        "schema": "kingdom.os-starter-release/0.1", "status": "preview", "version": version,
        "repository": REPOSITORY, "canonicalURL": CANONICAL_URL,
        "source": {**source, "commitURL": REPOSITORY + "/commit/" + source["commit"],
                   "treeURL": REPOSITORY + "/tree/" + source["commit"],
                   "tag": tag, "tagURL": REPOSITORY + "/tree/" + tag},
        "artifactURL": base + filename, "filename": filename,
        "sha256": digest(archive), "size": len(archive), "checksumURL": base + "SHA256SUMS",
        "licenses": {"code": "MIT", "foundation": "CC0-1.0"},
        "requirements": {"node": ">=22", "releaseTooling": "Python >=3.11; POSIX; Git for build"},
        "testedPlatform": {"os": "macOS", "version": "26.3.1", "architecture": "arm64",
                           "basis": "maintainer-reported host; not tested by this builder"},
        "verification": {"testResults": "not-embedded",
                         "commands": ["node --test test/*.test.mjs",
                                      "PYTHONDONTWRITEBYTECODE=1 python3 tools/test_release.py"],
                         "limits": "Hashes match bytes, not safety, authority, installation, awakefulness, or conformance. Publication requires separate test review."},
        "effects": {"readingOrExtracting": "starts nothing", "execution": "explicit invocation only",
                    "observers": "coarse host metadata", "awake": "explicit finite foreground power action"},
        "foundationScope": "optional partial reference export; no automatic import or adoption",
    }


def build(repo, ref, version, output):
    root = validate_version(version)
    output = Path(output).absolute()
    require(not os.path.lexists(output), "output directory must not exist")
    require(output.parent.is_dir(), "output parent directory must already exist")
    source, payload = read_source(Path(repo).absolute(), ref)
    archive = make_archive(version, source, payload)
    summary = verify_bytes(archive, digest(archive))
    filename = root + ".tar.gz"
    files = {filename: archive,
             "SHA256SUMS": (summary["sha256"] + "  " + filename + "\n").encode("ascii"),
             "release.json": json_bytes(release_descriptor(version, source, archive))}
    # Atomic absent-directory claim; no exist_ok, overwrite, rollback or deletion.
    # An I/O failure can leave an owned partial directory for human inspection.
    output.mkdir(mode=0o755)
    for name, data in files.items():
        with (output / name).open("xb") as stream:
            stream.write(data)
    return {**summary, "archive": str(output / filename), "checksums": str(output / "SHA256SUMS"),
            "descriptor": str(output / "release.json")}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    builder = commands.add_parser("build", help="build from a committed allowlisted Git tree")
    builder.add_argument("--repo", required=True)
    builder.add_argument("--ref", required=True)
    builder.add_argument("--version", required=True)
    builder.add_argument("--output", required=True)
    verifier = commands.add_parser("verify", help="verify bytes without extraction, execution or network")
    verifier.add_argument("archive")
    verifier.add_argument("--sha256", required=True)
    args = parser.parse_args(argv)
    try:
        require(sys.version_info >= (3, 11) and os.name == "posix", "Python >=3.11 on POSIX is required")
        if args.command == "build":
            result = build(args.repo, args.ref, args.version, args.output)
        else:
            result = verify_archive(args.archive, args.sha256)
    except (ReleaseError, OSError, UnicodeError, subprocess.SubprocessError) as error:
        print("release: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
