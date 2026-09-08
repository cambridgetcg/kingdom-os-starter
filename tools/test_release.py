#!/usr/bin/env python3
"""Offline release tests; Python >=3.11, POSIX, Git. No real-repository writes.

All Git mutations and archive fixtures belong to isolated temporary directories.
Run: PYTHONDONTWRITEBYTECODE=1 python3 tools/test_release.py
"""

import builtins
import copy
import gzip
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
import build_release as release

TOOL = Path(__file__).resolve().with_name("build_release.py")
SOURCE = TOOL.parent.parent
# Independent inventory assertion: do not derive the expected export from the
# production allowlist, or deleting a dependency there would make tests agree.
EXPECTED = {
    "bin/mac.mjs", "platform/account.mjs", "platform/command.mjs",
    "platform/macos-awake.mjs", "platform/macos-capabilities.mjs",
    "platform/macos-encryption.mjs", "platform/macos-keychain.mjs", "platform/macos-policy.mjs",
    "test/mac-cli.test.mjs", "test/macos-awake.test.mjs", "test/macos-capabilities.test.mjs",
    "test/macos-encryption.test.mjs", "test/macos-keychain.test.mjs", "test/macos-policy.test.mjs",
    "foundation/FOUNDATION.md", "foundation/foundation.json", "foundation/LICENSE",
    "README.md", "LICENSE", "NOTICE", "PROVENANCE.md", "tools/build_release.py", "tools/test_release.py",
}


def fixture_git(repo, *args, data=None):
    env = release.git_environment() | {
        "GIT_AUTHOR_NAME": "Release fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Release fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+0000", "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+0000",
    }
    return subprocess.run(
        [shutil.which("git", path=os.defpath), "-c", "core.hooksPath=/dev/null",
         "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "protocol.allow=never",
         "-C", str(repo), *args], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, check=True, timeout=30,
    ).stdout.decode("ascii").strip()


def commit_fixture(repo):
    fixture_git(repo, "add", "--all")
    fixture_git(repo, "commit", "-m", "Isolated fixture\n\nCo-Authored-By: Claude Fable 5 <noreply@anthropic.com>")
    return fixture_git(repo, "rev-parse", "HEAD")


def fixture_repo(parent):
    repo = parent / "repo"
    repo.mkdir()
    fixture_git(repo, "init", "--initial-branch=fixture")
    for path in EXPECTED:
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(("// owned fixture: " + path + "\n").encode("ascii"))
    return repo, commit_fixture(repo)


def gzip_bytes(raw):
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0, filename="", compresslevel=9) as stream:
        stream.write(raw)
    return output.getvalue()


def unpack_fixture(archive):
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as stream:
        return [(copy.copy(info), stream.extractfile(info).read()) for info in stream.getmembers()]


def pack_fixture(entries, format=tarfile.USTAR_FORMAT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=format) as stream:
        for info, data in entries:
            stream.addfile(info, io.BytesIO(data))
    return gzip_bytes(output.getvalue())


class ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.owned = tempfile.TemporaryDirectory(prefix="starter-release-tests-")
        cls.addClassCleanup(cls.owned.cleanup)
        cls.base = Path(cls.owned.name)
        cls.repo, cls.commit = fixture_repo(cls.base)
        cls.result = release.build(cls.repo, cls.commit, "0.1.0", cls.base / "initial")
        cls.archive_path = Path(cls.result["archive"])
        cls.archive = cls.archive_path.read_bytes()
        cls.entries = unpack_fixture(cls.archive)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="case-", dir=self.base)
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)

    def reject(self, archive, message=None):
        with self.assertRaisesRegex(release.ReleaseError, message or "."):
            release.verify_bytes(archive, release.digest(archive))

    def changed_manifest(self, change=None, raw=None):
        entries = copy.deepcopy(self.entries)
        for info, data in entries:
            if info.name.endswith("/manifest.json"):
                if raw is None:
                    value = json.loads(data)
                    change(value)
                    raw = release.json_bytes(value)
                info.size = len(raw)
                entries[entries.index((info, data))] = (info, raw)
                break
        return pack_fixture(entries)

    def test_exact_inventory_and_normalization(self):
        self.assertEqual(len(EXPECTED), 23)
        self.assertEqual(set(release.PAYLOAD), EXPECTED)
        self.assertEqual(release.PAYLOAD, tuple(sorted(EXPECTED)))
        self.assertEqual(len(self.entries), 24)
        names = [info.name for info, _data in self.entries]
        self.assertEqual(names, sorted("kingdom-os-starter-0.1.0/" + p for p in EXPECTED | {"manifest.json"}))
        for info, data in self.entries:
            self.assertEqual(info.type, tarfile.REGTYPE)
            self.assertEqual((info.uid, info.gid, info.mtime, info.uname, info.gname), (0, 0, 0, "", ""))
            self.assertEqual(info.mode, 0o755 if info.name.endswith("/bin/mac.mjs") else 0o644)
            if not info.name.endswith("/manifest.json"):
                relative = info.name.split("/", 1)[1]
                self.assertEqual(data, ("// owned fixture: " + relative + "\n").encode("ascii"))
        self.assertEqual(self.archive[:10], b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff")
        manifest = next(json.loads(data) for info, data in self.entries if info.name.endswith("/manifest.json"))
        self.assertEqual(manifest["source"]["commit"], self.commit)
        self.assertEqual(manifest["source"]["tree"], fixture_git(self.repo, "rev-parse", "HEAD^{tree}"))
        self.assertEqual([row["path"] for row in manifest["files"]], list(release.PAYLOAD))

    def test_reproducible_despite_process_umask(self):
        previous = os.umask(0o077)
        try:
            result = release.build(self.repo, self.commit, "0.1.0", self.home / "second")
        finally:
            os.umask(previous)
        for key in ("archive", "checksums", "descriptor"):
            self.assertEqual(Path(result[key]).read_bytes(), Path(self.result[key]).read_bytes())

    def test_commit_beats_dirty_worktree_and_index(self):
        repo, commit = fixture_repo(self.home)
        (repo / "README.md").write_text("staged change\n", encoding="utf-8")
        fixture_git(repo, "add", "README.md")
        (repo / "README.md").write_text("different dirty change\n", encoding="utf-8")
        (repo / "private-untracked.txt").write_text("not exported\n", encoding="utf-8")
        result = release.build(repo, commit, "0.1.0", self.home / "dirty-build")
        self.assertEqual(Path(result["archive"]).read_bytes(), self.archive)
        self.assertTrue((repo / "private-untracked.txt").exists())

    def test_tags_pin_a_commit(self):
        repo, commit = fixture_repo(self.home)
        fixture_git(repo, "tag", "-a", "v0.1.0", "-m", "Fixture tag")
        self.assertEqual(release.read_source(repo, "v0.1.0")[0]["commit"], commit)

    def test_ref_and_version_refusals(self):
        for ref in ("--help", "HEAD~0", "HEAD:README.md", "HEAD\nHEAD", "missing", "a" * 201):
            with self.subTest(ref=ref), self.assertRaises(release.ReleaseError):
                release.build(self.repo, ref, "0.1.0", self.home / "absent")
        for version in ("../1.0.0", "01.0.0", "v0.1.0", "1.0", "1.0.0/evil", "1.0.0\n", "1" * 100 + ".0.0"):
            with self.subTest(version=version), self.assertRaises(release.ReleaseError):
                release.build(self.repo, self.commit, version, self.home / "absent")
        self.assertFalse((self.home / "absent").exists())

    def test_existing_outputs_are_never_clobbered(self):
        directory = self.home / "existing-dir"
        directory.mkdir()
        sentinel = directory / "sentinel"
        sentinel.write_bytes(b"preserve")
        file = self.home / "existing-file"
        file.write_bytes(b"preserve")
        link = self.home / "dangling-link"
        link.symlink_to(self.home / "not-created")
        for output in (directory, file, link):
            with self.subTest(output=output.name), self.assertRaises(release.ReleaseError):
                release.build(self.repo, self.commit, "0.1.0", output)
        self.assertEqual(sentinel.read_bytes(), b"preserve")
        self.assertEqual(file.read_bytes(), b"preserve")
        self.assertTrue(link.is_symlink())
        self.assertFalse((self.home / "not-created").exists())

    def test_output_created_during_build_is_not_clobbered(self):
        source, payload = release.read_source(self.repo, self.commit)
        output = self.home / "racing-output"

        def concurrent_creation(*_args):
            output.mkdir()
            (output / "sentinel").write_bytes(b"preserve")
            return source, payload

        with mock.patch.object(release, "read_source", side_effect=concurrent_creation):
            with self.assertRaises(FileExistsError):
                release.build(self.repo, self.commit, "0.1.0", output)
        self.assertEqual({p.name for p in output.iterdir()}, {"sentinel"})
        self.assertEqual((output / "sentinel").read_bytes(), b"preserve")

    def test_new_output_requires_existing_parent(self):
        with self.assertRaises(release.ReleaseError):
            release.build(self.repo, self.commit, "0.1.0", self.home / "missing" / "out")
        self.assertFalse((self.home / "missing").exists())

    def test_extra_and_missing_committed_files_refuse(self):
        repo, _commit = fixture_repo(self.home)
        (repo / "unreviewed.txt").write_bytes(b"not approved")
        extra = commit_fixture(repo)
        with self.assertRaisesRegex(release.ReleaseError, "unexpected tracked"):
            release.build(repo, extra, "0.1.0", self.home / "extra")
        (repo / "unreviewed.txt").unlink()
        (repo / "platform/account.mjs").unlink()
        missing = commit_fixture(repo)
        with self.assertRaisesRegex(release.ReleaseError, "missing allowlisted"):
            release.build(repo, missing, "0.1.0", self.home / "missing")
        self.assertFalse((self.home / "extra").exists())
        self.assertFalse((self.home / "missing").exists())

    def test_catalog_is_the_only_exception_and_is_not_read(self):
        repo, _commit = fixture_repo(self.home)
        (repo / "release.json").write_bytes(b"catalog is exterior; not payload JSON")
        commit = commit_fixture(repo)
        source, payload = release.read_source(repo, commit)
        self.assertEqual(source["commit"], commit)
        self.assertEqual(set(payload), EXPECTED)
        result = release.build(repo, commit, "0.1.0", self.home / "catalog")
        self.assertNotIn("release.json", [i.name.split("/", 1)[1] for i, _ in unpack_fixture(Path(result["archive"]).read_bytes())])

    def test_git_symlink_and_submodule_refuse(self):
        repo, commit = fixture_repo(self.home)
        path = repo / "README.md"
        path.unlink()
        path.symlink_to("LICENSE")
        symlink_commit = commit_fixture(repo)
        with self.assertRaisesRegex(release.ReleaseError, "unsupported Git mode"):
            release.build(repo, symlink_commit, "0.1.0", self.home / "symlink")
        fixture_git(repo, "update-index", "--add", "--cacheinfo", "160000," + commit + ",README.md")
        fixture_git(repo, "commit", "-m", "Owned submodule fixture")
        with self.assertRaisesRegex(release.ReleaseError, "unsupported Git mode"):
            release.build(repo, "HEAD", "0.1.0", self.home / "submodule")

    def test_safe_git_executable_modes_are_normalized(self):
        repo, _commit = fixture_repo(self.home)
        (repo / "README.md").chmod(0o755)
        commit = commit_fixture(repo)
        result = release.build(repo, commit, "0.1.0", self.home / "mode")
        info = next(i for i, _ in unpack_fixture(Path(result["archive"]).read_bytes()) if i.name.endswith("/README.md"))
        self.assertEqual(info.mode, 0o644)

    def test_git_file_and_total_size_bounds(self):
        repo, _commit = fixture_repo(self.home)
        (repo / "README.md").write_bytes(b"a" * (release.MAX_FILE + 1))
        commit = commit_fixture(repo)
        with self.assertRaisesRegex(release.ReleaseError, "file exceeds size"):
            release.build(repo, commit, "0.1.0", self.home / "large-file")
        for path in list(release.PAYLOAD)[:5]:
            (repo / path).write_bytes(b"a" * release.MAX_FILE)
        commit = commit_fixture(repo)
        with self.assertRaisesRegex(release.ReleaseError, "payload exceeds size"):
            release.build(repo, commit, "0.1.0", self.home / "large-total")

    def test_replacements_and_inherited_git_settings_are_ignored(self):
        repo, original = fixture_repo(self.home)
        (repo / "README.md").write_bytes(b"replacement body\n")
        replacement = commit_fixture(repo)
        fixture_git(repo, "replace", original, replacement)
        hostile = {"GIT_DIR": str(self.home / "missing"), "GIT_CONFIG_COUNT": "1",
                   "GIT_CONFIG_KEY_0": "core.bare", "GIT_CONFIG_VALUE_0": "true",
                   "GIT_CONFIG_GLOBAL": str(self.home / "unread"), "HOME": str(self.home / "unread"),
                   "PATH": str(self.home / "unread"), "PRIVATE_ENV_FIXTURE": "not-forwarded"}
        with mock.patch.dict(os.environ, hostile):
            result = release.build(repo, original, "0.1.0", self.home / "original")
        self.assertEqual(Path(result["archive"]).read_bytes(), self.archive)
        self.assertNotIn("PRIVATE_ENV_FIXTURE", release.git_environment())
        self.assertEqual(release.git_environment()["GIT_NO_LAZY_FETCH"], "1")

    def test_missing_promisor_blob_does_not_fetch(self):
        repo, commit = fixture_repo(self.home)
        oid = fixture_git(repo, "rev-parse", "HEAD:README.md")
        fixture_git(repo, "config", "extensions.partialClone", "origin")
        fixture_git(repo, "config", "remote.origin.promisor", "true")
        fixture_git(repo, "config", "remote.origin.url", str(self.repo))
        (repo / ".git" / "objects" / oid[:2] / oid[2:]).unlink()
        with self.assertRaises(release.ReleaseError):
            release.build(repo, commit, "0.1.0", self.home / "no-fetch")
        self.assertFalse((repo / ".git" / "objects" / oid[:2] / oid[2:]).exists())
        self.assertFalse((self.home / "no-fetch").exists())

    def test_sha_is_required_before_parsing(self):
        with mock.patch.object(release.zlib, "decompressobj", side_effect=AssertionError("parsed before digest")):
            for sha in ("0" * 64, "bad", "f" * 63, "f" * 65):
                with self.subTest(sha=sha), self.assertRaises(release.ReleaseError):
                    release.verify_bytes(self.archive, sha)
        self.assertEqual(release.verify_bytes(self.archive, release.digest(self.archive).upper())["payload_files"], 23)

    def test_tampered_archive_hash_refuses(self):
        data = bytearray(self.archive)
        data[-10] ^= 1
        with self.assertRaisesRegex(release.ReleaseError, "SHA-256 mismatch"):
            release.verify_bytes(bytes(data), release.digest(self.archive))

    def test_extra_missing_duplicate_and_unsorted_entries(self):
        extra = tarfile.TarInfo("kingdom-os-starter-0.1.0/unexpected.txt")
        extra.mode = 0o644
        cases = [self.entries + [(extra, b"")], self.entries[1:],
                 self.entries[:1] + self.entries, list(reversed(self.entries))]
        for entries in cases:
            with self.subTest(names=[i.name for i, _ in entries]):
                self.reject(pack_fixture(entries))

    def test_traversal_absolute_wrong_roots_and_long_names(self):
        for name in ("../escape", "/absolute", "kingdom-os-starter-0.1.0/../LICENSE",
                     "kingdom-os-starter-0.1.0//LICENSE", "kingdom-os-starter-0.1.0/./LICENSE",
                     "kingdom-os-starter-0.1.0/tools/../../LICENSE", "kingdom-os-starter-0.2.0/LICENSE",
                     "other/LICENSE", "kingdom-os-starter-0.1.0/" + "x" * 80):
            with self.subTest(name=name):
                entries = copy.deepcopy(self.entries)
                entries[0][0].name = name
                self.reject(pack_fixture(entries, tarfile.PAX_FORMAT))

    def test_nonregular_types_and_modes_refuse(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.CHRTYPE,
                     tarfile.BLKTYPE, tarfile.FIFOTYPE, tarfile.XHDTYPE, tarfile.XGLTYPE,
                     tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_SPARSE, tarfile.AREGTYPE):
            with self.subTest(kind=kind):
                entries = copy.deepcopy(self.entries)
                info, _ = entries[0]
                info.type, info.size = kind, 0
                info.linkname = "LICENSE" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                entries[0] = (info, b"")
                self.reject(pack_fixture(entries))
        for mode in (0o777, 0o600, 0o4755, 0o1777):
            with self.subTest(mode=mode):
                entries = copy.deepcopy(self.entries)
                entries[0][0].mode = mode
                self.reject(pack_fixture(entries))

    def test_header_ownership_time_labels_and_checksum_refuse(self):
        for field, value in (("uid", 1), ("gid", 1), ("mtime", 1), ("uname", "operator"), ("gname", "staff")):
            with self.subTest(field=field):
                entries = copy.deepcopy(self.entries)
                setattr(entries[0][0], field, value)
                self.reject(pack_fixture(entries))
        raw = bytearray(gzip.decompress(self.archive))
        raw[148] ^= 1
        self.reject(gzip_bytes(raw))

    def test_payload_size_and_digest_mismatch(self):
        entries = copy.deepcopy(self.entries)
        info, data = entries[0]
        entries[0] = (info, b"X" + data[1:])
        self.reject(pack_fixture(entries), "manifest file")
        entries[0] = (info, data + b"X")
        info.size += 1
        self.reject(pack_fixture(entries), "manifest file")

    def test_unknown_manifest_keys_at_every_level(self):
        changes = [lambda m: m.update(extra=True), lambda m: m["source"].update(extra=True),
                   lambda m: m["files"][0].update(extra=True)]
        for change in changes:
            self.reject(self.changed_manifest(change))

    def test_manifest_identity_inventory_and_types(self):
        changes = [lambda m: m.update(schema="wrong"), lambda m: m.update(version="0.2.0"),
                   lambda m: m["source"].update(commit="HEAD"), lambda m: m["source"].update(tree="f" * 64),
                   lambda m: m["source"].update(repository="https://example.invalid"),
                   lambda m: m["source"].pop("tree"), lambda m: m["files"].pop(),
                   lambda m: m["files"].append(m["files"][0]), lambda m: m["files"].reverse(),
                   lambda m: m["files"][0].update(path="../LICENSE"),
                   lambda m: m["files"][0].update(size=True), lambda m: m["files"][0].update(size=-1),
                   lambda m: m["files"][0].update(mode="0777"), lambda m: m["files"][0].update(sha256="0" * 64),
                   lambda m: m.update(files={}), lambda m: m.update(source=[])]
        for index, change in enumerate(changes):
            with self.subTest(case=index):
                self.reject(self.changed_manifest(change))

    def test_malformed_duplicate_key_and_deep_json(self):
        for raw in (b"{", b"[]", b"null", b"\xff", b'{"schema":1,"schema":2}',
                    b'{"source":{"commit":"a","commit":"b"}}', b'{"n":NaN}',
                    b'{"n":Infinity}', b"[" * 2000 + b"]" * 2000):
            with self.subTest(raw=raw[:40]):
                self.reject(self.changed_manifest(raw=raw))

    def test_compressed_expanded_entry_and_manifest_bounds(self):
        oversized = self.home / "large.tar.gz"
        with oversized.open("wb") as stream:
            stream.truncate(release.MAX_COMPRESSED + 1)
        with mock.patch.object(release, "verify_bytes", side_effect=AssertionError("oversize was read")):
            with self.assertRaisesRegex(release.ReleaseError, "compressed archive exceeds"):
                release.verify_archive(oversized, "0" * 64)
        self.reject(gzip_bytes(b"\x00" * (release.MAX_EXPANDED + 1)), "expanded archive exceeds")
        raw = release.tar_header("kingdom-os-starter-0.1.0/LICENSE", release.MAX_FILE + 1, 0o644)
        self.reject(gzip_bytes(raw), "entry exceeds")
        self.reject(self.changed_manifest(raw=b" " * (release.MAX_MANIFEST + 1)), "entry exceeds")
        with mock.patch.object(release, "MAX_PAYLOAD", 1):
            self.reject(self.archive, "payload exceeds")

    def test_gzip_and_tar_truncation_trailing_bytes_and_padding(self):
        raw = gzip.decompress(self.archive)
        for archive in (self.archive[:-1], self.archive + b"extra", self.archive + gzip_bytes(b""),
                        gzip_bytes(raw[:-512]), gzip_bytes(raw + b"\x00" * 10240), gzip_bytes(raw + b"hidden")):
            self.reject(archive)
        padding = bytearray(raw)
        padding[512 + self.entries[0][0].size] = 1
        self.reject(gzip_bytes(padding), "padding")
        changed = bytearray(self.archive)
        changed[4] = 1
        self.reject(bytes(changed), "gzip header")

    def test_verify_refuses_filesystem_links_and_fifo(self):
        link = self.home / "archive-link"
        link.symlink_to(self.archive_path)
        with self.assertRaises(OSError):
            release.verify_archive(link, release.digest(self.archive))
        fifo = self.home / "fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(release.ReleaseError, "regular file"):
            release.verify_archive(fifo, release.digest(self.archive))

    def test_verify_has_no_writes_extraction_execution_or_network(self):
        before = sorted(str(p.relative_to(self.base)) for p in self.base.rglob("*"))
        original_open = os.open

        def read_only_open(path, flags, *args, **kwargs):
            self.assertEqual(Path(path), self.archive_path)
            self.assertEqual(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND), 0)
            return original_open(path, flags, *args, **kwargs)

        def forbidden(*_args, **_kwargs):
            raise AssertionError("verify attempted a side effect")

        with mock.patch.object(os, "open", side_effect=read_only_open), \
             mock.patch.object(builtins, "open", side_effect=forbidden), \
             mock.patch.object(subprocess, "Popen", side_effect=forbidden), \
             mock.patch.object(os, "system", side_effect=forbidden), \
             mock.patch.object(socket, "socket", side_effect=forbidden), \
             mock.patch.object(Path, "mkdir", side_effect=forbidden), \
             mock.patch.object(Path, "write_bytes", side_effect=forbidden), \
             mock.patch.object(Path, "write_text", side_effect=forbidden), \
             mock.patch.object(os, "unlink", side_effect=forbidden), \
             mock.patch.object(tarfile.TarFile, "extract", side_effect=forbidden), \
             mock.patch.object(tarfile.TarFile, "extractall", side_effect=forbidden):
            result = release.verify_archive(self.archive_path, release.digest(self.archive))
        self.assertEqual(result["source_commit"], self.commit)
        self.assertEqual(before, sorted(str(p.relative_to(self.base)) for p in self.base.rglob("*")))

    def test_payload_code_is_not_executed(self):
        source, payload = release.read_source(self.repo, self.commit)
        marker = self.home / "must-not-exist"
        payload["tools/build_release.py"] = ("raise RuntimeError('payload executed')\n").encode("ascii")
        payload["bin/mac.mjs"] = b"throw new Error('payload executed');\n"
        archive = release.make_archive("0.1.0", source, payload)
        release.verify_bytes(archive, release.digest(archive))
        self.assertFalse(marker.exists())

    def test_public_data_heuristics_and_exact_fake_exceptions(self):
        home_path = "/Us" + "ers/" + "actual-operator/private.txt"
        linux_home = "/ho" + "me/" + "actual-operator/private.txt"
        cases = ["AK" + "IA" + "1234567890ABCDEF", "gh" + "p_" + "a" * 36,
                 "github_" + "pat_" + "a" * 82, "sk_" + "live_" + "a" * 24,
                 "-----BEGIN " + "OPENSSH PRIVATE KEY-----", home_path, linux_home,
                 "token = '" + "aB3dE6gH9jK2mN5pQ8sT1vW4" + "'",
                 "PROVIDER_API_TOKEN = '" + "aB3dE6gH9jK2mN5pQ8sT1vW4" + "'",
                 "https://" + "account:credential@example.invalid"]
        for value in cases:
            with self.subTest(shape=value[:10]), self.assertRaises(release.ReleaseError):
                release.check_public_data("README.md", value.encode("ascii"))
        fake_home = "/Us" + "ers/private"
        release.check_public_data("test/macos-capabilities.test.mjs", fake_home.encode("ascii"))
        with self.assertRaises(release.ReleaseError):
            release.check_public_data("README.md", fake_home.encode("ascii"))
        for path in EXPECTED:
            release.check_public_data(path, b"const privateText = 'TOP-SECRET-DO-NOT-PRINT';\n")
        for data in (b"binary\x00", b"\xff"):
            with self.assertRaises(release.ReleaseError):
                release.check_public_data("README.md", data)

    def test_repeated_base64url_prefixes_have_bounded_scan_time(self):
        probe = (
            "import sys; sys.path.insert(0, sys.argv[1]); import build_release as r; "
            "text=('eyJ'+'a'*8+'-')*87381; "
            "assert len(text.encode()) <= r.MAX_FILE; "
            "r.check_public_data('README.md', text.encode())"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", probe, str(TOOL.parent)],
            capture_output=True, check=False, timeout=3,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        token = "ey" + "J" + "a" * 12 + "." + "b" * 12 + "." + "c" * 20
        for value in (token, "Bearer " + token, '"' + token + '-"'):
            with self.subTest(value=value[:6]), self.assertRaises(release.ReleaseError):
                release.check_public_data("README.md", value.encode())

    def test_public_data_is_checked_at_build(self):
        repo, _commit = fixture_repo(self.home)
        (repo / "README.md").write_text("gh" + "p_" + "a" * 36, encoding="ascii")
        commit = commit_fixture(repo)
        with self.assertRaisesRegex(release.ReleaseError, "credential-shaped"):
            release.build(repo, commit, "0.1.0", self.home / "private")
        self.assertFalse((self.home / "private").exists())

    def test_shipped_source_public_scan_and_static_import_closure(self):
        # Reads only shipped files; no real Git HEAD or working-tree cleanliness
        # required. This also proves the heuristic does not reject its own code.
        dependencies = 0
        for path in EXPECTED:
            data = (SOURCE / path).read_bytes()
            release.check_public_data(path, data)
            if path.endswith(".mjs"):
                text = data.decode("utf-8")
                for specifier in re.findall(r'''(?m)^\s*import\s+(?:[A-Za-z0-9_$*{},\s]+?\s+from\s+)?["']([^"']+)["']''', text):
                    if specifier.startswith("node:"):
                        continue
                    self.assertTrue(specifier.startswith("."), (path, specifier))
                    resolved = (SOURCE / path).parent.joinpath(specifier).resolve()
                    self.assertTrue(resolved.is_relative_to(SOURCE), (path, specifier))
                    self.assertIn(resolved.relative_to(SOURCE).as_posix(), EXPECTED)
                    dependencies += 1
        self.assertGreater(dependencies, 20)

    def test_actual_source_build_in_isolated_git_fixture(self):
        repo, _commit = fixture_repo(self.home)
        for path in EXPECTED:
            (repo / path).write_bytes((SOURCE / path).read_bytes())
        commit = commit_fixture(repo)
        first = release.build(repo, commit, "0.1.0", self.home / "actual-first")
        second = release.build(repo, commit, "0.1.0", self.home / "actual-second")
        self.assertEqual(Path(first["archive"]).read_bytes(), Path(second["archive"]).read_bytes())
        entries = unpack_fixture(Path(first["archive"]).read_bytes())
        for info, data in entries:
            path = info.name.split("/", 1)[1]
            if path in EXPECTED:
                self.assertEqual(data, (SOURCE / path).read_bytes())
        self.assertEqual(release.verify_archive(first["archive"], first["sha256"])["source_commit"], commit)

    def test_descriptor_and_checksum_contract(self):
        descriptor = json.loads(Path(self.result["descriptor"]).read_bytes())
        self.assertEqual(descriptor["schema"], "kingdom.os-starter-release/0.1")
        self.assertEqual(descriptor["status"], "preview")
        self.assertEqual(descriptor["canonicalURL"], release.CANONICAL_URL)
        self.assertEqual(descriptor["source"]["commit"], self.commit)
        self.assertEqual(descriptor["source"]["tagURL"], release.REPOSITORY + "/tree/v0.1.0")
        self.assertEqual(descriptor["artifactURL"], release.REPOSITORY + "/releases/download/v0.1.0/kingdom-os-starter-0.1.0.tar.gz")
        self.assertEqual(descriptor["checksumURL"], release.REPOSITORY + "/releases/download/v0.1.0/SHA256SUMS")
        self.assertEqual(descriptor["sha256"], release.digest(self.archive))
        self.assertEqual(descriptor["size"], len(self.archive))
        self.assertEqual(descriptor["licenses"], {"code": "MIT", "foundation": "CC0-1.0"})
        self.assertEqual(descriptor["requirements"]["node"], ">=22")
        self.assertEqual(descriptor["verification"]["testResults"], "not-embedded")
        self.assertEqual(Path(self.result["checksums"]).read_text(encoding="ascii"),
                         release.digest(self.archive) + "  kingdom-os-starter-0.1.0.tar.gz\n")
        self.assertEqual({p.name for p in Path(self.result["archive"]).parent.iterdir()},
                         {"kingdom-os-starter-0.1.0.tar.gz", "SHA256SUMS", "release.json"})

    def test_cli_json_and_failure_exit_codes(self):
        env = {"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C"}
        command = [sys.executable, "-B", str(TOOL)]
        result = subprocess.run(command + ["build", "--repo", str(self.repo), "--ref", self.commit,
                                "--version", "0.1.0", "--output", str(self.home / "cli")],
                                env=env, capture_output=True, check=True, timeout=60)
        summary = json.loads(result.stdout)
        self.assertEqual(set(summary), {"archive", "checksums", "descriptor", "version", "sha256", "size",
                                       "source_commit", "source_tree", "payload_files"})
        self.assertEqual(result.stderr, b"")
        verified = subprocess.run(command + ["verify", summary["archive"], "--sha256", summary["sha256"]],
                                  env=env, capture_output=True, check=True, timeout=30)
        self.assertEqual(json.loads(verified.stdout)["sha256"], summary["sha256"])
        failed = subprocess.run(command + ["verify", summary["archive"], "--sha256", "0" * 64],
                                env=env, capture_output=True, timeout=30)
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(failed.stdout, b"")
        self.assertIn(b"SHA-256 mismatch", failed.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
