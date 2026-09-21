"""Recovery invariants for the source snapshot tool; uses only disposable files."""

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "capture_baseline.py"
SPEC = importlib.util.spec_from_file_location("capture_baseline_under_test", SCRIPT)
baseline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(baseline)


class CaptureBaselineTests(unittest.TestCase):
    def setUp(self):
        # This affects only the test process, never xcode-select or host settings.
        command_line_tools = Path("/Library/Developer/CommandLineTools")
        if sys.platform == "darwin" and command_line_tools.is_dir():
            self.enterContext(
                mock.patch.dict(os.environ, {"DEVELOPER_DIR": str(command_line_tools)})
            )
        self.enterContext(mock.patch.dict(os.environ, {"GIT_OPTIONAL_LOCKS": "0"}))
        self.temporary = self.enterContext(tempfile.TemporaryDirectory(prefix="baseline-test-"))
        self.folder = Path(self.temporary)
        self.repo = self.folder / "repo"
        self.repo.mkdir()
        self.snapshot = self.folder / "snapshot"
        self.enterContext(mock.patch.object(baseline, "ROOT", self.repo))
        self.policy_path = self.repo / "docs/baseline/SELECTION.json"
        self.enterContext(mock.patch.object(baseline, "POLICY_PATH", self.policy_path))
        self.policy = {
            "include_files": ["README.md"],
            "include_directories": ["docs", "src", "scripts"],
            "excluded_roots": {".git": "git_metadata", "target": "build_cache"},
            "exclude_paths": {},
            "exclude_directory_names": ["__pycache__"],
            "exclude_file_globs": [".env", "*.key"],
            "file_exceptions": {},
            "synthetic_private_key_allowances": {},
        }
        self.write("README.md", b"A disposable recovery fixture.\n")
        self.write("src/main.rs", b"fn main() {}\n")
        self.write("scripts/run.sh", b"#!/bin/sh\nprintf 'fixture\\n'\n", mode=0o755)
        self.write("docs/baseline/SELECTION.json", json.dumps(self.policy).encode())
        # Sentinel values are deliberately not real credentials or secret formats.
        self.write("src/.env", b"LOCAL_SENTINEL=excluded\n")
        self.write("src/operator.key", b"excluded-key-sentinel\n")
        self.write("src/__pycache__/cached.pyc", b"excluded-cache-sentinel\n")
        self.write("target/generated", b"excluded-build-sentinel\n")
        self.write("unreviewed.txt", b"outside-allowlist-sentinel\n")
        self.git("init", "--quiet", "--initial-branch=main")
        # A real staged file proves capture neither rewrites nor removes an index.
        self.git("add", "--", "README.md")

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.repo), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def write(self, relative, data, mode=0o644):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def capture(self):
        result = baseline.capture(self.snapshot)
        manifest = json.loads((self.snapshot / baseline.MANIFEST_NAME).read_text())
        return result, manifest

    def entries(self):
        with tarfile.open(self.snapshot / baseline.ARCHIVE_NAME, "r:gz") as archive:
            return [(member, archive.extractfile(member).read()) for member in archive]

    def rewrite_archive(self, entries):
        """Keep a valid outer checksum so verification must inspect inner members."""
        path = self.snapshot / baseline.ARCHIVE_NAME
        with tarfile.open(path, "w:gz") as archive:
            for member, content in entries:
                archive.addfile(member, io.BytesIO(content) if member.isfile() else None)
        manifest_path = self.snapshot / baseline.MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text())
        manifest["archive_sha256"] = baseline.file_digest(path)
        manifest_path.write_text(json.dumps(manifest))

    def test_capture_restores_bytes_modes_excludes_artifacts_and_preserves_index(self):
        before_index = (self.repo / ".git/index").read_bytes()
        before_status = self.git("status", "--porcelain=v1", "--untracked-files=all")
        source_bytes = (self.repo / "src/main.rs").read_bytes()
        result, manifest = self.capture()
        self.assertEqual(result["restored_files"], 4)
        self.assertTrue(result["bytes_and_modes_verified"])
        self.assertEqual(
            baseline.verify(self.snapshot),
            {"restored_files": 4, "bytes_and_modes_verified": True},
        )
        expected_paths = {
            "README.md", "src/main.rs", "scripts/run.sh", "docs/baseline/SELECTION.json"
        }
        self.assertEqual({item["path"] for item in manifest["files"]}, expected_paths)
        self.assertEqual(manifest["git"]["branch"], "main")
        self.assertIsNone(manifest["git"]["revision"])
        self.assertEqual(manifest["git"]["index_sha256"], baseline.digest(before_index))
        self.assertTrue(manifest["git_metadata_unchanged"])
        entries = {member.name: (member, content) for member, content in self.entries()}
        self.assertEqual(entries["scripts/run.sh"][0].mode, 0o755)
        self.assertEqual(entries["src/main.rs"][1], source_bytes)
        self.assertEqual((self.repo / "src/main.rs").read_bytes(), source_bytes)
        self.assertEqual((self.repo / ".git/index").read_bytes(), before_index)
        self.assertEqual(
            self.git("status", "--porcelain=v1", "--untracked-files=all"), before_status
        )
        self.assertFalse((self.snapshot / "INCOMPLETE").exists())

    def test_archive_checksum_rejects_modified_compressed_bytes(self):
        self.capture()
        archive = self.snapshot / baseline.ARCHIVE_NAME
        archive.write_bytes(archive.read_bytes() + b"altered")
        with self.assertRaisesRegex(ValueError, "Archive SHA-256 mismatch"):
            baseline.verify(self.snapshot)

    def test_missing_member_rejected_with_valid_archive_checksum(self):
        self.capture()
        self.rewrite_archive(self.entries()[1:])
        with self.assertRaisesRegex(ValueError, "missing selected source files"):
            baseline.verify(self.snapshot)

    def test_changed_file_bytes_rejected_with_valid_archive_checksum(self):
        self.capture()
        entries = self.entries()
        for index, (member, content) in enumerate(entries):
            if member.name == "src/main.rs":
                changed = b"X" + content[1:]
                entries[index] = (member, changed)
        self.rewrite_archive(entries)
        with self.assertRaisesRegex(ValueError, "Restored source hash/mode mismatch"):
            baseline.verify(self.snapshot)

    def test_traversal_rejected_with_valid_archive_checksum(self):
        self.capture()
        entries = self.entries()
        entry = tarfile.TarInfo("../outside-sentinel")
        entry.size = 1
        entry.mode = 0o644
        entries.insert(0, (entry, b"X"))
        self.rewrite_archive(entries)
        with self.assertRaisesRegex(ValueError, "Unsafe archive path"):
            baseline.verify(self.snapshot)
        self.assertFalse((self.folder / "outside-sentinel").exists())

    def test_symlink_rejected_with_valid_archive_checksum(self):
        self.capture()
        entries = self.entries()
        member = tarfile.TarInfo("src/main.rs")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../outside-sentinel"
        member.mode = 0o644
        entries = [(m, data) for m, data in entries if m.name != member.name]
        entries.insert(0, (member, b""))
        self.rewrite_archive(entries)
        with self.assertRaisesRegex(ValueError, "nonregular"):
            baseline.verify(self.snapshot)

    def test_permission_change_rejected_with_valid_archive_checksum(self):
        self.capture()
        entries = self.entries()
        for member, _ in entries:
            if member.name == "src/main.rs":
                member.mode = 0o755
        self.rewrite_archive(entries)
        with self.assertRaisesRegex(ValueError, "Archive size/mode mismatch"):
            baseline.verify(self.snapshot)

    def test_git_failure_cannot_be_misreported_as_unborn_repository(self):
        failure = subprocess.CompletedProcess(
            args=["git"], returncode=72, stdout="", stderr="tool unavailable"
        )
        with mock.patch.object(baseline.subprocess, "run", return_value=failure):
            with self.assertRaisesRegex(ValueError, "Git metadata unavailable"):
                baseline.capture(self.snapshot)
        self.assertFalse(self.snapshot.exists())

    def test_missing_git_executable_stops_capture(self):
        with mock.patch.object(
            baseline.subprocess, "run", side_effect=FileNotFoundError("missing git")
        ):
            with self.assertRaises(FileNotFoundError):
                baseline.capture(self.snapshot)
        self.assertFalse(self.snapshot.exists())


if __name__ == "__main__":
    unittest.main()
