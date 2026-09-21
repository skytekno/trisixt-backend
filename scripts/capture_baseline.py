#!/usr/bin/env python3
"""Capture and verify the reviewed MAN-5 source selection without changing Git."""

import argparse
import collections
import fnmatch
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "docs/baseline/SELECTION.json"
ARCHIVE_NAME = "source.tar.gz"
MANIFEST_NAME = "manifest.json"
HAZARDS = {
    "private_key_material": re.compile(
        rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
        rb"\s+[A-Za-z0-9+/=\s]{150,}-----END"
    ),
    "aws_access_key_id": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "github_token": re.compile(
        rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"
    ),
    "slack_token": re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "stripe_live_key": re.compile(rb"\b[rs]k_live_[A-Za-z0-9]{16,}\b"),
    "google_api_key": re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b"),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def safe_relative(name):
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or ".." in path.parts
        or str(path) != name
        or "\\" in name
    ):
        raise ValueError(f"Unsafe archive path: {name!r}")
    return path


def metadata():
    def git(*args, allow_missing=False):
        result = subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, check=False
        )
        if result.returncode == 0:
            return result.stdout.strip()
        if allow_missing and result.returncode == 1:
            return None
        # Git stderr can contain user configuration; keep diagnostics redacted.
        raise ValueError(
            "Git metadata unavailable; verify the installed Git tools "
            "(on this Mac use DEVELOPER_DIR=/Library/Developer/CommandLineTools)"
        )

    if git("rev-parse", "--is-inside-work-tree") != "true":
        raise ValueError("Capture requires a Git worktree")
    return {
        "revision": git("rev-parse", "--verify", "--quiet", "HEAD", allow_missing=True),
        "branch": git("symbolic-ref", "--quiet", "--short", "HEAD", allow_missing=True),
        "index_sha256": file_digest(ROOT / ".git/index")
        if (ROOT / ".git/index").is_file()
        else None,
    }


def inventory(policy):
    records, exclusions, allowances, hazards = [], [], [], []
    roots = set(policy["include_files"] + policy["include_directories"])
    exceptions = policy["file_exceptions"]

    def reason(path, is_directory):
        parts = path.parts
        name = path.as_posix()
        if parts[0] in policy["excluded_roots"]:
            return policy["excluded_roots"][parts[0]]
        if parts[0] not in roots:
            return "outside_reviewed_allowlist"
        for prefix, why in policy["exclude_paths"].items():
            if name == prefix or name.startswith(prefix + "/"):
                return why
        if is_directory and path.name in policy["exclude_directory_names"]:
            return "generated_or_local_directory"
        if not is_directory and name not in exceptions:
            for pattern in policy["exclude_file_globs"]:
                if fnmatch.fnmatchcase(path.name, pattern):
                    return "credential_or_local_artifact_pattern"
        return None

    def walk(directory):
        for entry in sorted(directory.iterdir(), key=lambda item: item.name):
            relative = entry.relative_to(ROOT)
            is_directory = entry.is_dir()
            why = reason(relative, is_directory)
            if why:
                exclusions.append(
                    {
                        "path": relative.as_posix(),
                        "kind": "directory" if is_directory else "file",
                        "reason": why,
                        "contents_counted": False if is_directory else True,
                    }
                )
                continue
            if entry.is_symlink():
                raise ValueError(f"Selected symlink is forbidden: {relative}")
            if is_directory:
                walk(entry)
                continue
            attributes = entry.stat()
            if not stat.S_ISREG(attributes.st_mode) or attributes.st_mode & 0o7000:
                raise ValueError(f"Selected file is not an ordinary source file: {relative}")
            safe_relative(relative.as_posix())
            data = entry.read_bytes()
            for label, pattern in HAZARDS.items():
                matches = list(pattern.finditer(data))
                if not matches:
                    continue
                finding = {"path": relative.as_posix(), "pattern": label}
                allowance = policy["synthetic_private_key_allowances"].get(
                    relative.as_posix()
                )
                if (
                    label == "private_key_material"
                    and allowance
                    and all(digest(match.group()) in allowance["material_sha256"] for match in matches)
                ):
                    finding["reason"] = allowance["reason"]
                    allowances.append(finding)
                else:
                    hazards.append(finding)
            records.append(
                {
                    "path": relative.as_posix(),
                    "sha256": digest(data),
                    "size": len(data),
                    "mode": format(stat.S_IMODE(attributes.st_mode), "04o"),
                }
            )

    walk(ROOT)
    if hazards:
        # Only names and pattern labels are reported; matched values never leave memory.
        raise ValueError("Credential hazard requires review: " + json.dumps(hazards))
    return sorted(records, key=lambda item: item["path"]), exclusions, allowances


def verify(snapshot):
    manifest = json.loads((snapshot / MANIFEST_NAME).read_text())
    records = manifest["files"]
    if digest(canonical(records)) != manifest["source_sha256"]:
        raise ValueError("Manifest source identity mismatch")
    archive = snapshot / ARCHIVE_NAME
    if file_digest(archive) != manifest["archive_sha256"]:
        raise ValueError("Archive SHA-256 mismatch")
    expected = {}
    for record in records:
        name = record["path"]
        safe_relative(name)
        if name in expected:
            raise ValueError(f"Duplicate manifest entry: {name}")
        expected[name] = record
    seen = set()
    with tempfile.TemporaryDirectory(prefix="trisixt-baseline-restore-") as temporary:
        restored = Path(temporary)
        with tarfile.open(archive, "r:gz") as stream:
            for member in stream:
                name = member.name
                safe_relative(name)
                if not member.isfile() or name not in expected or name in seen:
                    raise ValueError(f"Unexpected, nonregular or duplicate archive entry: {name}")
                record = expected[name]
                if member.mode & ~0o777:
                    raise ValueError(f"Unsafe archive permission mode: {name}")
                if member.size != record["size"] or member.mode != int(record["mode"], 8):
                    raise ValueError(f"Archive size/mode mismatch: {name}")
                target = restored.joinpath(*PurePosixPath(name).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                content = stream.extractfile(member)
                if content is None:
                    raise ValueError(f"Unreadable archive entry: {name}")
                with content, target.open("xb") as output:
                    shutil.copyfileobj(content, output)
                target.chmod(member.mode)
                if (
                    file_digest(target) != record["sha256"]
                    or format(stat.S_IMODE(target.stat().st_mode), "04o") != record["mode"]
                ):
                    raise ValueError(f"Restored source hash/mode mismatch: {name}")
                seen.add(name)
        if seen != set(expected):
            raise ValueError("Archive is missing selected source files")
    return {"restored_files": len(seen), "bytes_and_modes_verified": True}


def capture(output):
    output = output.resolve()
    if output == ROOT or ROOT in output.parents:
        raise ValueError("Snapshot output must be outside the repository")
    if output.exists():
        raise ValueError("Snapshot output must be a new directory")
    policy_bytes = POLICY_PATH.read_bytes()
    policy = json.loads(policy_bytes)
    before = metadata()
    records, exclusions, allowances = inventory(policy)
    if not records:
        raise ValueError("No intended source files selected")
    output.mkdir(mode=0o700, parents=False)
    archive = output / ARCHIVE_NAME
    try:
        with archive.open("xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as stream:
                    for record in records:
                        source = ROOT / record["path"]
                        if source.is_symlink():
                            raise ValueError(f"Source changed to symlink: {record['path']}")
                        data = source.read_bytes()
                        mode = stat.S_IMODE(source.stat().st_mode)
                        if digest(data) != record["sha256"] or mode != int(record["mode"], 8):
                            raise ValueError(f"Source changed during capture: {record['path']}")
                        member = tarfile.TarInfo(record["path"])
                        member.size = len(data)
                        member.mode = mode
                        stream.addfile(member, io.BytesIO(data))
        after = metadata()
        if before != after:
            raise ValueError("Git metadata changed during capture; retry after concurrent work stops")
        if POLICY_PATH.read_bytes() != policy_bytes or inventory(policy)[0] != records:
            raise ValueError("Source selection changed during capture; retry after writers stop")
        manifest = {
            "format_version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "repository": str(ROOT),
            "git": before,
            "git_metadata_unchanged": True,
            "selection_policy": "docs/baseline/SELECTION.json",
            "selection_policy_sha256": digest(policy_bytes),
            "source_sha256": digest(canonical(records)),
            "archive": ARCHIVE_NAME,
            "archive_sha256": file_digest(archive),
            "source_file_count": len(records),
            "source_bytes": sum(item["size"] for item in records),
            "files": records,
            "exclusions": exclusions,
            "excluded_entry_counts_by_reason": dict(
                sorted(collections.Counter(item["reason"] for item in exclusions).items())
            ),
            "exclusion_count_unit": "entries; excluded directories are pruned, descendants are not counted",
            "credential_scan": {
                "unresolved_high_confidence_hazards": 0,
                "synthetic_private_key_allowances": allowances,
                "limitation": "Pattern scan plus reviewed selection; not proof that arbitrary text contains no secret",
            },
        }
        manifest_path = output / MANIFEST_NAME
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        result = verify(output)
        manifest["recovery_verification"] = result
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        return {
            "snapshot": str(output),
            "source_sha256": manifest["source_sha256"],
            "archive_sha256": manifest["archive_sha256"],
            "git_revision": before["revision"],
            **result,
        }
    except Exception:
        # Keep partial output for diagnosis; never delete caller paths or an old backup.
        (output / "INCOMPLETE").write_text("Capture or recovery verification failed. Do not use this snapshot.\n")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    for command in ("capture", "verify"):
        subparser = subcommands.add_parser(command)
        subparser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "verify" and (args.directory / "INCOMPLETE").exists():
            raise ValueError("Snapshot is marked incomplete")
        result = capture(args.directory) if args.command == "capture" else verify(args.directory)
        print(json.dumps(result, indent=2))
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        print(f"Baseline capture/verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
