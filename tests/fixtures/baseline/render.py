#!/usr/bin/env python3
"""Render the baseline contract locally; never contacts an application or provider."""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid


def deterministic_id(namespace, run_id, key):
    """UUIDv8: first 128 SHA-256 bits, with version and RFC variant bits set."""
    raw = bytearray(hashlib.sha256(f"{namespace}/{run_id}/{key}".encode()).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x80
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def render(manifest, run_id, anchor):
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,39}", run_id):
        raise ValueError("run-id must match [a-z][a-z0-9-]{0,39}")
    if anchor.tzinfo is None or anchor.utcoffset() != dt.timedelta(0):
        raise ValueError("anchor must be an explicit UTC timestamp")
    if anchor.time() != dt.time(0, 0):
        raise ValueError("anchor must be UTC midnight")
    keys = manifest["id_keys"]
    if len(keys) != len(set(keys)):
        raise ValueError("id_keys must be unique")
    ids = {k: deterministic_id(manifest["namespace"], run_id, k) for k in keys}

    def substitute(match):
        token = match.group(1)
        if token == "run_id":
            return run_id
        if token.startswith("id:"):
            return ids[token[3:]]
        if token.startswith("time:"):
            stamp = anchor + dt.timedelta(seconds=int(token[5:]))
            return stamp.isoformat().replace("+00:00", "Z")
        raise ValueError(f"unknown token: {token}")

    def walk(value):
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v) for v in value]
        if isinstance(value, str):
            value = re.sub(r"\{\{([^{}]+)\}\}", substitute, value)
            if "{{" in value or "}}" in value:
                raise ValueError(f"unresolved token: {value}")
        return value

    result = walk(manifest)
    result["resolved"] = {
        "run_id": run_id,
        "anchor_utc": anchor.isoformat().replace("+00:00", "Z"),
        "ids": ids,
        "identity_note": "Server-assigned IDs from public creation routes must replace matching references in a separate runtime map; record that map as evidence.",
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--anchor", required=True, help="Explicit UTC midnight, e.g. 2026-09-18T00:00:00Z")
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    manifest = json.loads((folder / "manifest.v1.json").read_text())
    for asset in manifest["assets"]:
        path = folder / asset["file"]
        raw = path.read_bytes()
        if len(raw) != asset["bytes"] or hashlib.sha256(raw).hexdigest() != asset["sha256"]:
            parser.error(f"asset bytes/hash mismatch: {asset['file']}")
    try:
        anchor = dt.datetime.fromisoformat(args.anchor.replace("Z", "+00:00"))
        result = render(manifest, args.run_id, anchor)
    except (ValueError, KeyError) as error:
        parser.error(str(error))
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
