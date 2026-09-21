#!/usr/bin/env python3
"""Reject obsolete product names except legally required original notices."""
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parents[1]
old_name = "gr" + "ovs"
excluded = {".git", "target", "vendor", "node_modules", ".terraform"}
legal = {Path("LICENSE"), Path("ee/LICENSE")}
errors = []
for path in root.rglob("*"):
    rel = path.relative_to(root)
    if any(part in excluded for part in rel.parts) or path.is_symlink():
        continue
    if re.search(old_name, path.name, re.IGNORECASE):
        errors.append(f"obsolete path: {rel}")
    if not path.is_file() or rel in legal or (path.name.startswith(".env") and path.name not in {".env.example", ".env.rust.example", ".env.test"}):
        continue
    try:
        contents = path.read_text()
    except (OSError, UnicodeDecodeError):
        continue
    if re.search(old_name, contents, re.IGNORECASE):
        errors.append(f"obsolete product reference: {rel}")
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print("Product branding check passed; original license notices retained.")
