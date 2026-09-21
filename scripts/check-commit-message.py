#!/usr/bin/env python3
"""Validate PR squash titles or the current main commit, without shell interpolation."""
import os
import re
import subprocess

if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
    title = os.environ["PR_TITLE"]
    body = os.environ.get("PR_BODY", "")
else:
    message = subprocess.check_output(["git", "log", "-1", "--format=%B"], text=True)
    title, _, body = message.partition("\n")
if re.search(r"^\s*Release-As:", title + "\n" + body, re.IGNORECASE | re.MULTILINE):
    raise SystemExit("Release-As overrides are forbidden; use Conventional Commits.")
subprocess.run(["./node_modules/.bin/commitlint"], input=title + "\n", text=True, check=True)
