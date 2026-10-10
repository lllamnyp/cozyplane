#!/usr/bin/env python3
"""Fail export on recognizable private-key, XFRM-key or literal secret content.

Findings print only relative file names and line numbers, never matching values.
This is a bounded sanity check, not proof that every possible secret is absent.
"""
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1]).resolve()
patterns = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    re.compile(r"^\s*(?:auth(?:-trunc)?|enc|aead) \S+ 0x[0-9a-f]{16,}", re.I),
    re.compile(r"\b(?:secret|password|psk)\s*[:=]\s*[\"']?[0-9a-f]{32,}\b", re.I),
]
findings = []
checked = 0
for path in sorted(root.rglob("*")):
    if path.is_symlink():
        findings.append({"file": str(path.relative_to(root)), "reason": "unexpected symlink"})
        continue
    if not path.is_file():
        continue
    checked += 1
    for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        if any(pattern.search(line) for pattern in patterns):
            findings.append({"file": str(path.relative_to(root)), "line": number})
print(json.dumps({"checkedFiles": checked, "findings": findings, "passed": not findings}))
raise SystemExit(bool(findings))
