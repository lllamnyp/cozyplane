#!/usr/bin/env python3
"""Record public harness files actually used by an individual test phase."""
import hashlib
import json
import pathlib
import shutil
import sys

root, report = map(pathlib.Path, sys.argv[1:3])
phase = sys.argv[3]
assert report.parent.name == "cozyplane-ipsec-test" and report.name.startswith("results-")
assert phase in ("measurement", "lifecycle", "roadwarrior", "observer-adjusted", "reporting", "reorder-control", "backend-transition")
destination = report / "harness-phases" / phase
destination.mkdir(parents=True, exist_ok=True)
rows = []
for filename in sys.argv[4:]:
    assert pathlib.Path(filename).name == filename and filename.startswith(("ipsec-", "wireguard-client-"))
    source = root / "test" / filename
    shutil.copyfile(source, destination / filename)
    rows.append({"path": "test/" + filename, "sha256": hashlib.sha256(source.read_bytes()).hexdigest()})
(destination / "manifest.json").write_text(json.dumps(rows, indent=2) + "\n")
