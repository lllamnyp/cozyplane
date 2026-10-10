#!/usr/bin/env python3
"""Hash explicit source paths, never secret fixtures, caches or Git internals."""
import argparse
import hashlib
import json
import pathlib
import re

parser = argparse.ArgumentParser()
parser.add_argument("root", type=pathlib.Path)
parser.add_argument("report", type=pathlib.Path)
parser.add_argument("--config-id", required=True)
parser.add_argument("--manifest-digest", required=True)
parser.add_argument("--index-digest", required=True)
args = parser.parse_args()
assert all(re.fullmatch(r"sha256:[0-9a-f]{64}", value)
           for value in (args.config_id, args.manifest_digest, args.index_digest))
args.report.mkdir(parents=True, exist_ok=True)
directories = ["api", "bpf", "cmd", "config", "datapath", "deploy", "internal", "pkg", "chart"]
extensions = {".go", ".c", ".h", ".o", ".yaml", ".yml", ".tpl"}
files = [args.root / name for name in ["Dockerfile", "go.mod", "go.sum"]]
for directory in directories:
    files += [path for path in (args.root / directory).rglob("*")
              if path.is_file() and path.suffix in extensions]
def fingerprint(paths):
    rows, tree = [], hashlib.sha256()
    for path in sorted(paths, key=lambda path: path.relative_to(args.root).as_posix()):
        relative = path.relative_to(args.root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        tree.update(relative.encode() + b"\0" + bytes.fromhex(digest))
        rows.append({"path": relative, "sha256": digest})
    return tree.hexdigest(), rows
source_digest, sources = fingerprint(files)
helpers = [path for path in (args.root / "test").iterdir()
           if path.is_file() and path.name.startswith(("ipsec-", "wireguard-client-"))]
helper_digest, helper_rows = fingerprint(helpers)
result = {"productImageConfigID": args.config_id, "productImageManifestDigest": args.manifest_digest,
          "productImageIndexDigest": args.index_digest,
          "sourceTreeSHA256": source_digest, "sourceFiles": sources,
          "harnessTreeSHA256": helper_digest, "harnessFiles": helper_rows,
          "algorithm": "SHA256 of sorted UTF8 relative path, NUL, binary file SHA256"}
(args.report / "provenance.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({key: value for key, value in result.items() if not key.endswith("Files")}))
