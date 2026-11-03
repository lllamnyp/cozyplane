#!/usr/bin/env python3
"""Read actual runtime configuration digests from a public Docker save archive."""
import json
import re
import sys
import tarfile

with tarfile.open(sys.argv[1]) as archive:
    manifest = json.load(archive.extractfile("manifest.json"))
configs = {}
for image in manifest:
    match = re.search(r"(?:^|/)([0-9a-f]{64})(?:\.json)?$", image["Config"])
    assert match, "unknown Docker save Config encoding"
    for tag in image.get("RepoTags", []):
        configs[tag] = "sha256:" + match.group(1)
print(json.dumps(configs))
