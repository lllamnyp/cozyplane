#!/usr/bin/env python3
"""Keep an initiator's IKE identity, use another fixture's valid EAP credential.

Secret data arrives only on stdin and remains in disposable private files.
"""
import json
import pathlib
import re
import sys

cfg = json.load(sys.stdin)
ike, eap, password = (cfg[key] for key in ("ikeIdentity", "eapIdentity", "password"))
assert ike.endswith(".example.invalid") and eap.endswith(".example.invalid") and ike != eap
assert len(password) >= 32 and all(character in "0123456789abcdef" for character in password)
path = pathlib.Path("/run/ipsec-test/swanctl.conf")
text = path.read_text()
original_ike = re.search(r"\blocal\s*\{[^}]*\bid\s*=\s*(\S+)", text).group(1)
assert original_ike == ike
backup = path.with_name("swanctl-before-cross.conf")
backup.write_text(text)
backup.chmod(0o600)
text, changed = re.subn(r"\beap_id\s*=\s*\S+", "eap_id = " + eap, text)
assert changed == 1
text, changed = re.subn(r"(eap-peer-3\s*\{\s*id\s*=\s*)\S+", lambda match: match[1] + eap, text)
assert changed == 1
text, changed = re.subn(r"\bsecret\s*=\s*[0-9a-f]+", "secret = " + password, text)
assert changed == 1 and re.search(r"\blocal\s*\{[^}]*\bid\s*=\s*(\S+)", text).group(1) == original_ike
path.write_text(text)
path.chmod(0o600)
print(json.dumps({"ikeIdentity": ike, "eapIdentity": eap, "ikeIdentityPreserved": True}))
