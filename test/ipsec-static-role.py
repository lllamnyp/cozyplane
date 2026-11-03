#!/usr/bin/env python3
"""Recheck captured public role markers; preserve the original harness verdict."""
import json
import pathlib
import re
import sys

report = pathlib.Path(sys.argv[1])
original_exit = int(sys.argv[2]) if len(sys.argv) > 2 else 1
text = (report / "static-initiator-sas.txt").read_text()
matches = re.findall(r"^peer-1: #\d+, ESTABLISHED, IKEv2, ([0-9a-f]+)_i(\*?) ([0-9a-f]+)_r(\*?)$", text, re.M)
if len(matches) != 1 or matches[0][1] or matches[0][3] != "*":
    raise SystemExit("Exactly one actual responder IKE SA not demonstrated")
initiator, _, responder, _ = matches[0]
appliances = []
for path in report.glob("static-appliance-*-sas-raw.txt"):
    raw = path.read_text()
    if f"initiator-spi={initiator}" in raw and f"responder-spi={responder}" in raw and "initiator=yes" in raw:
        appliances.append(path.name)
if not appliances:
    raise SystemExit("Matching live appliance initiator SPI pair not demonstrated")
result = {"clientRole": "responder", "initiatorSPI": initiator, "responderSPI": responder, "oneEstablishedPeerSA": True, "matchingLiveApplianceEvidence": appliances, "originalHarnessExit": original_exit, "correction": "StrongSwan VICI omits initiator=no; list-sas _r* marks local responder", "officialImplementation": "https://github.com/strongswan/strongswan/blob/5.9.14/src/swanctl/commands/list_sas.c#L230-L235"}
(report / "static-role-recheck.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result))
