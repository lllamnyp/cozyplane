#!/usr/bin/env python3
"""Temporary malicious outbound policy in one disposable fixture initiator.

Raw SA/key material remains in subprocess memory, never in diagnostics/artifacts.
"""
import ipaddress
import json
import pathlib
import subprocess
import sys

source, target = map(ipaddress.ip_address, sys.argv[1:3])
if source.version != target.version:
    raise SystemExit("Source/target family mismatch")
pools = [ipaddress.ip_network("10.250.150.0/24"), ipaddress.ip_network("fd42:250:150::/120")]
if not any(source in pool for pool in pools):
    raise SystemExit("Not a fixture pool")
bits = source.max_prefixlen
selector = ["src", f"{source}/{bits}", "dst", f"{target}/{bits}", "dir", "out", "if_id", "42"]

def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, **kwargs)

def public_states():
    result = run(["ip", "-s", "xfrm", "state"])
    if result.returncode:
        raise RuntimeError("Cannot read fixture states")
    filtered = run([sys.executable, str(pathlib.Path(__file__).with_name("ipsec-sa-public.py"))], input=result.stdout)
    if filtered.returncode:
        raise RuntimeError("Cannot filter actual fixture states")
    return json.loads(filtered.stdout)

eth = json.loads(run(["ip", "-j", "addr", "show", "dev", "eth0"], check=True).stdout)
local = next(a["local"] for link in eth for a in link["addr_info"] if a["family"] == "inet")
inner = json.loads(run(["ip", "-j", "addr", "show", "dev", "ipsec0"], check=True).stdout)
if any(a["local"] == str(source) for link in inner for a in link["addr_info"]):
    raise SystemExit("Spoof source already belongs to this fixture initiator")
before = [s for s in public_states() if s["src"] == local and s.get("if_id") == 42]
if not before or any("lifetime-current" not in s or "spi" not in s for s in before):
    raise SystemExit("Actual outgoing SA counters missing")
sa = before[0]
policy = ["ip", "xfrm", "policy", "add", *selector, "priority", "0", "tmpl", "src", sa["src"], "dst", sa["dst"], "proto", "esp", "mode", "tunnel", "reqid", str(sa["reqid"])]
address = ["ip", f"-{source.version}", "addr"]
added_address = added_policy = False
report = {"source": str(source), "target": str(target), "beforeSpis": [s["spi"] for s in before]}
try:
    run([*address, "add", f"{source}/{bits}", "dev", "ipsec0", *(["nodad"] if source.version == 6 else [])], check=True)
    added_address = True
    run(policy, check=True)
    added_policy = True
    url_target = f"[{target}]" if target.version == 6 else str(target)
    response = run(["curl", "--interface", str(source), "--noproxy", "*", "-sS", "-m", "4", "-o", "/dev/null", "-w", "%{http_code}", f"http://{url_target}:8080/"])
    after = [s for s in public_states() if s["src"] == local and s.get("if_id") == 42]
    counts = {s["spi"]: s["lifetime-current"]["packets"] for s in before}
    delta = sum(max(0, s.get("lifetime-current", {}).get("packets", 0) - counts.get(s.get("spi"), 0)) for s in after)
    report.update(afterSpis=[s["spi"] for s in after], espPacketDelta=delta, httpCode=response.stdout, httpExitCode=response.returncode, encryptedSpoofProven=delta > 0, denied=response.stdout == "000")
finally:
    policy_restored = not added_policy or run(["ip", "xfrm", "policy", "delete", *selector]).returncode == 0
    address_restored = not added_address or run([*address, "del", f"{source}/{bits}", "dev", "ipsec0"]).returncode == 0
    report["policyRestored"] = policy_restored
    report["addressRestored"] = address_restored
    print(json.dumps(report))
if not all(report.get(key) for key in ["encryptedSpoofProven", "denied", "policyRestored", "addressRestored"]):
    raise SystemExit("Encrypted pool-source spoof proof failed")
