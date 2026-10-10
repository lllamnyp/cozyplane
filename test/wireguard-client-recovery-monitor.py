#!/usr/bin/env python3
"""Observe HTTP outage intervals near the end of the isolated load run."""
import argparse
import datetime
import json
import os
import pathlib
import re
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument("namespace")
parser.add_argument("harness_pid", type=int)
parser.add_argument("report", type=pathlib.Path)
parser.add_argument("--soak-seconds", type=int, default=600)
args = parser.parse_args()
if not re.fullmatch(r"wg-client-[0-9]+-[0-9]+", args.namespace):
    parser.error("namespace must be an isolated WireGuard client fixture")
if not str(args.report).startswith("/tmp/cozyplane-wg-client/results-"):
    parser.error("report must stay in the dedicated result directory")
environment = dict(os.environ, KUBECONFIG="/tmp/cozyplane-wg-client/kubeconfig")
kube = ["kubectl", "--context", "kind-cozyplane-wg-client", "-n", args.namespace]
client = "cozyplane-wgc-" + args.namespace.removeprefix("wg-client-") + "-1"

def active():
    try:
        return b"wireguard-client-e2e.sh" in pathlib.Path(f"/proc/{args.harness_pid}/cmdline").read_bytes()
    except FileNotFoundError:
        return False

def run(command):
    return subprocess.run(command, capture_output=True, text=True, timeout=5, env=environment)

# Avoid adding requests throughout the throughput phase. The iperf output file
# is opened at sample start, so its creation time marks the soak window.
soak = args.report / "soak-client1.json"
while active():
    if soak.exists() and time.time() - soak.stat().st_mtime >= args.soak_seconds - 5:
        break
    time.sleep(5)
if not active():
    raise SystemExit("Harness finished before the recovery phase.")
ports = run(kube + ["get", "ports", "-l", f"sdn.cozystack.io/pod-namespace={args.namespace},sdn.cozystack.io/pod-name=server-a", "-o", "json"])
target = next(item["spec"]["ip"] for item in json.loads(ports.stdout)["items"] if ":" not in item["spec"]["ip"])
if not re.fullmatch(r"10\.250\.1\.\d+", target):
    raise SystemExit("Target must stay inside the isolated fixture VPC.")
with (args.report / "recovery-monitor.jsonl").open("a") as report:
    while active():
        started = time.monotonic()
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result = run(["docker", "exec", client, "curl", "-fsS", "--noproxy", "*", "--connect-timeout", "1", "--max-time", "1", f"http://{target}:8080/"])
        row = {"timestamp": timestamp, "duration_seconds": round(time.monotonic() - started, 3),
               "success": result.returncode == 0 and result.stdout.strip() == "site-a", "returncode": result.returncode}
        checks = (args.report / "checks.log").read_text().splitlines()
        row["last_check"] = checks[-1] if checks else ""
        report.write(json.dumps(row) + "\n")
        report.flush()
        time.sleep(max(0, 1 - (time.monotonic() - started)))
print("Dedicated WireGuard HTTP recovery monitoring completed.")
