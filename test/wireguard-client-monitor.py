#!/usr/bin/env python3
"""Observe only a named local fixture while its harness is alive."""
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
args = parser.parse_args()
fixture = os.environ.get("FIXTURE_CLUSTER", "cozyplane-wg-client")
fixtures = {"cozyplane-wg-client": ("wg-client-", "cozyplane-wgc-", b"wireguard-client-e2e.sh"),
            "cozyplane-ipsec-test": ("ipsec-test-", "cozyplane-ipsec-peer-", b"ipsec-e2e.sh")}
if fixture not in fixtures:
    parser.error("fixture is not allowlisted")
ns_prefix, container_prefix, harness_name = fixtures[fixture]
if not re.fullmatch(re.escape(ns_prefix) + r"[0-9]+-[0-9]+", args.namespace):
    parser.error("namespace must be an isolated fixture")
if not str(args.report).startswith(f"/tmp/{fixture}/results-"):
    parser.error("report must stay in the dedicated result directory")
kube = ["kubectl", "--context", f"kind-{fixture}", "-n", args.namespace]
run_id = args.namespace.removeprefix(ns_prefix)
environment = dict(os.environ, KUBECONFIG=f"/tmp/{fixture}/kubeconfig")

def read(command):
    timeout = 50 if fixture == "cozyplane-ipsec-test" and command[:2] == ["docker", "stats"] else 12
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=environment)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, 124, "", "observation timed out")

with (args.report / "resource-monitor.jsonl").open("a") as report:
    sample_number = 0
    while True:
        try:
            command = pathlib.Path(f"/proc/{args.harness_pid}/cmdline").read_bytes()
        except FileNotFoundError:
            break
        if harness_name not in command:
            break
        row = {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "appliances": []}
        # proc/stat covers the shared Linux VM, including kernel workers that
        # cannot reliably be charged to a particular privileged kind pod.
        row["vm_cpu_stat"] = pathlib.Path("/proc/stat").read_text().splitlines()[0]
        containers = read(["docker", "ps", "--filter", f"name={container_prefix}{run_id}-", "--format", "{{.Names}}"])
        names = containers.stdout.splitlines() + [f"{fixture}-worker", f"{fixture}-worker2"]
        stats = read(["docker", "stats", "--no-stream", "--format", "{{json .}}", *names])
        row["docker_stats_exit_code"] = stats.returncode
        row["docker"] = [json.loads(line) for line in stats.stdout.splitlines() if line.startswith("{")]
        pods = read(kube + ["get", "pods", "-l", "sdn.cozystack.io/vpn-gateway=gateway", "-o", "json"])
        if pods.returncode == 0:
            for pod in json.loads(pods.stdout).get("items", []):
                name = pod["metadata"]["name"]
                measured = read(kube + ["exec", name, "--", "cat", "/proc/1/stat", "/proc/1/cgroup", "/proc/self/mountinfo"])
                if measured.returncode == 0:
                    lines = measured.stdout.splitlines()
                    entry = {"name": name, "process_stat": lines[0]}
                    cgroup = next((line.removeprefix("0::") for line in lines[1:] if line.startswith("0::")), "")
                    # kind exposes the node cgroup mount inside pods. Follow the
                    # process's real scope, never label the mount root as pod memory.
                    mounts = [line.split() for line in lines if " - cgroup2 " in line]
                    mount = next((fields for fields in mounts if fields[4] == "/sys/fs/cgroup"), None)
                    if re.fullmatch(r"/kubelet\.slice/[A-Za-z0-9_./-]+\.scope", cgroup) and mount:
                        root, destination = mount[3:5]
                        if root != "/" and not cgroup.startswith(root + "/"):
                            row["appliances"].append(entry)
                            continue
                        relative = cgroup if root == "/" else cgroup[len(root):]
                        base = destination + relative
                        memory = read(kube + ["exec", name, "--", "cat", base + "/memory.current", base + "/memory.events", base + "/memory.max", base + "/cpu.stat"])
                        if memory.returncode == 0:
                            entry["container_memory"] = memory.stdout
                            entry["cgroup_scope"] = "container"
                            entry["cgroup_path"] = cgroup
                            entry["cgroup_mount_root"] = root
                    row["appliances"].append(entry)
        if sample_number % 3 == 0:
            network = []
            for name in ["server-a", *[entry["name"] for entry in row["appliances"]]]:
                counters = read(kube + ["exec", name, "--", "cat", "/proc/net/snmp", "/proc/net/snmp6", "/proc/net/dev"])
                if counters.returncode == 0:
                    network.append({"name": name, "counters": counters.stdout})
            row["network_counters"] = network
        report.write(json.dumps(row) + "\n")
        report.flush()
        sample_number += 1
        time.sleep(5)
print(f"Dedicated {fixture} resource monitoring completed.")
