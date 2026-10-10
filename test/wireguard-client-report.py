#!/usr/bin/env python3
"""Summarize only measurements; raw iperf JSON never contains keys."""
import json
import pathlib
import re
import statistics
import sys
import datetime
from collections import defaultdict

root = pathlib.Path(sys.argv[1])
rows = []
groups = defaultdict(dict)
for path in sorted(root.glob("*.json")):
    try:
        obj = json.loads(path.read_text())
    except (ValueError, OSError):
        continue
    if "start" not in obj and "error" not in obj:
        continue
    end = obj.get("end", {})
    measured = end.get("sum_received", end.get("sum", {}))
    rows.append({"sample": path.stem, "mbps": round(measured.get("bits_per_second", 0) / 1e6, 3),
                 "loss_pct": measured.get("lost_percent"), "jitter_ms": measured.get("jitter_ms"),
                 "retransmits": end.get("sum_sent", {}).get("retransmits"),
                 "error": obj.get("error")})
    match = re.fullmatch(r"tcp-(1|8|16)-(\d+)-client\d+", path.stem)
    if match and not obj.get("error"):
        count, sample = match.groups()
        groups[count][sample] = groups[count].get(sample, 0) + measured.get("bits_per_second", 0) / 1e6
backend_file = root / "backend.txt"
backend = backend_file.read_text().strip() if backend_file.exists() else ""
assert backend in ("", "ipsec", "wireguard")
ipsec = backend == "ipsec" or (not backend and root.parent.name == "cozyplane-ipsec-test")
title = "IPsec" if ipsec else "WireGuard client"
out = [f"# Local {title} test measurements", "", "Docker Desktop is a shared host; throughput is observational.", "",
       "| Sample | Mbit/s received | UDP loss % | Jitter ms | TCP retransmits | Error |", "|---|---:|---:|---:|---:|---|"]
for row in rows:
    out.append("| {sample} | {mbps} | {loss_pct} | {jitter_ms} | {retransmits} | {error} |".format(**row))
if groups:
    out += ["", "Aggregate concurrent TCP throughput (sum of receiver rates):", "",
            "| Clients | Samples | Median Mbit/s | Minimum | Maximum |", "|---:|---:|---:|---:|---:|"]
    for count, samples in sorted(groups.items(), key=lambda item: int(item[0])):
        values = list(samples.values())
        out.append(f"| {count} | {len(values)} | {statistics.median(values):.3f} | {min(values):.3f} | {max(values):.3f} |")
soak_rows = [row for row in rows if re.fullmatch(r"soak-client\d+", row["sample"])]
if soak_rows:
    out.append(f"\nTen-minute soak: {len(soak_rows)} clients, aggregate received {sum(row['mbps'] for row in soak_rows):.3f} Mbit/s; TCP retransmissions {sum(row['retransmits'] or 0 for row in soak_rows)}; iperf errors {sum(bool(row['error']) for row in soak_rows)}.")
for path in sorted(root.glob("*-ping.txt")):
    values = []
    for line in path.read_text().splitlines():
        if "time=" in line:
            try:
                values.append(float(line.split("time=")[1].split()[0]))
            except ValueError:
                pass
    if values:
        values.sort()
        quantile = lambda p: values[min(len(values) - 1, int((len(values) - 1) * p))]
        out += ["", f"{path.stem}: n={len(values)}, median={statistics.median(values):.3f} ms, p95={quantile(.95):.3f} ms, p99={quantile(.99):.3f} ms."]
    packet_loss = re.search(r"([0-9.]+)% packet loss", path.read_text())
    if packet_loss:
        out.append(f"{path.stem}: ICMP packet loss {packet_loss.group(1)}%.")
resources = root / "resource-monitor.jsonl"
if resources.exists():
    observed = defaultdict(list)
    rss, scoped_memory, scoped_oom = [], [], 0
    network = defaultdict(list)
    vm_previous, vm_busy = None, []
    for line in resources.read_text().splitlines():
        try:
            sample = json.loads(line)
        except ValueError:
            continue
        cpu = sample.get("vm_cpu_stat")
        if cpu:
            current = list(map(int, cpu.split()[1:9]))
            if vm_previous:
                elapsed = sum(current) - sum(vm_previous)
                idle = sum(current[3:5]) - sum(vm_previous[3:5])
                if elapsed > 0:
                    vm_busy.append((elapsed-idle) / elapsed * 100)
            vm_previous = current
        for container in sample.get("docker", []):
            try:
                observed[container["Name"]].append(float(container["CPUPerc"].rstrip("%")))
            except (KeyError, ValueError):
                pass
        for appliance in sample.get("appliances", []):
            process = appliance.get("process_stat", appliance.get("process_and_cgroup", "").splitlines()[0] if appliance.get("process_and_cgroup") else "")
            if process:
                # Linux /proc stat field 24 is RSS in pages. Command name may contain spaces.
                fields = process.rsplit(")", 1)[-1].split()
                if len(fields) > 21:
                    rss.append(int(fields[21]) * 4096 / 2**20)
            if appliance.get("cgroup_scope") == "container":
                memory = appliance.get("container_memory", "")
                if memory:
                    scoped_memory.append(int(memory.splitlines()[0]) / 2**20)
                    matches = re.findall(r"^oom_kill (\d+)$", memory, re.MULTILINE)
                    scoped_oom = max([scoped_oom] + list(map(int, matches)))
        for counter in sample.get("network_counters", []):
            udp = [line.split()[1:] for line in counter["counters"].splitlines() if line.startswith("Udp:")]
            if len(udp) == 2:
                network[counter["name"]].append((sample["timestamp"], dict(zip(udp[0], map(int, udp[1])))))
    out += ["", "Resources sampled during the live run (Docker CPU 100% = one CPU; node values include the full kind node):", "",
            "| Container | CPU samples | Median CPU % | Maximum CPU % |", "|---|---:|---:|---:|"]
    for name, values in sorted(observed.items()):
        out.append(f"| {name} | {len(values)} | {statistics.median(values):.2f} | {max(values):.2f} |")
    if rss:
        out.append(f"\nAppliance process RSS median/max: {statistics.median(rss):.2f}/{max(rss):.2f} MiB (4KiB pages, local Linux kernel).")
    if scoped_memory:
        out.append(f"\nAppliance container cgroup memory.current median/max: {statistics.median(scoped_memory):.2f}/{max(scoped_memory):.2f} MiB; maximum observed oom_kill counter: {scoped_oom}.")
    if ipsec:
        out.append("\nOnly resolved container-scope memory is reported. Go process RSS excludes the child charon daemon; the container cgroup includes both. Kernel XFRM/eBPF execution runs outside these processes. Docker node CPU includes charged work; kernel workers/softIRQ may be charged elsewhere in the isolated 4-vCPU KVM guest. These results are not directly comparable with native Docker Desktop WireGuard measurements.")
    else:
        out.append("\nEarly observer mount-root memory values are excluded: privileged kind pods expose the node cgroup tree. Only resolved container-scope memory is reported. Kernel WireGuard/eBPF execution runs outside the Go process; Docker node CPU includes work charged to that node, while kernel workers/softIRQ may be charged elsewhere in the shared Linux VM.")
    if vm_busy:
        scope = "isolated 4-vCPU KVM guest, including its kind/control-plane workloads" if ipsec else "all VM CPUs (includes unrelated Docker Desktop workloads; sampling began during impairment tests)"
        out.append(f"\nLinux VM total CPU utilization median/max: {statistics.median(vm_busy):.2f}/{max(vm_busy):.2f}% across {scope}.")
    if network:
        heading = "UDP receive-error counter windows:" if ipsec else "UDP receive-error counter windows (sampling began during injected-loss tests, after baseline):"
        out += ["", heading, "",
                "| Pod | First sample UTC | Last sample UTC | InErrors delta | RcvbufErrors delta |", "|---|---|---|---:|---:|"]
        for name, values in sorted(network.items()):
            first_time, first = values[0]
            last_time, last = values[-1]
            out.append(f"| {name} | {first_time} | {last_time} | {last.get('InErrors',0)-first.get('InErrors',0)} | {last.get('RcvbufErrors',0)-first.get('RcvbufErrors',0)} |")
        if ipsec:
            out.append("\nRaw namespace SNMP, IPv6 SNMP and netdev counters remain in resource-monitor.jsonl. Additional udp-counters.jsonl records server and gateway counters before and after each UDP baseline and injected-loss phase. UDP payload is explicitly 1200 bytes to fit tunnel MTU1280. Configured netem loss and observed application loss are distinct measurements.")
        else:
            out.append("\nRaw namespace SNMP, IPv6 SNMP and netdev counters remain in resource-monitor.jsonl. Receiver buffer errors are evidence of UDP socket drops; baseline loss cannot be attributed precisely because its pre-run counters were not sampled.")
recovery = root / "recovery-monitor.jsonl"
if recovery.exists():
    previous_success, failed_at, failure_context, intervals = None, None, "", []
    for line in recovery.read_text().splitlines():
        try:
            sample = json.loads(line)
            timestamp = datetime.datetime.fromisoformat(sample["timestamp"])
        except (ValueError, KeyError):
            continue
        if sample.get("success"):
            if failed_at:
                intervals.append((failed_at, timestamp, previous_success, failure_context))
                failed_at = None
            previous_success = timestamp
        elif failed_at is None:
            failed_at = timestamp
            failure_context = sample.get("last_check", "")
    out += ["", "HTTP outage observations across restart, key rotation and WarmStandby tests (approximately 1-second probing):", "",
            "| Last completed check at first failure | First failed probe UTC | First recovered probe UTC | Observed gap seconds | Last-success to recovery upper bound seconds |", "|---|---|---|---:|---:|"]
    for failure, recovered, prior, context in intervals:
        upper = (recovered - prior).total_seconds() if prior else None
        out.append(f"| {context} | {failure.isoformat()} | {recovered.isoformat()} | {(recovered-failure).total_seconds():.3f} | {upper} |")
    if failed_at:
        out.append("\nThe final failed probe may coincide with fixture cleanup; it has no observed recovery and is excluded from recovered intervals.")
ready_retest = root / "ha-ready-retest-probes.tsv"
if ready_retest.exists():
    prior, failure, intervals = None, None, []
    for line in ready_retest.read_text().splitlines():
        timestamp, result = line.split("\t")
        timestamp = datetime.datetime.fromisoformat(timestamp)
        if result == "success":
            if failure:
                intervals.append((failure, timestamp, prior))
                failure = None
            prior = timestamp
        elif failure is None:
            failure = timestamp
    out += ["", "WarmStandby selected-appliance loss retest: both replicas Ready and current-generation client config checked before fault; fixture provider already running automatically. Probe starts are approximately 0.5 seconds apart plus each HTTP request duration.", "",
            "| First failed probe UTC | First recovered probe UTC | Observed gap seconds | Last-success to recovery upper bound seconds |", "|---|---|---:|---:|"]
    for failed, recovered, previous in intervals:
        upper = (recovered-previous).total_seconds() if previous else None
        out.append(f"| {failed.isoformat()} | {recovered.isoformat()} | {(recovered-failed).total_seconds():.3f} | {upper} |")
notes = root / "run-notes.md"
ha = root / "ha-probes.jsonl"
if ipsec and ha.exists():
    previous, failed, intervals = None, None, []
    for line in ha.read_text().splitlines():
        sample = json.loads(line)
        timestamp = datetime.datetime.fromisoformat(sample["timestamp"])
        if sample["http"] == "200":
            if failed:
                intervals.append((failed, timestamp, previous))
                failed = None
            previous = timestamp
        elif failed is None:
            failed = timestamp
    out += ["", "WarmStandby fault: both appliances Ready and exact current checksum acknowledged before deleting the selected appliance. Probe spacing is 0.5 seconds plus HTTP duration.", "",
            "| First failure UTC | First recovery UTC | Observed gap seconds | Last-success to recovery upper bound seconds |", "|---|---|---:|---:|"]
    for failure, recovery_time, prior in intervals:
        upper = (recovery_time-prior).total_seconds() if prior else None
        out.append(f"| {failure.isoformat()} | {recovery_time.isoformat()} | {(recovery_time-failure).total_seconds():.3f} | {upper} |")
    if failed:
        out.append("\nA failed tail has no observed recovery within the recorded window.")
if notes.exists():
    out += ["", notes.read_text().strip()]
(root / "summary.md").write_text("\n".join(out) + "\n")
print(f"Summarized {len(rows)} traffic samples in {root / 'summary.md'}")
