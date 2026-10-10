#!/usr/bin/env python3
"""Summarize matched pre/post UDP counters, without inferring loss causes."""
import json
import pathlib
import sys

report = pathlib.Path(sys.argv[1])
samples = {}
for line in (report / "udp-counters.jsonl").read_text().splitlines():
    row = json.loads(line)
    phase, edge = row["phase"].rsplit("-", 1)
    udp = [line.split()[1:] for line in row["counters"].splitlines() if line.startswith("Udp:")]
    values = dict(zip(udp[0], map(int, udp[1]))) if len(udp) == 2 else {}
    samples.setdefault((phase, row["name"]), {})[edge] = (row["timestamp"], values)
out = ["# UDP counter deltas", "", "Only matched before/after windows are included. Counters are namespace observations; loss attribution requires corroborating evidence.", "",
       "| Phase | Pod | Before UTC | After UTC | InDatagrams | InErrors | RcvbufErrors | SndbufErrors |", "|---|---|---|---|---:|---:|---:|---:|"]
result = []
for (phase, name), edges in sorted(samples.items()):
    if "before" not in edges or "after" not in edges:
        continue
    start, before = edges["before"]
    finish, after = edges["after"]
    delta = {key: after.get(key, 0)-before.get(key, 0)
             for key in ("InDatagrams", "InErrors", "RcvbufErrors", "SndbufErrors")}
    result.append({"phase": phase, "pod": name, "before": start, "after": finish, "delta": delta})
    out.append(f"| {phase} | {name} | {start} | {finish} | " + " | ".join(str(value) for value in delta.values()) + " |")
(report / "udp-counter-deltas.json").write_text(json.dumps(result, indent=2) + "\n")
(report / "udp-counter-deltas.md").write_text("\n".join(out) + "\n")
print(json.dumps(result))
