#!/usr/bin/env python3
"""Summarize separate idle UDP controls and matched XFRM/SA observations."""
import json
import pathlib
import re
import sys

report = pathlib.Path(sys.argv[1])
packets = [json.loads(line) for line in (report / "packet-counters.jsonl").read_text().splitlines()]
states = [json.loads(line) for line in (report / "sa-public-counters.jsonl").read_text().splitlines()]
result = []
phases = sys.argv[2:] or ["targeted-100M", "targeted-20M"]
for phase in phases:
    if not re.fullmatch(r"targeted-(100M|20M|reorder)", phase):
        raise SystemExit("Unknown targeted phase")
    sample = json.loads((report / f"{phase}-udp-client1.json").read_text())
    if sample.get("error"):
        raise SystemExit("Targeted iperf error")
    end = sample["end"]["sum_received"]
    if end["seconds"] < 19:
        raise SystemExit("Targeted iperf duration incomplete")
    delta = []
    before_rows = [row for row in packets if row["phase"] == phase + "-before" and "name" in row]
    for before in before_rows:
        after = next(row for row in packets if row["phase"] == phase + "-after" and row.get("name") == before["name"])
        values = []
        for row in (before, after):
            values.append({key: int(number) for key, number in re.findall(r"^(Xfrm\w+)\s+(\d+)$", row["counters"], re.M)})
        delta.append({"name": before["name"], "before": before["timestamp"], "after": after["timestamp"], "xfrm": {key: values[1].get(key, 0)-number for key, number in values[0].items()}})
    windows = [{"name": row["name"], "phase": row["phase"], "spis": [{"spi": state["spi"], "src": state["src"], "dst": state["dst"], "window": state.get("replay-window"), "current": state.get("lifetime-current"), "stats": state.get("stats")} for state in row["states"]]} for row in states if row["phase"].startswith(phase)]
    result.append({"phase": phase, "receivedBitsPerSecond": end["bits_per_second"], "lossPercent": end["lost_percent"], "lostPackets": end["lost_packets"], "packets": end["packets"], "seconds": end["seconds"], "xfrmDeltas": delta, "saWindows": windows})
(report / "targeted-udp-attribution.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps([{key: value for key, value in row.items() if key != "saWindows"} for row in result]))
