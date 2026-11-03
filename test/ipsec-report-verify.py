#!/usr/bin/env python3
"""Verify full nominal durations and file counts before publishing aggregates."""
import json
import pathlib
import sys

report = pathlib.Path(sys.argv[1])
assert report.parent.name == "cozyplane-ipsec-test" and report.name.startswith("results-")
expected = {}
for count in (1, 8, 16):
    for repetition in (1, 2, 3):
        for peer in range(1, count + 1):
            expected[f"tcp-{count}-{repetition}-client{peer}.json"] = 60
for peer in range(1, 17):
    expected[f"soak-client{peer}.json"] = 600
for phase in ("baseline-100M-udp", "baseline-20M-udp", "loss-1", "loss-5", "loss-10", "delay-jitter-reorder"):
    expected[f"{phase}-client1.json"] = 60
rows, problems = [], []
for filename, target in expected.items():
    try:
        obj = json.loads((report / filename).read_text())
        end = obj.get("end", {})
        received = end.get("sum_received", end.get("sum", {}))
        seconds = received.get("seconds", 0)
        error = obj.get("error")
        rows.append({"file": filename, "seconds": seconds, "targetSeconds": target,
                     "error": error, "receivedMbps": received.get("bits_per_second", 0) / 1e6})
        if error or seconds < target - 1:
            problems.append({"file": filename, "reason": "iperf error or truncated duration"})
    except (OSError, ValueError) as exc:
        problems.append({"file": filename, "reason": type(exc).__name__})
result = {"expectedTCPFiles": 75, "expectedSoakFiles": 16, "expectedUDPFiles": 6,
          "observedFiles": len(rows), "passed": not problems,
          "problems": problems, "samples": rows}
(report / "measurement-verification.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({key: value for key, value in result.items() if key != "samples"}))
sys.exit(bool(problems))
