#!/usr/bin/env python3
"""Filter XFRM JSON in memory: keys/algorithms never enter public artifacts."""
import json
import sys
import re

allowed = {"src", "dst", "proto", "spi", "mode", "reqid", "if_id", "stats"}
raw = sys.stdin.read()
if raw.lstrip().startswith("["):
    states = json.loads(raw)
else:
    states = []
    for line in raw.splitlines():
        found = re.match(r"src (\S+) dst (\S+)", line)
        if found:
            states.append({"src": found[1], "dst": found[2]})
        elif states:
            state = states[-1]
            found = re.search(r"proto (\S+) spi (0x[0-9a-f]+).*reqid (\d+).*mode (\S+)", line)
            if found:
                state.update(proto=found[1], spi=found[2], reqid=int(found[3]), mode=found[4])
            for field, expression in [("if_id", r"if_id (0x[0-9a-f]+|\d+)"), ("replay-window", r"replay-window (\d+)")]:
                found = re.search(expression, line)
                if found and field not in state:
                    state[field] = int(found[1], 0) if found[1].startswith("0x") else int(found[1])
            found = re.search(r"(\d+)\(bytes\), (\d+)\(packets\)", line)
            if found:
                state["lifetime-current"] = {"bytes": int(found[1]), "packets": int(found[2])}
            found = re.search(r"\bseq (0x[0-9a-f]+)", line)
            if found:
                state.setdefault("stats", {})["sequence"] = int(found[1], 16)
            found = re.match(r"\s*replay-window \d+ replay (\d+) failed (\d+)", line)
            if found:
                state.setdefault("stats", {}).update(replay=int(found[1]), failed=int(found[2]))
if not states or any("spi" not in state for state in states):
    raise SystemExit("No complete actual XFRM SA evidence")
print(json.dumps([{key: value for key, value in state.items()
                   if key in allowed or key.startswith(("replay", "lifetime"))}
                  for state in states]))
