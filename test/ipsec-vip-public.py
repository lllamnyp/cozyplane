#!/usr/bin/env python3
"""Identify the fixture VIP from actual outbound ESP policies, excluding BYPASS."""
import ipaddress
import re
import sys

POOLS = tuple(map(ipaddress.ip_network, ("10.250.150.0/24", "fd42:250:150::/120")))

def actual_vip(text):
    addresses = set()
    for block in re.split(r"(?m)(?=^src )", text):
        source = re.match(r"src (\S+)", block)
        if (not source or not re.search(r"\bdir out\b", block)
                or not re.search(r"\btmpl src\b", block)
                or not re.search(r"\bproto esp\b", block)
                or not re.search(r"\bif_id (?:0x2a|42)\b", block)):
            continue
        interface = ipaddress.ip_interface(source[1])
        if interface.network.prefixlen != interface.ip.max_prefixlen:
            raise ValueError("Pool selector is not a single assigned address")
        if any(interface.ip in pool for pool in POOLS):
            addresses.add(str(interface.ip))
    if len(addresses) != 1:
        raise ValueError("Exactly one current outbound ESP pool VIP required")
    return addresses.pop()

if __name__ == "__main__":
    print(actual_vip(sys.stdin.read()))
