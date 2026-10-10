#!/usr/bin/env python3
"""Regression for the observed stale IPv6 BYPASS selector after reconnection."""
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location("vip", pathlib.Path(__file__).with_name("ipsec-vip-public.py"))
vip = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vip)

def policy(source, direction="out", template=True, if_id="0x2a"):
    text = f"src {source} dst fd42:250:1::/64\n\tdir {direction} priority 1 ptype main\n"
    if template:
        text += f"\ttmpl src 172.18.0.5 dst 172.18.255.6\n\t\tproto esp reqid 1 mode tunnel\n\tif_id {if_id}\n"
    return text

class PoolVIP(unittest.TestCase):
    def test_actual_ipv6_ignores_stale_bypass(self):
        self.assertEqual(vip.actual_vip(policy("fd42:250:150::1/128", template=False) + policy("fd42:250:150::3/128")), "fd42:250:150::3")
    def test_ipv4_decimal_id_ignores_inbound(self):
        self.assertEqual(vip.actual_vip(policy("10.250.150.1/32", "in") + policy("10.250.150.2/32", if_id="42")), "10.250.150.2")
    def test_bypass_only_is_not_a_lease(self):
        with self.assertRaises(ValueError):
            vip.actual_vip(policy("10.250.150.1/32", template=False))
    def test_multiple_live_esp_addresses_are_ambiguous(self):
        with self.assertRaises(ValueError):
            vip.actual_vip(policy("10.250.150.1/32") + policy("10.250.150.2/32"))
    def test_wrong_interface_is_not_current(self):
        with self.assertRaises(ValueError):
            vip.actual_vip(policy("10.250.150.1/32", if_id="0x2b"))

unittest.main()
