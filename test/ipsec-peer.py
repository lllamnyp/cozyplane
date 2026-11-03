#!/usr/bin/env python3
"""Install an ephemeral native strongSwan initiator. Credentials arrive on stdin."""
import json
import pathlib
import subprocess
import sys
import time

cfg = json.load(sys.stdin)
run = pathlib.Path("/run/ipsec-test")
run.mkdir(mode=0o700, exist_ok=True)
for directory in ("x509", "x509ca", "x509ocsp", "x509aa", "x509ac", "x509crl",
                  "pubkey", "private", "rsa", "ecdsa", "bliss", "pkcs8", "pkcs12"):
    (run / directory).mkdir(mode=0o700, exist_ok=True)
name, endpoint, identity = cfg["name"], cfg["endpoint"], cfg["identity"]
assert name.startswith("peer-") and identity.endswith(".example.invalid")
mode = cfg.get("mode", "psk")
assert mode in ("psk", "certificate", "eap")
local = f"auth = psk; id = {identity}"
remote = "auth = psk"
secrets = f"ike-{name} {{ id = {identity}; secret = {cfg.get('psk', '')} }}"
vip = ""
local_ts = "0.0.0.0/0, ::/0"
if mode == "psk":
    assert all(character in "0123456789abcdef" for character in cfg["psk"])
else:
    assert cfg["family"] in (4, 6)
    vip = "vips = " + ("0.0.0.0" if cfg["family"] == 4 else "::")
    local_ts = "dynamic"
    remote = "auth = pubkey; id = gateway.example.invalid"
    ca = run / "x509ca"
    ca.mkdir(parents=True, exist_ok=True)
    (ca / "fixture-ca.pem").write_text(cfg["ca"])
    if mode == "certificate":
        local = f"auth = pubkey; id = {identity}; certs = fixture-client.pem"
        for directory, filename, key in [("x509", "fixture-client.pem", "certificate"),
                                         ("private", "fixture-client.key", "privateKey")]:
            target = run / directory
            target.mkdir(parents=True, exist_ok=True)
            (target / filename).write_text(cfg[key])
            (target / filename).chmod(0o600)
        secrets = ""
    else:
        local = f"auth = eap-mschapv2; id = {identity}; eap_id = {identity}"
        assert all(character in "0123456789abcdef" for character in cfg["password"])
        secrets = f"eap-{name} {{ id = {identity}; secret = {cfg['password']} }}"
path = run / "swanctl.conf"
path.write_text(f"""
connections {{
  {name} {{
    version = 2
    remote_addrs = {endpoint}
    {vip}
    proposals = aes256-sha256-modp2048
    encap = yes
    dpd_delay = 5s
    local {{ {local} }}
    remote {{ {remote} }}
    children {{
      {name} {{
        local_ts = {local_ts}
        remote_ts = 0.0.0.0/0, ::/0
        esp_proposals = aes256-sha256-modp2048
        if_id_in = 42
        if_id_out = 42
        dpd_action = restart
        close_action = restart
        start_action = none
        rekey_time = 120s
      }}
    }}
  }}
}}
secrets {{ {secrets} }}
""".replace("; ", "\n"))
path.chmod(0o600)
pathlib.Path("/etc/strongswan.conf").write_text("""charon {
  install_routes = no
  retransmit_timeout = 1
  retransmit_base = 1.5
  retransmit_tries = 10
  plugins { include strongswan.d/charon/*.conf }
}
include strongswan.d/*.conf
""")
def call(*command):
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
call("ip", "route", "replace", endpoint + "/32", "via", cfg["node"])
call("ip", "link", "add", "ipsec0", "type", "xfrm", "if_id", "42")
call("ip", "link", "set", "ipsec0", "mtu", "1280", "up")
if mode == "psk":
    call("ip", "addr", "add", cfg["ipv4"] + "/32", "dev", "ipsec0")
    call("ip", "-6", "addr", "add", cfg["ipv6"] + "/128", "dev", "ipsec0")
for prefix in ["10.250.0.0/16", "fd42:250::/32"]:
    call("ip", "-6" if ":" in prefix else "-4", "route", "replace", prefix, "dev", "ipsec0")
log = (run / "charon.log").open("w")
subprocess.Popen(["/usr/lib/strongswan/charon"], stdout=log, stderr=log, start_new_session=True)
for attempt in range(50):
    if pathlib.Path("/var/run/charon.vici").exists():
        break
    time.sleep(.1)
call("swanctl", "--load-all", "--file", str(path))
# Initiation is explicitly performed by the harness after all replicas settle.
