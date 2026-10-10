#!/usr/bin/env bash
# Check the shipped binary, never a replacement Go test binary. Run only in the
# dedicated Linux test guest; all network changes stay in this owned container.
set -euo pipefail
image=${1:?usage: ipsec-image-runtime-check.sh IMAGE EXPECTED_IMAGE_ID}
expected=${2:?expected image ID is required}
name=cozyplane-ipsec-image-runtime-check
if docker container inspect "$name" >/dev/null 2>&1; then
    echo "refusing existing fixture container: $name" >&2
    exit 2
fi
actual=$(docker image inspect --format '{{.Id}}' "$image")
[[ "$actual" == "sha256:$expected" || "$actual" == "$expected" ]] || {
    echo "image ID differs from the requested final image" >&2
    exit 2
}
echo "kernel: $(uname -r)"
echo "image: $image"
echo "image ID: $actual"
echo "binary: /usr/local/bin/cozyplane-vpn-gateway-ipsec (from image)"
docker run -d --name "$name" --privileged --network none \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    --sysctl net.ipv6.conf.default.disable_ipv6=0 \
    --entrypoint /bin/sleep "$actual" 300 >/dev/null
trap 'docker rm -f "$name" >/dev/null' EXIT
inside() { docker exec "$name" "$@"; }
inside ip link add fabric-fixture type dummy
inside ip link set fabric-fixture up
inside ip addr add 192.0.2.1/24 dev fabric-fixture
inside ip -6 addr add fd00:ffff::1/64 dev fabric-fixture nodad
inside ip route add default dev fabric-fixture
inside ip -6 route add default dev fabric-fixture

for scenario in missing malformed; do
    # Legacy empty aliases must also recover after a process dies during probe.
    inside ip link add cpxfrmprobe type xfrm if_id 3249
    inside ip link add ipsec7 type xfrm if_id 7
    inside ip link set ipsec7 alias cozyplane-vpn-ipsec
    inside ip link set ipsec7 up
    inside ip route replace 10.9.0.0/16 dev ipsec7 proto static
    inside ip -6 route replace fd00:9::/64 dev ipsec7 proto static
    # Synthetic fixture keys are unrelated to any product credential.
    inside ip xfrm state add src 192.0.2.1 dst 192.0.2.2 proto esp spi 7 \
        reqid 7 mode tunnel if_id 7 \
        auth-trunc 'hmac(sha256)' 0x1111111111111111111111111111111111111111111111111111111111111111 128 \
        enc 'cbc(aes)' 0x22222222222222222222222222222222
    inside ip xfrm policy add src 10.1.0.0/24 dst 10.9.0.0/16 dir out \
        if_id 7 tmpl src 192.0.2.1 dst 192.0.2.2 proto esp reqid 7 mode tunnel
    config=/tmp/cozyplane-image-missing.json
    if [[ "$scenario" == malformed ]]; then
        config=/tmp/cozyplane-image-malformed.json
        inside /bin/sh -c 'printf "{" > /tmp/cozyplane-image-malformed.json'
    fi
    echo "scenario: $scenario config, legacy probe + owned XFRM + IPv4/IPv6 routes + SA/policy"
    set +e
    docker exec -e "VPN_CONFIG=$config" "$name" /usr/local/bin/cozyplane-vpn-gateway-ipsec
    status=$?
    set -e
    [[ "$status" == 1 ]] || { echo "unexpected binary exit: $status" >&2; exit 1; }
    # Parse only counts, link names and public route metadata: do not emit SA keys.
    python3 - "$name" <<'PY'
import json, subprocess, sys
name = sys.argv[1]
def ip(*args):
    return json.loads(subprocess.check_output(["docker", "exec", name, "ip", "-j", *args]))
names = {link["ifname"] for link in ip("link", "show")}
assert "cpxfrmprobe" not in names and "ipsec7" not in names, names
for resource in ("state", "policy"):
    # iproute2 xfrm does not implement JSON consistently; empty text is exact.
    assert not subprocess.check_output(["docker", "exec", name, "ip", "xfrm", resource]).strip(), resource
for family, prefix, destination in (("-4", "10.9.0.0/16", "10.9.0.1"), ("-6", "fd00:9::/64", "fd00:9::1")):
    routes = ip(family, "route", "show", "table", "main")
    assert any(r.get("dst") == prefix and r.get("type") == "blackhole" for r in routes), routes
    assert any(r.get("dst") == "default" and r.get("dev") == "fabric-fixture" for r in routes), routes
    result = subprocess.run(["docker", "exec", name, "ip", family, "route", "get", destination], capture_output=True)
    assert result.returncode != 0, result.stdout.decode()
print("PASS: probe/devices removed; SAs/policies cleared; IPv4/IPv6 BLACKHOLE retained; fabric defaults preserved; no default fallback")
PY
done
echo "PASS: actual final-image binary cleanup before missing/malformed configuration"
