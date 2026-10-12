#!/usr/bin/env bash
# Isolated strongSwan allocator evidence: two independent responders, two exact
# identities, one pool CIDR. No product credentials or existing tunnels involved.
set -euo pipefail
IMAGE=cozyplane-ipsec-test-bench:local
NETWORK=cozyplane-ipsec-allocator-repro
NAMES=(cozyplane-ipsec-allocator-server-a cozyplane-ipsec-allocator-server-b cozyplane-ipsec-allocator-client-a cozyplane-ipsec-allocator-client-b)
for name in "${NAMES[@]}"; do
  if docker container inspect "$name" >/dev/null 2>&1; then
    printf 'Refusing an existing fixture container: %s\n' "$name" >&2; exit 2
  fi
done
if docker network inspect "$NETWORK" >/dev/null 2>&1; then
  printf 'Refusing an existing fixture network\n' >&2; exit 2
fi
cleanup() {
  docker rm -f "${NAMES[@]}" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker network create "$NETWORK" >/dev/null
for name in "${NAMES[@]}"; do
  docker run -d --name "$name" --network "$NETWORK" --cap-add NET_ADMIN "$IMAGE" >/dev/null
done
configure() {
  local container=$1 role=$2 identity=$3 endpoint=${4:-}
  docker exec -i "$container" python3 - "$role" "$identity" "$endpoint" <<'PY'
import pathlib, subprocess, sys, time
role, identity, endpoint = sys.argv[1:]
run = pathlib.Path('/run/ipsec-allocator-repro')
run.mkdir(mode=0o700)
for directory in ('x509','x509ca','x509ocsp','x509aa','x509ac','x509crl','pubkey','private','rsa','ecdsa','bliss','pkcs8','pkcs12'):
 (run/directory).mkdir(mode=0o700)
# Explicitly synthetic PSK, confined to this disposable fixture.
secret = '0123456789abcdef' * 4
pathlib.Path('/etc/strongswan.conf').write_text('''charon {
 install_routes = no
 plugins { include /etc/strongswan.d/charon/*.conf }
}
include /etc/strongswan.d/*.conf
''')
local_id = 'gateway.example.invalid' if role == 'server' else identity
remote_id = identity if role == 'server' else 'gateway.example.invalid'
extra = 'pools = lease-pool' if role == 'server' else f'remote_addrs = {endpoint}\n vips = 0.0.0.0'
local_ts = '10.1.0.0/24' if role == 'server' else 'dynamic'
remote_ts = 'dynamic' if role == 'server' else '10.1.0.0/24'
pool = 'pools { lease-pool { addrs = 10.200.0.0/24 } }' if role == 'server' else ''
config = f'''connections {{
 lease {{
  version = 2
  proposals = aes256-sha256-modp2048
  {extra}
  local {{ auth = psk; id = {local_id} }}
  remote {{ auth = psk; id = {remote_id} }}
  children {{ lease {{
   local_ts = {local_ts}
   remote_ts = {remote_ts}
   esp_proposals = aes256-sha256
   if_id_in = 42
   if_id_out = 42
   start_action = none
  }} }}
 }}
}}
{pool}
secrets {{ ike-fixture {{ id-1 = {local_id}; id-2 = {remote_id}; secret = {secret} }} }}
'''.replace('; ', '\n')
path = run / 'swanctl.conf'
path.write_text(config); path.chmod(0o600)
subprocess.run(['ip','link','add','ipsec-fixture','type','xfrm','if_id','42'],check=True)
subprocess.run(['ip','link','set','ipsec-fixture','up'],check=True)
with (run/'charon.log').open('w') as log:
 subprocess.Popen(['/usr/lib/strongswan/charon'],stdout=log,stderr=log,start_new_session=True)
for _ in range(100):
 if pathlib.Path('/var/run/charon.vici').exists(): break
 time.sleep(.1)
subprocess.run(['swanctl','--load-all','--file',str(path)],check=True,stdout=subprocess.DEVNULL)
PY
}
for pair in a b; do
  server="cozyplane-ipsec-allocator-server-$pair"
  client="cozyplane-ipsec-allocator-client-$pair"
  endpoint=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$server")
  configure "$server" server "peer-$pair.example.invalid"
  configure "$client" client "peer-$pair.example.invalid" "$endpoint"
  docker exec "$client" swanctl --initiate --child lease --timeout 15 >/dev/null
done
vip() {
  docker exec "$1" ip -j addr | python3 -c 'import json,sys; print(next(a["local"] for link in json.load(sys.stdin) for a in link["addr_info"] if a["local"].startswith("10.200.")))'
}
first=$(vip "${NAMES[2]}")
second=$(vip "${NAMES[3]}")
printf 'Independent responder A / peer-a virtual IP: %s\n' "$first"
printf 'Independent responder B / peer-b virtual IP: %s\n' "$second"
[[ "$first" == "$second" ]] || { printf 'Expected allocator collision was not observed\n' >&2; exit 1; }
printf 'CONFIRMED: independent strongSwan pools allocate the same VIP to distinct clients.\n'
