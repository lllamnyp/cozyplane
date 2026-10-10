# Local WireGuard workstation validation

All commands below operate on the dedicated `cozyplane-wg-client` kind cluster.
They do not use the current Kubernetes context. The tooling container is
`cozyplane-wg-client-tools`; its checkout is mounted at `/src` and its private
kubeconfig is `/tmp/cozyplane-wg-client/kubeconfig`.

## Running the product suite

Build the product image from the updated checkout, then:

```powershell
rtk proxy docker build -f test/wireguard-client-tools.Dockerfile -t cozyplane-wg-client-bench:local .
rtk proxy docker exec cozyplane-wg-client-tools bash test/wireguard-client-local.sh create
rtk proxy docker exec -e IMAGE=cozyplane-wireguard-client:local cozyplane-wg-client-tools bash test/wireguard-client-local.sh install
rtk proxy docker exec -e KEEP=1 -e RUN_LOAD=0 -e CLIENTS=2 cozyplane-wg-client-tools bash test/wireguard-client-local.sh run
rtk proxy docker exec -e KEEP=1 cozyplane-wg-client-tools bash test/wireguard-client-local.sh run
```

The Linux tooling container requires Docker socket access, the checkout mounted
at `/src`, kind, kubectl, Helm, Python 3, Go, clang/LLVM, WireGuard tools,
iproute2/tc, iperf3, curl and jq. Join it to the kind Docker network after cluster
creation. Creation and deletion refuse any cluster name other than the dedicated
fixture; deletion does not remove the tooling container or measurement reports.

The smoke run exercises real handshakes, application traffic, IPv6, MTU,
source preservation, SecurityGroups, unauthorized VPCs, inter-client isolation,
source spoofing, rights reduction, revocation, restart and WarmStandby.
The full run adds three 60-second TCP samples at 1, 8 and 16 concurrent clients,
UDP measurement, controlled loss of 1/5/10%, 100 ms delay with 20 ms jitter and
1% reordering, a 30-second cut and ten minutes of steady load.

Keys are generated inside client `/run` directories and never included in
fixtures, API payloads, measurement JSON or reports. Cleanup removes only the
created client containers and namespace. `KEEP=1` preserves the namespace for
inspection and the Windows test, while deleting the Linux client containers.
The Windows test needs a quota slot: the suite deletes `client-2` before exit.

Run the Windows test with the namespace printed by the suite and the VPC address
of `server-a` or `server-b`:

```powershell
rtk proxy powershell -NoProfile -File test/wireguard-client-windows.ps1 -Namespace wg-client-<timestamp>-<pid> -Target 10.250.1.<host>
```

The script creates a temporary profile restricted to the test CIDRs, installs
its own tunnel service, verifies HTTP through the Windows client, and removes
the profile, tunnel and test API resources. WireGuard must already be installed
and the process must have permission to install its temporary service.
The Windows path is UDP NodePort through localhost `51829`; Linux uses the
FloatingIP path. These are reported separately.

Results remain inside `/tmp/cozyplane-wg-client/results-*` in the tooling
container. Copy only measurement reports, never private-key directories.

Optional read-only observers accept the printed namespace, harness PID and
result directory: `wireguard-client-monitor.py` samples Docker CPU/memory and
resolves the gateway process's real cgroup scope; `wireguard-client-recovery-monitor.py`
starts approximately one-second HTTP probes near the end of the ten-minute soak.
The report summarizes aggregate receiver throughput, ICMP percentiles/loss,
scoped resource use and observed outage intervals. Node CPU includes work charged
to that node. Kernel workers/softIRQ may be charged elsewhere; shared Linux VM
CPU samples include them together with unrelated Docker Desktop workloads.

## Infrastructure evidence, 2026-10-10

Docker Desktop Linux kernel `6.6.87.2-microsoft-standard-WSL2` accepted real
WireGuard interfaces both in the tooling container and a dedicated kind node.
A separate two-container kernel probe completed before product installation:

| Measurement | Observed |
|---|---:|
| TCP baseline, 15 seconds | 3529.995 Mbit/s |
| UDP baseline, 20 Mbit/s requested | 19.999 Mbit/s, 0% loss |
| Injected 1% loss | 0.9923% observed loss |
| Injected 5% loss | 5.1841% observed loss |
| Injected 10% loss | 10.1273% observed loss |
| Baseline median ping | 0.279 ms |
| 100 ms delay + 20 ms jitter + reordering | 100 ms median, 115 ms p95 |
| Recovery median ping | 0.291 ms |

These two-container measurements validate the apparatus. The separate product
suite below validates Cozyplane's authorization and control plane. Docker Desktop
shares host resources with other applications; throughput is observational.

## Product evidence, 2026-10-10

The long suite used image configuration ID
`632db859ff53cf6cf8d61f8d5473dc761b4b448eabe761f1d7b5c4bb09e41829`
on the shared Docker Desktop Linux VM (8 CPUs, about 16 GiB RAM).

| Product measurement | Observed |
|---|---:|
| TCP 1 client, three 60-second runs, median aggregate | 1117.776 Mbit/s |
| TCP 8 clients, three 60-second runs, median aggregate | 3846.169 Mbit/s |
| TCP 16 clients, three 60-second runs, median aggregate | 4646.619 Mbit/s |
| TCP 16 clients, 600-second soak | 4152.791 Mbit/s aggregate |
| Soak TCP retransmissions / iperf command errors | 124062 / 0 |
| Soak ICMP loss / p95 latency | 0.102389% / 11.1 ms |
| UDP baseline, 100 Mbit/s requested | 99.343 Mbit/s, 0.654778% loss |
| UDP with injected 1 / 5 / 10% loss | 1.764744 / 6.708256 / 10.376880% observed loss |
| 100 ms delay + 20 ms jitter + reordering, ICMP | 103 ms median, 120 ms p95 |
| UDP follow-up, 20 Mbit/s requested for 15 seconds | 19.997 Mbit/s, 1/30536 datagrams lost (0.003275%) |
| Corrected WarmStandby selected-appliance loss | about 17.03 seconds observed HTTP outage |

TCP recovered dropped packets; zero command errors does not mean zero loss.
The 20 Mbit/s follow-up observed one receiver `RcvbufErrors`/`InErrors` increment
and zero gateway increments. At 100 Mbit/s the receiver also had buffer drops,
but pre-baseline counters were not collected, so exact baseline attribution is
unknown. Shared VM CPU approached 95% during saturation; isolated process/node
CPU accounting does not cover every kernel worker and softIRQ.

Real IPv4/IPv6 application traffic, source preservation, SecurityGroups, MTU,
cleartext capture, endpoint roaming, unauthorized VPCs, client isolation,
IPv4/IPv6 source spoofing, live underlay API denial, key rotation, rights/client
revocation and restart passed. Impairment removal and the 30-second cut recovered
without rebuilding client profiles.

The first WarmStandby attempt revealed a harness limitation: it did not wait for
two Ready replicas and its one-shot fake provider lost the delegated Service's
address on recreation. That interval is excluded from product availability
claims. The corrected harness waits for both Ready replicas and current client
configuration, continuously emulates only the owned fixture provider, and the
unattended retest measured approximately 17 seconds of recovery. WarmStandby is
therefore not seamless in this local observation.

Native Windows testing actually ran: the non-elevated process hit SCM access
denied; the authorized UAC run passed at 08:05:34 UTC with HTTP 200 and the exact
VPC marker over UDP NodePort. Cleanup verification found no temporary tunnel
service, test route or profile directory. Linux used FloatingIP; Windows used
NodePort. This Windows evidence uses the long-suite image above.

Public full reports are in the sibling workspace cache directory
`.codex-test-cache/wireguard-client-full-20261010/`; native Windows result/log
and cleanup JSON are adjacent. The later final image
`db324780e37952fc33972a72825dab9cd97f0fef731567ebb31479d5664ddbe9`
adds controller closure for corrupt/unreadable state; its smoke is separate from
the long measurements. That final image's two-client `RUN_LOAD=0` smoke completed
with exit code 0, including the direct IPv6 spoof/underlay checks and corrected
WarmStandby/provider preconditions. Its public report is
`.codex-test-cache/wireguard-client-final-smoke-20261010/`. The dedicated cluster
and ephemeral clients are removed after report copying. Production provider and
real-cluster validation remain open.

## Source review and validation

The final source passed `go test -p2 ./...` after the unreadable-state withdrawal
call sites were added. Controller, VPN runtime and WireGuard filter packages
passed race-enabled tests; targeted `go vet` passed. API and helper tests also
passed, including 20 security regression cases covering compare-and-swap,
retired leases, disappearing Pods/Ports, nil/corrupt state, stale generations,
retired keys and removed scopes. Review findings were addressed before the final
image smoke.

Kernel validation ran 13 TC verdict cases and real WireGuard traffic across three
Linux network namespaces. These source/kernel checks complement the Docker
Desktop product and native Windows integration evidence above; production
provider and real-cluster validation are tracked separately.

Bash syntax, ShellCheck and PowerShell parsing pass for the test harness.
