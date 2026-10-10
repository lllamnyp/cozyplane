# Local IPsec validation

This disposable Docker Desktop suite uses the actual Cozyplane controller,
appliance and eBPF datapath. Independent native strongSwan initiators authenticate
with ephemeral PSKs and deliberately request broad IPv4/IPv6 traffic selectors.
Site-to-site peers use distinct configured source addresses; certificate and EAP
address-pool modes are checked separately and must have their own actual evidence.

The dedicated cluster is `cozyplane-ipsec-test`; no existing Kubernetes context or
unrelated container is modified. Reused provisioning, fake LoadBalancer provider,
resource observer and report helpers allow only the two named local fixtures.
The provider is an explicit laboratory substitute for a real external allocator.
Credentials remain in isolated namespaces and private ephemeral client files,
never in public reports.

Executed coverage: two served VPCs plus IPv6, forbidden VPC and management/local
destinations, authenticated source spoofing, SecurityGroups, external cleartext
capture, MTU, rekey/restart/secret rotation/peer deletion and Ready WarmStandby
loss. Measurements are 1/8/16 concurrent peers, three 60-second TCP samples,
100M and 20M UDP baselines with counters before/after, 1/5/10% transport loss,
100ms delay with 20ms jitter and 1% reorder, 30-second cut and 600-second soak.
All throughput/loss/CPU numbers are observations on a shared host, not promises.
Long measurements start only after review fixes and the product image are frozen.

The native Docker Desktop kernel (`6.6.87.2-microsoft-standard-WSL2`) has
`CONFIG_XFRM_INTERFACE` unset. The initial product appliance correctly stopped
before IKE with an unsupported-XFRM error; that run contains no traffic samples.
Its public evidence is in the workspace cache
`.codex-test-cache/ipsec-host-preflight-20261010`.

Testing therefore uses a disposable Debian VM inside a dedicated Docker
container, with KVM acceleration, four vCPUs and 6GiB guest RAM. Only this guest
was initially upgraded to the official Debian backports kernel `6.12.95+deb12-amd64`;
Docker Desktop and WSL settings were untouched. The guest hosts three kind nodes.
Its performance measurements must remain separate from native Docker Desktop
WireGuard measurements; they are not a direct throughput comparison.

The long samples ran on kernel 6.12.95. Subsequent teardown exposed a gateway
task blocked in `netdev_run_todo`, with `unregister_netdevice` reporting a
negative XFRM interface usage count. Crypto had already closed: charon absent,
SAD/SPD empty, interfaces down and protected blackhole routes retained. The old
namespace could not complete while that core Pod remained in deletion.
This is recorded as a kernel/availability limitation, not successful teardown.

The guest alone was then upgraded to the exact official bookworm-security
package `linux-image-6.12.111+deb12-amd64=6.12.111-1~deb12u1`, retaining the
same product image and source. Debian marks CVE-2026-64580 fixed from
`6.12.101-1~deb12u1`; its XFRM double-netdevice-put correction matches the
observed symptom. The original faulting error-path trace was not captured,
so this identifies a relevant vendor fix rather than proves complete causality.
See the [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-64580)
and [kernel-team record](https://kernel-team.pages.debian.net/kernel-sec/CVE-2026-64580.html).

Normal guest reboot stalled and a bounded fallback restarted only the dedicated
QEMU container. The old Pod then disappeared without finalizer changes, but the
guest cluster's SDN/Coredns components stayed Unknown and its aggregated API
unavailable. After capturing that recovery failure, only the disposable kind
cluster was recreated. That action is explicitly not a successful normal SDN
cleanup assertion. Targeted diagnostics, lifecycle and roadwarrior runs on
6.12.111 provide their own ordinary namespace-deletion evidence below.

The image used for the long measurements and first lifecycle run has configuration digest:
`sha256:f58651542d277cdb6801e92e19c858e7f8ce94c18ca4e72cfad1d7f2c6290cb0`.
The platform manifest is
`sha256:633db91cc14b271da5c55a82885edc22faff08423843f0e476f06014bb367b03`;
the final rebuild's OCI index is
`sha256:d46f8b2275bdc27cd618218ed7701e459c0958608f54e42d46f59bc84a5622ad`.
The deterministic production source-tree fingerprint is
`99a35e2dc01b4239322599a8596bdbb3d531d9e614c0112af48167a9582f01de`.
The public `final-provenance/provenance.json` records the sorted relative paths
and individual hashes; it identifies uncommitted source independently of Git HEAD.
A second build after source freeze produced the identical runtime configuration
and platform manifest. A direct check of that image's executable also passed
missing/corrupt-config cleanup, stale-probe recovery and IPv4/IPv6 blackhole
preservation, preventing cleartext fallback.

The two-peer final functional smoke passed: native IKEv2/CHILD SAs, two IPv4 VPCs
and IPv6 application traffic, MTU1280, forbidden VPC, spoofed IPv4/IPv6 sources,
SecurityGroup default deny/exact source, inter-peer transit denial, appliance
9410/local/fabric and underlay denial with positive listener controls. The
external capture observed encrypted UDP4500 traffic and zero cleartext tenant
packets. A wrong PSK produced an explicit authentication rejection while another
peer continuously retained real access; restoring the correct PSK restored access.
Public smoke report:
`.codex-test-cache/ipsec-product-20261010/results-1791623836-16770/summary.md`.
Earlier preparatory reports retain the bench's IPv6/sysctl and nsenter permission
failures; those failures were corrected in disposable probe/client containers
before accepting the final smoke.

The long measurement phase completed and its independent completeness check
passed all 97 expected samples: 75 TCP samples of 60 seconds, six UDP samples
of 60 seconds and 16 soak samples of 600 seconds, without iperf errors or
truncation. An additional IPv6 TCP smoke sample is separate. Aggregate received
TCP throughput (minimum/median/maximum of the three repetitions, Mbit/s) was
559/892/1062 for one peer, 1264/1357/1692 for eight and 1873/2647/3785 for sixteen.
These are KVM guest observations, not throughput guarantees or a comparison
against the earlier native WireGuard bench.

UDP payload was explicitly 1200 bytes, below tunnel MTU1280. Baseline loss was
5.229% at requested 100M and 0.810% at 20M. Injected transport loss of 1/5/10%
produced application loss of 3.641/9.443/13.335%; the delay/jitter/reorder phase
produced 87.564% loss. All impairment phases recovered application access.
The interruption included a recorded 30-second pause after its negative HTTP
probe; actual 100% qdisc impairment lasted at least 30 seconds, including that
probe and command overhead. The sixteen-peer soak received an aggregate
3564.556 Mbit/s with 1,531,002 TCP retransmissions and 0.308% ICMP loss; latency
median/p95/p99 was 0.176/2.210/11.400ms. This was not a loss-free soak.

Matched before/after UDP socket counters explain the 20M baseline loss
(1013 receiver buffer drops); 100M recorded 21,988 receiver buffer drops,
explaining only part of its packet loss. A later cumulative XFRM replay-error
snapshot cannot attribute the earlier baseline without its own before sample.
The observer had a documented Docker-stats timeout gap before its bounded
timeout was corrected. The controller, scheduler and kube-controller-manager
also restarted with exit 1 after leader lease/API timeouts; captured reasons
were not OOM kills. These cluster limits remain part of the evidence.
The Go appliance process RSS median/max was 18.60/18.85MiB; its resolved
container cgroup memory median/max was 23.57/24.12MiB, with observed oom_kill 0.
Go RSS excludes the child charon process; the cgroup includes both, while kernel
XFRM/eBPF and softIRQ accounting are outside those processes. Total four-vCPU
guest CPU utilization median/max was 92.34/97.97%, including control-plane work.

The encompassing long harness exited 1 *after* all nominal measurements when
its read-only SA observer tried to read SA state in the workload server, which
has no NET_ADMIN capability. The lifecycle-only retry then exposed a separate
observer error: this iproute2 version emits textual `ip xfrm` output even with
`-j`, while that observer expected JSON.
It therefore does not constitute a complete lifecycle-suite pass. Measurement
completeness, lifecycle recovery and certificate/EAP modes are reported
separately. The observer now filters text or JSON strictly in memory and retains
only addresses, SPIs, replay windows and packet/byte counters. Phase-specific
script snapshots identify the actual measurement code separately from later
lifecycle/roadwarrior corrections. The long report is
`.codex-test-cache/ipsec-product-20261010/results-1791624009-25223`.

The initial lifecycle-only retry passed its sixteen-peer functional controls but
stopped at CLI-format preflight before targeted UDP or recovery.
Its report is `results-1791626015-62092`. A mistaken exploratory contextual
filter briefly displayed two ephemeral fixture keys in a tool result, outside
public artifacts; that fixture was then removed, with its Pod and SAs gone.
Public reports pass a bounded recognizable secret-material scan before export;
this is not a comprehensive secret-audit certification. No raw XFRM state is retained.

On kernel 6.12.111, the sixteen-peer lifecycle run `results-1791627170-11859`
passed actual CHILD SPI renewal, appliance restart, secret rotation and retired
PSK rejection with a continuously healthy survivor, peer deletion and explicit
rejection, and WarmStandby recovery across both IPv4 VPCs and IPv6. Both replicas
were Ready with the current configuration before the selected Pod was deleted;
the selected UID changed. The observed HTTP failure-to-recovery gap was 6.136s,
bounded by 6.733s from the preceding success to the recovery. The controller
closes routes while replacing a replica until both observed Pods are Ready and
acknowledge configuration, so this is not uninterrupted availability.

That encompassing lifecycle harness exited 1 because its original observer
looked for an omitted `initiator=no` VICI field. Preserved human `list-sas`
evidence instead shows exactly one client responder `_r*` and a matching live
appliance `initiator=yes` with the same IKE SPI pair. The subsequent public
`static-role-recheck.json` records this evidence and preserves the original exit.
Its ordinary namespace deletion completed successfully; `cleanup-public.json`
confirms NotFound at 10:23:10Z, without finalizer removal or cluster recreation.

Separate idle UDP controls in that run received 87.294 Mbit/s at requested 100M
with 12.699% loss (26,456 packets), and about 19.91 Mbit/s at 20M with 0.449%
loss (187 packets). Matched server receive-buffer error deltas were exactly
26,456 and 187; client and appliance XFRM error deltas were zero in these windows,
with inbound replay protection configured to 32. This attributes these two
windows to socket receive drops, not the earlier kernel-95 impairment phase.

The first certificate/EAP pool run `results-1791627750-37871` on kernel 6.12.111
established two certificate IKE/CHILD SAs and their actual assigned IPv4 VIPs,
but stopped before application traffic when EAP peer 3 failed. Safe responder
categories recorded 138 missing EAP_DYNAMIC method events and zero MSCHAPv2
challenges. Product strongSwan 6.0.1 provides eap-mschapv2 but no eap-dynamic
plugin. This is an explicit EAP product failure, not a pool-suite pass.
The fixture was deleted normally, confirmed NotFound at 10:30:39Z. The subsequent
final-image runs separately validated explicit MSCHAPv2, identity-bound profile
selection and the controller backend-transition status correction.

The subsequent frozen image configuration is
`sha256:a263ff17d71b3b425b7fca19d9339342f22ade12f030454b347e797499be68e8`,
platform manifest
`sha256:f39a44fae1b2ebc205cc4540365385355c4faefcf0834d31d6c599bc20f83359`,
and OCI index
`sha256:dbfa69cbe2026595915d5c9203081d235feab66716604cd5e785df41c4452fee`.
Its production source fingerprint is
`e76c64f46bd2eba17838ad158e973d90c1b9c54288de9fa4519ee606f1fb2fb7`,
recorded separately in `final-provenance-a263ff17/provenance.json`.
The configuration ID was checked after transfer and installation in all three
guest nodes. Direct executable checks on kernel 6.12.111 passed missing and
malformed configuration cleanup, stale probe recovery and retained IPv4/IPv6
blackholes; the IPSec executable SHA256 is
`df580f27ae5fa49d07d078e3cf2ea88375412364a8287b48caa52fd682daefb5`.
Final pool and lifecycle runs on this image are recorded separately from the
unchanged long-measurement evidence above.

The first final-image pool attempt `results-1791628779-56540` authenticated all
eight certificate/EAP peers with actual IPv4/IPv6 VIPs, passed three concurrent
exact-marker traffic rounds and workload source checks, and demonstrated
encrypted spoof rejection of another pool member's source in both families.
Exact source SecurityGroup checks and management/isolation controls also passed.
It exited 1 before HA because the ActiveActive negative request omitted its
mandatory BGP block, so the API rejected that incomplete shape before reaching
the specific pool guard. This is a harness limitation, preserved separately;
the complete suite was replayed with an otherwise valid ActiveActive shape.
This fixture's ordinary deletion completed, NotFound at 10:45:26Z.

The next attempt `results-1791629141-70456` reached the specific ActiveActive
pool rejection and two Ready WarmStandby replicas. Native clients recovered SAs
automatically after the Single-to-Warm rollout, but the VIP observer mistook old
IPv6 BYPASS policies for current ESP selectors. The captured client-5 SA and
controller observation both show the same current `fd42:250:150::3` lease;
its stale BYPASS `::1` policy has no ESP template or if_id. The run was stopped
with an unsuccessful encompassing exit before selected-Pod loss. The corrected
observer requires outbound ESP with if_id42 and passed the actual captured
policy plus five regression cases; no live gateway or client policy was changed
to satisfy it. Automatic SA recovery was slow, consistent with the fixture's
approximately 171-second retransmission budget. A VIP-triggered MOBIKE cause
remains a hypothesis, not an established attribution.

The complete final-image pool run `results-1791629825-96126` exited 0. All eight
native certificate/EAP clients authenticated with current, unique IPv4/IPv6
VIPs. Three concurrent rounds per client passed before and after a selected
WarmStandby Pod loss; IPv4 clients also recovered the second VPC. Actual VIP
selectors and controller observations were refreshed after each rollout,
and both IPv4 and IPv6 encrypted cross-member source spoofing were rejected
with increasing outbound ESP counters and restored legitimate access.
SecurityGroup exact-VIP behavior, management/unserved-VPC denial, actual API
ActiveActive pool rejection, certificate and EAP CHILD SPI renewal passed.

Cross-profile EAP kept IKE identity 3 but supplied identity 4's valid EAP
password, and was explicitly rejected while another client stayed reachable.
Untrusted client CA, wrong EAP password and deleted certificate/EAP peers were
also explicitly rejected with continuous positive survivor controls. Correct
credentials restored authentication and actual application access; IPv4 and
IPv6 survivors retained access after the two withdrawals.

Pool WarmStandby selected UID changed after deletion at 11:01:07Z. The new
selection/current configuration was ready at 11:01:14Z, and the fixture's
manual route-source/VIP refresh finished at 11:01:24Z. This 17-second operational
interval includes client address setup; it is not a continuous network-outage
measurement or a claim of automatic native Windows client recovery.

The separate 20-second final-image/kernel-111 delay/jitter/reorder control
received 12.783Mbit/s and lost 87.152% (181,560 of 208,321 datagrams). Appliance
XfrmInStateSeqError increased by 170,337 while all other observed XFRM errors
and matched socket receive-buffer errors were zero; inbound replay windows
remained 32. This demonstrates a major anti-replay contribution in this window,
without retroactively attributing the old kernel-95 run. Another 11,223 missing
datagrams are not explained by these deltas. Netem's default queue limit under
100ms/100M load is a possible contributor, but active-qdisc drop counters were
not sampled in this run. Qdisc removal restored authorized HTTP access. No
production replay default was changed or replay protection disabled.

The final sixteen-peer site/lifecycle run `results-1791630440-134131`, on image
`a263ff17` and kernel 6.12.111, exited 0 with 87 PASS checks and zero FAIL checks.
Actual IPv4/IPv6 multi-VPC traffic, source isolation, forbidden management and
VPC destinations, SecurityGroups, MTU and encrypted-transport controls passed.
Rekey, appliance restart, PSK rotation and rejected retired credentials, peer
withdrawal with a continuously healthy survivor, and static appliance-initiated
IKE passed. The client responder and appliance initiator shared the same IKE
SPI pair. Ready WarmStandby loss changed the selected UID and recovered both
IPv4 VPCs and IPv6; the continuous HTTP failure-to-recovery gap was 5.413s,
bounded by 6.037s from the preceding success. This is an observed outage.

The review corrections require acknowledged configuration on every expected
Ready appliance before publishing forwarding grants, use the same selected
appliance across all VPC legs, and invalidate live connection status on failed
configuration or withdrawal. The XFRM ingress filter binds decrypted sources
to each authenticated peer and restricts destinations to served VPCs; real
packet tests caught and corrected the preserved-MAC-header offset. Runtime
cleanup removes only owned XFRM devices/state, joins workers and retains IPv4/
IPv6 blackhole routes during unavailable or corrupt configuration. Pool peers
share their interface without authorizing the entire pool as a remote source.
EAP explicitly uses the installed MSCHAPv2 plugin and binds the profile to the
IKE/EAP identity. These fixes have targeted regression and actual traffic evidence.

An actual API transition changed both the gateway and connection from IPSec to
WireGuard site mode while reconciliation was temporarily stopped. After resuming
the controller, the deliberately invalid new configuration withdrew the former
Established status and forwarding routes at the current generation, blocked
traffic and preserved handshake history. This verifies the backend-transition
correction beyond its eight regression cases. Controller replicas were restored.

The final run's independent 20-second UDP controls received 89.714Mbit/s at
requested 100M (10.269% loss, 21,394 datagrams) and 19.982Mbit/s at 20M (0.084%
loss, 35 datagrams). Matched server receive-buffer drops were 21,416 and 35;
all observed XFRM error deltas were zero. The 100M socket counter covers a
slightly wider observation window than iperf, so it is not an exact partition.
The delay/jitter/reorder control received 12.593Mbit/s and lost 87.351%
(181,973 of 208,323 datagrams). Its matched appliance XfrmInStateSeqError delta
was 168,822; the still-active netem qdisc, with queue limit 1000, recorded
13,200 drops. The server recorded another 26 receive-buffer drops. These
namespace-wide counters include concurrent ICMP and sampling overhead; they
demonstrate anti-replay and fixture-queue contributions without an exact
datagram attribution. See `matched-counter-analysis.json` and the captured
active-qdisc records. Qdisc removal restored access. Replay protection remains
enabled with the observed window of 32.

Final ordinary namespace deletion completed with exit 0 and NotFound confirmed
at 13:51:18Z, without finalizer removal or cluster recreation. The complete
eight-client certificate/EAP fixture also has ordinary deletion proof, NotFound
at 11:06:49Z. Full Linux `go test ./... -count=1`, the final controller/runtime/
filter race checks and scoped vet checks passed after the production fixes.
The final production fingerprint was rechecked before dismantling the bench;
the long measurement phase retains its earlier image/source identity explicitly.
Public artifacts are preserved outside the Git tree in
`.codex-test-cache/ipsec-product-20261010` and `ipsec-runtime-20261010`.
After export, the dedicated guest kind cluster, VM/tool containers and their
three volumes were removed. `bench-cleanup-public.json` records verified fixture
ownership and unchanged unrelated container IDs. Product images and public
reports remain available; no commit or push was made.

PSK with an address pool is unsupported and rejected. Certificate and EAP clients
with pools require actual independent success evidence; ActiveActive with pools
is rejected because independent charon allocators can allocate the same VIP.
A static `PeerAddress` inside its own `remoteCIDRs` is also unsupported: the
protected XFRM route captures the outer IKE destination, so establishment fails
closed. Use disjoint outer endpoint and inner prefixes; DNS overlap cannot be
trivially resolved by static API validation.

Real-cluster interoperability remains separate. These checks are scoped review
and regression evidence, not a claim of complete security certification.

## Replay on this Docker Desktop host

Run from the repository root in PowerShell. These commands create only dedicated
test resources. The Go tooling container owns its temporary SSH identity; the
guest exposes SSH only inside Docker's `kind` network, with no Windows host port.
The cloud disk's SHA512 was checked against `SHA512SUMS` downloaded over HTTPS
from the official Debian cloud site. A detached GPG signature was not verified.
Kernel packages are installed through Debian's signed APT repositories. The
replay helper selects the security branch and the exact 6.12.111 package tested;
it rejects a branch candidate older than the vendor's 6.12.101 fix.

```powershell
$taskRepo = (Get-Location).Path
docker network inspect kind
# If absent, create the kind network before starting the dedicated tools.
docker run -d --name cozyplane-ipsec-test-tools --hostname cozyplane-ipsec-test-tools --label cozyplane.test=ipsec --network kind --mount "type=bind,source=$taskRepo,target=/src" --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock --mount type=volume,source=cozyplane-ipsec-test-go-cache,target=/go/pkg/mod --mount type=volume,source=cozyplane-ipsec-test-build-cache,target=/root/.cache/go-build -w /src golang:1.26.8-trixie sleep infinity
docker exec cozyplane-ipsec-test-tools bash test/ipsec-toolchain.sh
docker exec cozyplane-ipsec-test-tools docker build --platform linux/amd64 -t cozyplane-ipsec:local -f Dockerfile .
docker exec cozyplane-ipsec-test-tools docker build -t cozyplane-ipsec-test-bench:local -f test/ipsec-bench.Dockerfile test
docker exec cozyplane-ipsec-test-tools docker build -t cozyplane-ipsec-test-etcd:local -f test/wireguard-client-etcd.Dockerfile test
docker exec cozyplane-ipsec-test-tools docker pull kindest/node:v1.34.3
docker exec cozyplane-ipsec-test-tools bash test/ipsec-vm-prepare.sh
docker exec cozyplane-ipsec-test-tools bash test/ipsec-vm-start.sh
docker exec cozyplane-ipsec-test-tools bash test/ipsec-vm-provision.sh
docker exec cozyplane-ipsec-test-tools bash test/ipsec-vm-ssh.sh "bash /src/test/ipsec-vm-kernel.sh"
docker exec cozyplane-ipsec-test-tools bash test/ipsec-vm-reboot.sh
# Verify the exact guest kernel, then create the guest cluster.
docker exec cozyplane-ipsec-test-tools bash test/ipsec-vm-cluster.sh
docker exec cozyplane-ipsec-test-tools bash test/ipsec-vm-ssh.sh "bash /src/test/ipsec-vm-kubeconfig.sh"
docker exec cozyplane-ipsec-test-tools bash test/ipsec-vm-install.sh
docker exec cozyplane-ipsec-test-tools bash test/ipsec-vm-ssh.sh "cd /src; CLIENTS=2 RUN_LOAD=0 RUN_LIFECYCLE=0 FIXTURE_HOST_RUNNER=1 bash test/ipsec-local.sh run"
docker exec cozyplane-ipsec-test-tools bash test/ipsec-vm-ssh.sh "cd /src; CLIENTS=16 RUN_LOAD=1 RUN_LIFECYCLE=1 FIXTURE_HOST_RUNNER=1 bash test/ipsec-local.sh run"
docker exec cozyplane-ipsec-test-tools bash test/ipsec-vm-ssh.sh "cd /src; CLIENTS=8 ROADWARRIOR=1 RUN_LOAD=0 FIXTURE_HOST_RUNNER=1 bash test/ipsec-local.sh run"
# Record this build's config/platform-manifest/index digests from its build output:
docker exec cozyplane-ipsec-test-tools python3 test/ipsec-provenance.py /src /tmp/cozyplane-ipsec-test/final-provenance --config-id "sha256:REPLACE_CONFIG" --manifest-digest "sha256:REPLACE_PLATFORM_MANIFEST" --index-digest "sha256:REPLACE_OCI_INDEX"
docker exec cozyplane-ipsec-test-tools bash test/ipsec-vm-export.sh
docker cp cozyplane-ipsec-test-tools:/tmp/cozyplane-ipsec-test/public-reports ./ipsec-public-reports
# Delete each fixture normally and confirm NotFound before dismantling the VM.
# Scan the exported public artifacts before sharing them:
python test/ipsec-public-scan.py ./ipsec-public-reports
# Only after public export and when the tools are no longer in use:
docker rm -f cozyplane-ipsec-test-vm cozyplane-ipsec-test-tools
docker volume rm cozyplane-ipsec-test-vm-disk cozyplane-ipsec-test-go-cache cozyplane-ipsec-test-build-cache
```

The first Debian cloud kernel is 6.1: provisioning prepares source/images/tools
then requests the guest-only kernel upgrade before TCX cluster installation.
The running guest's `/tmp` is cleared on reboot; the kubeconfig helper runs
through SSH to repair only this guest's private kubeconfig. Replace the three
provenance placeholders with the digests printed by the actual frozen build;
the configuration digest is distinct from the OCI index digest.

The local provider is fixture emulation. Native Windows IKEv2/IPsec and a real
external cluster/provider were not exercised by this IPsec suite.
