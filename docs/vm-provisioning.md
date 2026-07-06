# VM provisioning — metadata endpoint & guest autoconfiguration (design draft)

**Status: DRAFT — not implemented.** Covers `design.md` §10 (the metadata door)
and issue #8 (a v6 VM guest can't autoconfigure its address). One story: **a VM
boots into a VPC and comes up fully configured with no manual steps**, matching
what a cloud tenant expects.

## The two gaps, and why they're one story

The live-migration demo needed **manual guest config** for two reasons:

1. **No metadata service.** cirros (and every cloud image) fetches instance
   config from `169.254.169.254`. On a VPC there's nothing there, so cloud-init
   spins, retries ~20×, and the guest boots without SSH keys, hostname, or
   user-data. (The demo's ~90s boot stall was this.)
2. **No v6 autoconfiguration (#8).** KubeVirt bridge-binding hands the guest its
   address via the guest's own DHCP/autoconf. cozyplane pins a `/128` and runs
   no RA/DHCPv6, so a v6 guest gets no address at all; a v4 guest gets one only
   because KubeVirt's built-in DHCP is v4.

Both are "the guest asks the network for its identity and nobody answers." The
answer in both cases is a **per-node responder the datapath steers to**, not a
per-VPC service pod — consistent with the eBPF-first, gateway-optional model.

## Part 1 — Guest address autoconfiguration (#8)

The guest must learn: its address, the default route (`fe80::1` / `169.254.1.1`),
and — for v6 — that it should even ask. Three sub-problems:

- **v4**: KubeVirt's DHCP already hands the pod IP to the guest. **Nothing to
  do** for a v4 VM. (Confirmed working in the v4 migration validation.)
- **v6 "should I ask?"**: the guest does nothing until it sees a **Router
  Advertisement**. cozyplane must answer Router Solicitations on the pod veth.
- **v6 "what's my address?"**: cozyplane pins a `/128`, so SLAAC (which derives
  the address from a prefix) can't reproduce it. Two options:

  - **(A) RA with the /128 + Managed flag → DHCPv6.** The RA sets M=1; the guest
    then does DHCPv6; a tiny per-node DHCPv6 responder hands the exact pinned
    address. Correct, exactly mirrors v4, but two protocols.
  - **(B) RA carries a /64 PIO with the pinned address's interface-id fixed.**
    Doesn't work — SLAAC picks the IID from the MAC/stable-privacy, we don't
    control it.
  - **(C) RA advertises a /128 prefix (A=1,L=0).** RFC 4862 permits a /128
    prefix; the guest autoconfigures exactly that address (the "prefix" *is* the
    address, no IID). **Single protocol, no DHCPv6.** This is the proposal.

**Where it runs.** A new eBPF program at the **pod veth ingress** (`from_pod`'s
attachment point already sees the guest's NS/RS — they're link-scoped, currently
short-circuited to `TC_ACT_OK`). Instead of passing them, answer in-datapath:

- **RS → RA**: craft the RA (source `fe80::1`, the pinned /128 as an
  A=1,L=0,autonomous prefix, router lifetime, MTU option), reflect out the veth.
  The datapath knows the pod's VPC IP (it's about to configure the veth) — store
  it in a small `pod_ra` map keyed by ifindex at ADD.
- **NS for `fe80::1` → NA**: already effectively handled (host veth owns
  `fe80::1`); confirm it survives bridge binding.

This reuses the exact NDP-crafting code just written for `floating_ndp`
(checksum, option layout) — the third consumer of that primitive.

*As built (2026-07-06):* **review Q2 is answered empirically — option C does
not work on Linux guests.** `addrconf_prefix_rcv` hard-requires prefix length
64 on ethernet (RFC 4862's "prefix + IID = 128" rule), so a /128 PIO is
silently ignored; the e2e caught it. The implementation is therefore option
**A**: the RA sets M=1/O=1 and a **minimal per-veth DHCPv6 server** (RFC 8415
subset: SOLICIT/ADVERTISE/REQUEST/REPLY + confirm/renew/rebind and rapid
commit, one binding, infinite lifetimes) hands out the exact pinned address —
the same mechanism KubeVirt's masquerade binding uses, and the precise v6
mirror of the v4 DHCP the guest already gets. The /128 PIO is still sent for
stacks that do honor it. Both live in **userspace** (the agent's
`RunRAResponder`/`serveDHCPv6`, building on the announce.go machinery), not
the eBPF hooks: RAs and leases are control-plane chatter, a handful of packets
per pod lifetime — the eBPF tenet governs forwarding, isolation, and NAT.
Veths are discovered from their alias records (initial scan + netlink link
subscription); RDNSS/DNS options carry the v6 resolver when one exists.
e2e-covered: a pod flushes its address, receives the RA (proto-ra route), and
the stock busybox DHCPv6 client is leased the exact pinned /128.

**Why not just configure the guest?** We can't — the guest OS is the tenant's.
The network answering standard autoconf is the only tenant-agnostic path, and
it's what every cloud does.

## Part 2 — The metadata endpoint (§10)

`169.254.169.254:80` must answer the OpenStack/EC2 metadata routes with
per-instance data: `instance-id`, `hostname`, `public-keys`, and crucially
`user-data` (cloud-init's payload).

**Design decision — where does it live?** Three candidates:

- **Per-VPC gateway pod** (§10's literal text: "served at the gateway"). Simple,
  but requires egress to be enabled just to get metadata, and a VPC with no
  gateway (the common case) gets none.
- **A per-node metadata pod** the datapath DNATs `169.254.169.254` to. One per
  node, system-namespace, like the gateway image.
- **In-datapath** — rejected: HTTP + a templating layer doesn't belong in eBPF.

**Proposal: per-node responder, datapath-steered.** `to_pod`/`from_pod` DNAT
`169.254.169.254:80` (and the v6 `fd00:ec2::/...` equivalent, TBD) from any VPC
pod to a node-local metadata responder (hostNetwork, a `169.254.169.254` the
node owns on a dummy iface, or a fixed fabric address). The responder:

- identifies the caller by its **source** — the datapath rewrites the packet's
  source to a per-Port handle the responder resolves back to `(VPC, Port)` via
  the API, so it serves the right instance without trusting guest-provided
  identity;
- reads instance data from the **`VirtualMachine`/pod annotations** (KubeVirt
  already stores cloud-init `userData`/`networkData` in a Secret referenced by
  the VMI — the responder proxies it), so there's no new source of truth.

**Isolation**: the metadata address is link-local and answered only for a pod's
own instance; one tenant can never read another's user-data because the
datapath keys the response on the *rewritten source*, not anything the guest
sends.

This is the one part that genuinely wants a small userspace service (HTTP +
KubeVirt Secret proxy). It is **not** the VPC gateway — decoupling metadata from
egress is the main departure from §10's wording. (Review Q1.)

*Update (2026-07-06):* per the [services-in-vpc.md](services-in-vpc.md) review,
this responder and the split-horizon DNS resolver are **one per-node process**
(two listeners, shared datapath steering and per-net source identification).

## What this unblocks

- The IPv6 VM migration demo becomes **zero-touch**: boot, and the guest has its
  v6 address (Part 1) and its cloud-init config (Part 2), no console.
- Any cloud image (Fedora/Ubuntu/cirros) works unmodified.
- Closes #8 and the §10 metadata item together.

## Increments

1. **v6 RA responder (Part 1C)** — smallest, highest-value, pure datapath, kind
   + dev4 testable (a Fedora cloud-init containerDisk that does SLAAC). Closes #8.
2. **Metadata responder (Part 2)** — the per-node service + DNAT steering.
3. **Wire cloud-init** — user-data/network-data from the KubeVirt Secret.

## Open questions (review)

1. **Metadata location** — per-node responder (proposed) vs the §10 gateway?
   The gateway couples metadata to egress; per-node doesn't but adds a
   system-namespace DaemonSet.
2. **RA option (C) /128-prefix** — happy to rely on RFC 4862 /128 SLAAC, or
   prefer the DHCPv6 route (A) for maximum guest compatibility? (Some stacks are
   fussy about /128 PIOs.)
3. **Metadata identity source** — proxy the KubeVirt cloud-init Secret
   (proposed, no new source of truth), or a cozyplane-native `InstanceMetadata`
   object?
4. **Non-VM pods** — do ordinary VPC pods get metadata too (useful for
   config), or is this VM-only?
