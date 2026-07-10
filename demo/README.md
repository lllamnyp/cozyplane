# cozyplane live demo

Five acts, one script per act, run in order. Every script acts on **the
cluster kubectl currently points at** (`KUBECONFIG` + current-context) and
prints presenter notes: what exists, the exact commands for *you* to type
(highlighted in yellow), and the one-liner takeaways to say out loud.

| Act | Script | Shows |
|-----|--------|-------|
| 1 | `01-vpcs.sh` | Two tenants, two VPCs, netshoot pods. Intra-VPC works across nodes; cross-VPC fails **on the same node** — isolation by identity, not placement. |
| 2 | `02-peering.sh` | Two-half consent-based `VPCPeering`; the failed ping starts working. |
| 3 | `03-vm.sh` | A Fedora VM joins the VPC via the same one annotation. SSH into it from a VPC pod (password `cozyplane`). |
| 4 | `04-migrate.sh` | Live migration under the open SSH session — node changes, VPC IP + MAC don't, the session survives. |
| 5 | `05-nginx.sh` | nginx in the VPC: kubelet's HTTP readiness probe reaches it on the **fabric** IP (dual-address bridge), peers curl it on the **VPC** IP. |
| 6 | `06-egress.sh` | The door to the outside world: DNS already resolves but connections die; one `natGateway` flag on the VPC and `wget example.com` works. Pauses for Enter before opening the door. |
| — | `99-teardown.sh` | Deletes everything the demo created. |

## Prerequisites

- cozyplane installed on the cluster; at least two Ready nodes.
- KubeVirt, for acts 3–4 only (acts 1, 2, 5 run without it).
- First run pulls `nicolaka/netshoot` and the Fedora containerdisk — do a dry
  run before the audience so images are warm.

## Notes

- **No SecurityGroups are needed anywhere.** Enforcement is opt-in: a pod no
  group selects keeps allow-all intra-VPC ingress with default-deny at the VPC
  boundary. (Optional encore: attach one group and watch ingress snap shut.)
- The scripts are idempotent (`kubectl apply`); re-running an act is safe.
- Names to keep in your head: namespaces `demo-red`/`demo-blue`, VPCs
  `red` (10.50.1.0/24) / `blue` (10.50.2.0/24), pods `red-1`, `red-2`,
  `blue-1`, `web`, VM `demo-vm`.
