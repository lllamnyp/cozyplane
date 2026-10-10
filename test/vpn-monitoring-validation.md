# VPN monitoring validation

Local working-tree verification on 2026-10-10 covers the VPN monitoring
consumers and their data sources. It does not assert deployment or operator
selection in an external cluster. The earlier WireGuard/IPsec traffic and load
reports retain their own frozen source/image fingerprints; this monitoring
change is a subsequent independently verified phase.

| Indicator | Source | Coverage |
| --- | --- | --- |
| RX/TX bytes and rates | `cozyplane_vpn_connection_{rx,tx}_bytes_total` | WireGuard and IPsec, configured absent peers publish zero |
| Tunnel state | `cozyplane_vpn_connection_up` | Fresh WireGuard handshake or installed IPsec CHILD SA |
| Handshake / IKE establishment age | `cozyplane_vpn_connection_last_handshake_timestamp_seconds` | Both backends; zero means never established |
| Configured connections | `cozyplane_vpn_gateway_connections` | Both backends, including an empty gateway |
| RX/TX packets | `cozyplane_vpn_connection_{rx,tx}_packets_total` | IPsec only; WireGuard's peer API supplies no packet totals |
| XFRM errors, including replay rejection | `cozyplane_vpn_ipsec_xfrm_errors_total{reason}` | Bounded allowlist from the appliance's own network namespace |
| XFRM telemetry health | `cozyplane_vpn_ipsec_xfrm_collection_success` | A failed read reports zero success, not fabricated zero errors |
| Scrape health | VictoriaMetrics-generated `up` | Stable `job="cozyplane-vpn-gateways"` and pod/gateway/namespace labels |
| Missing targets | `kube_pod_container_info`, optional `kube_pod_deletion_timestamp` | kube-state-metrics inventory; terminating pods excluded |
| Restarts | `kube_pod_container_status_restarts_total` | kube-state-metrics; joined to appliance gateway identity |
| CPU and memory | `container_cpu_usage_seconds_total`, `container_memory_working_set_bytes` | kubelet/cAdvisor; joined to appliance gateway identity |

Tunnel state is a crypto observation, not an end-to-end application probe.
Application loss/latency and receiver socket drops require their own probes or
workload instrumentation. IPsec SA counters can reset during SA replacement;
rate queries tolerate resets, but these counters are not a billing ledger.

The review found incorrect HA aggregation retaining `instance`, an IPsec stale
handshake alert firing on healthy long-lived SAs, an unresolved Grafana datasource
variable, and no scrape/missing-target/XFRM/dependency monitoring. These are
corrected. Queries group logical connections by cluster/namespace/gateway/
connection/backend. Resource panels deduplicate the single named container per
pod and carry gateway identity from the VPN endpoint. Managed metric labels use
connection names, and unconfigured WireGuard peers are excluded. No address or
key label is introduced; the legacy unnamed configured-peer key fallback remains.

Alerts cover down/never-established/stale-WireGuard connections, failed scrapes,
undiscovered appliances, missing gateway inventory, incomplete connection metric
families (four for WireGuard, six for IPsec), missing inventory/restart/resource
dependencies, failed XFRM collection and sustained XFRM errors. Idle traffic is
an opt-in alert. A healthy HA replica suppresses logical connection-down; a
failed individual scraper remains visible independently.

Validation passed:

- Full Linux `go test -p 4 ./... -count=1`.
- Race and vet checks for both VPN commands and the common metrics formatter.
- Real HTTP handler tests with WireGuard/VICI boundaries supplied as fixtures;
  configured missing peers, unknown peers, negative counters, future handshakes,
  VICI failure and kernel telemetry failure are exercised. Prometheus parses the
  returned exposition. The real Linux namespace XFRM statistics reader passed
  without a skip on this Docker Desktop kernel, separately from interface support.
- Helm rendering, Prometheus rule validation and 32 time-series/alert scenarios,
  including HA, namespace separation, disappearing metrics, missing dependencies,
  absent individual counter families and duplicate scraper labels.
- Actual VictoriaMetrics v1.109.0 HTTP scraping of handler-output fixtures,
  complete series/label inventory, all 14 dashboard target queries and every
  rendered alert expression. Removing a real HTTP fixture produced `up=0`.
  Kubernetes discovery metadata and external exporter data are fixture inputs;
  a Kubernetes operator was not run in this test.
- Both Linux appliance executables built successfully. `git diff --check` passed.

Public artifacts are outside the Git tree in
`.codex-test-cache/vpn-monitoring-20261010`: rendered resources, dashboard JSON,
rule cases/results, handler exposition, actual namespace error exposition and
VictoriaMetrics query inventory. Test fixture/Victoria containers and their
network are removed by the runner, including on failure.
The dedicated Go tools container and its two cache volumes were also removed;
`cleanup-public.json` records ownership checks and unchanged unrelated container
IDs. The bounded public-artifact scan found no recognizable secret material.

## Deployment requirements

The chart creates `VMPodScrape`, `VMRule` and `GrafanaDashboard` only when their
CRDs are installed. Actual collection additionally requires VMAgent's
namespace/label selectors to include the scrape object, and evaluation requires
VMAlert to select the rule object. Configure the respective `additionalLabels`
values to match the installation. This is the
[operator's selection contract](https://docs.victoriametrics.com/operator/resources/vmagent/).
The real cluster's exporter availability, selectors, target health, Grafana
datasource and imported dashboard status remain to verify there.

kube-state-metrics must include VPN pods, container inventory and restart
metrics. kubelet/cAdvisor must include their CPU and memory metrics. Every
source must carry the same cluster/namespace/pod labels for joins. Existing
monitoring stack HA scraper deduplication remains the stack's responsibility.
An inventory/dependency alert exposes missing exports for known scraped pods;
if both discovery and Kubernetes inventory are entirely absent, these rules
cannot infer that an otherwise invisible gateway exists.

The Grafana datasource dropdown selects an installed Prometheus-compatible
datasource pointing at VictoriaMetrics. By default the dashboard matches Grafana
instances in its release namespace. For Grafana elsewhere, configure
`vpn.observability.dashboard.allowCrossNamespaceImport` and the intended
`instanceSelector`, following the
[GrafanaDashboard API](https://grafana.github.io/grafana-operator/docs/api/#grafanadashboardspec).
No deployed image was changed: deploying these monitoring additions requires
building and selecting an image containing this source.

## Replay

Requires Docker, RTK, Go tooling through Docker, and Python with PyYAML. From
the repository root in PowerShell, create an output directory and use its
absolute path for the report mount. The directory contains only synthetic
fixtures and public counters.

```powershell
$monitorRepo = (Get-Location).Path
$monitorReport = Join-Path (Split-Path $monitorRepo -Parent) '.codex-test-cache/vpn-monitoring-replay'
# Create $monitorReport first if absent.
rtk proxy docker run --rm --label cozyplane.test=vpn-monitor --mount "type=bind,source=$monitorRepo,target=/src" --mount "type=bind,source=$monitorReport,target=/report" -w /src -e VPN_MONITORING_ARTIFACT_DIR=/report golang:1.26.8-trixie go test -race ./cmd/vpn-gateway ./cmd/vpn-gateway-ipsec ./internal/vpnmetrics -count=1
rtk proxy python test/vpn-monitoring-test.py --report "$monitorReport"
```

The runner uses fixed dedicated names with ownership labels; run one instance
at a time. It uses cached/pulled Helm 3.19.0, Prometheus/promtool 3.2.1 and
VictoriaMetrics 1.109.0 images. It publishes VictoriaMetrics on an ephemeral
localhost port and removes its containers/network in `finally`. It performs no
commit, push, production scrape selection change or external deployment.
