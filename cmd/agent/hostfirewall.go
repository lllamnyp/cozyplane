/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
)

// Host firewall (docs/host-firewall.md): each agent compiles only its OWN
// node's view — the HostFirewalls whose nodeSelector matches this node's
// labels — into hf_allow rows and the CFG_HF_ENABLED flag. No cross-node
// state; a label change re-selects on the next Node event.

// hfSyncErrors counts failed map syncs, exposed as
// cozyplane_hf_sync_errors_total. Like np_allow, a failed hf_allow sync only
// ever over-drops (isolation is the flag, the map holds admissions), so it
// must be loud rather than dangerous.
var hfSyncErrors atomic.Uint64

// hfProtoNum maps the API protocol string to the IP protocol number.
func hfProtoNum(proto string) (uint8, bool) {
	switch proto {
	case "TCP":
		return 6, true
	case "UDP":
		return 17, true
	}
	return 0, false
}

// hfPortRow is one expanded {proto, port} the compiler emits rows under.
type hfPortRow struct {
	proto uint8
	port  uint16
}

// hfCompilePorts expands a rule's ports: empty means every port for both
// protocols; endPort ranges expand per-port (the address is hf_allow's LPM
// tail, so the port cannot be a suffix) and are capped at 64 — an invalid
// item is skipped, never widened (fail closed).
func hfCompilePorts(ports []sdnv1alpha1.HostFirewallPort) ([]hfPortRow, []string) {
	if len(ports) == 0 {
		return []hfPortRow{{proto: 6, port: 0}, {proto: 17, port: 0}}, nil
	}
	var out []hfPortRow
	var warnings []string
	for _, p := range ports {
		proto, ok := hfProtoNum(p.Protocol)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("protocol %q is not served (TCP/UDP only); rule port skipped (fail closed)", p.Protocol))
			continue
		}
		if p.Port < 0 || p.Port > 65535 {
			warnings = append(warnings, fmt.Sprintf("port %d out of range; rule port skipped (fail closed)", p.Port))
			continue
		}
		lo, hi := p.Port, p.Port
		if p.EndPort != 0 {
			hi = p.EndPort
		}
		if hi < lo || hi > 65535 || (lo == 0 && hi != 0) {
			warnings = append(warnings, fmt.Sprintf("endPort %d invalid for port %d; rule port skipped (fail closed)", p.EndPort, p.Port))
			continue
		}
		if int(hi)-int(lo)+1 > 64 {
			warnings = append(warnings, fmt.Sprintf("port range %d-%d expands beyond 64 ports; rule port skipped (fail closed)", lo, hi))
			continue
		}
		for port := int(lo); port <= int(hi); port++ {
			out = append(out, hfPortRow{proto: proto, port: uint16(port)})
		}
	}
	return out, warnings
}

// hfAnyPeers is the empty-`from` default: any source, either family.
var hfAnyPeers = []sdnv1alpha1.HostFirewallPeer{{CIDR: "0.0.0.0/0"}, {CIDR: "::/0"}}

// compileHostFirewalls turns the HostFirewalls selecting a node with
// `nodeLabels` into its hf_allow rows. `isolated` is true when at least one
// object selects the node — rules union across all of them.
func compileHostFirewalls(hfs []*sdnv1alpha1.HostFirewall, nodeLabels labels.Set) (isolated bool, entries []datapath.HFAllow, warnings []string) {
	for _, hf := range hfs {
		sel, err := metav1.LabelSelectorAsSelector(&hf.Spec.NodeSelector)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("HostFirewall %s: bad nodeSelector: %v (object ignored)", hf.Name, err))
			continue
		}
		if !sel.Matches(nodeLabels) {
			continue
		}
		isolated = true
		for _, rule := range hf.Spec.Ingress {
			rows, w := hfCompilePorts(rule.Ports)
			for _, warn := range w {
				warnings = append(warnings, fmt.Sprintf("HostFirewall %s: %s", hf.Name, warn))
			}
			peers := rule.From
			if len(peers) == 0 {
				peers = hfAnyPeers
			}
		peers:
			for _, peer := range peers {
				_, allowNet, err := net.ParseCIDR(peer.CIDR)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("HostFirewall %s: bad cidr %q: peer skipped (fail closed)", hf.Name, peer.CIDR))
					continue
				}
				var excepts []*net.IPNet
				for _, ex := range peer.Except {
					_, exNet, err := net.ParseCIDR(ex)
					if err != nil {
						// A broken except would fail OPEN if dropped alone;
						// skip the whole peer instead.
						warnings = append(warnings, fmt.Sprintf("HostFirewall %s: bad except %q: peer skipped (fail closed)", hf.Name, ex))
						continue peers
					}
					excepts = append(excepts, exNet)
				}
				for _, row := range rows {
					entries = append(entries, datapath.HFAllow{Proto: row.proto, Port: row.port, CIDR: allowNet, Allow: true})
					for _, exNet := range excepts {
						entries = append(entries, datapath.HFAllow{Proto: row.proto, Port: row.port, CIDR: exNet, Allow: false})
					}
				}
			}
		}
	}
	return isolated, entries, warnings
}

// watchHostFirewalls keeps this node's host-firewall state (hf_allow +
// CFG_HF_ENABLED) in sync with the HostFirewalls selecting it. It watches
// its own Node (labels drive selection) through a name-filtered informer and
// recomputes on any event, the watchSecurityGroups shape. Like the other sdn
// watchers it is best-effort at startup: the pinned maps keep enforcing the
// last-programmed policy while the API is unreachable.
func watchHostFirewalls(ctx context.Context, factory sdninformers.SharedInformerFactory, client kubernetes.Interface, mgr *datapath.Manager, nodeName string, log *slog.Logger) error {
	hfs := factory.Sdn().V1alpha1().HostFirewalls()

	selfFactory := informers.NewSharedInformerFactoryWithOptions(client, 0,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.FieldSelector = "metadata.name=" + nodeName
		}))
	selfInformer := selfFactory.Core().V1().Nodes()

	var mu sync.Mutex
	warned := map[string]bool{}
	resync := func() {
		mu.Lock()
		defer mu.Unlock()

		self, err := selfInformer.Lister().Get(nodeName)
		if err != nil {
			return // no Node yet: nothing to select against
		}
		all, err := hfs.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list hostfirewalls", "err", err)
			return
		}

		isolated, entries, warnings := compileHostFirewalls(all, self.Labels)
		for _, w := range warnings {
			if !warned[w] {
				warned[w] = true
				log.Warn("hostfirewall compile", "warning", w)
			}
		}

		// Ordering keeps every transition fail-closed: rules land before the
		// flag arms, and the flag drops before the rules are wiped.
		if isolated {
			if err := mgr.SyncHFAllows(entries); err != nil {
				hfSyncErrors.Add(1)
				log.Error("sync hf_allow", "err", err)
				return // do not arm on top of a failed sync
			}
			if err := mgr.SetHFEnabled(true); err != nil {
				hfSyncErrors.Add(1)
				log.Error("enable host firewall", "err", err)
				return
			}
			log.Info("host firewall armed", "rules", len(entries))
		} else {
			if err := mgr.SetHFEnabled(false); err != nil {
				hfSyncErrors.Add(1)
				log.Error("disable host firewall", "err", err)
				return
			}
			if err := mgr.SyncHFAllows(nil); err != nil {
				hfSyncErrors.Add(1)
				log.Error("clear hf_allow", "err", err)
			}
		}
	}

	if _, err := hfs.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, _ any) { resync() },
		DeleteFunc: func(any) { resync() },
	}); err != nil {
		return fmt.Errorf("add hostfirewall handler: %w", err)
	}
	if _, err := selfInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(any) { resync() },
		UpdateFunc: func(oldObj, newObj any) {
			// Only label changes re-select; ignore status-only node churn.
			o, ok1 := oldObj.(*corev1.Node)
			n, ok2 := newObj.(*corev1.Node)
			if ok1 && ok2 && labels.Equals(o.Labels, n.Labels) {
				return
			}
			resync()
		},
	}); err != nil {
		return fmt.Errorf("add hostfirewall node handler: %w", err)
	}

	selfFactory.Start(ctx.Done())
	return nil
}
