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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/lllamnyp/cozyplane/datapath"
)

// NetworkPolicy at net 0 (docs/network-policy.md): the agent compiles upstream
// networking.k8s.io/v1 NetworkPolicies into identity-pair rules and feeds the
// pinned np_ident/np_allow maps. Identities are pure functions of
// {namespace, filtered pod labels}, so every agent computes the same ids from
// the same watched objects — no allocation, no coordination. Membership
// follows label changes by construction: any Pod/Namespace/NetworkPolicy
// event triggers a full recompute + diff-sync (the SecurityGroups resync
// shape; steady-state cost is one in-memory recompute, map writes only for
// actual deltas).

// npFilteredLabel reports whether a label key is excluded from identity —
// Cilium's proven answer to identity cardinality: without the filter every
// Deployment rollout mints identities and a StatefulSet gets one per pod.
// Consequence (documented): these keys are unusable in NP selectors; the
// compiler warns when a policy references one.
func npFilteredLabel(key string) bool {
	switch key {
	case "pod-template-hash",
		"controller-revision-hash",
		"statefulset.kubernetes.io/pod-name",
		"apps.kubernetes.io/pod-index",
		// pre-batch.kubernetes.io spellings, still stamped by Jobs today:
		"controller-uid",
		"job-name":
		return true
	}
	return strings.HasPrefix(key, "batch.kubernetes.io/")
}

func npFilterLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if !npFilteredLabel(k) {
			out[k] = v
		}
	}
	return out
}

// npIdentityOf is THE identity function: the first 64 bits of SHA-256 over
// the canonical {namespace, filtered sorted labels} encoding, remapped off
// the reserved ids. Deterministic across agents; collisions analyzed in
// docs/network-policy.md (second preimage infeasible; a birthday collision
// only conflates label-sets the same author controls).
func npIdentityOf(namespace string, filtered map[string]string) uint64 {
	h := sha256.New()
	h.Write([]byte(namespace))
	h.Write([]byte{0})
	keys := make([]string, 0, len(filtered))
	for k := range filtered {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(filtered[k]))
		h.Write([]byte{0})
	}
	id := binary.BigEndian.Uint64(h.Sum(nil)[:8])
	if id < datapath.NPFirstRealID {
		id += datapath.NPFirstRealID
	}
	return id
}

// npNodeAddresses is the node-exemption feed for np_nodes: every address a
// node-originated packet may source from — all InternalIP/ExternalIP status
// addresses (both families) plus the agent-advertised default-route source
// (nodeAddrsAnnotation — the multi-NIC case where kubelet's probes source
// from a non-InternalIP interface).
func npNodeAddresses(node *corev1.Node) []net.IP {
	var out []net.IP
	for _, a := range node.Status.Addresses {
		if a.Type != corev1.NodeInternalIP && a.Type != corev1.NodeExternalIP {
			continue
		}
		if ip := net.ParseIP(a.Address); ip != nil {
			out = append(out, ip)
		}
	}
	for _, s := range strings.Split(node.Annotations[nodeAddrsAnnotation], ",") {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

// npCompiled is one full compilation of the cluster's NetworkPolicies.
type npCompiled struct {
	idents   []datapath.NPIdent
	allows   []datapath.NPAllow
	cidrs    []datapath.NPCidr
	warnings []string
}

// npSelectorWarnings flags selector keys the identity filter erases.
func npSelectorWarnings(policy string, sel *metav1.LabelSelector, warns *[]string) {
	if sel == nil {
		return
	}
	for k := range sel.MatchLabels {
		if npFilteredLabel(k) {
			*warns = append(*warns, fmt.Sprintf("%s: selector key %q is identity-filtered and matches nothing", policy, k))
		}
	}
	for _, e := range sel.MatchExpressions {
		if npFilteredLabel(e.Key) {
			*warns = append(*warns, fmt.Sprintf("%s: selector key %q is identity-filtered and matches nothing", policy, e.Key))
		}
	}
}

// npPort is one compiled (proto, port) pair; port 0 = any.
type npPort struct {
	proto uint8
	port  uint16
}

// npCompilePorts expands a rule's ports. An empty list means all ports of the
// gated protocols. Named ports and endPort ranges are not served yet
// (increments 2/3): warn, and compile that entry to nothing — fail closed.
func npCompilePorts(policy string, ports []networkingv1.NetworkPolicyPort, warns *[]string) []npPort {
	if len(ports) == 0 {
		return []npPort{{proto: 6, port: 0}, {proto: 17, port: 0}}
	}
	var out []npPort
	for _, p := range ports {
		proto := uint8(6) // upstream default TCP
		if p.Protocol != nil {
			switch *p.Protocol {
			case corev1.ProtocolTCP:
				proto = 6
			case corev1.ProtocolUDP:
				proto = 17
			default:
				*warns = append(*warns, fmt.Sprintf("%s: protocol %q not served (TCP/UDP only)", policy, *p.Protocol))
				continue
			}
		}
		if p.EndPort != nil {
			*warns = append(*warns, fmt.Sprintf("%s: endPort ranges not served yet — entry compiled closed", policy))
			continue
		}
		if p.Port == nil {
			out = append(out, npPort{proto: proto, port: 0})
			continue
		}
		if p.Port.IntValue() == 0 {
			*warns = append(*warns, fmt.Sprintf("%s: named port %q not served yet — entry compiled closed", policy, p.Port.String()))
			continue
		}
		out = append(out, npPort{proto: proto, port: uint16(p.Port.IntValue())})
	}
	return out
}

// compileNetworkPolicies is the pure compilation: pods + namespaces +
// policies in, identity rows + allow pairs + warnings out.
func compileNetworkPolicies(pods []*corev1.Pod, nss []*corev1.Namespace, nps []*networkingv1.NetworkPolicy) npCompiled {
	var c npCompiled

	nsLabels := map[string]labels.Set{}
	for _, ns := range nss {
		nsLabels[ns.Name] = labels.Set(ns.Labels)
	}

	// The identity registry: one entry per distinct {namespace, filtered
	// label-set}; selectors are evaluated per identity, never per pod.
	type identInfo struct {
		ns   string
		lbls labels.Set
	}
	registry := map[uint64]identInfo{}
	podIDs := map[*corev1.Pod]uint64{}
	for _, pod := range pods {
		// Policies do not apply to hostNetwork pods (their addresses are node
		// addresses — exempt plumbing); pods without an IP have nothing to key.
		if pod.Spec.HostNetwork || len(pod.Status.PodIPs) == 0 {
			continue
		}
		flt := npFilterLabels(pod.Labels)
		id := npIdentityOf(pod.Namespace, flt)
		registry[id] = identInfo{ns: pod.Namespace, lbls: labels.Set(flt)}
		podIDs[pod] = id
	}

	// Isolation flags and allow pairs, per identity.
	flags := map[uint64]uint32{}
	allows := map[datapath.NPAllow]bool{}
	for _, np := range nps {
		policy := np.Namespace + "/" + np.Name

		subjectSel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil {
			c.warnings = append(c.warnings, fmt.Sprintf("%s: bad podSelector: %v", policy, err))
			continue
		}
		npSelectorWarnings(policy, &np.Spec.PodSelector, &c.warnings)
		var subjects []uint64
		for id, info := range registry {
			if info.ns == np.Namespace && subjectSel.Matches(info.lbls) {
				subjects = append(subjects, id)
			}
		}

		// policyTypes: trust the (defaulted) field; recompute when absent.
		hasIngress, hasEgress := false, false
		if len(np.Spec.PolicyTypes) > 0 {
			for _, t := range np.Spec.PolicyTypes {
				hasIngress = hasIngress || t == networkingv1.PolicyTypeIngress
				hasEgress = hasEgress || t == networkingv1.PolicyTypeEgress
			}
		} else {
			hasIngress = true
			hasEgress = np.Spec.Egress != nil
		}
		for _, id := range subjects {
			if hasIngress {
				flags[id] |= datapath.NPIngIsolated
			}
			if hasEgress {
				// Fed, not yet enforced (increment 2) — truth over omission.
				flags[id] |= datapath.NPEgIsolated
			}
		}

		// resolvePeers compiles one rule's peer list into identity ids
		// (reserved ANY_POD for namespaceSelector:{}) and ipBlocks.
		resolvePeers := func(peers []networkingv1.NetworkPolicyPeer) ([]uint64, []*networkingv1.IPBlock) {
			var ids []uint64
			var blocks []*networkingv1.IPBlock
			for _, peer := range peers {
				if peer.IPBlock != nil {
					blocks = append(blocks, peer.IPBlock)
					continue
				}
				npSelectorWarnings(policy, peer.PodSelector, &c.warnings)
				npSelectorWarnings(policy, peer.NamespaceSelector, &c.warnings)

				switch {
				case peer.NamespaceSelector == nil:
					// Same-namespace pod peers.
					sel, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
					if err != nil {
						c.warnings = append(c.warnings, fmt.Sprintf("%s: bad peer podSelector: %v", policy, err))
						continue
					}
					for id, info := range registry {
						if info.ns == np.Namespace && sel.Matches(info.lbls) {
							ids = append(ids, id)
						}
					}
				case peer.PodSelector == nil && len(peer.NamespaceSelector.MatchLabels) == 0 && len(peer.NamespaceSelector.MatchExpressions) == 0:
					// namespaceSelector: {} — any pod, one reserved id.
					ids = append(ids, datapath.NPSrcAnyPod)
				default:
					nsSel, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
					if err != nil {
						c.warnings = append(c.warnings, fmt.Sprintf("%s: bad peer namespaceSelector: %v", policy, err))
						continue
					}
					podSel := labels.Everything()
					if peer.PodSelector != nil {
						podSel, err = metav1.LabelSelectorAsSelector(peer.PodSelector)
						if err != nil {
							c.warnings = append(c.warnings, fmt.Sprintf("%s: bad peer podSelector: %v", policy, err))
							continue
						}
					}
					for id, info := range registry {
						nsl, ok := nsLabels[info.ns]
						if !ok || !nsSel.Matches(nsl) {
							continue
						}
						if podSel.Matches(info.lbls) {
							ids = append(ids, id)
						}
					}
				}
			}
			return ids, blocks
		}

		// compileBlocks turns one ipBlock into np_cidr entries for one
		// isolated identity: the allow range plus a deny per except.
		compileBlocks := func(blocks []*networkingv1.IPBlock, self uint64, dir uint8, ports []npPort) {
			for _, b := range blocks {
				_, cidr, err := net.ParseCIDR(strings.TrimSpace(b.CIDR))
				if err != nil {
					c.warnings = append(c.warnings, fmt.Sprintf("%s: bad ipBlock cidr %q: %v", policy, b.CIDR, err))
					continue
				}
				for _, p := range ports {
					c.cidrs = append(c.cidrs, datapath.NPCidr{
						ID: self, Dir: dir, Proto: p.proto, Port: p.port,
						CIDR: cidr, Allow: true,
					})
				}
				for _, exs := range b.Except {
					_, ex, err := net.ParseCIDR(strings.TrimSpace(exs))
					if err != nil {
						c.warnings = append(c.warnings, fmt.Sprintf("%s: bad ipBlock except %q: %v", policy, exs, err))
						continue
					}
					for _, p := range ports {
						c.cidrs = append(c.cidrs, datapath.NPCidr{
							ID: self, Dir: dir, Proto: p.proto, Port: p.port,
							CIDR: ex, Allow: false,
						})
					}
				}
			}
		}

		if hasIngress {
			for _, rule := range np.Spec.Ingress {
				ports := npCompilePorts(policy, rule.Ports, &c.warnings)

				// An empty from admits everything, external included.
				// (Peers compiled before the empty-ports bail so their
				// warnings still surface.)
				var peerIDs []uint64
				var blocks []*networkingv1.IPBlock
				if len(rule.From) == 0 {
					peerIDs = []uint64{datapath.NPSrcAny}
				} else {
					peerIDs, blocks = resolvePeers(rule.From)
				}
				if len(ports) == 0 {
					continue
				}
				for _, dst := range subjects {
					for _, src := range peerIDs {
						for _, p := range ports {
							allows[datapath.NPAllow{
								DstID: dst,
								SrcID: src,
								Dir:   datapath.NPDirIn,
								Proto: p.proto,
								Port:  p.port,
							}] = true
						}
					}
					compileBlocks(blocks, dst, datapath.NPDirIn, ports)
				}
			}
		}

		if hasEgress {
			for _, rule := range np.Spec.Egress {
				ports := npCompilePorts(policy, rule.Ports, &c.warnings)

				// An empty to admits every destination, external included.
				var peerIDs []uint64
				var blocks []*networkingv1.IPBlock
				if len(rule.To) == 0 {
					peerIDs = []uint64{datapath.NPSrcAny}
				} else {
					peerIDs, blocks = resolvePeers(rule.To)
				}
				if len(ports) == 0 {
					continue
				}
				for _, src := range subjects {
					for _, dst := range peerIDs {
						for _, p := range ports {
							allows[datapath.NPAllow{
								DstID: dst, // the peer side for egress
								SrcID: src, // the isolated subject
								Dir:   datapath.NPDirEg,
								Proto: p.proto,
								Port:  p.port,
							}] = true
						}
					}
					compileBlocks(blocks, src, datapath.NPDirEg, ports)
				}
			}
		}
	}

	// Identity rows, one per pod address (dual-stack pods get one per family).
	seen := map[string]bool{}
	for pod, id := range podIDs {
		for _, pip := range pod.Status.PodIPs {
			ip := net.ParseIP(pip.IP)
			if ip == nil || seen[pip.IP] {
				continue
			}
			seen[pip.IP] = true
			c.idents = append(c.idents, datapath.NPIdent{IP: ip, ID: id, Flags: flags[id]})
		}
	}
	for a := range allows {
		c.allows = append(c.allows, a)
	}
	return c
}

// npSyncErrors counts failed map syncs, exposed as
// cozyplane_np_sync_errors_total: an np_allow that didn't fit only ever
// over-drops (fail-closed), but it must never be silent.
var npSyncErrors atomic.Uint64

// watchNetworkPolicies compiles NetworkPolicies into the pinned NP maps on
// every Pod/Namespace/NetworkPolicy event. Blocks until the caches sync.
func watchNetworkPolicies(ctx context.Context, client kubernetes.Interface, mgr *datapath.Manager, log *slog.Logger) error {
	factory := informers.NewSharedInformerFactory(client, 0)
	npInformer := factory.Networking().V1().NetworkPolicies()
	podInformer := factory.Core().V1().Pods()
	nsInformer := factory.Core().V1().Namespaces()

	var mu sync.Mutex
	warned := map[string]bool{}
	resync := func() {
		mu.Lock()
		defer mu.Unlock()

		nps, err := npInformer.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list networkpolicies", "err", err)
			npSyncErrors.Add(1)
			return
		}
		pods, err := podInformer.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list pods", "err", err)
			npSyncErrors.Add(1)
			return
		}
		nss, err := nsInformer.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list namespaces", "err", err)
			npSyncErrors.Add(1)
			return
		}

		c := compileNetworkPolicies(pods, nss, nps)
		for _, w := range c.warnings {
			if !warned[w] { // once per distinct warning, not per resync
				warned[w] = true
				log.Warn("networkpolicy compile", "warning", w)
			}
		}
		if err := mgr.SyncNPIdents(c.idents); err != nil {
			log.Error("sync np_ident", "err", err)
			npSyncErrors.Add(1)
		}
		if err := mgr.SyncNPAllows(c.allows); err != nil {
			log.Error("sync np_allow (a full map only over-drops — fail-closed)", "err", err)
			npSyncErrors.Add(1)
		}
		if err := mgr.SyncNPCidrs(c.cidrs); err != nil {
			log.Error("sync np_cidr (a full map only over-drops — fail-closed)", "err", err)
			npSyncErrors.Add(1)
		}
	}

	handler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, _ any) { resync() },
		DeleteFunc: func(any) { resync() },
	}
	if _, err := npInformer.Informer().AddEventHandler(handler); err != nil {
		return fmt.Errorf("add networkpolicy handler: %w", err)
	}
	if _, err := podInformer.Informer().AddEventHandler(handler); err != nil {
		return fmt.Errorf("add pod handler: %w", err)
	}
	if _, err := nsInformer.Informer().AddEventHandler(handler); err != nil {
		return fmt.Errorf("add namespace handler: %w", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(),
		npInformer.Informer().HasSynced,
		podInformer.Informer().HasSynced,
		nsInformer.Informer().HasSynced) {
		return fmt.Errorf("networkpolicy caches failed to sync")
	}
	resync()
	log.Info("net-0 NetworkPolicy compiler running")
	return nil
}
