package main

import (
	"fmt"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const policyRowLimit = 65536
const policyWorkLimit = 1 << 20

func npInputWork(pods []*corev1.Pod, nss []*corev1.Namespace, nps []*networkingv1.NetworkPolicy) (int, error) {
	work := len(pods) + len(nss) + len(nps)
	selector := func(s *metav1.LabelSelector) int {
		if s == nil {
			return 0
		}
		n := len(s.MatchLabels) + len(s.MatchExpressions)
		for _, e := range s.MatchExpressions {
			n += len(e.Values)
		}
		return n
	}
	peers := func(ps []networkingv1.NetworkPolicyPeer) int {
		n := len(ps)
		for _, p := range ps {
			n += selector(p.PodSelector) + selector(p.NamespaceSelector)
			if p.IPBlock != nil {
				n += len(p.IPBlock.Except) + 1
			}
		}
		return n
	}
	check := func() error {
		if work > policyWorkLimit {
			return fmt.Errorf("NetworkPolicy input exceeds %d operations", policyWorkLimit)
		}
		return nil
	}
	for _, p := range pods {
		work += len(p.Labels) + len(p.Status.PodIPs)
		if err := check(); err != nil {
			return work, err
		}
	}
	for _, ns := range nss {
		work += len(ns.Labels)
		if err := check(); err != nil {
			return work, err
		}
	}
	for _, np := range nps {
		work += selector(&np.Spec.PodSelector)
		for _, r := range np.Spec.Ingress {
			work += 1 + len(r.Ports) + peers(r.From)
		}
		for _, r := range np.Spec.Egress {
			work += 1 + len(r.Ports) + peers(r.To)
		}
		if err := check(); err != nil {
			return work, err
		}
	}
	return work, nil
}

// Preflight counts conservative expansion bounds without materializing rows.
// Invalid and duplicate entries still consume work and row budgets.
func validateSGCompilation(groups []*sdn.SecurityGroup, ports []*sdn.Port) error {
	if len(groups) > policyRowLimit || len(ports) > policyRowLimit {
		return fmt.Errorf("SecurityGroup input exceeds %d objects", policyRowLimit)
	}
	var ingress, egress, work uint64
	for _, sg := range groups {
		work++
		for _, rule := range sg.Spec.Ingress {
			n := max(len(rule.Ports), 2)
			ingress += uint64(n)
			work += uint64(n)
		}
		for _, rule := range sg.Spec.Egress {
			n := max(len(rule.Ports), 2)
			egress += uint64(n)
			work += uint64(n)
		}
		if ingress > policyRowLimit || egress > policyRowLimit || work > policyWorkLimit {
			return fmt.Errorf("SecurityGroup compilation exceeds resource budget")
		}
	}
	return nil
}

func validateHFCompilation(hfs []*sdn.HostFirewall, nodeLabels labels.Set) error {
	if len(hfs) > policyRowLimit {
		return fmt.Errorf("HostFirewall input exceeds %d objects", policyRowLimit)
	}
	var ingress, egress, work uint64
	count := func(peers []sdn.HostFirewallPeer, ports []sdn.HostFirewallPort) (uint64, error) {
		work++
		var portRows uint64
		if len(ports) == 0 {
			portRows = 2
		}
		for _, p := range ports {
			work++
			hi := p.Port
			if p.EndPort != 0 {
				hi = p.EndPort
			}
			if hi >= p.Port && int64(hi)-int64(p.Port) < 64 {
				portRows += uint64(int64(hi) - int64(p.Port) + 1)
			}
		}
		var peerRows uint64
		if len(peers) == 0 {
			peerRows = 2
		}
		for _, p := range peers {
			peerRows += uint64(len(p.Except)) + 1
			work += uint64(len(p.Except)) + 1
		}
		if work > policyWorkLimit || portRows > policyRowLimit || peerRows > policyWorkLimit {
			return 0, fmt.Errorf("HostFirewall compilation exceeds input budget")
		}
		return portRows * peerRows, nil
	}
	for _, hf := range hfs {
		work++
		sel, err := metav1.LabelSelectorAsSelector(&hf.Spec.NodeSelector)
		if err != nil || !sel.Matches(nodeLabels) {
			continue
		}
		ing, eg := hfIsolation(hf)
		if ing {
			for _, r := range hf.Spec.Ingress {
				n, err := count(r.From, r.Ports)
				if err != nil {
					return err
				}
				ingress += n
				if ingress > policyRowLimit {
					return fmt.Errorf("HostFirewall ingress exceeds %d rows", policyRowLimit)
				}
			}
		}
		if eg {
			for _, r := range hf.Spec.Egress {
				n, err := count(r.To, r.Ports)
				if err != nil {
					return err
				}
				egress += n
				if egress > policyRowLimit {
					return fmt.Errorf("HostFirewall egress exceeds %d rows", policyRowLimit)
				}
			}
		}
	}
	return nil
}
