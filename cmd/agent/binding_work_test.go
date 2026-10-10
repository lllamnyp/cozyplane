package main

import (
	"fmt"
	"net"
	"strings"
	"testing"

	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func bindingWorkFixture() ([]*sdnv1.VPCBinding, []*sdnv1.Port, localEndpointIndex) {
	grants := make([]*sdnv1.VPCBinding, 1501)
	for i := range grants {
		grants[i] = &sdnv1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "foreign"}, Spec: sdnv1.VPCBindingSpec{VPCRef: sdnv1.VPCRef{Namespace: "owner", Name: fmt.Sprintf("net-%d", i)}, AllowForwarding: true, ForwardingCIDRs: []string{"invalid-unused"}}}
	}
	grant := grants[0]
	grant.Namespace, grant.Spec.VPCRef.Name = "consumer", "net"
	grant.Spec.ForwardingCIDRs = make([]string, 32)
	for i := range grant.Spec.ForwardingCIDRs {
		grant.Spec.ForwardingCIDRs[i] = fmt.Sprintf("192.0.%d.0/24", i)
	}
	ports := make([]*sdnv1.Port, 100)
	veths := make([]datapath.LocalPortVeth, len(ports))
	for i := range ports {
		ip := net.ParseIP(fmt.Sprintf("10.0.0.%d", i+2))
		uid := fmt.Sprintf("port-%d", i)
		ports[i] = &sdnv1.Port{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("v101.10-0-0-%d", i+2), UID: types.UID(uid)}, Spec: sdnv1.PortSpec{IP: ip.String(), PodNamespace: "consumer", VPCRef: sdnv1.VPCRef{Namespace: "owner", Name: "net"}}}
		veths[i] = datapath.LocalPortVeth{Net: 101, Ifindex: i + 1, PortUID: uid, IPs: []net.IP{ip}}
	}
	return grants, ports, indexLocalPortVeths(veths)
}

func BenchmarkLocalBindingGrantResolution(b *testing.B) {
	grants, ports, endpoints := bindingWorkFixture()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolved := indexLocalBindingGrants(grants, ports, endpoints)
		for _, port := range ports {
			grant := resolved[portBindingKey(port)]
			if !grant.attached || !grant.forwarding || len(grant.cidrs) != 32 {
				b.Fatal(grant)
			}
		}
	}
}

func TestLocalBindingGrantIndexSharesUnionsAndRebuildsCurrentConsent(t *testing.T) {
	bindings, ports, endpoints := bindingWorkFixture()
	resolved := indexLocalBindingGrants(bindings, ports, endpoints)
	if len(resolved) != 1 {
		t.Fatal("indexed unrelated bindings", len(resolved))
	}
	first := resolved[portBindingKey(ports[0])]
	for _, port := range ports {
		grant := resolved[portBindingKey(port)]
		if !grant.attached || !grant.forwarding || len(grant.cidrs) != 32 || &grant.cidrs[0] != &first.cidrs[0] {
			t.Fatal("shared key was copied or refused", grant)
		}
	}
	deleted := bindings[0].DeepCopy()
	now := metav1.Now()
	deleted.DeletionTimestamp = &now
	bindings[0] = deleted
	grant := indexLocalBindingGrants(bindings, ports, endpoints)[portBindingKey(ports[0])]
	if grant.attached || grant.forwarding || grant.cidrs != nil {
		t.Fatal("previous pass retained revoked grant", grant)
	}
	bindings[0] = deleted.DeepCopy()
	bindings[0].DeletionTimestamp = nil
	bindings[0].Spec.ForwardingCIDRs = []string{"invalid-legacy"}
	grant = indexLocalBindingGrants(bindings, ports, endpoints)[portBindingKey(ports[0])]
	if !grant.attached || grant.forwarding || grant.cidrs != nil {
		t.Fatal("invalid scope was armed or lost attachment", grant)
	}
}

func TestLocalBindingGrantIndexKeepsFullIdentityAndNamespaceDefaults(t *testing.T) {
	bindings, ports, endpoints := bindingWorkFixture()
	ports[0].Spec.VPCRef.Namespace = "consumer"
	ports[1].Spec.PodNamespace = "foreign"
	ports[1].Spec.VPCRef.Namespace = "foreign"
	ports[1].Spec.VPCRef.Name = "net"
	local := &sdnv1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "consumer"}, Spec: sdnv1.VPCBindingSpec{VPCRef: sdnv1.VPCRef{Name: "net"}}}
	bindings = append(bindings, local)
	remote := ports[0].DeepCopy()
	remote.UID = "remote-only"
	remote.Name, remote.Spec.IP, remote.Spec.VPCRef.Name = "v101.10-0-0-200", "10.0.0.200", "remote-net"
	ports = append(ports, remote)
	resolved := indexLocalBindingGrants(bindings, ports, endpoints)
	if len(resolved) != 3 {
		t.Fatal("remote-only key retained", len(resolved))
	}
	if grant := resolved[portBindingKey(ports[0])]; !grant.attached || grant.forwarding {
		t.Fatal("default ref namespace lost or foreign forwarding inherited", grant)
	}
	if grant := resolved[portBindingKey(ports[1])]; grant.attached || grant.forwarding {
		t.Fatal("grant crossed consumer/VPC identity", grant)
	}
}

func TestLocalBindingGrantIndexRejectsUnusableLegacyReferences(t *testing.T) {
	bindings, ports, endpoints := bindingWorkFixture()
	for _, input := range []string{"bad/name", strings.Repeat("x", 128<<10)} {
		b := bindings[0].DeepCopy()
		b.Spec.VPCRef.Name = input
		p := ports[0].DeepCopy()
		p.Spec.VPCRef.Name = input
		grant := indexLocalBindingGrants([]*sdnv1.VPCBinding{b}, []*sdnv1.Port{p}, endpoints)[portBindingKey(p)]
		if grant.attached || grant.forwarding {
			t.Fatal("unusable legacy reference granted attachment/forwarding")
		}
	}
	grant := indexLocalBindingGrants(bindings, ports, endpoints)[portBindingKey(ports[0])]
	if !grant.attached || !grant.forwarding {
		t.Fatal("valid grant did not recover")
	}
}
