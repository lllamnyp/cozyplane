package main

import (
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestPeeringInvalidReferencesDoNotReachVPCLookup(t *testing.T) {
	for _, bad := range []string{"bad/name", strings.Repeat("x", 128<<10)} {
		for _, field := range []string{"local", "remote", "namespace"} {
			p := half("tenant-a", "to-b", "net-a", "tenant-b", "net-b")
			switch field {
			case "local":
				p.Spec.VPCRef.Name = bad
			case "remote":
				p.Spec.PeerRef.Name = bad
			case "namespace":
				p.Spec.PeerRef.Namespace = bad
			}
			r := half(p.Spec.PeerRef.Namespace, "to-a", p.Spec.PeerRef.Name, p.Namespace, p.Spec.VPCRef.Name)
			calls := 0
			links := desiredPeerLinks([]*sdn.VPCPeering{p, r}, func(_, _ string) *sdn.VPC { calls++; return vpcWith(101, "10.1.0.0/24") })
			if len(links) != 0 || calls != 0 {
				t.Fatalf("invalid=%s links=%d lookups=%d", field, len(links), calls)
			}
		}
	}
	valid := []*sdn.VPCPeering{half("tenant-a", "to-b", "net-a", "tenant-b", "net-b"), half("tenant-b", "to-a", "net-b", "tenant-a", "net-a")}
	lookup := vpcTable(map[string]*sdn.VPC{"tenant-a/net-a": vpcWith(101, "10.1.0.0/24"), "tenant-b/net-b": vpcWith(102, "10.2.0.0/24")})
	if len(desiredPeerLinks(valid, lookup)) != 1 {
		t.Fatal("valid reciprocal consent lost")
	}
	if len(desiredPeerLinks(valid[:1], lookup)) != 0 {
		t.Fatal("unilateral consent authorized")
	}
}
