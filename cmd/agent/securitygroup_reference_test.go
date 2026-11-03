package main

import (
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestStoredSecurityGroupPeerReferences(t *testing.T) {
	for _, peer := range []sdn.SecurityGroupPeer{
		{Group: "peer"},
		{Group: strings.Repeat("a.", 126) + "a", VPC: &sdn.VPCRef{Namespace: strings.Repeat("a", 63), Name: "net"}},
	} {
		if !securityGroupPeerReference(peer) {
			t.Fatal("valid peer refused")
		}
	}
	for _, peer := range []sdn.SecurityGroupPeer{
		{Group: strings.Repeat("x", 128<<10)},
		{Group: "bad/name"},
		{Group: "peer", VPC: &sdn.VPCRef{Namespace: "tenant-b", Name: strings.Repeat("x", 128<<10)}},
		{Group: "peer", VPC: &sdn.VPCRef{Namespace: strings.Repeat("x", 128<<10), Name: "net"}},
		{Group: "peer", VPC: &sdn.VPCRef{}},
	} {
		if securityGroupPeerReference(peer) {
			t.Fatal("invalid legacy peer accepted")
		}
	}
}
