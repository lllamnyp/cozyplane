package main

import (
	"strings"
	"testing"
)

func TestIPsecProposalBudgetBeforeVICI(t *testing.T) {
	p := peer{Name: "peer", RemoteID: "peer.example.invalid", PSK: "test-key", LocalCIDRs: []string{"10.10.0.0/16"}, RemoteCIDRs: []string{"203.0.113.0/24"}}
	for _, proposals := range [][]string{make([]string, 17), {"input-canary-" + strings.Repeat("a", 128<<10)}} {
		p.Proposals = proposals
		sess := &recordingVICI{}
		for _, err := range []error{validatePeerIdentities([]peer{p}), loadPeer(sess, p)} {
			if err == nil || len(err.Error()) > 128 || strings.Contains(err.Error(), "input-canary") {
				t.Fatal("unbounded or absent proposal rejection")
			}
		}
		if len(sess.commands) != 0 {
			t.Fatal("invalid proposal reached VICI commands")
		}
	}
	p.Proposals = []string{"aes256gcm16-prfsha384-ecp384"}
	sess := &recordingVICI{}
	if err := validatePeerIdentities([]peer{p}); err != nil {
		t.Fatal(err)
	}
	if err := loadPeer(sess, p); err != nil {
		t.Fatal(err)
	}
	if len(sess.commands) != 2 {
		t.Fatal("valid recovery did not load credentials and connection")
	}
}
