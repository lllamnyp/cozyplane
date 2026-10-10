package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestNetworkAnnotationBudgetsAndDuplicateDelegatePins(t *testing.T) {
	entries := make([]netEntry, maxAttachments+1)
	for i := range entries {
		entries[i] = netEntry{VPC: "net", Name: fmt.Sprintf("net%d", i+1)}
	}
	tooMany, _ := json.Marshal(entries)
	for _, text := range []string{
		string(tooMany),
		"[" + strings.Repeat("{},", 20000) + "{}]",
		`[{"vpc":"net","name":"net1","ip":"10.0.0.2"},{"vpc":"net","name":"net1","ip":"10.0.0.3"}]`,
		`[{"vpc":"net","name":"net1","ip":"` + strings.Repeat("x", 1024) + `"}]`,
		`[{"vpc":"` + strings.Repeat("x", 1024) + `","name":"net1"}]`,
		`[{"vpc":"net","name":"net1"}] {}`,
		`null`,
		`[{"vpc":` + strings.Repeat("9", 1024) + `}]`,
	} {
		if a, err := delegateAttachment("tenant/net", "net1", text, "tenant"); err == nil || len(err.Error()) > 512 {
			t.Errorf("delegate accepted or amplified payload: %+v err=%v", a, err)
		}
		if a, err := parseAttachments("", text, "tenant"); err == nil || len(err.Error()) > 512 {
			t.Errorf("annotation accepted or amplified payload: %+v err=%v", a, err)
		}
	}
	if _, err := parseAttachments(strings.Repeat("x", 1024), "", "tenant"); err == nil || len(err.Error()) > 512 {
		t.Fatal("single VPC reference unbounded", err)
	}
}

func TestNetworkAnnotationMaximumRetainsAddressPins(t *testing.T) {
	entries := make([]netEntry, maxAttachments)
	for i := range entries {
		entries[i] = netEntry{VPC: "tenant/net", Name: fmt.Sprintf("net%d", i+1), IP: fmt.Sprintf("10.0.0.%d", i+2), MAC: "02:00:00:00:00:01"}
	}
	text, _ := json.Marshal(entries)
	for i, entry := range entries {
		attachment, err := delegateAttachment("tenant/net", entry.Name, string(text), "tenant")
		if err != nil || attachment.IP.String() != entry.IP || attachment.MAC.String() != entry.MAC || !attachment.Delegated {
			t.Fatal(i, attachment, err)
		}
	}
	attachments, err := parseAttachments("", string(text), "tenant")
	if err != nil || len(attachments) != 0 {
		t.Fatal("delegated pins created primary legs", attachments, err)
	}
}

func TestNetworkAnnotationByteBoundary(t *testing.T) {
	prefix, suffix := `[{"vpc":"net","name":"net1","padding":"`, `"}]`
	text := prefix + strings.Repeat("x", maxNetworksAnnotationBytes-len(prefix)-len(suffix)) + suffix
	if _, err := delegateAttachment("tenant/net", "net1", text, "tenant"); err != nil {
		t.Fatal("exact byte budget refused", err)
	}
	if _, err := delegateAttachment("tenant/net", "net1", text+" ", "tenant"); err == nil {
		t.Fatal("oversized byte budget accepted")
	}
}

func BenchmarkNetworkAnnotationRejectedLargeList(b *testing.B) {
	text := "[" + strings.Repeat("{},", 20000) + "{}]"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseAttachments("", text, "tenant")
	}
}
