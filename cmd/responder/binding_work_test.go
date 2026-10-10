package main

import (
	"testing"

	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func BenchmarkDNSBindingAttachmentWithScopedGrant(b *testing.B) {
	index := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	ref := sdnv1.VPCRef{Namespace: "owner", Name: "net"}
	grant := &sdnv1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "consumer", Name: "grant"}, Spec: sdnv1.VPCBindingSpec{VPCRef: ref, AllowForwarding: true, ForwardingCIDRs: make([]string, sdnv1.MaxForwardingPrefixes)}}
	for i := range grant.Spec.ForwardingCIDRs {
		grant.Spec.ForwardingCIDRs[i] = "192.0.2.0/24"
	}
	if err := index.Add(grant); err != nil {
		b.Fatal(err)
	}
	state := &informerState{bindings: index}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !state.bindingExists("consumer", ref) {
			b.Fatal("attachment refused")
		}
	}
}

func TestDNSAttachmentIgnoresForwardingPayloadAndTracksRevocation(t *testing.T) {
	index := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	state := &informerState{bindings: index}
	ref := sdnv1.VPCRef{Namespace: "consumer", Name: "net"}
	grant := &sdnv1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "consumer", Name: "grant"}, Spec: sdnv1.VPCBindingSpec{VPCRef: sdnv1.VPCRef{Name: "net"}, AllowForwarding: true, ForwardingCIDRs: []string{"invalid-legacy"}}}
	if err := index.Add(grant); err != nil {
		t.Fatal(err)
	}
	if !state.bindingExists("consumer", ref) {
		t.Fatal("invalid forwarding payload removed valid attachment")
	}
	if state.bindingExists("foreign", ref) || state.bindingExists("consumer", sdnv1.VPCRef{Namespace: "owner", Name: "net"}) {
		t.Fatal("attachment crossed identity")
	}
	deleted := grant.DeepCopy()
	now := metav1.Now()
	deleted.DeletionTimestamp = &now
	if err := index.Update(deleted); err != nil {
		t.Fatal(err)
	}
	if state.bindingExists("consumer", ref) {
		t.Fatal("deleted grant retained attachment")
	}
}
