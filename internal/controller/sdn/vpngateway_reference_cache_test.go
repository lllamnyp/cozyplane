package sdn

import (
	"strings"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestVPNReferenceCacheRejectsUnusableKeysAndRecovers(t *testing.T) {
	for _, kind := range []string{"gateway", "credential", "VPC"} {
		t.Run(kind, func(t *testing.T) {
			large := strings.Repeat("a", 128<<10)
			peer := &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "peer", ResourceVersion: "1"}}
			gateway := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway", ResourceVersion: "1"}}
			var obj client.Object
			var list client.ObjectList
			var field string
			var extract client.IndexerFunc
			var set func(string)
			switch kind {
			case "gateway":
				obj, field, extract = peer, vpnConnectionGatewayIndex, vpnConnectionGatewayKeys
				set = func(name string) { peer.Spec.GatewayRef.Name = name }
			case "credential":
				obj, field, extract = peer, vpnCredentialIndex, vpnCredentialKeys
				peer.Spec.WireGuard = &sdnv1alpha1.VPNConnectionWireGuard{}
				set = func(name string) { peer.Spec.WireGuard.PresharedKeySecretRef = name }
			case "VPC":
				obj, field, extract = gateway, gatewayVPCIndex, gatewayVPCKeys
				set = func(name string) { gateway.Spec.VPCRef.Name = name }
			}
			set(large)
			if kind == "VPC" {
				list = &sdnv1alpha1.VPNGatewayList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}, Items: []sdnv1alpha1.VPNGateway{*gateway}}
			} else {
				list = &sdnv1alpha1.VPNConnectionList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}, Items: []sdnv1alpha1.VPNConnection{*peer}}
			}
			cached, index := vpnObjectCache(t, obj, list, field, extract)
			lookup := func(name string, want int) {
				t.Helper()
				if err := cached.List(t.Context(), list, client.InNamespace("tenant-a"), client.MatchingFields{field: name}); err != nil {
					t.Fatal(err)
				}
				rows, err := meta.ExtractList(list)
				if err != nil || len(rows) != want {
					t.Fatalf("index rows=%d want=%d error=%v", len(rows), want, err)
				}
			}
			lookup(large, 0)
			set("valid-target")
			if err := index.Update(obj.DeepCopyObject()); err != nil {
				t.Fatal(err)
			}
			lookup("valid-target", 1)
			set("bad/target")
			if err := index.Update(obj.DeepCopyObject()); err != nil {
				t.Fatal(err)
			}
			lookup("valid-target", 0)
			lookup("bad/target", 0)
		})
	}
}
