package sdn

import (
	"encoding/json"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestIPsecConfigBindsUniquePeerIdentities(t *testing.T) {
	scheme := svcScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "psk", Namespace: "tenant"}, Data: map[string][]byte{"psk": []byte("test-credential")},
	}).Build()
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme}
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant"}}
	conn := sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Name: "peer-a"}, Spec: sdnv1alpha1.VPNConnectionSpec{
		RemoteCIDRs: []string{"10.20.0.0/16"}, IPsec: &sdnv1alpha1.VPNConnectionIPsec{
			PeerAddress: "192.0.2.10", Auth: sdnv1alpha1.VPNConnectionIPsecAuth{PSKSecretRef: "psk"},
		},
	}}
	raw, err := r.buildIPsecConfig(t.Context(), gw, []*sdnv1alpha1.VPC{{}}, []sdnv1alpha1.VPNConnection{conn}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Peers []struct{ RemoteIdentity string }
	}
	if err := json.Unmarshal(raw, &cfg); err != nil || len(cfg.Peers) != 1 || cfg.Peers[0].RemoteIdentity != "192.0.2.10" {
		t.Fatalf("identity not bound: config=%s err=%v", raw, err)
	}
	other := *conn.DeepCopy()
	other.Name = "peer-b"
	if _, err := r.buildIPsecConfig(t.Context(), gw, []*sdnv1alpha1.VPC{{}}, []sdnv1alpha1.VPNConnection{conn, other}, 1280); err == nil {
		t.Fatal("accepted duplicate authenticated identity")
	}
	conn.Spec.IPsec.RemoteIdentity = "%any"
	if _, err := r.buildIPsecConfig(t.Context(), gw, []*sdnv1alpha1.VPC{{}}, []sdnv1alpha1.VPNConnection{conn}, 1280); err == nil {
		t.Fatal("accepted wildcard identity in legacy object")
	}
	for _, pair := range [][2]string{
		{"peer.example.invalid", "@PEER.example.invalid"},
		{"peer@example.invalid", "email:PEER@example.invalid"},
		{"2001:db8::10", "2001:0db8:0:0:0:0:0:10"},
		{"CN=peer, E=peer@example.invalid", "cn = PEER,emailAddress=PEER@example.invalid"},
	} {
		conn.Spec.IPsec.RemoteIdentity = pair[0]
		other = *conn.DeepCopy()
		other.Name = "peer-b"
		other.Spec.IPsec.RemoteIdentity = pair[1]
		other.Spec.RemoteCIDRs = []string{"10.30.0.0/16"}
		if _, err := r.buildIPsecConfig(t.Context(), gw, []*sdnv1alpha1.VPC{{}}, []sdnv1alpha1.VPNConnection{conn, other}, 1280); err == nil {
			t.Errorf("accepted equivalent authenticated identities %q and %q", pair[0], pair[1])
		}
	}
	conn.Name = "peer-75b2bb8120fd8edf"
	conn.Spec.IPsec.RemoteIdentity = "192.0.2.10"
	other = *conn.DeepCopy()
	other.Name = "peer-df2cb6e65b135aa4"
	other.Spec.IPsec.RemoteIdentity = "192.0.2.11"
	if ipsecIfID(conn.Name) != ipsecIfID(other.Name) {
		t.Fatal("collision fixture invalid")
	}
	if _, err := r.buildIPsecConfig(t.Context(), gw, []*sdnv1alpha1.VPC{{}}, []sdnv1alpha1.VPNConnection{conn, other}, 1280); err == nil {
		t.Fatal("accepted colliding xfrm interfaces")
	}
}

func TestRemovedVPNCredentialDrainsOldAuthorization(t *testing.T) {
	scheme := svcScheme(t)
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant", UID: "gateway-uid"}}
	gw.Spec.VPCRef.Name = "vpc"
	gw.Spec.IPsec = &sdnv1alpha1.VPNGatewayIPsec{}
	vpc := &sdnv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Name: "vpc", Namespace: "tenant"}, Status: sdnv1alpha1.VPCStatus{VNI: 100}}
	conn := &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Name: "peer", Namespace: "tenant"}, Spec: sdnv1alpha1.VPNConnectionSpec{
		GatewayRef: sdnv1alpha1.LocalVPNGatewayRef{Name: gw.Name}, RemoteCIDRs: []string{"10.20.0.0/16"},
		IPsec: &sdnv1alpha1.VPNConnectionIPsec{PeerAddress: "192.0.2.10", Auth: sdnv1alpha1.VPNConnectionIPsecAuth{PSKSecretRef: "removed-psk"}},
	}}
	workload := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "gateway-vpn", Namespace: "tenant", UID: "workload-uid"}}
	binding := &sdnv1alpha1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Name: "gateway-vpn", Namespace: "tenant", UID: "binding-uid"}}
	for _, obj := range []client.Object{workload, binding} {
		if err := controllerutil.SetControllerReference(gw, obj, scheme); err != nil {
			t.Fatal(err)
		}
	}
	c := vpnIndexClient(t, gw, vpc, conn, workload, binding)
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme, Config: VPNGatewayConfig{Image: "example.invalid/appliance:test"}}
	requests := r.mapCredentialToVPNGateways(t.Context(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "removed-psk", Namespace: "tenant"}})
	if len(requests) != 1 || requests[0].NamespacedName != client.ObjectKeyFromObject(gw) {
		t.Fatalf("credential deletion did not enqueue its gateway: %v", requests)
	}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)}); err == nil {
		t.Fatal("missing credential did not fail reconciliation")
	}
	for _, obj := range []client.Object{workload, binding} {
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); !apierrors.IsNotFound(err) {
			t.Fatalf("old authorization still active: %T err=%v", obj, err)
		}
	}
}

func TestVPNResourceCollisionsArePreserved(t *testing.T) {
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant", UID: "current-gateway"}}
	gw.Spec.VPCRef.Name = "vpc"
	cases := []struct {
		name   string
		object client.Object
		ensure func(*VPNGatewayReconciler) error
	}{
		{"keys", &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "gateway-wg-keys", Namespace: "tenant"}, Data: map[string][]byte{"preserve": []byte("original")}}, func(r *VPNGatewayReconciler) error { _, _, err := r.ensureKeypairs(t.Context(), gw, 1); return err }},
		{"config", &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "gateway-wg-config", Namespace: "tenant"}}, func(r *VPNGatewayReconciler) error {
			_, err := r.ensureConfigSecret(t.Context(), gw, []byte("new"))
			return err
		}},
		{"binding", &sdnv1alpha1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Name: "gateway-vpn", Namespace: "tenant"}}, func(r *VPNGatewayReconciler) error {
			return r.ensureBindings(t.Context(), gw, []*sdnv1alpha1.VPC{{ObjectMeta: metav1.ObjectMeta{Name: gw.Spec.VPCRef.Name}}}, []string{"10.250.0.0/24"})
		}},
		{"deployment", &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "gateway-vpn", Namespace: "tenant"}}, func(r *VPNGatewayReconciler) error {
			return r.ensureDeployment(t.Context(), gw, backendWireGuard, "new")
		}},
		{"statefulset", &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "gateway-vpn", Namespace: "tenant"}}, func(r *VPNGatewayReconciler) error {
			return r.ensureStatefulSet(t.Context(), gw, backendWireGuard, "new")
		}},
		{"service", &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "gateway-vpn-headless", Namespace: "tenant"}}, func(r *VPNGatewayReconciler) error { return r.ensureHeadlessService(t.Context(), gw) }},
		{"floatingip", &sdnv1alpha1.FloatingIP{ObjectMeta: metav1.ObjectMeta{Name: "gateway-vpn", Namespace: "tenant"}}, func(r *VPNGatewayReconciler) error {
			_, err := r.ensureFloatingIP(t.Context(), gw, "10.0.0.2")
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scheme := svcScheme(t)
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tc.object).Build()
			r := &VPNGatewayReconciler{Client: c, Scheme: scheme}
			if err := tc.ensure(r); err == nil {
				t.Fatal("foreign resource was accepted")
			}
			if err := r.deleteVPNOwned(t.Context(), gw, tc.object.DeepCopyObject().(client.Object)); err != nil {
				t.Fatal(err)
			}
			got := tc.object.DeepCopyObject().(client.Object)
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(tc.object), got); err != nil {
				t.Fatalf("foreign resource deleted: %v", err)
			}
			if len(got.GetOwnerReferences()) != 0 {
				t.Fatal("foreign resource adopted")
			}
		})
	}
}

func TestVPNCurrentOwnerCanUpdateButRecreatedOwnerCannot(t *testing.T) {
	scheme := svcScheme(t)
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant", UID: "current"}}
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "gateway-wg-config", Namespace: "tenant"}}
	if err := controllerutil.SetControllerReference(gw, sec, scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sec).Build()
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme}
	if _, err := r.ensureConfigSecret(t.Context(), gw, []byte("authorized")); err != nil {
		t.Fatal(err)
	}
	gw.UID = "replacement"
	if _, err := r.ensureConfigSecret(t.Context(), gw, []byte("unauthorized")); err == nil {
		t.Fatal("name-reused gateway accepted old resource")
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(sec), sec); err != nil {
		t.Fatal(err)
	}
	if string(sec.Data["config.json"]) != "authorized" {
		t.Fatal("foreign data overwritten")
	}
}

func TestVPNResolutionRequiresCurrentVPCClaim(t *testing.T) {
	for _, mutation := range []string{"current", "old-vni", "wrong-address", "terminating-vpc"} {
		t.Run(mutation, func(t *testing.T) {
			scheme := gatewayScheme(t)
			gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant-a", UID: "gateway-current"}}
			gw.Spec.VPCRef.Name = "net"
			vpc := vpcWithCIDRs(gw.Namespace, "net", 101, "10.0.0.0/24")
			dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn", Namespace: gw.Namespace, UID: "deployment-current"}}
			rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "appliance-replicaset", Namespace: gw.Namespace, UID: "replicaset-current"}}
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "appliance-pod", Namespace: gw.Namespace, UID: "pod-current", Labels: map[string]string{vpnGatewayLabel: gw.Name}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "192.0.2.10", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
			for _, pair := range [][2]client.Object{{gw, dep}, {dep, rs}, {rs, pod}} {
				if err := controllerutil.SetControllerReference(pair[0], pair[1], scheme); err != nil {
					t.Fatal(err)
				}
			}
			port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-2", Labels: map[string]string{sdnv1alpha1.LabelVPCNamespace: gw.Namespace, sdnv1alpha1.LabelVPC: vpc.Name, sdnv1alpha1.LabelPodUID: string(pod.UID)}}, Spec: sdnv1alpha1.PortSpec{IP: "10.0.0.2", VPCRef: sdnv1alpha1.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}, PodNamespace: pod.Namespace, PodName: pod.Name}}
			switch mutation {
			case "old-vni":
				vpc.Status.VNI = 102
			case "wrong-address":
				port.Spec.IP = "10.0.0.99"
			case "terminating-vpc":
				now := metav1.Now()
				vpc.DeletionTimestamp = &now
			}
			r := &VPNGatewayReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithIndex(&sdnv1alpha1.Port{}, vpnAppliancePodIndex, vpnAppliancePodKeys).WithObjects(gw, dep, rs, pod, port).Build(), Scheme: scheme}
			chosen, _, _ := r.resolveAppliancePort(t.Context(), gw, vpc)
			choices := r.resolveAppliancePorts(t.Context(), gw, vpc, 2)
			if mutation == "current" {
				if chosen != port.Name || len(choices) != 1 {
					t.Fatalf("current appliance not selected: %q %+v", chosen, choices)
				}
			} else if chosen != "" || len(choices) != 0 {
				t.Fatalf("stale VPC appliance selected: %q %+v", chosen, choices)
			}
		})
	}
}
