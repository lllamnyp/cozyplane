package sdn

import (
	"context"
	"net"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func routeSecurityFixture(t *testing.T, cidrs ...string) (*VPCGatewayReconciler, *sdnv1alpha1.VPCGateway, *sdnv1alpha1.VPC) {
	t.Helper()
	vpc := vpcWithCIDRs("tenant-a", "net", 101, "10.0.0.0/24")
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "router", UID: "pod-current", Labels: map[string]string{"app": "router"}}}
	port := &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-2", Labels: map[string]string{sdnv1alpha1.LabelVPCNamespace: "tenant-a", sdnv1alpha1.LabelVPC: "net", sdnv1alpha1.LabelPodUID: string(pod.UID)}},
		Spec:       sdnv1alpha1.PortSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: "tenant-a", Name: "net"}, IP: "10.0.0.2", Node: "node-a", PodNamespace: pod.Namespace, PodName: pod.Name},
	}
	gw := &sdnv1alpha1.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "door"}}
	gw.Spec.VPCRef.Name = vpc.Name
	gw.Spec.Routes = []sdnv1alpha1.VPCGatewayRoute{{CIDRs: cidrs, Via: sdnv1alpha1.VPCGatewayVia{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "router"}}}}}
	return &VPCGatewayReconciler{Client: gwClient(t, vpc, pod, port, gw)}, gw, vpc
}

func TestVPCRoutesRejectReservedPrefixes(t *testing.T) {
	for _, bad := range []string{"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4", "::1/128", "fe80::/10", "ff00::/8", "0.0.0.0/0", "::/0", "invalid"} {
		t.Run(bad, func(t *testing.T) {
			r, gw, vpc := routeSecurityFixture(t, bad, "203.0.113.0/24")
			out, problem, err := r.reconcileRoutes(context.Background(), gw, vpc)
			if err != nil {
				t.Fatal(err)
			}
			if len(out) != 1 || len(out[0].CIDRs) != 1 || out[0].CIDRs[0] != "203.0.113.0/24" || out[0].Port == "" || problem == "" {
				t.Fatalf("forbidden prefix projected: status=%+v problem=%q", out, problem)
			}
			if gw.Spec.Routes[0].CIDRs[0] != bad {
				t.Fatal("mutated route input")
			}
		})
	}
}

func TestVPCRoutesRejectConfiguredInternalPrefixes(t *testing.T) {
	for _, bad := range []string{"10.96.0.0/12", "10.96.1.0/24", "10.0.0.0/8", "fd00:1::/64"} {
		t.Run(bad, func(t *testing.T) {
			r, gw, vpc := routeSecurityFixture(t, bad)
			for _, cidr := range []string{"10.96.0.0/12", "fd00:1::/48"} {
				_, n, err := net.ParseCIDR(cidr)
				if err != nil {
					t.Fatal(err)
				}
				r.InternalCIDRs = append(r.InternalCIDRs, n)
			}
			out, problem, err := r.reconcileRoutes(context.Background(), gw, vpc)
			if err != nil {
				t.Fatal(err)
			}
			if len(out) != 1 || len(out[0].CIDRs) != 0 || out[0].Port != "" || problem == "" {
				t.Fatalf("internal route admitted: %+v %q", out, problem)
			}
		})
	}
}

func TestVPCNextHopRequiresCurrentClaim(t *testing.T) {
	for _, mutation := range []string{"old-pod", "missing-uid", "old-vni", "wrong-vpc", "terminating-port", "terminating-pod"} {
		for _, appliance := range []bool{false, true} {
			t.Run(mutation+map[bool]string{false: "/route", true: "/appliance"}[appliance], func(t *testing.T) {
				r, gw, vpc := routeSecurityFixture(t, "203.0.113.0/24")
				port := &sdnv1alpha1.Port{}
				if err := r.Get(t.Context(), client.ObjectKey{Name: "v101.10-0-0-2"}, port); err != nil {
					t.Fatal(err)
				}
				switch mutation {
				case "old-pod":
					port.Labels[sdnv1alpha1.LabelPodUID] = "pod-predecessor"
				case "missing-uid":
					delete(port.Labels, sdnv1alpha1.LabelPodUID)
				case "old-vni":
					vpc.Status.VNI = 102
				case "wrong-vpc":
					port.Spec.VPCRef.Name = "other"
				case "terminating-port":
					port.Finalizers = []string{"example.invalid/cleanup"}
				case "terminating-pod":
					pod := &corev1.Pod{}
					if err := r.Get(t.Context(), client.ObjectKey{Namespace: "tenant-a", Name: "router"}, pod); err != nil {
						t.Fatal(err)
					}
					pod.Finalizers = []string{"example.invalid/cleanup"}
					if err := r.Update(t.Context(), pod); err != nil {
						t.Fatal(err)
					}
					if err := r.Delete(t.Context(), pod); err != nil {
						t.Fatal(err)
					}
				}
				if err := r.Update(t.Context(), port); err != nil {
					t.Fatal(err)
				}
				if mutation == "terminating-port" {
					if err := r.Delete(t.Context(), port); err != nil {
						t.Fatal(err)
					}
				}
				if appliance {
					gw.Spec.Appliance = &sdnv1alpha1.VPCGatewayAppliance{PodSelector: gw.Spec.Routes[0].Via.PodSelector}
					chosen, _, err := r.reconcileAppliance(t.Context(), gw, vpc)
					if err != nil {
						t.Fatal(err)
					}
					if chosen != "" {
						t.Fatalf("stale claim became door: %s", chosen)
					}
				} else {
					out, _, err := r.reconcileRoutes(t.Context(), gw, vpc)
					if err != nil {
						t.Fatal(err)
					}
					if len(out) != 1 || out[0].Port != "" {
						t.Fatalf("stale route next hop: %+v", out)
					}
				}
			})
		}
	}
}

func TestVPCNextHopRecoversAfterPersistentClaimCutover(t *testing.T) {
	r, gw, vpc := routeSecurityFixture(t, "203.0.113.0/24")
	port := &sdnv1alpha1.Port{}
	key := client.ObjectKey{Name: "v101.10-0-0-2"}
	if err := r.Get(t.Context(), key, port); err != nil {
		t.Fatal(err)
	}
	port.Labels[sdnv1alpha1.LabelPodUID] = "old-launcher"
	if err := r.Update(t.Context(), port); err != nil {
		t.Fatal(err)
	}
	out, _, err := r.reconcileRoutes(t.Context(), gw, vpc)
	if err != nil || len(out) != 1 || out[0].Port != "" {
		t.Fatalf("old binding admitted: %+v %v", out, err)
	}
	port.Labels[sdnv1alpha1.LabelPodUID] = "pod-current"
	if err := r.Update(t.Context(), port); err != nil {
		t.Fatal(err)
	}
	out, _, err = r.reconcileRoutes(t.Context(), gw, vpc)
	if err != nil || len(out) != 1 || out[0].Port != key.Name {
		t.Fatalf("cutover claim not selected: %+v %v", out, err)
	}
	gw.Spec.Appliance = &sdnv1alpha1.VPCGatewayAppliance{PodSelector: gw.Spec.Routes[0].Via.PodSelector}
	chosen, _, err := r.reconcileAppliance(t.Context(), gw, vpc)
	if err != nil || chosen != key.Name {
		t.Fatalf("cutover door not selected: %s %v", chosen, err)
	}
}

func TestLosingGatewayCannotPublishRoutesOrClearWinningDoor(t *testing.T) {
	r, winner, _ := routeSecurityFixture(t, "203.0.113.0/24")
	winner.Spec.Appliance = &sdnv1alpha1.VPCGatewayAppliance{PodSelector: winner.Spec.Routes[0].Via.PodSelector}
	if err := r.Update(t.Context(), winner); err != nil {
		t.Fatal(err)
	}
	reconcileGateway(t, r.Client, winner.Namespace, winner.Name)
	if !portGateway(t, r.Client, "v101.10-0-0-2") {
		t.Fatal("winner has no door")
	}
	loser := winner.DeepCopy()
	loser.Name = "z-loser"
	loser.ResourceVersion = ""
	loser.Spec.Appliance = nil
	loser.Status = sdnv1alpha1.VPCGatewayStatus{}
	if err := r.Create(t.Context(), loser); err != nil {
		t.Fatal(err)
	}
	got := reconcileGateway(t, r.Client, loser.Namespace, loser.Name)
	if len(got.Status.Routes) != 0 {
		t.Errorf("losing gateway publishes routes: %+v", got.Status.Routes)
	}
	if !portGateway(t, r.Client, "v101.10-0-0-2") {
		t.Error("losing gateway cleared winning appliance door")
	}
}
