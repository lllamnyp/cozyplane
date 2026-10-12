package sdn

import (
	"context"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func runtimeClassGateway() *sdnv1alpha1.VPNGateway {
	return &sdnv1alpha1.VPNGateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant-vpn-test", UID: "gateway-uid"},
		Spec:       sdnv1alpha1.VPNGatewaySpec{VPCRef: sdnv1alpha1.LocalVPCRef{Name: "vpc-a"}},
	}
}

func TestVPNRuntimeClassPodTemplates(t *testing.T) {
	for _, backend := range []string{backendWireGuard, backendIPsec} {
		for _, class := range []string{"", "cozyplane-vpn"} {
			for _, hardened := range []bool{false, true} {
				t.Run(backend+"/"+class+"/hardened="+map[bool]string{false: "false", true: "true"}[hardened], func(t *testing.T) {
					r := &VPNGatewayReconciler{Config: VPNGatewayConfig{
						Image: "example.invalid/cozyplane:test", RuntimeClassName: class, HardenedAppliance: hardened,
					}}
					gw := runtimeClassGateway()
					for _, tpl := range []corev1.PodTemplateSpec{
						r.deployment(gw, backend, "checksum").Spec.Template,
						r.statefulSet(gw, backend, "checksum").Spec.Template,
					} {
						if class == "" {
							if tpl.Spec.RuntimeClassName != nil {
								t.Fatal("empty config must omit runtimeClassName")
							}
						} else if tpl.Spec.RuntimeClassName == nil || *tpl.Spec.RuntimeClassName != class {
							t.Fatalf("runtimeClassName = %v, want %q", tpl.Spec.RuntimeClassName, class)
						}
						sc := tpl.Spec.Containers[0].SecurityContext
						if !hardened {
							if sc.Privileged == nil || !*sc.Privileged || tpl.Spec.SecurityContext != nil || tpl.Spec.AutomountServiceAccountToken != nil {
								t.Fatal("compatibility mode changed")
							}
							continue
						}
						if sc.Privileged != nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
							t.Fatalf("unexpected hardened context: %+v", sc)
						}
						wantCaps := &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"NET_ADMIN", "NET_RAW", "NET_BIND_SERVICE"}}
						if backend == backendIPsec {
							// The IPsec appliance loads its source filter.
							wantCaps.Add = append(wantCaps.Add, "BPF")
						}
						if !reflect.DeepEqual(sc.Capabilities, wantCaps) {
							t.Fatalf("capabilities = %+v, want %+v", sc.Capabilities, wantCaps)
						}
						wantSysctls := []corev1.Sysctl{{Name: "net.ipv4.ip_forward", Value: "1"}, {Name: "net.ipv6.conf.all.forwarding", Value: "1"}}
						if tpl.Spec.SecurityContext == nil || !reflect.DeepEqual(tpl.Spec.SecurityContext.Sysctls, wantSysctls) {
							t.Fatalf("missing forwarding sysctls: %+v", tpl.Spec.SecurityContext)
						}
						if tpl.Spec.AutomountServiceAccountToken == nil || *tpl.Spec.AutomountServiceAccountToken {
							t.Fatal("hardened appliance must not receive API credentials")
						}
					}
				})
			}
		}
	}
}

type runtimeClassCountingClient struct {
	client.Client
	updates     int
	defaultPods bool
}

func (c *runtimeClassCountingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.updates++
	if c.defaultPods {
		var tpl *corev1.PodTemplateSpec
		switch obj := obj.(type) {
		case *appsv1.Deployment:
			tpl = &obj.Spec.Template
		case *appsv1.StatefulSet:
			tpl = &obj.Spec.Template
		}
		if tpl != nil {
			tpl.Spec.DNSPolicy = corev1.DNSClusterFirst
			tpl.Spec.RestartPolicy = corev1.RestartPolicyAlways
			tpl.Spec.SchedulerName = corev1.DefaultSchedulerName
			tpl.Spec.TerminationGracePeriodSeconds = new(int64(30))
			if tpl.Spec.SecurityContext == nil {
				tpl.Spec.SecurityContext = &corev1.PodSecurityContext{}
			}
			for i := range tpl.Spec.Containers {
				tpl.Spec.Containers[i].TerminationMessagePath = corev1.TerminationMessagePathDefault
				tpl.Spec.Containers[i].TerminationMessagePolicy = corev1.TerminationMessageReadFile
			}
		}
	}
	return c.Client.Update(ctx, obj, opts...)
}

func TestVPNRuntimeClassReconcileRollout(t *testing.T) {
	for _, stateful := range []bool{false, true} {
		t.Run(map[bool]string{false: "Deployment-warm-standby", true: "StatefulSet-active-active"}[stateful], func(t *testing.T) {
			scheme := testScheme(t)
			if err := appsv1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			c := &runtimeClassCountingClient{Client: fake.NewClientBuilder().WithScheme(scheme).Build()}
			r := &VPNGatewayReconciler{Client: c, Scheme: scheme, Config: VPNGatewayConfig{Image: "example.invalid/cozyplane:test", HardenedAppliance: true}}
			gw := runtimeClassGateway()
			gw.Spec.HA = &sdnv1alpha1.VPNGatewayHA{Mode: sdnv1alpha1.VPNGatewayHAModeWarmStandby}
			if stateful {
				gw.Spec.HA.Mode = sdnv1alpha1.VPNGatewayHAModeActiveActive
			}
			ensure := func() {
				t.Helper()
				var err error
				if stateful {
					err = r.ensureStatefulSet(context.Background(), gw, backendIPsec, "unchanged")
				} else {
					err = r.ensureDeployment(context.Background(), gw, backendIPsec, "unchanged")
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			fetch := func() (client.Object, *corev1.PodTemplateSpec) {
				t.Helper()
				key := client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name + "-vpn"}
				if stateful {
					obj := &appsv1.StatefulSet{}
					if err := c.Get(context.Background(), key, obj); err != nil {
						t.Fatal(err)
					}
					return obj, &obj.Spec.Template
				}
				obj := &appsv1.Deployment{}
				if err := c.Get(context.Background(), key, obj); err != nil {
					t.Fatal(err)
				}
				return obj, &obj.Spec.Template
			}
			for _, class := range []string{"", "cozyplane-vpn", "cozyplane-vpn-v2", ""} {
				r.Config.RuntimeClassName = class
				ensure()
				_, tpl := fetch()
				got := ""
				if tpl.Spec.RuntimeClassName != nil {
					got = *tpl.Spec.RuntimeClassName
				}
				if got != class || (class == "" && tpl.Spec.RuntimeClassName != nil) {
					t.Fatalf("class transition to %q rendered %q", class, got)
				}
				before := c.updates
				for i := 0; i < 3; i++ {
					ensure()
				}
				if c.updates != before {
					t.Fatal("unchanged reconciliation writes repeatedly")
				}
			}
			if c.updates != 3 {
				t.Fatalf("rollout writes = %d, want three class transitions", c.updates)
			}
			// API defaults must not create repeated rollouts/API writes (CPU risk).
			obj, tpl := fetch()
			c.defaultPods = true
			tpl.Spec.DNSPolicy = corev1.DNSClusterFirst
			tpl.Spec.RestartPolicy = corev1.RestartPolicyAlways
			tpl.Spec.SchedulerName = corev1.DefaultSchedulerName
			tpl.Spec.TerminationGracePeriodSeconds = new(int64(30))
			tpl.Spec.Containers[0].TerminationMessagePath = corev1.TerminationMessagePathDefault
			tpl.Spec.Containers[0].TerminationMessagePolicy = corev1.TerminationMessageReadFile
			if err := c.Update(context.Background(), obj); err != nil {
				t.Fatal(err)
			}
			before := c.updates
			for i := 0; i < 10; i++ {
				ensure()
			}
			if c.updates != before {
				t.Fatalf("API defaults cause %d unnecessary writes", c.updates-before)
			}
			// A previously privileged template must not survive hardened mode.
			obj, tpl = fetch()
			tpl.Spec.Containers[0].SecurityContext.Privileged = new(true)
			if err := c.Update(context.Background(), obj); err != nil {
				t.Fatal(err)
			}
			ensure()
			_, tpl = fetch()
			if tpl.Spec.Containers[0].SecurityContext.Privileged != nil {
				t.Fatal("privileged drift survived hardened reconciliation")
			}
			obj, tpl = fetch()
			tpl.Spec.HostNetwork, tpl.Spec.HostPID, tpl.Spec.HostIPC = true, true, true
			if err := c.Update(context.Background(), obj); err != nil {
				t.Fatal(err)
			}
			ensure()
			_, tpl = fetch()
			if tpl.Spec.HostNetwork || tpl.Spec.HostPID || tpl.Spec.HostIPC {
				t.Fatal("host namespace drift survived reconciliation")
			}
			// Clearing hardened mode also clears its sysctls and token setting,
			// while the API's empty PodSecurityContext remains a harmless default.
			r.Config.HardenedAppliance = false
			ensure()
			_, tpl = fetch()
			if tpl.Spec.Containers[0].SecurityContext.Privileged == nil || !*tpl.Spec.Containers[0].SecurityContext.Privileged || len(tpl.Spec.SecurityContext.Sysctls) != 0 || tpl.Spec.AutomountServiceAccountToken != nil {
				t.Fatal("compatibility transition kept hardened-only configuration")
			}
			before = c.updates
			for i := 0; i < 10; i++ {
				ensure()
			}
			if c.updates != before {
				t.Fatal("defaulted empty security context causes compatibility rollouts")
			}
		})
	}
}

func TestVPNRuntimeClassHubRemovalChangesTemplate(t *testing.T) {
	scheme := testScheme(t)
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := &runtimeClassCountingClient{Client: fake.NewClientBuilder().WithScheme(scheme).Build()}
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme, Config: VPNGatewayConfig{Image: "example.invalid/cozyplane:test", HardenedAppliance: true, RuntimeClassName: "cozyplane-vpn"}}
	gw := runtimeClassGateway()
	gw.Spec.AdditionalVPCRefs = []sdnv1alpha1.LocalVPCRef{{Name: "vpc-b"}}
	if err := r.ensureDeployment(context.Background(), gw, backendIPsec, "same-config"); err != nil {
		t.Fatal(err)
	}
	gw.Spec.AdditionalVPCRefs = nil
	if err := r.ensureDeployment(context.Background(), gw, backendIPsec, "same-config"); err != nil {
		t.Fatal(err)
	}
	got := &appsv1.Deployment{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name + "-vpn"}, got); err != nil {
		t.Fatal(err)
	}
	if c.updates != 1 || got.Spec.Template.Annotations[sdnv1alpha1.AnnotationVPC] != "vpc-a" {
		t.Fatal("removing a hub leg did not change the pod template")
	}
	if _, found := got.Spec.Template.Annotations[sdnv1alpha1.AnnotationNetworks]; found {
		t.Fatal("obsolete multi-attachment annotation retained")
	}
	if got.Spec.Template.Spec.RuntimeClassName == nil || *got.Spec.Template.Spec.RuntimeClassName != r.Config.RuntimeClassName {
		t.Fatal("hub removal lost runtime class")
	}
}
