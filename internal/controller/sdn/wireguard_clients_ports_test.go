package sdn

import (
	"context"
	"errors"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func wgWitnessPort() *sdn.Port {
	return &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-2", UID: "port-predecessor", Labels: map[string]string{sdn.LabelPodUID: "pod-predecessor"}, Finalizers: []string{sdn.FinalizerSever}}, Spec: sdn.PortSpec{PodNamespace: "tenant-a", PodName: "appliance", VPCRef: sdn.VPCRef{Namespace: "tenant-a", Name: "app"}}}
}

func TestWGClientPortRevocationRequiresSeverCompletion(t *testing.T) {
	for _, scenario := range []string{"live predecessor", "terminating predecessor", "UID replacement", "absent", "missing pod UID"} {
		t.Run(scenario, func(t *testing.T) {
			gw, _, _ := wgSecurityFixture()
			port := wgWitnessPort()
			var objects []client.Object
			switch scenario {
			case "terminating predecessor":
				now := metav1.Now()
				port.DeletionTimestamp = &now
			case "UID replacement":
				port.UID = "port-replacement"
			case "missing pod UID":
				delete(port.Labels, sdn.LabelPodUID)
			}
			if scenario != "absent" {
				objects = append(objects, port)
			}
			live := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(objects...).Build()
			// The informer cache has missed the old port. Only a LIVE Get can
			// prove the sever barrier complete after the Pod object disappeared.
			cached := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).Build()
			r := &VPNGatewayReconciler{Client: cached, Reader: live}
			record := wgClientGatewayReservation{PodUIDs: []string{"pod-predecessor"}, PortUIDs: map[string]string{port.Name: "port-predecessor"}}
			clear, err := r.wgClientPortsRevoked(t.Context(), gw, record, &corev1.PodList{})
			if err != nil {
				t.Fatal(err)
			}
			want := scenario == "UID replacement" || scenario == "absent"
			if clear != want {
				t.Fatalf("clear=%v want=%v", clear, want)
			}
		})
	}
}

func TestWGClientPortWitnessLiveFallbackAfterCacheOrPodLoss(t *testing.T) {
	for _, scenario := range []string{"cache missed Port", "cache missed secondary leg", "Pod API gone", "Ports severed"} {
		t.Run(scenario, func(t *testing.T) {
			gw, _, _ := wgSecurityFixture()
			port := wgWitnessPort()
			pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: port.Spec.PodName, Namespace: gw.Namespace, UID: "pod-predecessor"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "192.0.2.5"}}
			cachedBuilder := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithIndex(&sdn.Port{}, vpnAppliancePodIndex, vpnAppliancePodKeys)
			if scenario == "cache missed secondary leg" {
				cachedBuilder.WithObjects(port)
			}
			cached := cachedBuilder.Build()
			var objects []client.Object
			if scenario != "Ports severed" {
				objects = append(objects, port)
			}
			if scenario == "cache missed secondary leg" {
				secondary := port.DeepCopy()
				secondary.Name = "v102.10-2-0-2"
				secondary.UID = "secondary-port"
				secondary.Spec.VPCRef.Name = "second-app"
				objects = append(objects, secondary)
			}
			live := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(objects...).Build()
			r := &VPNGatewayReconciler{Client: cached, Reader: live}
			record := wgClientGatewayReservation{PodUIDs: []string{string(pod.UID)}}
			pods := &corev1.PodList{}
			if scenario != "Pod API gone" {
				pods.Items = []corev1.Pod{pod}
			}
			if err := r.rememberWGClientPorts(t.Context(), gw, &record, pods); err != nil {
				t.Fatal(err)
			}
			if scenario == "Ports severed" {
				if len(record.PortUIDs) != 0 {
					t.Fatal("bootstrap or completed sever resurrected witnesses")
				}
				return
			}
			if record.PortUIDs[port.Name] != string(port.UID) {
				t.Fatal("live predecessor Port lost", record.PortUIDs)
			}
			if scenario == "cache missed secondary leg" && record.PortUIDs["v102.10-2-0-2"] != "secondary-port" {
				t.Fatal("partial cache delivery lost secondary VPC witness", record.PortUIDs)
			}
		})
	}
}

func TestWGClientPortWitnessKeepsOnlyCurrentAfterConfirmation(t *testing.T) {
	gw, _, _ := wgSecurityFixture()
	scheme := gatewayScheme(t)
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn", Namespace: gw.Namespace, UID: "deployment-current"}}
	replicaSet := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "appliance-current", Namespace: gw.Namespace, UID: "replicaset-current"}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "appliance", Namespace: gw.Namespace, UID: "pod-current"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	for _, pair := range [][2]client.Object{{gw, deployment}, {deployment, replicaSet}, {replicaSet, pod}} {
		if err := controllerutil.SetControllerReference(pair[0], pair[1], scheme); err != nil {
			t.Fatal(err)
		}
	}
	port := wgWitnessPort()
	port.Labels[sdn.LabelPodUID] = string(pod.UID)
	port.UID = "port-current"
	c := fake.NewClientBuilder().WithScheme(scheme).WithIndex(&sdn.Port{}, vpnAppliancePodIndex, vpnAppliancePodKeys).WithObjects(gw, deployment, replicaSet, pod, port).Build()
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme}
	list := &corev1.PodList{Items: []corev1.Pod{*pod}}
	record := wgClientGatewayReservation{PodUIDs: []string{string(pod.UID)}, PortUIDs: map[string]string{"v101.10-0-0-9": "removed-port"}}
	if err := r.rememberWGClientPorts(t.Context(), gw, &record, list); err != nil {
		t.Fatal(err)
	}
	if len(record.PortUIDs) != 2 || record.PortUIDs[port.Name] != string(port.UID) {
		t.Fatal("current or historical witness lost", record.PortUIDs)
	}
	clear, err := r.wgClientPortsRevoked(t.Context(), gw, record, list)
	if err != nil || !clear {
		t.Fatal("confirmed current configuration still held", clear, err)
	}
	current, err := r.currentWGClientPorts(t.Context(), gw, record, list)
	if err != nil || len(current) != 1 || current[port.Name] != string(port.UID) {
		t.Fatal("historical witness not pruned", current, err)
	}
}

type wgPortWitnessPartialClient struct{ client.Client }

func (c wgPortWitnessPartialClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if err := c.Client.List(ctx, list, opts...); err != nil {
		return err
	}
	list.(*sdn.PortList).Continue = "more"
	return nil
}

type wgPortWitnessErrorReader struct{ client.Reader }

func (r wgPortWitnessErrorReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("live read failed")
}

func TestWGClientWitnessErrorsFailClosed(t *testing.T) {
	gw, _, _ := wgSecurityFixture()
	port := wgWitnessPort()
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: port.Spec.PodName, Namespace: gw.Namespace, UID: "pod-predecessor"}}
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithIndex(&sdn.Port{}, vpnAppliancePodIndex, vpnAppliancePodKeys).WithObjects(port).Build()
	record := wgClientGatewayReservation{PodUIDs: []string{string(pod.UID)}, PortUIDs: map[string]string{"retained": "retained-port"}}
	r := &VPNGatewayReconciler{Client: wgPortWitnessPartialClient{c}}
	if err := r.rememberWGClientPorts(t.Context(), gw, &record, &corev1.PodList{Items: []corev1.Pod{*pod}}); err == nil {
		t.Fatal("partial port scan accepted")
	}
	if len(record.PortUIDs) != 1 || record.PortUIDs["retained"] != "retained-port" {
		t.Fatal("partial scan mutated witnesses", record.PortUIDs)
	}
	r = &VPNGatewayReconciler{Client: c, Reader: wgPortWitnessErrorReader{c}}
	if clear, err := r.wgClientPortsRevoked(t.Context(), gw, record, &corev1.PodList{}); err == nil || clear {
		t.Fatal("read failure released witness")
	}
}
