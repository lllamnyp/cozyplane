package main

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnclient "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	sdntyped "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/typed/sdn/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"
)

type persistentRaceClient struct {
	sdnclient.Interface
	ports sdntyped.PortInterface
}

func (c *persistentRaceClient) SdnV1alpha1() sdntyped.SdnV1alpha1Interface {
	return &persistentRaceSDN{SdnV1alpha1Interface: c.Interface.SdnV1alpha1(), ports: c.ports}
}

type persistentRaceSDN struct {
	sdntyped.SdnV1alpha1Interface
	ports sdntyped.PortInterface
}

func (c *persistentRaceSDN) Ports() sdntyped.PortInterface { return c.ports }

type persistentRacePorts struct {
	sdntyped.PortInterface
	reads          atomic.Int64
	ready          chan struct{}
	occupancyReads atomic.Int64
	occupancyReady chan struct{}
	removeForeign  func(context.Context) error
}

func (p *persistentRacePorts) List(ctx context.Context, options metav1.ListOptions) (*sdn.PortList, error) {
	if p.removeForeign != nil && !strings.Contains(options.LabelSelector, labelVMName+"=") {
		if p.occupancyReads.Add(1) == 1 {
			list, err := p.PortInterface.List(ctx, options)
			if err == nil {
				err = p.removeForeign(ctx)
			}
			close(p.occupancyReady)
			return list, err
		}
		select {
		case <-p.occupancyReady:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	list, err := p.PortInterface.List(ctx, options)
	if err != nil || !strings.Contains(options.LabelSelector, labelVMName+"=") {
		return list, err
	}
	// Wait outside Fake.Invokes' lock. Both initial live lookups must complete
	// before either launcher can claim, a legal interleaving across two nodes.
	read := p.reads.Add(1)
	if read <= 2 {
		if read == 2 {
			close(p.ready)
		}
		select {
		case <-p.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return list, nil
}

func TestPersistentNICConcurrentFirstADDUsesOneIdentity(t *testing.T) {
	testPersistentNICConcurrentFirstADD(t, false)
}

func TestPersistentNICConcurrentDifferentCandidatesUsesOneIdentity(t *testing.T) {
	testPersistentNICConcurrentFirstADD(t, true)
}

func testPersistentNICConcurrentFirstADD(t *testing.T, differentCandidates bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	fake := sdnfake.NewSimpleClientset()
	ports := &persistentRacePorts{PortInterface: fake.SdnV1alpha1().Ports(), ready: make(chan struct{})}
	client := &persistentRaceClient{Interface: fake, ports: ports}
	vpc := newVPC("tenant", "net", 101, "10.0.0.0/24")
	if differentCandidates {
		foreign := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: portName(101, "10.0.0.2"), Labels: map[string]string{labelVPCNamespace: "tenant", labelVPC: "net"}}, Spec: sdn.PortSpec{IP: "10.0.0.2"}}
		if _, err := fake.SdnV1alpha1().Ports().Create(ctx, foreign, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		ports.occupancyReady = make(chan struct{})
		ports.removeForeign = func(ctx context.Context) error {
			return fake.SdnV1alpha1().Ports().Delete(ctx, foreign.Name, metav1.DeleteOptions{})
		}

	}
	// Model the API's persistent NIC create contract. The independent real
	// etcd test proves that two different candidate keys cannot both commit.
	fake.PrependReactor("create", "ports", func(action clienttesting.Action) (bool, runtime.Object, error) {
		incoming := action.(clienttesting.CreateAction).GetObject().(*sdn.Port)
		obj, err := fake.Tracker().List(sdn.SchemeGroupVersion.WithResource("ports"), sdn.SchemeGroupVersion.WithKind("Port"), "")
		if err != nil {
			return true, nil, err
		}
		for _, held := range obj.(*sdn.PortList).Items {
			if held.Labels[labelVMName] == incoming.Labels[labelVMName] && held.Labels[labelVMNIC] == incoming.Labels[labelVMNIC] && held.Spec.PodNamespace == incoming.Spec.PodNamespace && held.Spec.VPCRef == incoming.Spec.VPCRef {
				return true, nil, apierrors.NewAlreadyExists(sdn.Resource("ports"), held.Name)
			}
		}
		return false, nil, nil
	})
	type result struct {
		ip, mac string
		err     error
	}
	results := make(chan result, 2)
	for node := range 2 {
		go func() {
			r := res(vpc, vpc.Namespace)
			r.containerID = fmt.Sprintf("sandbox-%d", node)
			r.cniIfName = "eth0"
			state := &datapath.AgentState{NodeName: fmt.Sprintf("node-%d", node), NodeIP: fmt.Sprintf("192.0.2.%d", node+1)}
			ip, mac, _, _, err := attachPort(ctx, client, r, state, "tenant", fmt.Sprintf("launcher-%d", node), fmt.Sprintf("pod-%d", node), "vm", `{"kubevirt.io/created-by":"instance"}`)
			results <- result{ip: ip.String(), mac: mac.String(), err: err}
		}()
	}
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatal("concurrent ADD failed", first.err, second.err)
	}
	list, err := fake.SdnV1alpha1().Ports().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || first.ip != second.ip || first.mac != second.mac {
		t.Fatalf("one VM NIC acquired multiple identities: claims=%d first=%s/%s second=%s/%s", len(list.Items), first.ip, first.mac, second.ip, second.mac)
	}
}
