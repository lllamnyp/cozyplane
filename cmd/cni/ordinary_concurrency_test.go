package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	sdntyped "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/typed/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ordinaryRacePorts struct {
	sdntyped.PortInterface
	lookups, occupancy atomic.Int64
	ready, removed     chan struct{}
	foreign            string
}

func TestSandboxLockCoversActualClaimRollback(t *testing.T) {
	dir := rootLockFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	fake := sdnfake.NewSimpleClientset()
	vpc := newVPC("tenant", "net", 101, "10.0.0.0/24")
	r := res(vpc, vpc.Namespace)
	r.containerID = "sandbox"
	r.cniIfName = "eth0"
	state := &datapath.AgentState{NodeName: "node", NodeIP: "192.0.2.1"}
	rollbackStarted, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	done := make(chan error, 1)
	go func() {
		done <- withSandboxLock(ctx, dir, r.containerID, r.cniIfName, func() error {
			_, _, claim, bound, err := attachPort(ctx, fake, r, state, "tenant", "pod", "pod-uid", "", "")
			if err != nil {
				return err
			}
			if bound {
				return errors.New("first allocation was unexpectedly reused")
			}
			defer func() {
				close(rollbackStarted)
				select {
				case <-release:
				case <-ctx.Done():
				}
				cctx, ccancel := cleanupContext(ctx)
				defer ccancel()
				_ = deleteClaimedPort(cctx, fake, claim)
			}()
			return errors.New("injected setup failure")
		})
	}()
	select {
	case <-rollbackStarted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	wait, wcancel := context.WithTimeout(ctx, 80*time.Millisecond)
	err := withSandboxLock(wait, dir, r.containerID, r.cniIfName, func() error { t.Error("retry entered during first ADD rollback"); return nil })
	wcancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("retry not serialized through cleanup", err)
	}
	close(release)
	if err = <-done; err == nil {
		t.Fatal("setup failure lost")
	}
	if err = withSandboxLock(ctx, dir, r.containerID, r.cniIfName, func() error {
		ip, _, _, bound, err := attachPort(ctx, fake, r, state, "tenant", "pod", "pod-uid", "", "")
		if err != nil {
			return err
		}
		if bound || ip.String() != "10.0.0.2" {
			return errors.New("retry failed to acquire fresh claim after rollback")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	claims, err := fake.SdnV1alpha1().Ports().List(ctx, metav1.ListOptions{})
	if err != nil || len(claims.Items) != 1 {
		t.Fatal("retry claim lost", err)
	}
}

func (p *ordinaryRacePorts) List(ctx context.Context, options metav1.ListOptions) (*sdn.PortList, error) {
	if strings.Contains(options.LabelSelector, labelPodUID+"=") {
		list, err := p.PortInterface.List(ctx, options)
		if err != nil {
			return nil, err
		}
		if n := p.lookups.Add(1); n <= 2 {
			if n == 2 {
				close(p.ready)
			}
			select {
			case <-p.ready:
			case <-time.After(100 * time.Millisecond): // serialized ADD has no second lookup yet
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return list, nil
	}
	if p.occupancy.Add(1) == 1 {
		list, err := p.PortInterface.List(ctx, options)
		if err == nil {
			err = p.PortInterface.Delete(ctx, p.foreign, metav1.DeleteOptions{})
		}
		close(p.removed)
		return list, err
	}
	select {
	case <-p.removed:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return p.PortInterface.List(ctx, options)
}

func TestOrdinaryConcurrentDifferentCandidatesUsesOneSandboxIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("host lock requires root-owned fixtures")
	}
	dir := t.TempDir() + "/locks"
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	foreign := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: portName(101, "10.0.0.2"), Labels: map[string]string{labelVPCNamespace: "tenant", labelVPC: "net"}}, Spec: sdn.PortSpec{IP: "10.0.0.2"}}
	fake := sdnfake.NewSimpleClientset(foreign)
	ports := &ordinaryRacePorts{PortInterface: fake.SdnV1alpha1().Ports(), ready: make(chan struct{}), removed: make(chan struct{}), foreign: foreign.Name}
	client := &persistentRaceClient{Interface: fake, ports: ports}
	vpc := newVPC("tenant", "net", 101, "10.0.0.0/24")
	r := res(vpc, vpc.Namespace)
	r.containerID = "sandbox"
	r.cniIfName = "eth0"
	state := &datapath.AgentState{NodeName: "node", NodeIP: "192.0.2.1"}
	type result struct {
		ip  string
		err error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			var address string
			err := withSandboxLock(ctx, dir, r.containerID, r.cniIfName, func() error {
				ip, _, _, _, err := attachPort(ctx, client, r, state, "tenant", "pod", "pod-uid", "", "")
				address = ip.String()
				return err
			})
			results <- result{ip: address, err: err}
		}()
	}
	a, b := <-results, <-results
	if a.err != nil || b.err != nil {
		t.Fatal(a.err, b.err)
	}
	list, err := fake.SdnV1alpha1().Ports().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || a.ip != b.ip {
		t.Fatalf("same sandbox allocated twice: claims=%d IPs=%s and %s", len(list.Items), a.ip, b.ip)
	}
}
