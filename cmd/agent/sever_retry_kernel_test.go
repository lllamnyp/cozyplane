package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/lllamnyp/cozyplane/datapath"
	localinformers "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/informers/externalversions"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func testKernelSeverAcknowledgementRetry(t *testing.T, mgr *datapath.Manager, localFactory localinformers.SharedInformerFactory) {
	port := severTestPort()
	client := sdnfake.NewSimpleClientset(port)
	api, recovery := recoverableSeverAPI(t, client, port)
	recovery.fail.Store(true)
	factory := sdninformers.NewSharedInformerFactory(client, 0)
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); factory.Shutdown() }()
	if err := watchPorts(ctx, factory, localFactory, api, corefake.NewSimpleClientset(), mgr, "local", "192.0.2.200", slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	inf := factory.Sdn().V1alpha1().Ports().Informer()
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		t.Fatal("Port cache did not sync")
	}
	select {
	case <-recovery.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("real SDN request did not start")
	}
	close(recovery.resume)
	select {
	case <-recovery.failed:
	case <-time.After(2 * time.Second):
		t.Fatal("initial SDN failure was not delivered")
	}
	// Allow the initial-list replay and its one pending pass to finish failing.
	last, stable, limit := recovery.gets.Load(), time.Now(), time.Now().Add(2*time.Second)
	for time.Since(stable) < 500*time.Millisecond {
		if count := recovery.gets.Load(); count != last {
			last, stable = count, time.Now()
		}
		if time.Now().After(limit) {
			t.Fatal("initial acknowledgement work never settled")
		}
		time.Sleep(10 * time.Millisecond)
	}
	current, err := client.SdnV1alpha1().Ports().Get(ctx, port.Name, metav1.GetOptions{})
	if err != nil || len(current.Finalizers) != 1 {
		t.Fatal("temporary API failure did not retain barrier", current, err)
	}
	recovery.fail.Store(false) // No Port, Pod, Binding or informer notification.
	deadline := time.Now().Add(16 * time.Second)
	for {
		current, err = client.SdnV1alpha1().Ports().Get(ctx, port.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(current.Finalizers) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("healthy API never retried sever acknowledgement without a new event", recovery.gets.Load(), last)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if recovery.puts.Load() != 1 || ctx.Err() != nil {
		t.Fatal("sever retry amplified writes or canceled parent", recovery.puts.Load(), ctx.Err())
	}
}
