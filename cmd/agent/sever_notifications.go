package main

import (
	"context"
	"log/slog"

	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	localinformers "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/informers/externalversions"
	sdnclient "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const terminatingPortIndex = "cozyplane-terminating-port"

func terminatingPortKeys(obj any) ([]string, error) {
	port, ok := obj.(*sdnv1.Port)
	if !ok || port == nil || port.DeletionTimestamp == nil {
		return nil, nil
	}
	return []string{"terminating"}, nil
}

// API work reads current claims once per coalesced pass, never old event objects.
func portSeverNotifications(ctx context.Context, informer cache.SharedIndexInformer, localFactory localinformers.SharedInformerFactory, sdn sdnclient.Interface, core kubernetes.Interface, self string, log *slog.Logger) (func(), error) {
	if err := informer.AddIndexers(cache.Indexers{terminatingPortIndex: terminatingPortKeys}); err != nil {
		return nil, err
	}
	reconcile := func() {
		objects, err := informer.GetIndexer().ByIndex(terminatingPortIndex, "terminating")
		if err != nil {
			log.Error("read terminating Ports", "err", err)
			return
		}
		if len(objects) == 0 {
			return
		}
		veths, err := datapath.ListLocalPortVeths()
		if err != nil {
			log.Error("list terminating Port endpoints", "err", err)
			return
		}
		known := indexLocalPortVeths(knownPortVeths(veths))
		// Initial-list callbacks can precede HasSynced. Quarantine every proven
		// owner in that replay before the first possibly stalled API request.
		for _, obj := range objects {
			p := obj.(*sdnv1.Port)
			if err := severLocalPort(ctx, core, localFactory, p, self, log, known.forPort(p)); err != nil {
				log.Error("sever proven terminating Port endpoints", "port", p.Name, "err", err)
			}
		}
		all := indexLocalPortVeths(veths)
		for _, obj := range objects {
			if ctx.Err() != nil {
				return
			}
			p := obj.(*sdnv1.Port)
			if p.Spec.Node == self {
				releaseSeveredPort(ctx, sdn, core, localFactory, p, log)
			} else if err := severLocalPort(ctx, core, localFactory, p, self, log, all.forPort(p)); err != nil {
				log.Error("sever terminating staged Port", "port", p.Name, "err", err)
			}
		}
	}
	return periodicResyncAfterCacheSync(ctx, revocationRetryPeriod, reconcile, informer.HasSynced), nil
}

func knownPortVeths(veths []datapath.LocalPortVeth) []datapath.LocalPortVeth {
	var known []datapath.LocalPortVeth
	for _, v := range veths {
		if v.PortUID != "" {
			known = append(known, v)
		}
	}
	return known
}

func severKnownLocalPort(ctx context.Context, core kubernetes.Interface, localFactory localinformers.SharedInformerFactory, port *sdnv1.Port, self string, log *slog.Logger) error {
	veths, err := datapath.ListLocalPortVeths()
	if err != nil {
		return err
	}
	return severLocalPort(ctx, core, localFactory, port, self, log, knownPortVeths(veths))
}
