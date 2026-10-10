package main

import (
	"context"
	"log/slog"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	localinformers "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/informers/externalversions"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
)

// watchBindingGrants applies revocations and forwarding changes to running
// legs; CNI ADD alone cannot enforce a grant that changes afterwards.
func watchBindingGrants(ctx context.Context, factory sdninformers.SharedInformerFactory, localFactory localinformers.SharedInformerFactory, core kubernetes.Interface, nodeName string, log *slog.Logger) {
	bindings := factory.Sdn().V1alpha1().VPCBindings()
	ports := factory.Sdn().V1alpha1().Ports()
	reconcile := func() {
		reconcileBindingGrants(ctx, factory, localFactory, core, nodeName, log)
	}
	reconcile = periodicResyncAfterCacheSync(ctx, revocationRetryPeriod, reconcile, bindings.Informer().HasSynced, ports.Informer().HasSynced)
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { reconcile() },
		UpdateFunc: func(any, any) { reconcile() },
		DeleteFunc: func(any) { reconcile() },
	}
	_, _ = bindings.Informer().AddEventHandler(handler)
	_, _ = ports.Informer().AddEventHandler(handler)
}

func reconcileBindingGrants(ctx context.Context, factory sdninformers.SharedInformerFactory, localFactory localinformers.SharedInformerFactory, core kubernetes.Interface, nodeName string, log *slog.Logger) {
	bindings := factory.Sdn().V1alpha1().VPCBindings()
	ports := factory.Sdn().V1alpha1().Ports()
	if !bindings.Informer().HasSynced() || !ports.Informer().HasSynced() {
		return
	}
	grants, err := bindings.Lister().List(labels.Everything())
	if err != nil {
		log.Error("list binding grants", "err", err)
		return
	}
	allPorts, err := ports.Lister().List(labels.Everything())
	if err != nil {
		log.Error("list ports for binding grants", "err", err)
		return
	}
	veths, err := datapath.ListLocalPortVeths()
	if err != nil {
		log.Error("list binding endpoints", "err", err)
		return
	}
	index := indexLocalPortVeths(veths)
	localGrants := indexLocalBindingGrants(grants, allPorts, index)
	for _, v := range orphanPortVeths(allPorts, veths) {
		if _, err := datapath.SeverVethIfOwned(v.Net, v.IPs[0], v.Ifindex, v.Alias, ""); err != nil {
			log.Error("sever orphaned Port endpoint", "ifindex", v.Ifindex, "portUID", v.PortUID, "err", err)
		}
	}
	// Apply every UID-proven endpoint before any legacy API lookup can fail.
	// Each phase keeps one map snapshot/diff batch rather than a scan per leg.
	for _, knownPhase := range []bool{true, false} {
		phaseCtx := ctx
		if !knownPhase {
			// Several stalled reads must not hold the next proven-owner
			// revocation pass for one full timeout per legacy endpoint.
			var cancel context.CancelFunc
			phaseCtx, cancel = context.WithTimeout(ctx, legacyOwnershipReadTimeout)
			defer cancel()
		}
		var forwardingEntries []datapath.ForwardingEndpoint
		var legacyEndpoints []verifiedBindingEndpoint
	phasePorts:
		for _, port := range allPorts {
			if port.Spec.PodNamespace == "" {
				continue
			}
			vni, ok := vniFromPortName(port.Name)
			if !ok {
				continue
			}
			grant := localGrants[portBindingKey(port)]
			for _, v := range index.forPort(port) {
				if (v.PortUID != "") != knownPhase {
					continue
				}
				if phaseCtx.Err() != nil {
					break phasePorts
				}
				candidates := []datapath.LocalPortVeth{v}
				if !grant.attached || !port.DeletionTimestamp.IsZero() {
					err = severLocalPort(phaseCtx, core, localFactory, port, nodeName, log, candidates)
				} else {
					var endpoints []datapath.LocalPortVeth
					endpoints, err = ownedPortVeths(phaseCtx, core, localFactory, port, nodeName, candidates)
					if err == nil {
						for _, endpoint := range endpoints {
							if knownPhase {
								forwardingEntries = append(forwardingEntries, datapath.ForwardingEndpoint{Net: vni, Ifindex: endpoint.Ifindex, Alias: endpoint.Alias, Allow: grant.forwarding, CIDRs: grant.cidrs})
							} else {
								legacyEndpoints = append(legacyEndpoints, verifiedBindingEndpoint{port, endpoint})
							}
						}
					}
				}
				if err != nil {
					log.Error("apply binding grant", "port", port.Name, "err", err)
				}
			}
		}
		if !knownPhase && len(legacyEndpoints) > 0 {
			forwardingEntries = currentLegacyBindingEntries(ctx, factory, localFactory, core, nodeName, log, legacyEndpoints, index)
		}
		if err := datapath.SyncEndpointForwarding(forwardingEntries); err != nil {
			log.Error("sync binding forwarding grants", "err", err)
		}
	}
}

type verifiedBindingEndpoint struct {
	port *sdnv1.Port
	veth datapath.LocalPortVeth
}

// An ownership proof does not freeze consent while a live Pod read is pending.
// Resolve only the verified batch against current claims and binding consent.
func currentLegacyBindingEntries(ctx context.Context, factory sdninformers.SharedInformerFactory, localFactory localinformers.SharedInformerFactory, core kubernetes.Interface, nodeName string, log *slog.Logger, verified []verifiedBindingEndpoint, index localEndpointIndex) []datapath.ForwardingEndpoint {
	bindings, err := factory.Sdn().V1alpha1().VPCBindings().Lister().List(labels.Everything())
	if err != nil {
		log.Error("refresh legacy binding grants", "err", err)
		return nil
	}
	ports := factory.Sdn().V1alpha1().Ports().Lister()
	currentPorts := make([]*sdnv1.Port, 0, len(verified))
	live := verified[:0]
	for _, proof := range verified {
		current, err := ports.Get(proof.port.Name)
		if err != nil && !apierrors.IsNotFound(err) {
			log.Error("refresh legacy Port grant", "port", proof.port.Name, "err", err)
			continue
		}
		if apierrors.IsNotFound(err) || current.UID != proof.port.UID || current.DeletionTimestamp != nil || current.Spec.IP != proof.port.Spec.IP || current.Spec.VPCRef != proof.port.Spec.VPCRef || current.Spec.PodNamespace != proof.port.Spec.PodNamespace {
			if err := severLocalPort(ctx, core, localFactory, proof.port, nodeName, log, []datapath.LocalPortVeth{proof.veth}); err != nil {
				log.Error("sever obsolete verified legacy endpoint", "port", proof.port.Name, "err", err)
			}
			continue
		}
		currentPorts = append(currentPorts, current)
		live = append(live, verifiedBindingEndpoint{current, proof.veth})
	}
	grants := indexLocalBindingGrants(bindings, currentPorts, index)
	entries := make([]datapath.ForwardingEndpoint, 0, len(live))
	for _, proof := range live {
		grant := grants[portBindingKey(proof.port)]
		if !grant.attached {
			if err := severLocalPort(ctx, core, localFactory, proof.port, nodeName, log, []datapath.LocalPortVeth{proof.veth}); err != nil {
				log.Error("sever withdrawn legacy binding", "port", proof.port.Name, "err", err)
			}
			continue
		}
		v := proof.veth
		entries = append(entries, datapath.ForwardingEndpoint{Net: v.Net, Ifindex: v.Ifindex, Alias: v.Alias, Allow: grant.forwarding, CIDRs: grant.cidrs})
	}
	return entries
}
