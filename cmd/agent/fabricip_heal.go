package main

import (
	"context"
	corev1 "k8s.io/api/core/v1"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/podrepair"
	localclientset "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned"
)

// A Pod status address alone does not authorize reclaiming an IP. Require the
// same address in a successfully rebuilt local endpoint, and never adopt a
// conflicting claim. Legacy aliases repair with no invented sandbox identity.
func healLocalFabricIPs(ctx context.Context, core kubernetes.Interface, local localclientset.Interface, node string, rebuilt []datapath.LocalFabricIP, log *slog.Logger) error {
	ctx, cancel := context.WithTimeout(ctx, startupBestEffortTimeout)
	defer cancel()
	endpoints := map[string]datapath.LocalFabricIP{}
	ambiguous := map[string]bool{}
	for _, endpoint := range rebuilt {
		if ip := net.ParseIP(endpoint.Address); ip != nil {
			address := ip.String()
			if previous, exists := endpoints[address]; exists && (previous.ContainerID != endpoint.ContainerID || previous.IfName != endpoint.IfName) {
				ambiguous[address] = true
			}
			endpoints[address] = endpoint
		}
	}
	candidates := make(map[string]struct{}, len(endpoints))
	for address := range endpoints {
		if !ambiguous[address] {
			candidates[address] = struct{}{}
		} else {
			log.Warn("fabric repair refused ambiguous sandbox ownership", "address", address)
		}
	}
	pods, err := podrepair.ListLocalRunningPodAddresses(ctx, core, node, candidates)
	if err != nil {
		return err
	}
	var missing, conflicts int64
	for _, pod := range pods {
		endpoint := endpoints[pod.Address]
		name := localv1alpha1.FabricIPName(pod.Address)
		existing, err := local.LocalV1alpha1().FabricIPs().Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			if existing.Spec.PodUID != pod.UID || existing.Spec.Node != node {
				conflicts++
				log.Warn("fabric repair refused conflicting claim", "claim", name, "pod", pod.Namespace+"/"+pod.Name)
			}
			continue
		}
		if !apierrors.IsNotFound(err) {
			return err
		}
		missing++
		claim := &localv1alpha1.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"local.sdn.cozystack.io/pod-uid": pod.UID, "local.sdn.cozystack.io/pod-namespace": pod.Namespace, "local.sdn.cozystack.io/node": node}}, Spec: localv1alpha1.FabricIPSpec{Address: pod.Address, Node: node, PodNamespace: pod.Namespace, PodName: pod.Name, PodUID: pod.UID, ContainerID: endpoint.ContainerID, IfName: endpoint.IfName}}
		if _, err := local.LocalV1alpha1().FabricIPs().Create(ctx, claim, metav1.CreateOptions{}); err != nil {
			if apierrors.IsAlreadyExists(err) {
				continue
			}
			return err
		}
		fabricHealed.Add(1)
		log.Warn("recreated missing FabricIP from rebuilt local endpoint", "address", pod.Address, "pod", pod.Namespace+"/"+pod.Name, "sandboxKnown", strings.TrimSpace(endpoint.ContainerID) != "")
	}
	fabricMissing.Store(missing)
	fabricConflict.Store(conflicts)
	return nil
}

var (
	fabricHealed   atomic.Uint64 // claims this agent re-created
	fabricMissing  atomic.Int64  // pods on this node with an address and no claim, last pass
	fabricConflict atomic.Int64  // claims held by a DIFFERENT pod's UID, last pass
)

// fabricHealInterval is the periodic pass. A missing claim costs cross-node
// reachability for as long as it is missing, so this is minutes, not hours; it
// is one node-scoped pod List per interval against a cached claim lister.
const fabricHealInterval = time.Minute

// fabricIPGetter resolves a claim by object name. The informer's store in
// practice; an interface so the pass is testable without a cache.
type fabricIPGetter interface {
	Get(name string) (*localv1alpha1.FabricIP, error)
}

// healFabricIPs runs a heal pass immediately and then every interval, until ctx
// is done.
func healFabricIPs(ctx context.Context, client kubernetes.Interface, lc localclientset.Interface,
	claims fabricIPGetter, nodeName string, interval time.Duration, log *slog.Logger) {
	for {
		if err := healFabricIPsOnce(ctx, client, lc, claims, nodeName, log); err != nil {
			log.Warn("fabric IP heal pass failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func healFabricIPsOnce(ctx context.Context, client kubernetes.Interface, lc localclientset.Interface,
	_ fabricIPGetter, nodeName string, log *slog.Logger, inventory ...func() ([]datapath.LocalFabricIP, error)) error {
	read := datapath.SnapshotLocalFabricIPs
	if len(inventory) != 0 {
		read = inventory[0]
	}
	endpoints, err := read()
	if err != nil {
		return err
	}
	return healLocalFabricIPs(ctx, client, lc, nodeName, endpoints, log)
}

// podFabricAddrs returns the underlay addresses a pod should hold claims for:
// its `status.podIP`s, which for a default-network pod IS the underlay address
// and for a VPC pod is its fabric handle. Nothing for a hostNetwork pod — it
// shares the node's address and claims nothing — nor for one that has not been
// wired yet or has finished.
func podFabricAddrs(pod *corev1.Pod) []string {
	if pod.Spec.HostNetwork {
		return nil
	}
	switch pod.Status.Phase {
	case corev1.PodSucceeded, corev1.PodFailed:
		return nil // no sandbox left to be reachable
	}
	var out []string
	for _, pi := range pod.Status.PodIPs {
		if pi.IP != "" {
			out = append(out, pi.IP)
		}
	}
	if len(out) == 0 && pod.Status.PodIP != "" {
		out = append(out, pod.Status.PodIP) // older kubelets fill only the scalar
	}
	return out
}
