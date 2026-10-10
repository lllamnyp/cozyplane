/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/lllamnyp/cozyplane/internal/ipam"
	"hash/fnv"
	"net"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	localclientset "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned"
)

// Underlay IPAM (docs/api-groups.md). The address is claimed by CREATING a
// FabricIP whose name is the address: the API server's name uniqueness is the
// lock, so the claim is atomic cluster-wide with no per-node range, no file
// store, and no possibility of double-allocation.
//
// This replaces the `host-local` plugin, whose on-disk reservations are
// released only by a CNI DEL — so a pod that vanishes while kubelet is down
// leaks its address across the reboot, invisibly and forever. A FabricIP is an
// object: the controller reaps it when its pod is gone.

// Pod UID labels narrow lookups; only the sandbox identity authorizes DEL.
const (
	labelFabricPodUID = localv1alpha1.LabelFabricPodUID
	labelFabricPodNS  = localv1alpha1.LabelFabricPodNamespace
	labelFabricNode   = localv1alpha1.LabelFabricNode
)

func localClient() (localclientset.Interface, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", datapath.PluginKubeconfig)
	if err != nil {
		return nil, err
	}
	cfg.Timeout = apiRequestTimeout
	return localclientset.NewForConfig(cfg)
}

// poolFor returns the pools to allocate from: the FLAT cluster-wide supernet
// when the agent published one, else this node's slice of it
// (docs/api-groups.md — the slice is the pre-flat fallback).
//
// A node's range is a Flannel-era artifact of file-based IPAM, which can only
// be safe within a range it exclusively owns. A FabricIP claim is atomic
// cluster-wide, so there is nothing left to carve — and nothing to exhaust
// per-node while the cluster has room.
func poolFor(state *datapath.AgentState) []string {
	if len(state.ClusterPodCIDRs) > 0 {
		return state.ClusterPodCIDRs
	}
	if len(state.PodCIDRs) > 0 {
		return state.PodCIDRs
	}
	return []string{state.PodCIDR}
}

// poolOfFamily narrows a pool set to one family — a VPC pod's fabric handle
// follows the VPC's family where the cluster has it.
func poolOfFamily(pools []string, wantV6 bool) []string {
	var out []string
	for _, c := range pools {
		if v6, err := cidrIsV6(c); err == nil && v6 == wantV6 {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return pools[:1] // the cluster has no pool of that family; fall back
	}
	return out
}

// claimFabricIPs allocates one address per pool (a v4 and, dual-stack, a v6).
// It walks candidates and lets Create decide: AlreadyExists means someone else
// holds it, so try the next. Nothing is reserved that is not created, so a
// crashed plugin leaks nothing.
type fabricAllocation struct {
	Addresses []net.IP
	Created   []localv1alpha1.FabricIP
}

func claimFabricIPs(ctx context.Context, client localclientset.Interface, cidrs []string, node, podNS, podName, podUID, containerID, ifName string) (*fabricAllocation, error) {
	if podUID == "" || containerID == "" || ifName == "" {
		return nil, fmt.Errorf("fabric allocation requires pod UID, container ID and interface")
	}
	claimed := &fabricAllocation{}
	for _, cidr := range cidrs {
		ip, created, err := claimOne(ctx, client, cidr, node, podNS, podName, podUID, containerID, ifName)
		if err != nil {
			// Roll back whatever we already took for this pod: a half-addressed
			// pod is worse than a failed ADD, and the addresses would leak
			// until the controller's GC noticed.
			cctx, ccancel := cleanupContext(ctx)
			cleanupErr := releaseFabricClaims(cctx, client, claimed.Created, nil)
			ccancel()
			return nil, errors.Join(err, cleanupErr)
		}
		claimed.Addresses = append(claimed.Addresses, ip)
		if created != nil {
			claimed.Created = append(claimed.Created, *created)
		}
	}
	if len(claimed.Addresses) == 0 {
		return nil, fmt.Errorf("no pod CIDR to allocate from")
	}
	return claimed, nil
}

func claimOne(ctx context.Context, client localclientset.Interface, cidr, node, podNS, podName, podUID, containerID, ifName string) (net.IP, *localv1alpha1.FabricIP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, fmt.Errorf("parse pod CIDR %q: %w", cidr, err)
	}
	claims, err := sandboxFabricClaims(ctx, client, labelFabricPodUID+"="+podUID, podUID, containerID, ifName)
	if err != nil {
		return nil, nil, fmt.Errorf("list sandbox fabric claims: %w", err)
	}
	var existing net.IP
	for i := range claims {
		claim := &claims[i]
		ip := net.ParseIP(claim.Spec.Address)
		if ip == nil || !ipnet.Contains(ip) {
			continue
		}
		if isReserved(ipnet, ip) {
			return nil, nil, fmt.Errorf("sandbox fabric claim uses reserved address %s", ip)
		}
		if !claim.DeletionTimestamp.IsZero() || claim.Spec.Node != node || claim.Spec.PodNamespace != podNS || claim.Spec.PodName != podName || claim.Name != localv1alpha1.FabricIPName(ip.String()) {
			return nil, nil, fmt.Errorf("sandbox fabric claim has inconsistent ownership")
		}
		if existing != nil && !existing.Equal(ip) {
			return nil, nil, fmt.Errorf("sandbox holds multiple addresses in pool %s", cidr)
		}
		existing = ip
	}
	if existing != nil {
		return existing, nil, nil
	}

	// Where to start walking. A flat pool is large (a /16 is 65k addresses) and
	// every node allocates from all of it, so a linear walk from the bottom
	// would make every node race for the same low addresses and burn a Create
	// conflict per contender. Start at an offset derived from the pod's UID:
	// spread by construction, no coordination, and still a plain walk — so the
	// pool is fully used, not merely sampled.
	ones, bits := ipnet.Mask.Size()
	// span saturates: a v6 /56 has 2^72 addresses, which does not fit a uint64
	// (and does not need to — we only ever walk a bounded number of candidates).
	span := ^uint64(0)
	if shift := uint(bits - ones); shift < 64 {
		span = uint64(1) << shift
	}
	start := uint64(2)
	if span > 4 {
		h := fnv.New64a()
		_, _ = h.Write([]byte(podUID))
		// Skip the network address and the node-gateway convention (.0/.1).
		start = 2 + h.Sum64()%(span-2)
	}

	// Bound the walk. In a healthy pool the first candidate wins; a long run of
	// conflicts means the pool is full or something is badly wrong, and hammering
	// the API server for 65k Creates is not how we should find that out.
	maxTries := uint64(256)
	if span < maxTries {
		maxTries = span
	}

	candidate := addOffset(ipnet.IP, start)
	for tried := uint64(0); tried < maxTries; tried++ {
		if !ipnet.Contains(candidate) {
			candidate = addOffset(ipnet.IP, 2) // wrapped past the end: restart low
			continue
		}
		if isReserved(ipnet, candidate) {
			candidate = nextIP(candidate)
			continue
		}
		fip := &localv1alpha1.FabricIP{
			ObjectMeta: metav1.ObjectMeta{
				Name: localv1alpha1.FabricIPName(candidate.String()),
				Labels: map[string]string{
					labelFabricPodUID: podUID,
					labelFabricPodNS:  podNS,
					labelFabricNode:   node,
				},
			},
			Spec: localv1alpha1.FabricIPSpec{
				Address:      candidate.String(),
				Node:         node,
				PodNamespace: podNS,
				PodName:      podName,
				PodUID:       podUID,
				ContainerID:  containerID,
				IfName:       ifName,
			},
		}
		created, err := client.LocalV1alpha1().FabricIPs().Create(ctx, fip, metav1.CreateOptions{})
		if err == nil {
			return candidate, created, nil
		}
		if !apierrors.IsAlreadyExists(err) {
			return nil, nil, fmt.Errorf("claim fabric IP %s: %w", candidate, err)
		}
		// Another concurrent retry may have created this sandbox's claim since
		// the initial List. Reuse it instead of advancing to a second address.
		held, err := client.LocalV1alpha1().FabricIPs().Get(ctx, fip.Name, metav1.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, nil, err
		}
		if err == nil && held.DeletionTimestamp.IsZero() && ownsFabricSandbox(held, podUID, containerID, ifName) && held.Spec.Node == node && held.Spec.PodNamespace == podNS && held.Spec.PodName == podName && held.Spec.Address == candidate.String() {
			return candidate, nil, nil
		}
		candidate = nextIP(candidate)
	}
	return nil, nil, fmt.Errorf("pod pool %s: no free address found in %d attempts (pool full, or claims are leaking)", cidr, maxTries)
}

// isReserved keeps the network address and the .1 gateway convention out of the
// pool.
func isReserved(ipnet *net.IPNet, ip net.IP) bool {
	return ipam.IsPoolReserved(ipnet, ip)
}

// addOffset returns base + n (big-endian, both families).
func addOffset(base net.IP, n uint64) net.IP {
	out := make(net.IP, len(base))
	copy(out, base)
	for i := len(out) - 1; i >= 0 && n > 0; i-- {
		sum := uint64(out[i]) + n&0xff
		out[i] = byte(sum & 0xff)
		n >>= 8
		n += sum >> 8
	}
	return out
}

func ownsFabricSandbox(claim *localv1alpha1.FabricIP, podUID, containerID, ifName string) bool {
	return containerID != "" && ifName != "" && (podUID == "" || claim.Spec.PodUID == podUID) && claim.Spec.ContainerID == containerID && claim.Spec.IfName == ifName
}

// DEL never touches an unidentified legacy claim or another sandbox of this Pod.
func releaseFabricIPs(ctx context.Context, client localclientset.Interface, podUID, containerID, ifName string, delBridge func(string) error) error {
	if containerID == "" || ifName == "" {
		return nil
	}
	selector := ""
	if podUID != "" {
		selector = labelFabricPodUID + "=" + podUID
	}
	owned, err := sandboxFabricClaims(ctx, client, selector, podUID, containerID, ifName)
	if err != nil {
		return err
	}
	return releaseFabricClaims(ctx, client, owned, delBridge)
}

// Retain only owned claims, and never publish ownership from a partial list.
// A UID-less DEL still needs to scan the cluster, but one response cannot copy
// every unrelated FabricIP into the short-lived CNI process.
func sandboxFabricClaims(ctx context.Context, client localclientset.Interface, selector, podUID, containerID, ifName string) ([]localv1alpha1.FabricIP, error) {
	var owned []localv1alpha1.FabricIP
	err := ipam.WalkClaims(ctx, func(limit int64, token string) ([]localv1alpha1.FabricIP, string, error) {
		list, err := client.LocalV1alpha1().FabricIPs().List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: limit, Continue: token})
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	}, func(claim *localv1alpha1.FabricIP) {
		if ownsFabricSandbox(claim, podUID, containerID, ifName) {
			owned = append(owned, *claim)
		}
	})
	if err != nil {
		return nil, err
	}
	return owned, nil
}

func releaseFabricClaims(ctx context.Context, client localclientset.Interface, claims []localv1alpha1.FabricIP, delBridge func(string) error) error {
	var errs []error
	for i := range claims {
		claim := &claims[i]
		current, err := client.LocalV1alpha1().FabricIPs().Get(ctx, claim.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if current.UID != claim.UID || current.ResourceVersion != claim.ResourceVersion || current.Spec != claim.Spec {
			continue
		}
		if delBridge != nil {
			if err := delBridge(claim.Spec.Address); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		err = client.LocalV1alpha1().FabricIPs().Delete(ctx, claim.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &claim.UID, ResourceVersion: &claim.ResourceVersion}})
		if err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
