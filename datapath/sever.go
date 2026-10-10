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

package datapath

import (
	"fmt"
	"net"
	"sync"

	"github.com/vishvananda/netlink"
)

var localGrantMu sync.Mutex

// SeverLocal cuts a still-running local pod off its VPC, used when the pod's
// Port is reaped (e.g. its VPCBinding was revoked) rather than the pod being
// deleted. It keeps the pod and its veth/hooks in place but:
//
//   - reassigns the ports-map entry to QuarantineNet, so from_pod (egress) and
//     to_pod (ingress) drop all of the pod's traffic via the isolation check;
//   - removes the locals entry, so same-node peers stop redirecting to it;
//   - tears down the fabric<->vpc bridge, so north-south via the fabric IP stops.
//
// Cross-node reachability is already removed by the other nodes' agents deleting
// the remote /32 when the Port disappears. It returns false if there is no local
// entry for vpcIP (nothing to sever — e.g. the pod is on another node or was
// already cleaned up by CNI DEL).
//
// Re-granting access requires the pod to be recreated; SeverLocal does not
// reverse on its own.
func SeverLocal(net_ uint32, vpcIP net.IP, fabricIP string) (bool, error) {
	ifindex, _, found, err := GetLocal(net_, vpcIP)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return false, fmt.Errorf("find revoked link: %w", err)
	}
	return SeverVethIfOwned(net_, vpcIP, ifindex, link.Attrs().Alias, fabricIP)
}

// SeverVethIfOwned also drains staged endpoints, which have no locals entry.
// The captured alias is checked under the shared writer lock before revocation.
func SeverVethIfOwned(net_ uint32, vpcIP net.IP, ifindex int, expectedAlias, fabricIP string) (bool, error) {
	localGrantMu.Lock()
	defer localGrantMu.Unlock()
	var link netlink.Link
	var ownedIPs []net.IP
	owned := false
	err := withBridgeLock(func() error {
		var err error
		link, err = netlink.LinkByIndex(ifindex)
		if err != nil {
			return err
		}
		if link.Type() != "veth" || link.Attrs().Alias != expectedAlias {
			return nil
		}
		_, ownedIPs, _, _ = parseVethAlias(expectedAlias)
		if err := setVethAlias(link, QuarantineNet, nil, nil); err != nil {
			_ = setPortNet(ifindex, QuarantineNet)
			return err
		}
		if err := setPortNet(ifindex, QuarantineNet); err != nil {
			return err
		}
		owned = true
		return nil
	})
	if err != nil || !owned {
		return false, err
	}
	// A persistent Port may already describe a migration target while locals
	// still resolves to the source. The actual veth route owns the bridge.
	if address, err := fabricRouteIP(link); err != nil {
		return false, fmt.Errorf("resolve revoked bridge: %w", err)
	} else if address != "" {
		fabricIP = address
	}
	// The rebuild record must be revoked before acknowledging deletion. Pinned
	// maps can be recreated on upgrade; a map-only quarantine is not durable.
	if fabricIP != "" {
		if err := DelBridge(fabricIP, link.Attrs().Name); err != nil {
			return false, fmt.Errorf("remove revoked bridge: %w", err)
		}
	}
	// Keep the lookup until every other cleanup step succeeds, so a retry
	// can still locate the quarantined link after a partial failure.
	if err := DelLocalIfOwned(net_, vpcIP, map[int]bool{ifindex: true}); err != nil {
		return false, fmt.Errorf("remove local: %w", err)
	}
	for _, ip := range ownedIPs {
		if ip.Equal(vpcIP) {
			continue
		}
		if err := DelLocalIfOwned(net_, ip, map[int]bool{ifindex: true}); err != nil {
			return false, fmt.Errorf("remove additional local: %w", err)
		}
	}
	return true, nil
}
