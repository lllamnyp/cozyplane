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

	"github.com/vishvananda/netlink"
)

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
func SeverLocal(vpcIP net.IP, fabricIP string) (bool, error) {
	ifindex, _, found, err := GetLocal(vpcIP)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}

	if err := SetPortNet(ifindex, QuarantineNet); err != nil {
		return false, fmt.Errorf("quarantine port: %w", err)
	}
	if err := DelLocal(vpcIP); err != nil {
		return false, fmt.Errorf("remove local: %w", err)
	}
	if fabricIP != "" {
		if link, e := netlink.LinkByIndex(ifindex); e == nil {
			_ = DelBridge(fabricIP, vpcIP.String(), link.Attrs().Name)
		}
	}
	return true, nil
}
