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
	"encoding/binary"
	"fmt"
	"net"
)

// Live-migration forwarding (docs/live-migration.md, stage 2): when a VM moves,
// its former (source) node re-encapsulates traffic for the VM's VPC IP to the
// new node during the brief window in which remote nodes' `remotes` entries
// still point at the source. The source agent installs the entry at cutover and
// removes it once the window has passed.

// SetMigrateFwd forwards (net, vmIP) to targetNodeIP from this node's overlay
// hook — the cutover propagation-window safety net.
func (m *Manager) SetMigrateFwd(net_ uint32, vmIP net.IP, targetNodeIP net.IP) error {
	key, err := localKey(net_, vmIP)
	if err != nil {
		return err
	}
	ip4 := targetNodeIP.To4()
	if ip4 == nil {
		return fmt.Errorf("migrate target node IP %q is not IPv4", targetNodeIP)
	}
	// Host byte order, matching remotes (consumed by bpf_skb_set_tunnel_key).
	if err := m.objs.MigrateFwd.Put(&key, binary.BigEndian.Uint32(ip4)); err != nil {
		return fmt.Errorf("set migrate_fwd: %w", err)
	}
	return nil
}

// DelMigrateFwd removes the forward for (net, vmIP) (idempotent).
func (m *Manager) DelMigrateFwd(net_ uint32, vmIP net.IP) error {
	key, err := localKey(net_, vmIP)
	if err != nil {
		return err
	}
	if err := m.objs.MigrateFwd.Delete(&key); err != nil && !isNotExist(err) {
		return fmt.Errorf("del migrate_fwd: %w", err)
	}
	return nil
}
