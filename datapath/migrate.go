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
	"time"
)

// Live-migration forwarding (docs/live-migration.md, stage 2): when a VM moves,
// its former (source) node re-encapsulates traffic for the VM's VPC IP to the
// new node during the brief window in which remote nodes' `remotes` entries
// still point at the source. The source agent installs the entry at cutover and
// removes it once the window has passed.

type migrateForwardOwner struct {
	target    uint32
	installed time.Time
}

// InstallMigrateFwd returns a cleanup lease for this installation only. A timer
// from an older move cannot remove a replacement, even with the same target.
func (m *Manager) InstallMigrateFwd(net_ uint32, vmIP net.IP, targetNodeIP net.IP) (func() error, error) {
	key, err := localKey(net_, vmIP)
	if err != nil {
		return nil, err
	}
	ip4 := targetNodeIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("migrate target node IP %q is not IPv4", targetNodeIP)
	}
	m.migrateMu.Lock()
	defer m.migrateMu.Unlock()
	if m.migrateOwners[key] == nil && uint64(len(m.migrateOwners)) >= uint64(m.objs.MigrateFwd.MaxEntries()) {
		return nil, fmt.Errorf("migration forwarding ownership capacity exhausted")
	}
	owner := &migrateForwardOwner{target: binary.BigEndian.Uint32(ip4), installed: time.Now()}
	// Host byte order, matching remotes (consumed by bpf_skb_set_tunnel_key).
	if err := m.objs.MigrateFwd.Put(&key, owner.target); err != nil {
		return nil, fmt.Errorf("set migrate_fwd: %w", err)
	}
	if m.migrateOwners == nil {
		m.migrateOwners = map[overlayLocalKey]*migrateForwardOwner{}
	}
	m.migrateOwners[key] = owner
	return func() error {
		m.migrateMu.Lock()
		defer m.migrateMu.Unlock()
		if m.migrateOwners[key] != owner {
			return nil
		}
		return m.delMigrateForward(key)
	}, nil
}

// ExpireMigrateForwards sweeps current installations, not the event history.
// Ownership admission bounds the state to the map's capacity. Holding the
// installation lock also fences expiry against same-key/target replacement.
// Failed deletions retain ownership so the next sweep can retry.
func (m *Manager) ExpireMigrateForwards(now time.Time, grace time.Duration) error {
	m.migrateMu.Lock()
	defer m.migrateMu.Unlock()
	var firstErr error
	for key, owner := range m.migrateOwners {
		if owner.installed.Add(grace).After(now) {
			continue
		}
		if err := m.delMigrateForward(key); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// DelMigrateFwd removes the forward for (net, vmIP) (idempotent).
func (m *Manager) DelMigrateFwd(net_ uint32, vmIP net.IP) error {
	key, err := localKey(net_, vmIP)
	if err != nil {
		return err
	}
	m.migrateMu.Lock()
	defer m.migrateMu.Unlock()
	return m.delMigrateForward(key)
}

func (m *Manager) delMigrateForward(key overlayLocalKey) error {
	if err := m.objs.MigrateFwd.Delete(&key); err != nil && !isNotExist(err) {
		return fmt.Errorf("del migrate_fwd: %w", err)
	}
	delete(m.migrateOwners, key)
	return nil
}

func (m *Manager) clearMigrateForwards() error {
	m.migrateMu.Lock()
	defer m.migrateMu.Unlock()
	if err := syncMap(m.objs.MigrateFwd, map[overlayLocalKey]uint32{}); err != nil {
		return err
	}
	m.migrateOwners = nil
	return nil
}
