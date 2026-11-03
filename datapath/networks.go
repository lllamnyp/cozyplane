package datapath

import "fmt"

// Both partitions share one map: preserve the other writer's rows, reject
// collisions and total capacity overflow before pruning the observed snapshot.
func (m *Manager) syncNetworkPartition(desired []PeerNet, own bool) error {
	m.networkMu.Lock()
	defer m.networkMu.Unlock()
	if len(desired) > 65536 {
		return fmt.Errorf("network snapshot exceeds input work budget")
	}
	want := map[overlayLpmKey]uint32{}
	for _, entry := range desired {
		if (entry.Scope == entry.Net) != own {
			return fmt.Errorf("network entry belongs to the other partition")
		}
		if len(entry.CIDR) > 64 {
			return fmt.Errorf("network CIDR exceeds text budget")
		}
		key, err := lpmKey(entry.Scope, entry.CIDR)
		if err != nil {
			return fmt.Errorf("invalid network CIDR")
		}
		if value, exists := want[key]; exists && value != entry.Net {
			return fmt.Errorf("conflicting scoped network destinations")
		}
		if err := putDesired(m.objs.Networks, want, key, entry.Net); err != nil {
			return err
		}
	}
	desiredCount := len(want)
	retained := 0
	var key overlayLpmKey
	var value uint32
	var stale []overlayLpmKey
	it := m.objs.Networks.Iterate()
	for it.Next(&key, &value) {
		if (key.ScopeNet == value) != own {
			retained++
			if _, collision := want[key]; collision {
				return fmt.Errorf("network entry collides with the other partition")
			}
			continue
		}
		if desiredValue, keep := want[key]; !keep {
			stale = append(stale, key)
		} else if desiredValue == value {
			delete(want, key) // unchanged rows need no kernel write
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate networks: %w", err)
	}
	if uint64(desiredCount+retained) > uint64(m.objs.Networks.MaxEntries()) {
		return fmt.Errorf("network partitions exceed shared map capacity")
	}
	for _, key := range stale {
		if err := m.objs.Networks.Delete(key); err != nil && !isNotExist(err) {
			return fmt.Errorf("delete stale network: %w", err)
		}
	}
	for key, value := range want {
		if err := m.objs.Networks.Put(key, value); err != nil {
			return fmt.Errorf("put network entry: %w", err)
		}
	}
	return nil
}
