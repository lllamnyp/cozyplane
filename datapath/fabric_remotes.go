package datapath

import "fmt"

// PruneFabricRemotes removes net-0 entries absent from the synchronized claim
// list. The agent serializes this with all other fabric-route writers.
func (m *Manager) PruneFabricRemotes(cidrs []string) error {
	want := make(map[overlayLpmKey]bool, len(cidrs))
	for _, cidr := range cidrs {
		key, err := lpmKey(0, cidr)
		if err != nil {
			return err
		}
		want[key] = true
	}
	var key overlayLpmKey
	var value uint32
	var stale []overlayLpmKey
	it := m.objs.Remotes.Iterate()
	for it.Next(&key, &value) {
		if key.ScopeNet == 0 && !want[key] {
			stale = append(stale, key)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate fabric remotes: %w", err)
	}
	for _, key := range stale {
		if err := m.objs.Remotes.Delete(key); err != nil && !isNotExist(err) {
			return err
		}
	}
	return nil
}
