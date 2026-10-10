package datapath

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// SyncVPCCounterScopes consumes only a complete current VPC snapshot. It keeps
// current values intact, including terminating VPCs until their object is gone.
func (m *Manager) SyncVPCCounterScopes(scopes []uint32) error {
	if len(scopes) > 65536 {
		return fmt.Errorf("VPC counter snapshot exceeds scope budget")
	}
	current := make(map[uint32]bool, len(scopes))
	for _, scope := range scopes {
		if scope == 0 || scope >= 1<<22 {
			return fmt.Errorf("invalid VPC counter scope")
		}
		current[scope] = true
	}
	m.counterMu.Lock()
	defer m.counterMu.Unlock()
	if m.counterScopes != nil && !m.counterDirty && len(current) == len(m.counterScopes) {
		unchanged := true
		for scope := range current {
			if !m.counterScopes[scope] {
				unchanged = false
				break
			}
		}
		if unchanged {
			return nil // CIDR/status events need no kernel key scan
		}
	}
	maps := []*ebpf.Map{m.objs.VpcCounters, m.objs.SgDrops}
	stale := make([][]uint32, len(maps))
	for i, mp := range maps {
		if mp == nil {
			return fmt.Errorf("VPC counter map unavailable")
		}
		seen := make(map[uint32]bool)
		var previous any // an untyped nil starts kernel key enumeration
		for {
			var key uint32
			if err := mp.NextKey(previous, &key); isNotExist(err) {
				break
			} else if err != nil {
				return fmt.Errorf("enumerate VPC counter scopes: %w", err)
			}
			if seen[key] || uint32(len(seen)) >= mp.MaxEntries() {
				return fmt.Errorf("VPC counter scope enumeration incomplete")
			}
			seen[key] = true
			if !current[key] {
				stale[i] = append(stale[i], key)
			}
			previous = key
		}
	}
	// Both key scans completed before the first mutation. This also excludes
	// late SG compiler seeds for deleted scopes without another worker or timer.
	m.counterScopes = current
	m.counterDirty = true
	for i, mp := range maps {
		for _, scope := range stale[i] {
			if err := mp.Delete(scope); err != nil && !isNotExist(err) {
				return fmt.Errorf("retire VPC counter scope: %w", err)
			}
		}
	}
	m.counterDirty = false
	return nil
}
