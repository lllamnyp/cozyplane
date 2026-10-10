package main

import (
	"sort"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

type routeInput struct {
	ref    sdn.VPCRef
	routes []sdn.VPCGatewayRouteStatus
}

type routeNamespace struct {
	demand  uint64
	invalid bool
	scopes  map[uint32]struct{}
	inputs  []routeInput
}

// routeBudgets is max-min fair per owner namespace. Small demands are served
// first; namespace order deterministically distributes indivisible leftovers.
// Callers omit an entire over-budget namespace rather than truncate its routes.
func routeBudgets(groups map[string]*routeNamespace, capacity uint64) map[string]uint64 {
	names := make([]string, 0, len(groups))
	for name, group := range groups {
		if group.demand != 0 && !group.invalid {
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := groups[names[i]].demand, groups[names[j]].demand
		if a != b {
			return a < b
		}
		return names[i] < names[j]
	})
	out := make(map[string]uint64, len(names))
	for i, name := range names {
		remaining := uint64(len(names) - i)
		share := capacity / remaining
		if capacity%remaining != 0 {
			share++
		}
		budget := min(groups[name].demand, share)
		out[name] = budget
		capacity -= budget
	}
	return out
}
