package main

import (
	"reflect"
	"testing"
)

func TestRouteBudgetsFairAndBounded(t *testing.T) {
	for _, tc := range []struct {
		name         string
		capacity     uint64
		demand, want map[string]uint64
	}{
		{"ample", 9, map[string]uint64{"tenant-a": 6, "tenant-b": 1}, map[string]uint64{"tenant-a": 6, "tenant-b": 1}},
		{"small-tenant", 1, map[string]uint64{"tenant-a": 2, "tenant-b": 1}, map[string]uint64{"tenant-a": 0, "tenant-b": 1}},
		{"max-min", 7, map[string]uint64{"tenant-a": 1, "tenant-b": 2, "tenant-c": 8}, map[string]uint64{"tenant-a": 1, "tenant-b": 2, "tenant-c": 4}},
		{"ties", 3, map[string]uint64{"tenant-a": 2, "tenant-b": 2}, map[string]uint64{"tenant-a": 2, "tenant-b": 1}},
		{"zero", 0, map[string]uint64{"tenant-a": 1}, map[string]uint64{"tenant-a": 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			groups := map[string]*routeNamespace{}
			for name, demand := range tc.demand {
				groups[name] = &routeNamespace{demand: demand}
			}
			groups["invalid"] = &routeNamespace{demand: 100, invalid: true}
			groups["empty"] = &routeNamespace{}
			for i := 0; i < 100; i++ {
				if got := routeBudgets(groups, tc.capacity); !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("budgets=%v want=%v", got, tc.want)
				}
			}
		})
	}
}
