package main

import (
	"fmt"
	"testing"
)

func TestCompileWarningsBoundAndForgetObsoleteSnapshots(t *testing.T) {
	var cache compileWarnings
	for epoch := 0; epoch < 20; epoch++ {
		var warnings []string
		for i := 0; i < 1000; i++ {
			warnings = append(warnings, fmt.Sprintf("policy-%d-%d", epoch, i))
		}
		fresh, truncated := cache.update(warnings)
		if !truncated || len(cache) != 512 || len(fresh) != 512 {
			t.Fatal("warning cache grew or lost truncation", len(cache), len(fresh), truncated)
		}
		fresh, truncated = cache.update(warnings)
		if !truncated || len(fresh) != 0 {
			t.Fatal("same snapshot logged again")
		}
	}
	cache.update(nil)
	if len(cache) != 0 {
		t.Fatal("deleted policies retained warnings")
	}
	fresh, truncated := cache.update([]string{"recreated", "recreated"})
	if truncated || len(fresh) != 1 || len(cache) != 1 {
		t.Fatal("recreated warning missing or duplicated")
	}
}
