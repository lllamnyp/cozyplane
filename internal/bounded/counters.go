// Package bounded limits retained metric cardinality over a process lifetime.
package bounded

// Increment preserves detailed existing series, while aggregating new keys
// beyond the limit into one stable overflow series. Caller provides locking.
func Increment[K comparable](counters map[K]uint64, key, overflow K, limit int) {
	if _, exists := counters[key]; !exists && len(counters) >= limit {
		key = overflow
	}
	counters[key]++
}
