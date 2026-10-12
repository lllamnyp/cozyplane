package main

import "crypto/sha256"

const maxCompileWarnings = 512

// Deduplication keeps only the current snapshot and stores hashes rather than
// arbitrary warning strings. Caller serializes compilations.
type compileWarnings map[[32]byte]struct{}

func (previous *compileWarnings) update(warnings []string) ([]string, bool) {
	next := make(compileWarnings)
	var fresh []string
	truncated := len(warnings) > maxCompileWarnings
	for _, warning := range warnings {
		key := sha256.Sum256([]byte(warning))
		if _, exists := next[key]; exists {
			continue
		}
		if len(next) >= maxCompileWarnings {
			truncated = true
			break
		}
		next[key] = struct{}{}
		if _, exists := (*previous)[key]; !exists {
			fresh = append(fresh, warning)
		}
	}
	*previous = next
	return fresh, truncated
}

// Bound warning strings during compilation itself, before log deduplication.
func addCompileWarnings(warnings *[]string, values ...string) {
	room := maxCompileWarnings + 1 - len(*warnings)
	if room <= 0 {
		return
	}
	if len(values) > room {
		values = values[:room]
	}
	*warnings = append(*warnings, values...)
}
