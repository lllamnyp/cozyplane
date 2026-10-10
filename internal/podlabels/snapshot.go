// Package podlabels bounds complete label snapshots stored on Port annotations.
package podlabels

import (
	"encoding/json"
	"errors"
)

const (
	MaxLabels = 4096
	MaxBytes  = 128 * 1024
)

// Encode never truncates labels: losing a key changes selector membership.
// Preflight bounds work before json.Marshal sorts keys or allocates its buffer.
// For valid Kubernetes labels no JSON escaping is needed. A final size check
// also handles unexpected escaped input; its expansion is bounded by preflight.
func Encode(labels map[string]string) (string, error) {
	if len(labels) > MaxLabels {
		return "", errors.New("pod-label snapshot exceeds label count limit")
	}
	if len(labels) == 0 {
		return "", nil
	}
	size := 1 // braces, minus the final entry's omitted comma
	for key, value := range labels {
		// Six bytes account for quotes, colon and a comma, without summing
		// potentially oversized lengths.
		if len(key) > MaxBytes-size-6 || len(value) > MaxBytes-size-6-len(key) {
			return "", errors.New("pod-label snapshot exceeds byte limit")
		}
		size += len(key) + len(value) + 6
	}
	encoded, err := json.Marshal(labels)
	if err != nil {
		return "", err
	}
	if len(encoded) > MaxBytes {
		return "", errors.New("pod-label snapshot exceeds encoded byte limit")
	}
	return string(encoded), nil
}
