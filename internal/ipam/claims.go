package ipam

import (
	"context"
	"fmt"
)

const (
	ClaimPageSize = 128
	MaxClaimScan  = 65536
	maxClaimPages = MaxClaimScan / ClaimPageSize
)

// WalkClaims requires a complete, bounded live scan before the caller publishes
// an allocation. The visitor must only build temporary occupancy state.
func WalkClaims[T any](ctx context.Context, list func(int64, string) ([]T, string, error), visit func(*T)) error {
	token := ""
	total := 0
	for page := 0; page < maxClaimPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		items, next, err := list(ClaimPageSize, token)
		if err != nil {
			return err
		}
		if len(items) > ClaimPageSize || len(items) > MaxClaimScan-total {
			return fmt.Errorf("IPAM claim scan exceeds page or object budget")
		}
		total += len(items)
		for i := range items {
			if err := ctx.Err(); err != nil {
				return err
			}
			visit(&items[i])
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		if next == token {
			return fmt.Errorf("IPAM claim scan continuation made no progress")
		}
		token = next
	}
	return fmt.Errorf("IPAM claim scan exceeds %d pages", maxClaimPages)
}
