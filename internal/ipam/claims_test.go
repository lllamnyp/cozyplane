package ipam

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestClaimScanBudgetsAndCancellation(t *testing.T) {
	for _, mode := range []string{"complete", "object budget", "empty page budget", "cancelled page", "API error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			pages, visited := 0, 0
			err := WalkClaims(ctx, func(limit int64, token string) ([]int, string, error) {
				if limit != ClaimPageSize || token != "" && token != fmt.Sprint(pages) {
					t.Fatal("incorrect page request", limit, token)
				}
				pages++
				if mode == "API error" {
					return nil, "", errors.New("API unavailable")
				}
				if mode == "cancelled page" {
					cancel()
				}
				items := make([]int, ClaimPageSize)
				if mode == "empty page budget" {
					items = nil
				}
				if mode == "complete" && pages == maxClaimPages {
					return items, "", nil
				}
				return items, fmt.Sprint(pages), nil
			}, func(*int) { visited++ })
			if mode == "complete" {
				if err != nil || visited != MaxClaimScan || pages != maxClaimPages {
					t.Fatal("complete scan failed", visited, pages, err)
				}
			} else if err == nil || pages > maxClaimPages || visited > MaxClaimScan {
				t.Fatal("scan escaped budget", visited, pages, err)
			}
			if (mode == "cancelled page" || mode == "API error") && (visited != 0 || pages != 1) {
				t.Fatal("incomplete page was consumed", visited, pages, err)
			}
			if mode == "cancelled page" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation cause lost", err)
			}
		})
	}
}
