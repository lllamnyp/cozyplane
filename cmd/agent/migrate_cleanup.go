package main

import (
	"context"
	"net"
)

type migrationForwardInstaller interface {
	InstallMigrateFwd(uint32, net.IP, net.IP) (func() error, error)
}

// installMigrationForward is the source-forward installation path used by
// current Port move-away events.
func installMigrationForward(ctx context.Context, mgr migrationForwardInstaller, netID uint32, vmIP, nodeIP net.IP) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// The existing agent reconciliation ticker sweeps the current map owners.
	// Do not retain this event in a separate cleanup goroutine/timer.
	_, err := mgr.InstallMigrateFwd(netID, vmIP, nodeIP)
	return err
}
