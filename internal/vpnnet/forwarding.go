package vpnnet

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EnsureForwarding enables forwarding when the pod sysctl did not already do
// so. Avoiding a write when the value is already 1 lets a capability-bounded
// appliance run with Kubernetes' read-only /proc/sys mount.
func EnsureForwarding() error {
	if err := ensureProcSys("net/ipv4/ip_forward", "1"); err != nil {
		return fmt.Errorf("enable IPv4 forwarding: %w", err)
	}
	// IPv6 is optional for an IPv4-only appliance/kernel.
	_ = ensureProcSys("net/ipv6/conf/all/forwarding", "1")
	return nil
}

func ensureProcSys(name, want string) error {
	return ensureFileValue(filepath.Join("/proc/sys", name), want)
}

func ensureFileValue(path, want string) error {
	// #nosec G304 -- Production callers supply only the two fixed forwarding sysctl paths above; other paths are test fixtures.
	if current, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(current)) == want {
		return nil
	}
	// #nosec G304 -- Existing fixed forwarding sysctl only, with no create flag; path cannot come from tenant data.
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(want); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
