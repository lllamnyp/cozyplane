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
	if current, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(current)) == want {
		return nil
	}
	return os.WriteFile(path, []byte(want), 0o644)
}
