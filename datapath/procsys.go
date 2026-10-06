/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package datapath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func procSysPath(name string) (string, error) {
	if name == "net/ipv4/ip_forward" {
		return "/proc/sys/net/ipv4/ip_forward", nil
	}
	parts := strings.Split(name, "/")
	if len(parts) != 5 || parts[0] != "net" || parts[2] != "conf" || parts[3] == "" || parts[3] == "." || parts[3] == ".." || len(parts[3]) > 15 {
		return "", fmt.Errorf("unsupported networking sysctl")
	}
	switch parts[1] {
	case "ipv4":
		if parts[4] != "rp_filter" && parts[4] != "proxy_arp" && parts[4] != "forwarding" {
			return "", fmt.Errorf("unsupported IPv4 sysctl")
		}
	case "ipv6":
		if parts[4] != "disable_ipv6" && parts[4] != "forwarding" {
			return "", fmt.Errorf("unsupported IPv6 sysctl")
		}
	default:
		return "", fmt.Errorf("unsupported sysctl address family")
	}
	return filepath.Join("/proc/sys", name), nil
}

// WriteProcSys only writes existing, explicitly allowed networking sysctls.
func WriteProcSys(name, val string) error {
	path, err := procSysPath(name)
	if err != nil {
		return err
	}
	if val != "0" && val != "1" {
		return fmt.Errorf("unsupported networking sysctl value")
	}
	// #nosec G304 -- procSysPath validates the family/key/interface whitelist before access; no creation or traversal is allowed.
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(val); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
