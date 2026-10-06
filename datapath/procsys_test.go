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

import "testing"

func TestProcSysPathCannotLeaveAllowedNetworkingControls(t *testing.T) {
	for _, name := range []string{"../../tmp/fixture", "/tmp/fixture", "kernel/core_pattern", "net/ipv4/conf/../rp_filter", "net/ipv4/conf/eth0/unknown", "net/ipv6/conf/eth0/proxy_arp"} {
		if _, err := procSysPath(name); err == nil {
			t.Errorf("unexpected writable sysctl %q", name)
		}
	}
	for _, name := range []string{"net/ipv4/ip_forward", "net/ipv4/conf/all/rp_filter", "net/ipv4/conf/eth0.1/proxy_arp", "net/ipv6/conf/all/forwarding", "net/ipv6/conf/eth1/disable_ipv6"} {
		if _, err := procSysPath(name); err != nil {
			t.Errorf("valid networking sysctl %q rejected: %v", name, err)
		}
	}
}
