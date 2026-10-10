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
	"context"
	"fmt"
	"math"
	"net"
	"testing"
)

func TestRebuildRejectsReservedNetworkBitsAndForgedFields(t *testing.T) {
	for _, id := range []uint64{1, 99, 1 << 22, 1 << 23, 1 << 24, math.MaxUint32} {
		alias := fmt.Sprintf("%snet=%d;gw=0;fwd=0;mac=02:a1:b2:c3:d4:e5;ips=10.0.0.2", vethAliasPrefix, id)
		if _, _, _, ok := parseVethAlias(alias); ok {
			t.Fatalf("reserved network accepted: %d", id)
		}
	}
	for _, fields := range []string{"net=100;net=101;gw=0;fwd=0", "net=100;gw=0;fwd=0;extra=1", "net=0;gw=1;fwd=0", "net=0;gw=0;fwd=1"} {
		if _, _, _, ok := parseVethAlias(vethAliasPrefix + fields + ";mac=02:a1:b2:c3:d4:e5;ips=10.0.0.2"); ok {
			t.Fatalf("forged alias accepted: %s", fields)
		}
	}
}

func TestAnnouncementRejectsInvalidFDWithoutPolling(t *testing.T) {
	for _, fd := range []int{-1, math.MaxInt32 + 1} {
		if err := watchGuestAnnounceSocket(context.Background(), fd, 1, nil, net.ParseIP("10.0.0.2"), true); err == nil {
			t.Fatalf("invalid descriptor accepted: %d", fd)
		}
	}
}
