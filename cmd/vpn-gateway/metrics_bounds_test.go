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

package main

import (
	"math"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestWireGuardNegativeCountersAreNotPublished(t *testing.T) {
	now := time.Unix(1700000000, 0)
	for _, count := range []int64{-1, math.MinInt64} {
		for _, rx := range []bool{false, true} {
			p := wgtypes.Peer{}
			if rx {
				p.ReceiveBytes = count
			} else {
				p.TransmitBytes = count
			}
			got := wireGuardSnapshot(&wgtypes.Device{Peers: []wgtypes.Peer{p}}, nil, now)
			if len(got.Connections) != 0 {
				t.Errorf("negative counter %d rx=%v published: %+v", count, rx, got.Connections)
			}
		}
	}
}
