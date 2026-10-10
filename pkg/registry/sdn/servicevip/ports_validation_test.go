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

package servicevip

import (
	"context"
	"math"
	"strconv"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestServiceVIPPortsAreBounded(t *testing.T) {
	s := NewStrategy(nil)
	for _, protocol := range []string{"TCP", "UDP", "", "ICMP"} {
		for _, port := range []int32{-1, 0, 1, 65535, 65536, math.MaxInt32} {
			t.Run(protocol+"/"+strconv.FormatInt(int64(port), 10), func(t *testing.T) {
				vip := &sdn.ServiceVIP{ObjectMeta: metav1.ObjectMeta{Name: sdn.ServiceVIPName(100, "10.0.0.2")}, Spec: sdn.ServiceVIPSpec{IP: "10.0.0.2", Ports: []sdn.VIPPort{{Protocol: protocol, Port: port}}}}
				valid := (protocol == "TCP" || protocol == "UDP") && port >= 1 && port <= 65535
				if errs := s.Validate(context.Background(), vip); (len(errs) == 0) != valid {
					t.Fatalf("create errors %v, valid %v", errs, valid)
				}
				if errs := s.ValidateUpdate(context.Background(), vip, vip.DeepCopy()); (len(errs) == 0) != valid {
					t.Fatalf("update errors %v, valid %v", errs, valid)
				}
				for _, target := range []bool{false, true} {
					backend := sdn.VIPBackendPort{Protocol: protocol, Port: 80, TargetPort: 80}
					if target {
						backend.TargetPort = port
					} else {
						backend.Port = port
					}
					vip.Status.Backends = []sdn.VIPBackend{{IP: "10.0.0.3", Ports: []sdn.VIPBackendPort{backend}}}
					if errs := NewStatusStrategy(s).ValidateUpdate(context.Background(), vip, vip.DeepCopy()); (len(errs) == 0) != valid {
						t.Fatalf("status target=%v errors %v, valid %v", target, errs, valid)
					}
				}
			})
		}
	}
}
