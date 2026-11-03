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

// Package netid bounds identifiers before they enter the datapath ABI.
package netid

const (
	FirstVNI int32 = 100
	// Geneve bits 22 and 23 carry forward/gateway flags, not tenant IDs.
	LastVNI   int32 = (1 << 22) - 1
	LastGroup int32 = 62 // 63 is the World pseudo-group.
)

func ValidVNI(v int32) bool   { return v >= FirstVNI && v <= LastVNI }
func ValidGroup(v int32) bool { return v >= 1 && v <= LastGroup }

// VNI returns zero for invalid identifiers. Consumers must treat it as pending.
func VNI(v int32) uint32 {
	if v < FirstVNI || v > LastVNI {
		return 0
	}
	return uint32(v)
}

func Group(v int32) uint16 {
	if v < 1 || v > LastGroup {
		return 0
	}
	return uint16(v)
}
