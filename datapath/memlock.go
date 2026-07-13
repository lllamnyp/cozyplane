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
	"bufio"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

// MapMemlock reports how many bytes each pinned map charges to the agent's memory
// cgroup, read from the kernel's own accounting (/proc/self/fdinfo/<fd>).
//
// This exists because the agent's memory is mostly NOT its heap. Since Linux 5.11
// a BPF map's memory is charged to the memcg of the process that created it, and
// most of cozyplane's maps are PREALLOCATED at load — the LRU conntrack and
// service tables alone (ct_fwd/ct_rev/svc_fwd/svc_rev, np_ct) run to ~100MB+
// before a single flow exists. The failure mode this produces is genuinely nasty
// to debug: the agent is OOM-killed while its RSS sits at ~10% of the limit,
// because `container_memory_rss` counts anonymous pages and the OOM killer counts
// `container_memory_working_set_bytes`, which includes the kernel charge. Graphing
// RSS tells you nothing is wrong right up until the kill.
//
// So publish the truth: per-map bytes, from the kernel.
func (m *Manager) MapMemlock() (map[string]uint64, error) {
	out := map[string]uint64{}
	v := reflect.ValueOf(m.objs.overlayMaps)
	t := v.Type()
	for i := range t.NumField() {
		mp, ok := v.Field(i).Interface().(*ebpf.Map)
		if !ok || mp == nil {
			continue
		}
		name := t.Field(i).Tag.Get("ebpf")
		if name == "" {
			name = strings.ToLower(t.Field(i).Name)
		}
		b, err := memlockOf(mp.FD())
		if err != nil {
			continue // a map without readable fdinfo tells us nothing; skip it
		}
		out[name] = b
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no map memlock readable")
	}
	return out, nil
}

// memlockOf reads the `memlock:` line the kernel exposes for a BPF map fd.
func memlockOf(fd int) (uint64, error) {
	f, err := os.Open(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		field, val, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.TrimSpace(field) != "memlock" {
			continue
		}
		return strconv.ParseUint(strings.TrimSpace(val), 10, 64)
	}
	return 0, fmt.Errorf("no memlock in fdinfo for fd %d", fd)
}
