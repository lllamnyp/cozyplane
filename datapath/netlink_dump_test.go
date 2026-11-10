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
	"errors"
	"fmt"
	"testing"

	"github.com/vishvananda/netlink"
)

// An interrupted dump is rerun; any other result, error or not, is final.
func TestRetryDump(t *testing.T) {
	calls := 0
	got, err := retryDump(func() (int, error) {
		calls++
		if calls < 3 {
			return -1, netlink.ErrDumpInterrupted
		}
		return 7, nil
	})
	if got != 7 || err != nil || calls != 3 {
		t.Errorf("got %d, %v after %d calls, want 7, nil after 3", got, err, calls)
	}

	calls = 0
	other := errors.New("boom")
	if _, err := retryDump(func() (int, error) { calls++; return 0, other }); !errors.Is(err, other) || calls != 1 {
		t.Errorf("got %v after %d calls, want boom after 1", err, calls)
	}

	calls = 0
	_, err = retryDump(func() (int, error) { calls++; return 0, fmt.Errorf("dump: %w", netlink.ErrDumpInterrupted) })
	if !errors.Is(err, netlink.ErrDumpInterrupted) || calls != dumpAttempts {
		t.Errorf("got %v after %d calls, want ErrDumpInterrupted after %d", err, calls, dumpAttempts)
	}
}
