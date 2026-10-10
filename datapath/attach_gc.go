package datapath

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/link"
)

func ownedTCXPin(name string) bool {
	index, ok := strings.CutPrefix(name, "in-")
	if !ok {
		index, ok = strings.CutPrefix(name, "eg-")
	}
	if !ok {
		return false
	}
	for _, suffix := range []string{"-guard-swap", "-guard", "-swap"} {
		if value, found := strings.CutSuffix(index, suffix); found {
			index = value
			break
		}
	}
	value, err := strconv.ParseUint(index, 10, 32)
	return err == nil && value != 0
}

// Interface deletion leaves TCX pins alive even though the kernel detaches the
// link. Stream the directory instead of retaining a history of retired veths.
func pruneDetachedTCXPins() (int, error) {
	dir, err := os.Open(filepath.Join(PinRoot, "links"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer dir.Close()
	removed := 0
	for {
		entries, readErr := dir.ReadDir(128)
		for _, entry := range entries {
			if entry.IsDir() || !ownedTCXPin(entry.Name()) {
				continue
			}
			pin := filepath.Join(PinRoot, "links", entry.Name())
			if err := withBridgeLock(func() error {
				pinned, err := link.LoadPinnedLink(pin, nil)
				if errors.Is(err, os.ErrNotExist) {
					return nil
				}
				if err != nil {
					return err
				}
				defer pinned.Close()
				info, err := pinned.Info()
				if err != nil {
					return err
				}
				if info.TCX() == nil || info.TCX().Ifindex != 0 {
					return nil // active or foreign link: absence of an alias proves nothing
				}
				if err := pinned.Unpin(); err != nil {
					return err
				}
				removed++
				return nil
			}); err != nil {
				return removed, fmt.Errorf("reap detached tcx pin %s: %w", entry.Name(), err)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return removed, nil
		}
		if readErr != nil {
			return removed, readErr
		}
	}
}
