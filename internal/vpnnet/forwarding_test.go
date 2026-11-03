package vpnnet

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureProcSysLeavesMatchingValueUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "forwarding")
	if err := os.WriteFile(path, []byte("1\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := ensureFileValue(path, "1"); err != nil {
		t.Fatalf("ensureFileValue() rewrote an already matching read-only value: %v", err)
	}
}
