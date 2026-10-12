package boundaryidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
)

// PrimaryPort names the immutable identity programmed into the primary map.
type PrimaryPort struct{ UID, IP string }

// Digest is independent of informer list order and never empty, including an
// empty primary set. An absent field from an older agent cannot acknowledge it.
func Digest(ports []PrimaryPort) string {
	ordered := slices.Clone(ports)
	slices.SortFunc(ordered, func(a, b PrimaryPort) int {
		if a.UID < b.UID {
			return -1
		}
		if a.UID > b.UID {
			return 1
		}
		if a.IP < b.IP {
			return -1
		}
		if a.IP > b.IP {
			return 1
		}
		return 0
	})
	if ordered == nil {
		ordered = []PrimaryPort{}
	}
	raw, _ := json.Marshal(ordered)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
