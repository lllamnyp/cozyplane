// Package sgidentity proves wire membership against current group identities.
package sgidentity

import (
	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	"k8s.io/apimachinery/pkg/types"
)

type Index map[sdn.VPCRef]map[int32]types.UID

// NewIndex is built once per complete, preflight-bounded agent snapshot.
func NewIndex(groups []*sdn.SecurityGroup) Index {
	index := Index{}
	for _, group := range groups {
		index.Add(group)
	}
	return index
}

func (index Index) Add(group *sdn.SecurityGroup) {
	if group == nil || !group.DeletionTimestamp.IsZero() || group.Status.ID <= 0 || group.Status.ID >= sdn.MaxSecurityGroupsPerVPC {
		return
	}
	if !vpnlimits.NamespaceName(group.Namespace) || !vpnlimits.ObjectName(group.Spec.VPCRef.Name) {
		return
	}
	ref := group.LocalRef()
	if index[ref] == nil {
		index[ref] = map[int32]types.UID{}
	}
	if _, duplicate := index[ref][group.Status.ID]; duplicate {
		index[ref][group.Status.ID] = "" // ambiguous wire identity grants nothing
	} else {
		index[ref][group.Status.ID] = group.UID
	}
}

// Bitmap retains bit zero for every unresolved membership. It never allocates
// a per-Port reference map or rescans the group's selector set.
func (index Index) Bitmap(port *sdn.Port) uint64 {
	if port.Status.GroupPodUID != types.UID(port.Labels[sdn.LabelPodUID]) {
		return 1
	}
	if len(port.Status.Groups) == 0 {
		return 0
	}
	if len(port.Status.Groups) > int(sdn.MaxSecurityGroupsPerVPC) || len(port.Status.GroupRefs) >= int(sdn.MaxSecurityGroupsPerVPC) {
		return 1
	}
	var proven, seen uint64
	for _, ref := range port.Status.GroupRefs {
		if ref.ID <= 0 || ref.ID >= sdn.MaxSecurityGroupsPerVPC {
			continue
		}
		bit := uint64(1) << uint(ref.ID)
		if seen&bit != 0 {
			proven &^= bit
			continue
		}
		seen |= bit
		if ref.UID != "" && index[port.Spec.VPCRef][ref.ID] == ref.UID {
			proven |= bit
		}
	}
	var bitmap uint64
	for _, id := range port.Status.Groups {
		if id > 0 && id < sdn.MaxSecurityGroupsPerVPC && proven&(uint64(1)<<uint(id)) != 0 {
			bitmap |= uint64(1) << uint(id)
		} else {
			bitmap |= 1
		}
	}
	return bitmap
}
