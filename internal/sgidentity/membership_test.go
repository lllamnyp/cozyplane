package sgidentity

import (
	"fmt"
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestInvalidLegacyGroupReferenceDoesNotEnterIdentityIndex(t *testing.T) {
	g := &sdn.SecurityGroup{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "group", UID: "group-current"}, Spec: sdn.SecurityGroupSpec{VPCRef: sdn.LocalVPCRef{Name: strings.Repeat("x", 128<<10)}}, Status: sdn.SecurityGroupStatus{ID: 1}}
	if index := NewIndex([]*sdn.SecurityGroup{g}); len(index) != 0 {
		t.Fatal("unusable VPC anchor retained by identity index")
	}
	g.Spec.VPCRef.Name = "net"
	if index := NewIndex([]*sdn.SecurityGroup{g}); index[g.LocalRef()][1] != g.UID {
		t.Fatal("valid group did not recover")
	}
}

func TestMembershipIdentityAndUnion(t *testing.T) {
	ref := sdn.VPCRef{Namespace: "tenant", Name: "net"}
	group := &sdn.SecurityGroup{ObjectMeta: metav1.ObjectMeta{Namespace: ref.Namespace, Name: "group", UID: "current-group"}, Spec: sdn.SecurityGroupSpec{VPCRef: sdn.LocalVPCRef{Name: ref.Name}}, Status: sdn.SecurityGroupStatus{ID: 1}}
	port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{sdn.LabelPodUID: "pod"}}, Spec: sdn.PortSpec{VPCRef: ref}, Status: sdn.PortStatus{Groups: []int32{1}, GroupPodUID: "pod", GroupRefs: []sdn.SecurityGroupMembership{{ID: 1, UID: group.UID}}}}
	for _, mode := range []string{"current", "recycled UID", "changed ID", "pod replaced", "terminating", "duplicate ID", "duplicate proof", "legacy", "wrong VPC", "oversized IDs", "oversized proofs", "union"} {
		t.Run(mode, func(t *testing.T) {
			p, g := port.DeepCopy(), group.DeepCopy()
			groups := []*sdn.SecurityGroup{g}
			want := uint64(1)
			switch mode {
			case "current":
				want = 2
			case "recycled UID":
				g.UID = "replacement-group"
			case "changed ID":
				g.Status.ID = 2
			case "pod replaced":
				p.Labels[sdn.LabelPodUID] = "replacement-pod"
			case "terminating":
				g.DeletionTimestamp = new(metav1.Now())
			case "duplicate ID":
				other := g.DeepCopy()
				other.Name, other.UID = "other", "other-group"
				groups = append(groups, other)
			case "duplicate proof":
				p.Status.GroupRefs = append(p.Status.GroupRefs, p.Status.GroupRefs[0], p.Status.GroupRefs[0])
			case "legacy":
				p.Status.GroupRefs = nil
			case "wrong VPC":
				g.Spec.VPCRef.Name = "other-net"
			case "oversized IDs":
				p.Status.Groups = make([]int32, 64)
			case "oversized proofs":
				p.Status.GroupRefs = make([]sdn.SecurityGroupMembership, 63)
			case "union":
				p.Status.Groups = append(p.Status.Groups, 2)
				p.Status.GroupRefs = append(p.Status.GroupRefs, sdn.SecurityGroupMembership{ID: 2, UID: "obsolete"})
				want = 3
			}
			if got := NewIndex(groups).Bitmap(p); got != want {
				t.Fatalf("membership=%b want=%b", got, want)
			}
		})
	}
	if got := NewIndex([]*sdn.SecurityGroup{group}).Bitmap(&sdn.Port{}); got != 0 {
		t.Fatal("empty membership changed", got)
	}
}

func BenchmarkMembershipProof(b *testing.B) {
	ref := sdn.VPCRef{Namespace: "tenant", Name: "net"}
	index := Index{ref: map[int32]types.UID{}}
	port := &sdn.Port{Spec: sdn.PortSpec{VPCRef: ref}}
	for id := int32(1); id < sdn.MaxSecurityGroupsPerVPC; id++ {
		uid := types.UID(fmt.Sprint("group-", id))
		index[ref][id] = uid
		port.Status.Groups = append(port.Status.Groups, id)
		port.Status.GroupRefs = append(port.Status.GroupRefs, sdn.SecurityGroupMembership{ID: id, UID: uid})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if index.Bitmap(port) != (uint64(1)<<63)-2 {
			b.Fatal("membership proof lost an identity")
		}
	}
}
