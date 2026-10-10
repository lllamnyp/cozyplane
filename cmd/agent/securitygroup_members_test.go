package main

import (
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSGMembersDoNotAdoptRecycledID(t *testing.T) {
	port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: "v100.10-0-0-2", Labels: map[string]string{sdn.LabelPodUID: "pod-uid"}}, Spec: sdn.PortSpec{IP: "10.0.0.2", VPCRef: sdn.VPCRef{Namespace: "tenant", Name: "net"}}, Status: sdn.PortStatus{Groups: []int32{1}}}
	replacement := &sdn.SecurityGroup{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "replacement", UID: "replacement-uid"}, Spec: sdn.SecurityGroupSpec{VPCRef: sdn.LocalVPCRef{Name: "net"}, PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "different"}}}, Status: sdn.SecurityGroupStatus{ID: 1}}
	members := securityGroupMembers([]*sdn.Port{port}, []*sdn.SecurityGroup{replacement})
	if len(members) != 1 || members[0].Groups != 1 {
		t.Fatal("predecessor numeric membership adopted replacement permissions", members)
	}
}

func TestSGMembershipProjectsSandboxOwner(t *testing.T) {
	port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: "v100.10-0-0-2", UID: "port-uid",
		Labels:      map[string]string{sdn.LabelPodUID: "pod-uid"},
		Annotations: map[string]string{sdn.AnnotationContainerID: "sandbox", sdn.AnnotationCNIIfName: "eth0"}},
		Spec: sdn.PortSpec{IP: "10.0.0.2"}, Status: sdn.PortStatus{GroupPodUID: "pod-uid"}}
	members := securityGroupMembers([]*sdn.Port{port}, nil)
	if len(members) != 1 || members[0].Owner != datapath.SGEndpointOwner("port-uid", "sandbox", "eth0") {
		t.Fatal("lost membership sandbox witness", members)
	}
	oldOwner := members[0].Owner
	port.Annotations[sdn.AnnotationContainerID] = "replacement"
	if next := securityGroupMembers([]*sdn.Port{port}, nil); next[0].Owner == oldOwner {
		t.Fatal("persistent Port adopted predecessor sandbox membership")
	}
}

func TestSGMembersWaitForInitialPodIdentityResolution(t *testing.T) {
	port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: "v100.10-0-0-2", Labels: map[string]string{sdn.LabelPodUID: "pod-uid"}}, Spec: sdn.PortSpec{IP: "10.0.0.2", VPCRef: sdn.VPCRef{Namespace: "tenant", Name: "net"}}}
	members := securityGroupMembers([]*sdn.Port{port}, nil)
	if len(members) != 1 || members[0].Groups != 1 {
		t.Fatal("unresolved initial membership projected legacy allow", members)
	}
	port.Status.GroupPodUID = "pod-uid"
	members = securityGroupMembers([]*sdn.Port{port}, nil)
	if len(members) != 1 || members[0].Groups != 0 {
		t.Fatal("resolved unselected membership was not published explicitly", members)
	}
}
