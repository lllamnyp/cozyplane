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

package responder

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

var (
	vpcA = sdnv1alpha1.VPCRef{Namespace: "team-a", Name: "vpc-a"}
	vpcB = sdnv1alpha1.VPCRef{Namespace: "team-b", Name: "vpc-b"}
)

type fakeState struct {
	ports map[string]*sdnv1alpha1.Port // fabric IP -> Port
	svcs  map[string]*corev1.Service   // ns/name -> Service
	eps   map[string][]Endpoint        // ns/name -> endpoints (pre-filtered per VPC in tests via vpcOf)
	vpcOf map[string]sdnv1alpha1.VPCRef
	peers map[sdnv1alpha1.VPCRef][]sdnv1alpha1.VPCRef
}

func (f *fakeState) PortByFabricIP(ip string) *sdnv1alpha1.Port { return f.ports[ip] }
func (f *fakeState) Service(ns, name string) *corev1.Service    { return f.svcs[ns+"/"+name] }
func (f *fakeState) Endpoints(ns, name string, vpc sdnv1alpha1.VPCRef) []Endpoint {
	if f.vpcOf[ns+"/"+name] != vpc {
		return nil // backends belong to another net: structurally invisible
	}
	return append([]Endpoint(nil), f.eps[ns+"/"+name]...)
}
func (f *fakeState) Peers(vpc sdnv1alpha1.VPCRef) []sdnv1alpha1.VPCRef { return f.peers[vpc] }

func headless(ns, name, vpcAnno string, ports ...corev1.ServicePort) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			Annotations: map[string]string{sdnv1alpha1.AnnotationVPC: vpcAnno},
		},
		Spec: corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone, Ports: ports},
	}
}

func testResolver() *Resolver {
	st := &fakeState{
		ports: map[string]*sdnv1alpha1.Port{
			"10.244.1.5": {Spec: sdnv1alpha1.PortSpec{VPCRef: vpcA, IP: "192.168.0.10", FabricIP: "10.244.1.5"}},
		},
		svcs: map[string]*corev1.Service{
			"team-a/etcd": headless("team-a", "etcd", "team-a/vpc-a",
				corev1.ServicePort{Name: "client", Protocol: corev1.ProtocolTCP, Port: 2379}),
			"team-a/plain":  {ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "plain"}, Spec: corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone}},
			"team-b/secret": headless("team-b", "secret", "team-b/vpc-b"),
		},
		eps: map[string][]Endpoint{
			"team-a/etcd": {
				{Hostname: "etcd-0", IP: net.ParseIP("192.168.0.10"), Ready: true},
				{Hostname: "etcd-1", IP: net.ParseIP("192.168.0.11"), Ready: true},
				{Hostname: "etcd-2", IP: net.ParseIP("192.168.0.12"), Ready: false},
			},
			"team-b/secret": {{Hostname: "s-0", IP: net.ParseIP("172.16.0.4"), Ready: true}},
		},
		vpcOf: map[string]sdnv1alpha1.VPCRef{
			"team-a/etcd":   vpcA,
			"team-b/secret": vpcB,
		},
	}
	return &Resolver{Domain: "cluster.local", State: st}
}

type fakeWriter struct {
	dns.ResponseWriter
	remote net.Addr
	msg    *dns.Msg
}

func (w *fakeWriter) RemoteAddr() net.Addr        { return w.remote }
func (w *fakeWriter) WriteMsg(m *dns.Msg) error   { w.msg = m; return nil }
func (w *fakeWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (w *fakeWriter) Write(b []byte) (int, error) { return len(b), nil }

func query(t *testing.T, r *Resolver, from string, name string, qtype uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	w := &fakeWriter{remote: &net.UDPAddr{IP: net.ParseIP(from), Port: 40000}}
	r.ServeDNS(w, req)
	if w.msg == nil {
		t.Fatalf("no reply written for %s", name)
	}
	return w.msg
}

func answers(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		switch a := rr.(type) {
		case *dns.A:
			out = append(out, a.A.String())
		case *dns.AAAA:
			out = append(out, a.AAAA.String())
		case *dns.SRV:
			out = append(out, a.Target)
		}
	}
	return out
}

func TestHeadlessServiceA(t *testing.T) {
	m := query(t, testResolver(), "10.244.1.5", "etcd.team-a.svc.cluster.local", dns.TypeA)
	got := answers(m)
	if len(got) != 2 { // etcd-2 is not ready and must be filtered
		t.Fatalf("want 2 ready A records, got %v", got)
	}
	for _, ip := range got {
		if ip == "10.244.1.5" {
			t.Fatalf("answer leaked a fabric IP: %v", got)
		}
	}
}

func TestPerHostnameRecord(t *testing.T) {
	m := query(t, testResolver(), "10.244.1.5", "etcd-1.etcd.team-a.svc.cluster.local", dns.TypeA)
	got := answers(m)
	if len(got) != 1 || got[0] != "192.168.0.11" {
		t.Fatalf("want [192.168.0.11], got %v", got)
	}
}

func TestUnknownHostnameNXDomain(t *testing.T) {
	m := query(t, testResolver(), "10.244.1.5", "etcd-9.etcd.team-a.svc.cluster.local", dns.TypeA)
	if m.Rcode != dns.RcodeNameError {
		t.Fatalf("want NXDOMAIN, got %v", dns.RcodeToString[m.Rcode])
	}
}

func TestSRV(t *testing.T) {
	m := query(t, testResolver(), "10.244.1.5", "_client._tcp.etcd.team-a.svc.cluster.local", dns.TypeSRV)
	got := answers(m)
	if len(got) != 2 {
		t.Fatalf("want 2 SRV records, got %v", got)
	}
	if got[0] != "etcd-0.etcd.team-a.svc.cluster.local." && got[1] != "etcd-0.etcd.team-a.svc.cluster.local." {
		t.Fatalf("SRV targets wrong: %v", got)
	}
	if len(m.Extra) == 0 {
		t.Fatalf("want additional-section addresses")
	}
}

func TestForeignVPCServiceInvisible(t *testing.T) {
	// vpc-a's pod asks for a service attached to vpc-b: must be NXDOMAIN,
	// indistinguishable from a name that does not exist at all.
	m := query(t, testResolver(), "10.244.1.5", "secret.team-b.svc.cluster.local", dns.TypeA)
	if m.Rcode != dns.RcodeNameError {
		t.Fatalf("want NXDOMAIN for foreign VPC's service, got %v", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 0 {
		t.Fatalf("foreign VPC's records leaked: %v", m.Answer)
	}
}

func TestUnannotatedServiceInvisible(t *testing.T) {
	m := query(t, testResolver(), "10.244.1.5", "plain.team-a.svc.cluster.local", dns.TypeA)
	if m.Rcode != dns.RcodeNameError {
		t.Fatalf("want NXDOMAIN for unannotated service, got %v", dns.RcodeToString[m.Rcode])
	}
}

func TestClusterDomainNeverForwarded(t *testing.T) {
	// kube-system names must be NXDOMAIN (authoritative), not forwarded.
	m := query(t, testResolver(), "10.244.1.5", "kube-dns.kube-system.svc.cluster.local", dns.TypeA)
	if m.Rcode != dns.RcodeNameError {
		t.Fatalf("want NXDOMAIN, got %v", dns.RcodeToString[m.Rcode])
	}
	var haveSOA bool
	for _, rr := range m.Ns {
		if _, ok := rr.(*dns.SOA); ok {
			haveSOA = true
		}
	}
	if !haveSOA {
		t.Fatalf("negative answer must carry the zone SOA")
	}
}

func TestUnknownSourceRefused(t *testing.T) {
	m := query(t, testResolver(), "10.9.9.9", "etcd.team-a.svc.cluster.local", dns.TypeA)
	if m.Rcode != dns.RcodeRefused {
		t.Fatalf("want REFUSED for a non-steered source, got %v", dns.RcodeToString[m.Rcode])
	}
}

func TestExternalNameForwarded(t *testing.T) {
	// No upstreams configured: the forward path must SERVFAIL — anything but
	// an authoritative NXDOMAIN proves the name left the cluster zone.
	m := query(t, testResolver(), "10.244.1.5", "example.com", dns.TypeA)
	if m.Rcode != dns.RcodeServerFailure {
		t.Fatalf("want SERVFAIL (no upstreams), got %v", dns.RcodeToString[m.Rcode])
	}
	if m.Authoritative {
		t.Fatalf("external name must not be answered authoritatively")
	}
}

func TestPeeredVPCServiceResolves(t *testing.T) {
	r := testResolver()
	st := r.State.(*fakeState)
	// vpc-a is actively peered with vpc-b: vpc-b's attached service becomes
	// resolvable from vpc-a, answered with vpc-b's backend VPC IPs.
	st.peers = map[sdnv1alpha1.VPCRef][]sdnv1alpha1.VPCRef{vpcA: {vpcB}}
	m := query(t, r, "10.244.1.5", "secret.team-b.svc.cluster.local", dns.TypeA)
	got := answers(m)
	if len(got) != 1 || got[0] != "172.16.0.4" {
		t.Fatalf("want the peer's backend VPC IP, got %v (rcode %v)", got, dns.RcodeToString[m.Rcode])
	}
}

func TestPeeringIsDirectional(t *testing.T) {
	r := testResolver()
	st := r.State.(*fakeState)
	// The peering is recorded for vpc-b only (its own Ready half); vpc-a has
	// none — vpc-b's service must stay invisible to vpc-a.
	st.peers = map[sdnv1alpha1.VPCRef][]sdnv1alpha1.VPCRef{vpcB: {vpcA}}
	m := query(t, r, "10.244.1.5", "secret.team-b.svc.cluster.local", dns.TypeA)
	if m.Rcode != dns.RcodeNameError {
		t.Fatalf("want NXDOMAIN without an active peering on the querier's side, got %v", dns.RcodeToString[m.Rcode])
	}
}

func TestPublishNotReady(t *testing.T) {
	r := testResolver()
	st := r.State.(*fakeState)
	st.svcs["team-a/etcd"].Spec.PublishNotReadyAddresses = true
	m := query(t, r, "10.244.1.5", "etcd.team-a.svc.cluster.local", dns.TypeA)
	if got := answers(m); len(got) != 3 {
		t.Fatalf("want 3 records with publishNotReadyAddresses, got %v", got)
	}
}
