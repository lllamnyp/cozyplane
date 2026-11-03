package responder

import (
	"fmt"
	"net"
	"testing"
	"time"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/miekg/dns"
	corev1 "k8s.io/api/core/v1"
)

func TestForwardOverloadIsBoundedAndVPCsIndependent(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 16)
	release := make(chan struct{})
	started := make(chan struct{})
	server := &dns.Server{PacketConn: packet, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if req.Question[0].Name == "blocked.invalid." {
			entered <- struct{}{}
			<-release
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		_ = w.WriteMsg(resp)
	})}
	go server.ActivateAndServe()
	defer server.Shutdown()
	defer close(release)
	<-started
	r := testResolver()
	r.Upstreams = []string{packet.LocalAddr().String()}
	r.State.(*fakeState).ports["10.244.1.6"] = &sdnv1alpha1.Port{Spec: sdnv1alpha1.PortSpec{VPCRef: vpcB}}
	done := make(chan int, 16)
	for range 16 {
		go func() {
			req := new(dns.Msg)
			req.SetQuestion("blocked.invalid.", dns.TypeA)
			w := &fakeWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.244.1.5"), Port: 40000}}
			r.ServeDNS(w, req)
			if w.msg == nil {
				done <- -1
			} else {
				done <- w.msg.Rcode
			}
		}()
	}
	for range 16 {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("requests did not reach upstream")
		}
	}
	if reply := query(t, r, "10.244.1.5", "excess.invalid", dns.TypeA); reply.Rcode != dns.RcodeServerFailure {
		t.Fatal("overload was not rejected")
	}
	if reply := query(t, r, "10.244.1.6", "other.invalid", dns.TypeA); reply.Rcode != dns.RcodeSuccess {
		t.Fatal("one VPC blocked another VPC")
	}
	for range 16 {
		release <- struct{}{}
	}
	for range 16 {
		select {
		case rcode := <-done:
			if rcode != dns.RcodeSuccess {
				t.Fatal("blocked query did not finish", rcode)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("query stuck after release")
		}
	}
	if reply := query(t, r, "10.244.1.5", "retry.invalid", dns.TypeA); reply.Rcode != dns.RcodeSuccess {
		t.Fatal("slots were not released")
	}
}

type blockedAuthoritativeState struct {
	*fakeState
	entered chan struct{}
	release chan struct{}
}

func (s *blockedAuthoritativeState) Service(ns, name string) *corev1.Service {
	if name == "etcd" {
		s.entered <- struct{}{}
		<-s.release
	}
	return s.fakeState.Service(ns, name)
}

func TestAuthoritativeAdmissionAndRecovery(t *testing.T) {
	r := testResolver()
	state := &blockedAuthoritativeState{fakeState: r.State.(*fakeState), entered: make(chan struct{}, 16), release: make(chan struct{})}
	state.ports["10.244.1.6"] = &sdnv1alpha1.Port{Spec: sdnv1alpha1.PortSpec{VPCRef: vpcB}}
	r.State = state
	done := make(chan struct{}, 16)
	for range 16 {
		go func() {
			req := new(dns.Msg)
			req.SetQuestion("etcd.team-a.svc.cluster.local.", dns.TypeA)
			w := &fakeWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.244.1.5"), Port: 40000}}
			r.ServeDNS(w, req)
			done <- struct{}{}
		}()
	}
	defer close(state.release)
	for range 16 {
		select {
		case <-state.entered:
		case <-time.After(time.Second):
			t.Fatal("authoritative query did not start")
		}
	}
	if response := query(t, r, "10.244.1.5", "unknown.team-a.svc.cluster.local", dns.TypeA); response.Rcode != dns.RcodeServerFailure {
		t.Fatal("authoritative requests bypassed admission", response.Rcode)
	}
	if response := query(t, r, "10.244.1.6", "unknown.team-b.svc.cluster.local", dns.TypeA); response.Rcode != dns.RcodeNameError {
		t.Fatal("one saturated VPC blocked another", response.Rcode)
	}
	for range 16 {
		state.release <- struct{}{}
	}
	for range 16 {
		<-done
	}
	if response := query(t, r, "10.244.1.5", "unknown.team-a.svc.cluster.local", dns.TypeA); response.Rcode != dns.RcodeNameError {
		t.Fatal("authoritative slots did not recover", response.Rcode)
	}
}

func TestDNSReplyByteBudgetOverTCP(t *testing.T) {
	r := testResolver()
	state := r.State.(*fakeState)
	state.ports["127.0.0.1"] = state.ports["10.244.1.5"]
	state.eps["team-a/etcd"] = nil
	for i := range 800 {
		state.eps["team-a/etcd"] = append(state.eps["team-a/etcd"], Endpoint{Hostname: fmt.Sprintf("backend-%050d", i), IP: net.IPv4(192, 0, byte(i>>8), byte(i)), Ready: true})
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	server := &dns.Server{Listener: listener, Handler: r, NotifyStartedFunc: func() { close(started) }}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ActivateAndServe() }()
	<-started
	defer func() { _ = server.Shutdown(); <-serverDone }()
	req := new(dns.Msg)
	req.SetQuestion("etcd.team-a.svc.cluster.local.", dns.TypeSRV)
	client := &dns.Client{Net: "tcp", Timeout: time.Second}
	response, _, err := client.Exchange(req, listener.Addr().String())
	if err != nil || response.Rcode != dns.RcodeServerFailure || len(response.Answer) != 0 {
		t.Fatal("oversized wire response was not rejected", response, err)
	}
}

func TestAuthoritativeSRVProductIsBounded(t *testing.T) {
	r := testResolver()
	state := r.State.(*fakeState)
	svc := state.svcs["team-a/etcd"]
	svc.Spec.Ports = nil
	for i := range 32 {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Name: fmt.Sprintf("port-%d", i), Protocol: corev1.ProtocolTCP, Port: int32(1000 + i)})
	}
	state.eps["team-a/etcd"] = nil
	for i := range 800 {
		state.eps["team-a/etcd"] = append(state.eps["team-a/etcd"], Endpoint{Hostname: fmt.Sprintf("pod-%d", i), IP: net.IPv4(192, 0, byte(i>>8), byte(i)), Ready: true})
	}
	req := new(dns.Msg)
	req.SetQuestion("etcd.team-a.svc.cluster.local.", dns.TypeSRV)
	w := &fakeWriter{remote: &net.TCPAddr{IP: net.ParseIP("10.244.1.5"), Port: 40000}}
	r.ServeDNS(w, req)
	if w.msg == nil || w.msg.Rcode != dns.RcodeServerFailure || len(w.msg.Answer) != 0 {
		if w.msg != nil {
			t.Fatalf("oversized SRV product retained: rcode=%d records=%d", w.msg.Rcode, len(w.msg.Answer))
		}
		t.Fatal("missing failure response")
	}
	state.eps["team-a/etcd"] = state.eps["team-a/etcd"][:2]
	r.ServeDNS(w, req)
	if w.msg.Rcode != dns.RcodeSuccess || len(w.msg.Answer) != 64 {
		t.Fatal("bounded service did not recover", w.msg.Rcode, len(w.msg.Answer))
	}
}
