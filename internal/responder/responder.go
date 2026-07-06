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

// Package responder implements the split-horizon DNS resolver for VPC pods
// (docs/services-in-vpc.md). The datapath steers a VPC pod's query to the
// cluster DNS address here, rewriting its source to the pod's fabric IP —
// the per-Port handle the resolver keys the tenant view on.
//
// Resolution is kube-dns-parity in shape, tenant-scoped in content:
//
//   - Cluster-domain names are answered authoritatively, never forwarded:
//     a headless Service annotated into the querier's VPC resolves to its
//     backends' VPC IPs (A/AAAA, per-hostname records, SRV); every other
//     cluster-domain name is NXDOMAIN. Not forwarding these prevents probing
//     other tenants' existence and never hands out dead-end ClusterIPs.
//   - Everything else defers to the node's upstream resolvers.
package responder

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	corev1 "k8s.io/api/core/v1"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// TTL for authoritative answers, matching CoreDNS's kubernetes-zone default.
const ttl = 5

// Endpoint is one backend of a headless Service, already resolved to a Port
// of the querying VPC.
type Endpoint struct {
	Hostname string // endpoint hostname (or the pod name when unset)
	IP       net.IP // the Port's VPC IP
	Ready    bool
}

// State is the read view the resolver answers from — informer-backed in the
// binary, stubbed in tests.
type State interface {
	// PortByFabricIP identifies the querying pod by the rewritten source
	// address the datapath gave its query. Nil for a non-steered client.
	PortByFabricIP(ip string) *sdnv1alpha1.Port
	// Service returns a Service, or nil.
	Service(ns, name string) *corev1.Service
	// Endpoints lists a Service's endpoints resolved to Ports of the given
	// VPC — the structural authz: backends outside the service's attached VPC
	// do not exist here, whatever the annotation claims.
	Endpoints(ns, svcName string, vpc sdnv1alpha1.VPCRef) []Endpoint
	// Peers lists the VPCs actively peered with vpc (VPCPeering halves whose
	// status is Ready — matched, both VPCs Ready, CIDRs disjoint).
	Peers(vpc sdnv1alpha1.VPCRef) []sdnv1alpha1.VPCRef
	// ServiceVIPFor returns the VIP materialized for an attached non-headless
	// Service within the given VPC, or nil while none is allocated.
	ServiceVIPFor(ns, name string, vpc sdnv1alpha1.VPCRef) net.IP
}

// Resolver serves the per-net DNS view.
type Resolver struct {
	Domain    string   // cluster domain, e.g. "cluster.local"
	Upstreams []string // "host:port" forwarders for non-cluster names
	State     State
}

// ServeDNS implements dns.Handler.
func (r *Resolver) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) != 1 {
		r.reply(w, req, r.refused(req))
		return
	}
	q := req.Question[0]
	qname := strings.ToLower(q.Name)

	host, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		r.reply(w, req, r.refused(req))
		return
	}
	port := r.State.PortByFabricIP(canonIP(host))
	if port == nil {
		// Not a datapath-steered VPC query (someone dialed the node address
		// directly): refuse rather than leak any view.
		r.reply(w, req, r.refused(req))
		return
	}

	zone := dns.Fqdn(r.Domain)
	if dns.IsSubDomain(zone, qname) {
		r.reply(w, req, r.authoritative(req, q, qname, port))
		return
	}
	r.forward(w, req)
}

// authoritative answers a cluster-domain name for the querying Port's VPC.
func (r *Resolver) authoritative(req *dns.Msg, q dns.Question, qname string, port *sdnv1alpha1.Port) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true

	// Strip the zone and dissect: <svc>.<ns>.svc | <host>.<svc>.<ns>.svc |
	// _<port>._<proto>.<svc>.<ns>.svc. Anything else in the cluster domain is
	// NXDOMAIN — including other tenants' names, which must stay unprovable.
	rel := strings.TrimSuffix(qname, dns.Fqdn(r.Domain))
	labels := dns.SplitDomainName(rel)
	n := len(labels)
	if n < 3 || labels[n-1] != "svc" {
		return r.nxdomain(m)
	}
	ns, svcName := labels[n-2], labels[n-3]
	var hostname, srvPort, srvProto string
	switch {
	case n == 3:
	case n == 4:
		hostname = labels[0]
	case n == 5 && strings.HasPrefix(labels[0], "_") && strings.HasPrefix(labels[1], "_"):
		srvPort, srvProto = labels[0][1:], labels[1][1:]
	default:
		return r.nxdomain(m)
	}

	// The service must be attached to the querier's VPC — or to a VPC the
	// querier's is actively peered with: a peering explicitly connects the two
	// networks (mutually created, disjoint CIDRs), so names follow
	// reachability. Anything else stays NXDOMAIN, indistinguishable from
	// not existing.
	svc := r.State.Service(ns, svcName)
	if svc == nil {
		return r.nxdomain(m)
	}
	svcVPC, attached := attachedVPC(svc)
	if !attached {
		return r.nxdomain(m)
	}
	if svcVPC != port.Spec.VPCRef && !containsVPC(r.State.Peers(port.Spec.VPCRef), svcVPC) {
		return r.nxdomain(m)
	}
	// A non-headless attached Service resolves to its ServiceVIP — the
	// ClusterIP-equivalent allocated from the VPC's own space, load-balanced
	// by the datapath. The cluster ClusterIP never appears inside a tenant.
	if svc.Spec.ClusterIP != corev1.ClusterIPNone {
		vip := r.State.ServiceVIPFor(ns, svcName, svcVPC)
		if vip == nil || hostname != "" {
			// No VIP allocated yet, or a per-hostname form (headless-only).
			return r.nxdomain(m)
		}
		if srvProto != "" {
			for _, p := range svc.Spec.Ports {
				if !strings.EqualFold(p.Name, srvPort) || !strings.EqualFold(string(p.Protocol), srvProto) {
					continue
				}
				if q.Qtype == dns.TypeSRV || q.Qtype == dns.TypeANY {
					m.Answer = append(m.Answer, &dns.SRV{
						Hdr:    dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: ttl},
						Weight: 100,
						Port:   uint16(p.Port),
						Target: dns.Fqdn(fmt.Sprintf("%s.%s.svc.%s", svcName, ns, r.Domain)),
					})
				}
				if rr := addrRecord(dns.Fqdn(fmt.Sprintf("%s.%s.svc.%s", svcName, ns, r.Domain)), dns.TypeA, vip); rr != nil {
					m.Extra = append(m.Extra, rr)
				}
				if rr := addrRecord(dns.Fqdn(fmt.Sprintf("%s.%s.svc.%s", svcName, ns, r.Domain)), dns.TypeAAAA, vip); rr != nil {
					m.Extra = append(m.Extra, rr)
				}
			}
		} else {
			addAddr(m, q, req.Question[0].Name, vip)
		}
		if len(m.Answer) == 0 {
			m.Ns = append(m.Ns, r.soa())
		}
		return m
	}

	// Backends resolve within the service's own VPC (for a peered query, the
	// peer's Ports — reachable natively, and unambiguous because peered CIDRs
	// are disjoint by construction).
	eps := r.State.Endpoints(ns, svcName, svcVPC)
	if !svc.Spec.PublishNotReadyAddresses {
		ready := eps[:0]
		for _, e := range eps {
			if e.Ready {
				ready = append(ready, e)
			}
		}
		eps = ready
	}

	owner := req.Question[0].Name // preserve the client's case
	switch {
	case srvProto != "":
		r.answerSRV(m, q, owner, svc, eps, srvPort, srvProto)
	case hostname != "":
		for _, e := range eps {
			if e.Hostname == hostname {
				addAddr(m, q, owner, e.IP)
			}
		}
		if !hasHostname(eps, hostname) {
			return r.nxdomain(m)
		}
	default:
		for _, e := range eps {
			addAddr(m, q, owner, e.IP)
		}
		if q.Qtype == dns.TypeSRV {
			// Bare-name SRV: one record per endpoint x declared port.
			for _, e := range eps {
				for _, p := range svc.Spec.Ports {
					m.Answer = append(m.Answer, srvRecord(owner, e, uint16(p.Port), r.Domain, svcName, ns))
				}
			}
		}
	}
	if len(m.Answer) == 0 {
		// The name exists (the service is attached) but yields no records of
		// this type: NODATA, not NXDOMAIN, so negative caching stays correct.
		m.Ns = append(m.Ns, r.soa())
	}
	return m
}

// answerSRV handles the _port._proto.<svc>... form.
func (r *Resolver) answerSRV(m *dns.Msg, q dns.Question, owner string, svc *corev1.Service, eps []Endpoint, srvPort, srvProto string) {
	for _, p := range svc.Spec.Ports {
		if !strings.EqualFold(p.Name, srvPort) || !strings.EqualFold(string(p.Protocol), srvProto) {
			continue
		}
		for _, e := range eps {
			if q.Qtype == dns.TypeSRV || q.Qtype == dns.TypeANY {
				m.Answer = append(m.Answer, srvRecord(owner, e, uint16(p.Port), r.Domain, svc.Name, svc.Namespace))
			}
			// Additional section: the target's address records.
			hdrName := targetName(e, r.Domain, svc.Name, svc.Namespace)
			if rr := addrRecord(hdrName, dns.TypeA, e.IP); rr != nil {
				m.Extra = append(m.Extra, rr)
			}
			if rr := addrRecord(hdrName, dns.TypeAAAA, e.IP); rr != nil {
				m.Extra = append(m.Extra, rr)
			}
		}
	}
}

func targetName(e Endpoint, domain, svc, ns string) string {
	return dns.Fqdn(fmt.Sprintf("%s.%s.%s.svc.%s", e.Hostname, svc, ns, domain))
}

func srvRecord(owner string, e Endpoint, port uint16, domain, svc, ns string) *dns.SRV {
	return &dns.SRV{
		Hdr:      dns.RR_Header{Name: owner, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: ttl},
		Priority: 0,
		Weight:   100,
		Port:     port,
		Target:   targetName(e, domain, svc, ns),
	}
}

// addrRecord builds an A or AAAA for ip when the family matches, else nil.
func addrRecord(name string, qtype uint16, ip net.IP) dns.RR {
	v4 := ip.To4()
	switch {
	case qtype == dns.TypeA && v4 != nil:
		return &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: v4}
	case qtype == dns.TypeAAAA && v4 == nil:
		return &dns.AAAA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}, AAAA: ip.To16()}
	}
	return nil
}

func addAddr(m *dns.Msg, q dns.Question, owner string, ip net.IP) {
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA && q.Qtype != dns.TypeANY {
		return
	}
	qtype := q.Qtype
	if qtype == dns.TypeANY {
		qtype = dns.TypeA
		if ip.To4() == nil {
			qtype = dns.TypeAAAA
		}
	}
	if rr := addrRecord(owner, qtype, ip); rr != nil {
		m.Answer = append(m.Answer, rr)
	}
}

func hasHostname(eps []Endpoint, hostname string) bool {
	for _, e := range eps {
		if e.Hostname == hostname {
			return true
		}
	}
	return false
}

// attachedVPC resolves the Service's explicit VPC attachment (nothing
// auto-projects). The annotation value is the same "[<owner-ns>/]<vpc>"
// syntax pods use, defaulting to the Service's own namespace.
func attachedVPC(svc *corev1.Service) (sdnv1alpha1.VPCRef, bool) {
	anno, ok := svc.Annotations[sdnv1alpha1.AnnotationVPC]
	if !ok || anno == "" {
		return sdnv1alpha1.VPCRef{}, false
	}
	ns, name := svc.Namespace, anno
	if owner, rest, found := strings.Cut(anno, "/"); found {
		ns, name = owner, rest
	}
	return sdnv1alpha1.VPCRef{Namespace: ns, Name: name}, true
}

func containsVPC(refs []sdnv1alpha1.VPCRef, want sdnv1alpha1.VPCRef) bool {
	return slices.Contains(refs, want)
}

// forward relays a non-cluster name to the node's upstream resolvers over the
// same transport the client used, returning the first response.
func (r *Resolver) forward(w dns.ResponseWriter, req *dns.Msg) {
	proto := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		proto = "tcp"
	}
	c := &dns.Client{Net: proto, Timeout: 3 * time.Second}
	for _, up := range r.Upstreams {
		in, _, err := c.Exchange(req.Copy(), up)
		if err != nil || in == nil {
			continue
		}
		in.Id = req.Id
		r.reply(w, req, in)
		return
	}
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)
	r.reply(w, req, m)
}

func (r *Resolver) nxdomain(m *dns.Msg) *dns.Msg {
	m.Rcode = dns.RcodeNameError
	m.Answer = nil
	m.Ns = []dns.RR{r.soa()}
	return m
}

func (r *Resolver) refused(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeRefused)
	return m
}

// soa synthesizes the zone SOA for negative answers (NXDOMAIN/NODATA), so
// stub resolvers cache them; the minimum field doubles as the negative TTL.
func (r *Resolver) soa() dns.RR {
	zone := dns.Fqdn(r.Domain)
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      "ns.dns." + zone,
		Mbox:    "hostmaster." + zone,
		Serial:  1,
		Refresh: 7200,
		Retry:   1800,
		Expire:  86400,
		Minttl:  ttl,
	}
}

// reply writes m, truncating UDP responses to the client's advertised size.
func (r *Resolver) reply(w dns.ResponseWriter, req *dns.Msg, m *dns.Msg) {
	if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		size := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			size = int(opt.UDPSize())
		}
		m.Truncate(size)
	}
	m.Compress = true
	_ = w.WriteMsg(m)
}

// canonIP normalizes a textual IP to its canonical form so map lookups match
// however the address was originally rendered.
func canonIP(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}
