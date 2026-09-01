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
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// DNSMetrics is the responder's Hubble-style DNS observability
// (docs/observability.md §D): query counts by record type and response counts
// by rcode, attributed to the querying VPC. Bounded cardinality by
// construction — qtype (a small fixed set), rcode (a small fixed set), VPCs.
// Never a domain name, never an address: this is a monitoring surface, not a
// query log. Nil-safe so a Resolver without metrics (tests) costs nothing.
type DNSMetrics struct {
	mu        sync.Mutex
	queries   map[dnsKey]uint64
	responses map[dnsKey]uint64
}

type dnsKey struct {
	label string // qtype for queries, rcode for responses
	ns    string // querying VPC namespace
	vpc   string // querying VPC name
}

// NewDNSMetrics builds an empty metrics sink.
func NewDNSMetrics() *DNSMetrics {
	return &DNSMetrics{
		queries:   map[dnsKey]uint64{},
		responses: map[dnsKey]uint64{},
	}
}

// Query records one received query of type qtype from the given VPC.
func (m *DNSMetrics) Query(qtype uint16, vpc sdnv1alpha1.VPCRef) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.queries[dnsKey{label: qtypeName(qtype), ns: vpc.Namespace, vpc: vpc.Name}]++
	m.mu.Unlock()
}

// Response records one answer with the given rcode to the given VPC.
func (m *DNSMetrics) Response(rcode int, vpc sdnv1alpha1.VPCRef) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.responses[dnsKey{label: rcodeName(rcode), ns: vpc.Namespace, vpc: vpc.Name}]++
	m.mu.Unlock()
}

// WriteMetrics renders the DNS series in Prometheus text form (hand-rolled, the
// house convention — no client_golang).
func (m *DNSMetrics) WriteMetrics(b *strings.Builder, node string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	q := make(map[dnsKey]uint64, len(m.queries))
	for k, v := range m.queries {
		q[k] = v
	}
	r := make(map[dnsKey]uint64, len(m.responses))
	for k, v := range m.responses {
		r[k] = v
	}
	m.mu.Unlock()

	fmt.Fprintf(b, "# HELP cozyplane_dns_queries_total VPC DNS queries steered to the resolver, by record type (this node).\n# TYPE cozyplane_dns_queries_total counter\n")
	for k, v := range q {
		fmt.Fprintf(b, "cozyplane_dns_queries_total{qtype=%q,vpc_namespace=%q,vpc=%q,node=%q} %d\n",
			k.label, k.ns, k.vpc, node, v)
	}
	fmt.Fprintf(b, "# HELP cozyplane_dns_responses_total VPC DNS responses from the resolver, by rcode (this node).\n# TYPE cozyplane_dns_responses_total counter\n")
	for k, v := range r {
		fmt.Fprintf(b, "cozyplane_dns_responses_total{rcode=%q,vpc_namespace=%q,vpc=%q,node=%q} %d\n",
			k.label, k.ns, k.vpc, node, v)
	}
}

// qtypeName maps a DNS record type to its short name, bucketing anything
// outside the known set into "other" so a hostile qtype cannot mint a series.
func qtypeName(qtype uint16) string {
	if s, ok := dns.TypeToString[qtype]; ok {
		return s
	}
	return "other"
}

// rcodeName maps an rcode to its short name, bucketing the unknown into "other".
func rcodeName(rcode int) string {
	if s, ok := dns.RcodeToString[rcode]; ok {
		return s
	}
	return "other"
}
