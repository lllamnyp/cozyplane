package responder

import (
	"fmt"
	"testing"

	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/miekg/dns"
)

func TestDNSMetricsBoundDuringTenantChurn(t *testing.T) {
	m := NewDNSMetrics()
	const count = 5000
	for i := 0; i < count; i++ {
		v := sdnv1.VPCRef{Namespace: "tenant", Name: fmt.Sprint(i)}
		m.Query(dns.TypeAAAA, v)
		m.Response(dns.RcodeSuccess, v)
	}
	if len(m.queries) > 4097 || len(m.responses) > 4097 {
		t.Errorf("unbounded historical tenants: queries=%d responses=%d", len(m.queries), len(m.responses))
	}
	for _, counters := range []map[dnsKey]uint64{m.queries, m.responses} {
		var total uint64
		for _, n := range counters {
			total += n
		}
		if total != count {
			t.Fatal("overflow lost counts", total)
		}
	}
}
