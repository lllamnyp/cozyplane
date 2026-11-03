package vpnmetrics

import (
	"strings"
	"testing"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

func TestEmptyGatewayStillPublishesInventory(t *testing.T) {
	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(Format("wireguard", nil, false)))
	if err != nil {
		t.Fatal(err)
	}
	if len(families) != 1 || families["cozyplane_vpn_gateway_connections"].Metric[0].Gauge.GetValue() != 0 {
		t.Fatal("empty gateway disappears from monitoring", families)
	}
}
