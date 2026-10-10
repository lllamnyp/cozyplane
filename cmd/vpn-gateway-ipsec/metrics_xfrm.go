package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
)

// These are error counters, not SA state: no key material or peer addresses.
var xfrmErrorNames = []string{
	"XfrmInError", "XfrmInBufferError", "XfrmInHdrError", "XfrmInNoStates",
	"XfrmInStateProtoError", "XfrmInStateModeError", "XfrmInStateSeqError",
	"XfrmInStateExpired", "XfrmInStateMismatch", "XfrmInStateInvalid",
	"XfrmInTmplMismatch", "XfrmInNoPols", "XfrmInPolBlock", "XfrmInPolError",
	"XfrmOutError", "XfrmOutBundleGenError", "XfrmOutBundleCheckError",
	"XfrmOutNoStates", "XfrmOutStateProtoError", "XfrmOutStateModeError",
	"XfrmOutStateSeqError", "XfrmOutStateExpired", "XfrmOutPolBlock",
	"XfrmOutPolDead", "XfrmOutPolError", "XfrmFwdHdrError", "XfrmOutStateInvalid",
	"XfrmAcquireError", "XfrmOutStateDirError", "XfrmInStateDirError",
}

func readXfrmErrors() (map[string]uint64, error) {
	f, err := os.Open("/proc/self/net/xfrm_stat")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseXfrmErrors(f)
}

func parseXfrmErrors(reader io.Reader) (map[string]uint64, error) {
	data, err := io.ReadAll(io.LimitReader(reader, (16<<10)+1))
	if err != nil || len(data) > 16<<10 {
		return nil, fmt.Errorf("XFRM statistics exceed read budget or are unavailable")
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	counters := make(map[string]uint64)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid XFRM statistics row")
		}
		if !slices.Contains(xfrmErrorNames, fields[0]) {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if _, duplicate := counters[fields[0]]; err != nil || duplicate {
			return nil, fmt.Errorf("invalid XFRM error counter")
		}
		counters[fields[0]] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if _, exists := counters["XfrmInStateSeqError"]; !exists {
		return nil, fmt.Errorf("XFRM replay statistics unavailable")
	}
	return counters, nil
}

func formatXfrmErrors(counters map[string]uint64, err error) string {
	var b strings.Builder
	b.WriteString("# HELP cozyplane_vpn_ipsec_xfrm_collection_success Whether kernel XFRM error statistics were read successfully.\n# TYPE cozyplane_vpn_ipsec_xfrm_collection_success gauge\n")
	success := 1
	if err != nil {
		success = 0
	}
	fmt.Fprintf(&b, "cozyplane_vpn_ipsec_xfrm_collection_success %d\n", success)
	b.WriteString("# HELP cozyplane_vpn_ipsec_xfrm_errors_total Kernel XFRM errors in this appliance network namespace.\n# TYPE cozyplane_vpn_ipsec_xfrm_errors_total counter\n")
	if err == nil {
		for _, reason := range xfrmErrorNames {
			if value, exists := counters[reason]; exists {
				fmt.Fprintf(&b, "cozyplane_vpn_ipsec_xfrm_errors_total{reason=%q} %d\n", reason, value)
			}
		}
	}
	return b.String()
}
