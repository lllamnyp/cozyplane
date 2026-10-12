package vpnlimits

import "github.com/lllamnyp/cozyplane/internal/vpnidentity"

const (
	IPsecProposals     = 16
	IPsecProposalBytes = 512
	IPsecAuthBytes     = 4096
	IPsecAddressBytes  = 512
	// Pool names are section keys; VICI represents key length with one byte.
	IPsecPoolNameBytes = 255
	// VICI represents each string value with a uint16 length.
	IPsecTLSBytes = 65535
)

// IPsecPoolNameProblem preserves name spelling and permits an empty optional ref.
func IPsecPoolNameProblem(name string, required bool) string {
	if required && name == "" {
		return "IPsec pool name must not be empty"
	}
	if len(name) > IPsecPoolNameBytes {
		return "IPsec pool name must contain at most 255 bytes"
	}
	return ""
}

// IPsecProposalProblem bounds the default list that may be repeated for every
// peer, without attempting to interpret strongSwan's algorithm grammar.
func IPsecProposalProblem(proposals []string) string {
	if len(proposals) > IPsecProposals {
		return "IPsec proposals must contain at most 16 entries"
	}
	for _, proposal := range proposals {
		if len(proposal) > IPsecProposalBytes {
			return "IPsec proposals must contain at most 512 bytes per entry"
		}
	}
	return ""
}

// IPsecScalarProblem only bounds work; Exact still decides remote identity
// grammar, and optional local identities retain their existing semantics.
func IPsecScalarProblem(address string, identities ...string) string {
	if len(address) > IPsecAddressBytes {
		return "IPsec peer address must contain at most 512 bytes"
	}
	for _, identity := range identities {
		if len(identity) > vpnidentity.MaxIdentityBytes {
			return "IPsec identity must contain at most 4096 bytes"
		}
	}
	return ""
}
