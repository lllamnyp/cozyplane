// Package vpnidentity validates exact identities before strongSwan parses them.
package vpnidentity

import (
	"net"
	"net/netip"
	"strings"
)

const MaxIdentityBytes = 4096

func Exact(identity string) bool {
	if identity == "" || len(identity) > MaxIdentityBytes || strings.TrimSpace(identity) != identity || strings.ContainsAny(identity, "%*?^{}#/") {
		return false
	}
	for _, r := range identity {
		if r < 32 || r > 126 {
			return false
		}
	}
	if ip := net.ParseIP(identity); ip != nil {
		return !ip.IsUnspecified()
	}
	lower := strings.ToLower(identity)
	for _, prefix := range []string{"ipv4net:", "ipv6net:", "ipv4range:", "ipv6range:"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	if left, right, ok := strings.Cut(identity, "-"); ok && net.ParseIP(left) != nil && net.ParseIP(right) != nil {
		return false
	}
	if _, typed := typedKey(identity); !typed && strings.Contains(identity, "=") {
		_, valid := dnKey(identity)
		return valid
	}
	return true
}

// Key identifies equivalent IP, FQDN, email and key-ID spellings parsed by
// strongSwan. Callers must first validate Exact.
func Key(identity string) string {
	if key, typed := typedKey(identity); typed {
		return key
	}
	if strings.Contains(identity, "=") {
		key, _ := dnKey(identity)
		return key
	}
	if strings.HasPrefix(identity, "@@") {
		return "email:" + strings.ToLower(identity[2:])
	}
	if strings.HasPrefix(identity, "@") {
		return "fqdn:" + strings.ToLower(identity[1:])
	}
	if strings.Contains(identity, "@") {
		return "email:" + strings.ToLower(identity)
	}
	if ip, err := netip.ParseAddr(identity); err == nil {
		kind := "ipv6:"
		if ip.Is4() {
			kind = "ipv4:"
		}
		return kind + string(ip.AsSlice())
	}
	if strings.Contains(identity, ":") {
		return "keyid:" + identity
	}
	return "fqdn:" + strings.ToLower(identity)
}

func typedKey(identity string) (string, bool) {
	if prefix, value, ok := strings.Cut(identity, ":"); ok {
		switch strings.ToLower(prefix) {
		case "fqdn", "dns":
			return "fqdn:" + strings.ToLower(value), true
		case "rfc822", "email", "userfqdn":
			return "email:" + strings.ToLower(value), true
		case "keyid", "ipv4", "ipv6", "asn1dn", "asn1gn", "uri":
			// Typed IP values are literal bytes, not textual IP addresses.
			return strings.ToLower(prefix) + ":" + value, true
		case "xmppaddr":
			return "xmppaddr:" + value, true
		}
	}
	return "", false
}

// DN input deliberately has a smaller grammar than strongSwan's permissive
// parser. Normalize only supported attributes and require complete components.
func dnKey(identity string) (string, bool) {
	parts := strings.SplitN(identity, ",", 21)
	if len(parts) > 20 {
		return "", false
	}
	for i, part := range parts {
		attribute, value, ok := strings.Cut(part, "=")
		attribute = strings.ToLower(strings.TrimSpace(attribute))
		value = strings.TrimRight(strings.TrimLeft(value, " ="), " ")
		if !ok || value == "" {
			return "", false
		}
		switch attribute {
		case "email", "emailaddress":
			attribute = "e"
		case "employeenumber":
			attribute = "en"
		case "unstructuredname":
			attribute = "un"
		case "unstructuredaddress":
			attribute = "ua"
		}
		switch attribute {
		case "nd", "uid", "dc", "cn", "sn", "serialnumber", "c", "l", "st", "street", "o", "ou", "organizationidentifier", "t", "d", "postaladdress", "postalcode", "n", "g", "i", "dnqualifier", "dmdname", "pseudonym", "id", "en", "e", "un", "ua", "tcgid":
		default:
			return "", false
		}
		if attribute == "e" || attribute != "un" && printableDNValue(value) {
			value = strings.ToLower(value)
		}
		// NUL is excluded by Exact, so it safely delimits the parsed components.
		parts[i] = attribute + "=" + value
	}
	return "dn:" + strings.Join(parts, "\x00"), true
}

func printableDNValue(value string) bool {
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(" '()+,-./:=?", r) {
			continue
		}
		return false
	}
	return true
}
