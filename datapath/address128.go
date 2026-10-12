package datapath

import "net"

// EncodeAddress128 uses the same RFC 6052 representation as the datapath maps.
func EncodeAddress128(ip net.IP) ([16]byte, error) {
	a, err := addr128(ip)
	return a.B, err
}
