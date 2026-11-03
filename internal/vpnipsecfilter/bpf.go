// Package vpnipsecfilter restricts decrypted IPsec traffic before kernel routing.
package vpnipsecfilter

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -Werror -I../../bpf" ipsec ../../bpf/vpnipsec.c
