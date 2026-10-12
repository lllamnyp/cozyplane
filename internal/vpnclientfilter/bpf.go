// Package vpnclientfilter restricts decrypted client traffic before kernel routing.
package vpnclientfilter

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -Werror -I../../bpf" client ../../bpf/vpnclient.c
