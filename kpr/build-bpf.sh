#!/usr/bin/env bash
# Rebuild the committed kpr/bpf_sock.o from Cilium's bpf_sock.c at the pinned
# tag. cozyplane never compiles BPF at runtime: the object is built once here,
# committed, and go:embed-ed (mirrors datapath/overlay_bpfel.o). Every per-node
# knob in bpf_sock.c is a load-time constant (.rodata.config), so one object
# configures at load.
#
# Usage:
#   kpr/build-bpf.sh [CILIUM_SRC]
# CILIUM_SRC defaults to a fresh shallow clone of the pinned tag into a tempdir.
# Provenance/license: bpf/ is dual GPL-2.0/BSD-2-Clause; reused here under
# BSD-2-Clause. The object's kernel license string stays "Dual BSD/GPL".
set -euo pipefail

# Keep in lockstep with kpr/go.mod's cilium require.
CILIUM_TAG="v1.19.5"
OUT="$(cd "$(dirname "$0")" && pwd)/bpf_sock.o"

SRC="${1:-}"
if [ -z "$SRC" ]; then
	SRC="$(mktemp -d)"
	trap 'rm -rf "$SRC"' EXIT
	echo "cloning cilium ${CILIUM_TAG} into ${SRC}…"
	git clone --depth 1 --branch "$CILIUM_TAG" https://github.com/cilium/cilium "$SRC"
fi

echo "building bpf_sock.o from ${SRC} (${CILIUM_TAG})…"
( cd "$SRC" && clang \
	-Ibpf -Ibpf/include \
	-DENABLE_IPV4 -DENABLE_IPV6 \
	-DENABLE_SOCKET_LB_TCP -DENABLE_SOCKET_LB_UDP \
	-g -O2 --target=bpf -std=gnu99 -nostdinc -mcpu=v3 \
	-c bpf/bpf_sock.c -o "$OUT" )

echo "wrote ${OUT} ($(stat -c%s "$OUT") bytes)"
# Sanity: the seven core socket-LB programs must be present.
readelf -sW "$OUT" | awk '$4=="FUNC"{print $8}' | grep -c '^cil_sock' | xargs -I{} echo "  {} socket-LB programs"
