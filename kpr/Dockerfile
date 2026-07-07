# cozyplane-kpr image. The binary is static (CGO_ENABLED=0) and embeds
# bpf_sock.o, so a distroless static base is all it needs; at runtime it wants
# the host bpffs + cgroup2 root mounted (see deploy/kpr-daemonset.yaml) and
# CAP_BPF/CAP_SYS_ADMIN/CAP_NET_ADMIN for the map ops and cgroup attach.
#
# Build the binary first (host module cache makes this fast):
#   CGO_ENABLED=0 go -C kpr build -o kpr/cozyplane-kpr .
#   docker build -t cozyplane-kpr:dev -f kpr/Dockerfile kpr
# A from-source multi-stage build is a later hardening; this keeps the e2e loop
# quick and avoids re-resolving Cilium's ~394-module tree in the image build.
FROM gcr.io/distroless/static-debian12:nonroot
COPY cozyplane-kpr /usr/bin/cozyplane-kpr
USER 0:0
ENTRYPOINT ["/usr/bin/cozyplane-kpr"]
