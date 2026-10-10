# syntax=docker/dockerfile:1

# Build the cozyplane agent and CNI plugin. The compiled eBPF object is
# committed and embedded via go:embed, so no clang is needed here.
# Pin the builder to the native build platform and cross-compile via GOARCH;
# otherwise buildx runs the toolchain under QEMU for the arm64 leg (glacial).
# Bases are digest-pinned for digest-reproducible releases (#4): a floating tag
# resolving to a new base silently changes every layer above it. Bump the pins
# deliberately.
FROM --platform=$BUILDPLATFORM golang:1.26.8-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH
# -buildvcs=false: VCS stamping embeds the commit hash, so two commits with
# identical sources produced different binaries — exactly what defeats the
# digest-pin loop (#4): the pin commit itself changed the digest it pinned.
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-agent ./cmd/agent && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane ./cmd/cni && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/sdn-controller ./cmd/sdn-controller && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-admission ./cmd/admission && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-apiserver ./cmd/apiserver && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-gateway ./cmd/gateway && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-vpn-gateway ./cmd/vpn-gateway && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-vpn-gateway-ipsec ./cmd/vpn-gateway-ipsec && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-vpn-routing ./cmd/vpn-routing && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-responder ./cmd/responder && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-flowctl ./cmd/flowctl

# Static control-plane services need no networking executables or shell.
# Keep this optional target before runtime so the default image stays compatible
# with the agent, CNI installer and managed VPN/gateway workloads.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 AS control-plane
COPY --from=build /out/sdn-controller /usr/local/bin/sdn-controller
COPY --from=build /out/cozyplane-apiserver /usr/local/bin/cozyplane-apiserver
COPY --from=build /out/cozyplane-admission /usr/local/bin/cozyplane-admission
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/sdn-controller"]

# Build the upstream plugins at the same pinned, patched Go version. Released
# archives can retain a vulnerable stdlib even when our own binaries are rebuilt.
FROM build AS cni
ARG TARGETARCH
# Resolve the pinned plugin module's build-only dependencies in this stage;
# they are absent from the agent's runtime dependency graph.
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -mod=mod -trimpath -buildvcs=false -o /tmp/cni/bin/host-local github.com/containernetworking/plugins/plugins/ipam/host-local && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -mod=mod -trimpath -buildvcs=false -o /tmp/cni/bin/loopback github.com/containernetworking/plugins/plugins/main/loopback

# Runtime exception to distroless: StrongSwan, FRR and iptables need their
# distribution-managed dynamic libraries and package metadata for CVE scanning.
FROM debian:13-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS runtime
# iptables (nft backend) for the conditional FORWARD ACCEPT rule and the legacy
# --masquerade=iptables mode; the init container shells out to `cp` to install
# plugins. strongswan + strongswan-swanctl provide charon and its VICI plugin —
# the IPsec backend of the managed VPN appliance runs charon directly and drives
# it over VICI. The extra plugins provide EAP roadwarrior authentication; FRR is
# the routing sidecar used by active-active gateways. Timestamped apt byproducts
# are removed in the same layer so the layer content is reproducible (#4).
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends iptables strongswan-charon=6.0.1-6+deb13u7 strongswan=6.0.1-6+deb13u7 strongswan-swanctl=6.0.1-6+deb13u7 libcharon-extra-plugins=6.0.1-6+deb13u7 libcharon-extauth-plugins=6.0.1-6+deb13u7 frr=10.3-3+deb13u1 && \
    rm -rf /var/lib/apt/lists/* /var/log/dpkg.log /var/log/apt \
           /var/log/alternatives.log /var/cache/ldconfig/aux-cache
COPY --from=build /out/cozyplane-agent /usr/local/bin/cozyplane-agent
COPY --from=build /out/sdn-controller /usr/local/bin/sdn-controller
COPY --from=build /out/cozyplane-admission /usr/local/bin/cozyplane-admission
COPY --from=build /out/cozyplane-apiserver /usr/local/bin/cozyplane-apiserver
COPY --from=build /out/cozyplane-gateway /usr/local/bin/cozyplane-gateway
COPY --from=build /out/cozyplane-vpn-gateway /usr/local/bin/cozyplane-vpn-gateway
COPY --from=build /out/cozyplane-vpn-gateway-ipsec /usr/local/bin/cozyplane-vpn-gateway-ipsec
COPY --from=build /out/cozyplane-vpn-routing /usr/local/bin/cozyplane-vpn-routing
COPY --from=build /out/cozyplane-responder /usr/local/bin/cozyplane-responder
COPY --from=build /out/cozyplane-flowctl /usr/local/bin/cozyplane-flowctl
COPY --from=build /out/cozyplane /opt/cni/bin/cozyplane
COPY --from=cni /tmp/cni/bin/host-local /opt/cni/bin/host-local
COPY --from=cni /tmp/cni/bin/loopback /opt/cni/bin/loopback
ENTRYPOINT ["/usr/local/bin/cozyplane-agent"]
