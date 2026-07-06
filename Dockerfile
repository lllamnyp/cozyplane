# syntax=docker/dockerfile:1

# Build the cozyplane agent and CNI plugin. The compiled eBPF object is
# committed and embedded via go:embed, so no clang is needed here.
# Pin the builder to the native build platform and cross-compile via GOARCH;
# otherwise buildx runs the toolchain under QEMU for the arm64 leg (glacial).
# Bases are digest-pinned for digest-reproducible releases (#4): a floating tag
# resolving to a new base silently changes every layer above it. Bump the pins
# deliberately.
FROM --platform=$BUILDPLATFORM golang:1.26@sha256:f96cc555eb8db430159a3aa6797cd5bae561945b7b0fe7d0e284c63a3b291609 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH=amd64
# -buildvcs=false: VCS stamping embeds the commit hash, so two commits with
# identical sources produced different binaries — exactly what defeats the
# digest-pin loop (#4): the pin commit itself changed the digest it pinned.
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-agent ./cmd/agent && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane ./cmd/cni && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/sdn-controller ./cmd/sdn-controller && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-apiserver ./cmd/apiserver && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-gateway ./cmd/gateway && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-responder ./cmd/responder

# Fetch the upstream host-local and loopback CNI plugins.
FROM --platform=$BUILDPLATFORM curlimages/curl:8.11.0@sha256:83a505ba2ba62f208ed6e410c268b7b9aa48f0f7b403c8108b9773b44199dbba AS cni
ARG TARGETARCH=amd64
ARG CNI_PLUGINS_VERSION=v1.9.1
RUN curl -sSL -o /tmp/cni.tgz \
      https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-${TARGETARCH}-${CNI_PLUGINS_VERSION}.tgz && \
    mkdir -p /tmp/cni/bin && \
    tar -xzf /tmp/cni.tgz -C /tmp/cni/bin ./host-local ./loopback

FROM debian:12-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
# iptables (nft backend) for the conditional FORWARD ACCEPT rule and the legacy
# --masquerade=iptables mode; the init container shells out to `cp` to install
# plugins. Timestamped apt byproducts (logs, caches) are removed in the same
# layer so the layer content is reproducible (#4); file mtimes are normalized
# by the release build's rewrite-timestamp.
RUN apt-get update && apt-get install -y --no-install-recommends iptables && \
    rm -rf /var/lib/apt/lists/* /var/log/dpkg.log /var/log/apt \
           /var/log/alternatives.log /var/cache/ldconfig/aux-cache
COPY --from=build /out/cozyplane-agent /usr/local/bin/cozyplane-agent
COPY --from=build /out/sdn-controller /usr/local/bin/sdn-controller
COPY --from=build /out/cozyplane-apiserver /usr/local/bin/cozyplane-apiserver
COPY --from=build /out/cozyplane-gateway /usr/local/bin/cozyplane-gateway
COPY --from=build /out/cozyplane-responder /usr/local/bin/cozyplane-responder
COPY --from=build /out/cozyplane /opt/cni/bin/cozyplane
COPY --from=cni /tmp/cni/bin/host-local /opt/cni/bin/host-local
COPY --from=cni /tmp/cni/bin/loopback /opt/cni/bin/loopback
ENTRYPOINT ["/usr/local/bin/cozyplane-agent"]
