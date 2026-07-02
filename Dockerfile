# syntax=docker/dockerfile:1

# Build the cozyplane agent and CNI plugin. The compiled eBPF object is
# committed and embedded via go:embed, so no clang is needed here.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -o /out/cozyplane-agent ./cmd/agent && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -o /out/cozyplane ./cmd/cni && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -o /out/sdn-controller ./cmd/sdn-controller && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -o /out/cozyplane-apiserver ./cmd/apiserver && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -o /out/cozyplane-gateway ./cmd/gateway

# Fetch the upstream host-local and loopback CNI plugins.
FROM curlimages/curl:8.11.0 AS cni
ARG TARGETARCH=amd64
ARG CNI_PLUGINS_VERSION=v1.9.1
RUN curl -sSL -o /tmp/cni.tgz \
      https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-${TARGETARCH}-${CNI_PLUGINS_VERSION}.tgz && \
    mkdir -p /tmp/cni/bin && \
    tar -xzf /tmp/cni.tgz -C /tmp/cni/bin ./host-local ./loopback

FROM debian:12-slim
# iptables (nft backend) for the FORWARD ACCEPT rule; the init container shells
# out to `cp` to install plugins.
RUN apt-get update && apt-get install -y --no-install-recommends iptables && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /out/cozyplane-agent /usr/local/bin/cozyplane-agent
COPY --from=build /out/sdn-controller /usr/local/bin/sdn-controller
COPY --from=build /out/cozyplane-apiserver /usr/local/bin/cozyplane-apiserver
COPY --from=build /out/cozyplane-gateway /usr/local/bin/cozyplane-gateway
COPY --from=build /out/cozyplane /opt/cni/bin/cozyplane
COPY --from=cni /tmp/cni/bin/host-local /opt/cni/bin/host-local
COPY --from=cni /tmp/cni/bin/loopback /opt/cni/bin/loopback
ENTRYPOINT ["/usr/local/bin/cozyplane-agent"]
