# syntax=docker/dockerfile:1

# cozyplane-kpr image, built from source. The binary is static (CGO_ENABLED=0)
# and embeds bpf_sock.o, so a distroless static base is all it needs; at runtime
# it wants the host bpffs + cgroup2 root mounted (see deploy/kpr-daemonset.yaml)
# and CAP_BPF/CAP_SYS_ADMIN/CAP_NET_ADMIN for the map ops and cgroup attach.
#
# The build context is kpr/ — a separate module that pins Cilium's dependency
# tree (see go.mod), so nothing outside this directory reaches the image.
#
#   docker build -t cozyplane-kpr:dev -f kpr/Dockerfile kpr
#
# Pin the builder to the native build platform and cross-compile via GOARCH;
# otherwise buildx runs the toolchain under QEMU for the arm64 leg, and Cilium's
# ~394-module tree makes that glacial. The embedded bpf_sock.o is `--target=bpf`
# bytecode (kpr/build-bpf.sh), which is architecture-neutral, so one object
# serves both legs.
# Bases are digest-pinned for digest-reproducible releases (#4): a floating tag
# resolving to a new base silently changes every layer above it. Bump the pins
# deliberately, and keep the golang pin in lockstep with the root Dockerfile.
FROM --platform=$BUILDPLATFORM golang:1.26@sha256:f96cc555eb8db430159a3aa6797cd5bae561945b7b0fe7d0e284c63a3b291609 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH=amd64
# -buildvcs=false: VCS stamping embeds the commit hash, so two commits with
# identical sources produced different binaries — exactly what defeats the
# digest-pin loop (#4): the pin commit itself changed the digest it pinned.
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-kpr .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/cozyplane-kpr /usr/bin/cozyplane-kpr
USER 0:0
ENTRYPOINT ["/usr/bin/cozyplane-kpr"]
