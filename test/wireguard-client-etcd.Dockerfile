# Docker Desktop may cache a manifest list without all platform blobs; give
# kind a single-platform fixture image with the same existing etcd executable.
FROM registry.k8s.io/etcd:3.5.16-0@sha256:c6a9d11cc5c04b114ccdef39a9265eeef818e3d02f5359be035ae784097fdec5
LABEL cozyplane.test="wireguard-client"
