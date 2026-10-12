# Docker Desktop may cache a manifest list without all platform blobs; give
# kind a single-platform fixture image with the same existing etcd executable.
FROM registry.k8s.io/etcd:3.5.16-0
LABEL cozyplane.test="wireguard-client"
