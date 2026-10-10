FROM alpine:3.21
# Native strongSwan peers, independent of the cozyplane runtime/config renderer.
RUN apk add --no-cache bash curl iproute2 iproute2-tc iputils iperf3 jq python3 tcpdump strongswan openssl
CMD ["sleep", "infinity"]
