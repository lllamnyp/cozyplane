FROM alpine:3.21
RUN apk add --no-cache bash curl iproute2 iproute2-tc iputils iperf3 jq wireguard-tools python3 tcpdump
CMD ["sleep", "infinity"]
