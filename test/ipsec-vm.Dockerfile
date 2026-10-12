FROM debian:bookworm-slim
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends qemu-system-x86 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY test/ipsec-vm-boot.sh /usr/local/bin/ipsec-vm-boot
ENTRYPOINT ["bash", "/usr/local/bin/ipsec-vm-boot"]
