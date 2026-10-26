FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -o Acquire::http::Timeout=20 -o Acquire::Retries=1 update && apt-get -o Acquire::http::Timeout=20 -y --no-install-recommends install iproute2 nftables curl dnsutils wireguard-tools openvpn python3 dbus systemd-resolved ca-certificates procps jq && rm -rf /var/lib/apt/lists/*
WORKDIR /test
