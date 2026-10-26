ARG UBUNTU_VERSION=24.04
FROM ubuntu:${UBUNTU_VERSION}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -o Acquire::http::Timeout=20 -o Acquire::Retries=1 update \
 && apt-get -o Acquire::http::Timeout=20 -y --no-install-recommends install \
    iproute2 nftables curl dnsutils wireguard-tools openvpn dbus \
    systemd-resolved ca-certificates openssl procps jq python3 network-manager \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /test
