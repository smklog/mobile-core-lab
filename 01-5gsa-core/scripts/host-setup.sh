#!/usr/bin/env bash
# Host prerequisites for Open5GS + UERANSIM on one Ubuntu VM. Run with sudo after every reboot.
set -euo pipefail

# UERANSIM reads /etc/iproute2/rt_tables; newer Ubuntu ships it under /usr/share/iproute2
if [ ! -f /etc/iproute2/rt_tables ]; then
  mkdir -p /etc/iproute2
  cp /usr/share/iproute2/rt_tables /etc/iproute2/ 2>/dev/null || cp /usr/lib/iproute2/rt_tables /etc/iproute2/
fi

modprobe sctp
sysctl -qw net.ipv4.ip_forward=1

# NAT for the UE pool
iptables -t nat -C POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE

# Docker sets FORWARD policy to DROP; allow UPF traffic through DOCKER-USER
for dir in -i -o; do
  iptables -C DOCKER-USER "$dir" ogstun -j ACCEPT 2>/dev/null \
    || iptables -I DOCKER-USER "$dir" ogstun -j ACCEPT
done

echo "host ready"
