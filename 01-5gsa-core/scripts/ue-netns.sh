#!/usr/bin/env bash
# Move the UE TUN interface into its own network namespace.
# With UE and UPF on one host they share a routing table: uplink packets leave ogstun
# with the UE source address and UERANSIM's source rule sends them back into uesimtun0
# (TTL exceeded loop). A separate namespace makes the UE behave like a separate device.
# Run with sudo after nr-ue reports "TUN interface ... is up".
set -euo pipefail

NS=${1:-ue1}
DEV=${2:-uesimtun0}

ADDR=$(ip -4 -o addr show dev "$DEV" | awk '{print $4}')
[ -n "$ADDR" ] || { echo "$DEV has no IPv4 address; is nr-ue running?"; exit 1; }

ip netns list | grep -qw "$NS" || ip netns add "$NS"
ip link set "$DEV" netns "$NS"
ip -n "$NS" link set lo up
ip -n "$NS" addr add "$ADDR" dev "$DEV"
ip -n "$NS" link set "$DEV" up
ip -n "$NS" route add default dev "$DEV"

echo "$DEV ($ADDR) is in netns $NS"
echo "test: sudo ip netns exec $NS ping -c4 8.8.8.8"
