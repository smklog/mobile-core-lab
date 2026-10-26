#!/usr/bin/env bash
# Add a subscriber to the Open5GS database (MongoDB in the "mongo" container).
# Defaults are the UERANSIM test key and OPc. Usage: ./add-subscriber.sh IMSI [K] [OPC]
set -euo pipefail

IMSI=${1:?IMSI}
K=${2:-465B5CE8B199B49FAA5F0A2EE238A6BC}
OPC=${3:-E8ED289DEBA952E4283B54E88E6183CA}

if ! sudo docker exec mongo test -f /dbctl; then
  curl -sLo /tmp/open5gs-dbctl https://raw.githubusercontent.com/open5gs/open5gs/main/misc/db/open5gs-dbctl
  sudo docker cp /tmp/open5gs-dbctl mongo:/dbctl
fi
sudo docker exec mongo bash /dbctl add "$IMSI" "$K" "$OPC"
