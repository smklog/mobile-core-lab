#!/usr/bin/env bash
# Set the PLMN in Open5GS and generate UERANSIM configs for it.
# Usage: sudo ./set-plmn.sh MCC MNC [UERANSIM_DIR]
set -euo pipefail

MCC=${1:?MCC}
MNC=${2:?MNC}
UERANSIM_DIR=${3:-/home/${SUDO_USER:-$USER}/UERANSIM}
IMSI="${MCC}${MNC}0000000001"

[ -d /etc/open5gs.orig ] || cp -r /etc/open5gs /etc/open5gs.orig
sed -i -E "s/mcc: [0-9]+/mcc: ${MCC}/; s/mnc: [0-9]+/mnc: ${MNC}/" /etc/open5gs/*.yaml
systemctl restart 'open5gs-*'

cd "$UERANSIM_DIR/config"
sed -E "s/mcc: '[0-9]+'/mcc: '${MCC}'/; s/mnc: '[0-9]+'/mnc: '${MNC}'/" open5gs-gnb.yaml > lab-gnb.yaml
sed -E "s/mcc: '[0-9]+'/mcc: '${MCC}'/; s/mnc: '[0-9]+'/mnc: '${MNC}'/; s/imsi-[0-9]+/imsi-${IMSI}/" open5gs-ue.yaml > lab-ue.yaml
chown "${SUDO_USER:-$USER}": lab-gnb.yaml lab-ue.yaml

grep -nE "^\s+(mcc|mnc):" /etc/open5gs/amf.yaml
grep -nE "mcc|mnc|supi" lab-gnb.yaml lab-ue.yaml
echo "UE IMSI: ${IMSI}"
