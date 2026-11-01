#!/usr/bin/env bash
# Point the srsRAN 4G example configs (~/.config/srsran) at the Open5GS EPC.
# Usage: ./srsran-config.sh [MCC] [MNC] [IMSI] [K] [OPC]
# Defaults: lab PLMN and the test subscriber added by 01-5gsa-core/scripts/add-subscriber.sh.
set -euo pipefail

MCC=${1:-250}
MNC=${2:-99}
IMSI=${3:-${MCC}${MNC}0000000001}
K=${4:-465B5CE8B199B49FAA5F0A2EE238A6BC}
OPC=${5:-E8ED289DEBA952E4283B54E88E6183CA}
DIR=${SRSRAN_CONF_DIR:-$HOME/.config/srsran}

cd "$DIR"

# eNB: PLMN and MME S1-MME address (Open5GS MME default)
sed -i -E "s/^mcc = .*/mcc = ${MCC}/; s/^mnc = .*/mnc = ${MNC}/; s/^mme_addr = .*/mme_addr = 127.0.0.2/" enb.conf
# Cell TAC lives in rr.conf
sed -i -E 's/(tac\s*=\s*)0x[0-9A-Fa-f]+;/\10x0001;/' rr.conf
# UE: soft USIM
sed -i -E "s/^imsi\s*=.*/imsi = ${IMSI}/; s/^k\s*=.*/k    = ${K}/; s/^opc\s*=.*/opc  = ${OPC}/" ue.conf

grep -nE "^(mcc|mnc|mme_addr) " enb.conf
grep -n "tac" rr.conf
grep -nE "^(algo|imsi|k|opc)\s*=" ue.conf
