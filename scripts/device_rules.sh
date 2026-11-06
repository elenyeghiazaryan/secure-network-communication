#!/usr/bin/env bash
# Install / remove the iptables rules that steer selected TCP traffic into the
# secgw NFQUEUEs on a device.
#
#   sudo scripts/device_rules.sh up|down LAN_IF WAN_IF PORT[,PORT...] [QUEUE_OUT QUEUE_IN]
#
#   LAN_IF  interface towards the protected host (PC)
#   WAN_IF  interface towards the peer device
# Traffic is selected when the TCP source OR destination port matches.
# No --queue-bypass is used on purpose: if secgw is not running the selected
# traffic is dropped (fail closed) instead of leaking in plaintext.
set -euo pipefail
[ $# -ge 4 ] || { sed -n '2,12p' "$0"; exit 2; }
ACT=$1; LAN=$2; WAN=$3; PORTS=$4; QOUT=${5:-0}; QIN=${6:-1}
case "$ACT" in up) OP=-I ;; down) OP=-D ;; *) echo "first arg must be up|down"; exit 2 ;; esac

rule() { if [ "$OP" = -D ]; then iptables "$@" 2>/dev/null || true; else iptables "$@"; fi; }

if [ "$ACT" = up ]; then
  sysctl -qw net.ipv4.ip_forward=1
  for i in "$LAN" "$WAN"; do   # checksum/segmentation offload would corrupt rewritten packets
    ethtool -K "$i" rx off tx off gso off gro off tso off >/dev/null 2>&1 || true
  done
fi
IFS=',' read -ra P <<< "$PORTS"
for p in "${P[@]}"; do
  for side in --dport --sport; do
    # host -> peer : encrypt
    rule "$OP" FORWARD -i "$LAN" -o "$WAN" -p tcp "$side" "$p" -j NFQUEUE --queue-num "$QOUT"
    # peer -> host : decrypt
    rule "$OP" FORWARD -i "$WAN" -o "$LAN" -p tcp "$side" "$p" -j NFQUEUE --queue-num "$QIN"
  done
done
echo "rules $ACT: LAN=$LAN WAN=$WAN ports=$PORTS queues out=$QOUT in=$QIN"
