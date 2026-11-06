#!/usr/bin/env bash
# End-to-end test: PC1 -> Device1 -> Device2 -> PC2 in network namespaces. Needs root.
#   sudo tests/e2e.sh
# Requires: build/secgw (make), iproute2, iptables, python3, openssl; tcpdump optional (wire check).
set -uo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "run as root: sudo tests/e2e.sh"; exit 1; }
[ -x build/secgw ] || { echo "build first: make"; exit 1; }
PORT=8080; T=$(mktemp -d); PASS=0; FAIL=0
MARK="SECRET-MARKER-$(openssl rand -hex 8)"
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
cleanup() { scripts/stop_lab_devices.sh $PORT >/dev/null 2>&1; kill ${SRV1:-} ${SRV2:-} ${TD1:-} ${TD2:-} 2>/dev/null; scripts/lab_teardown.sh >/dev/null; rm -rf "$T"; }
trap cleanup EXIT

echo "== building lab"; scripts/lab_setup.sh >/dev/null || { echo "lab setup failed"; exit 1; }
mkdir -p $T/www
echo "$MARK" > $T/www/secret.txt
head -c 5000000 /dev/urandom > $T/www/big.bin
echo "plain traffic" > $T/www/plain.txt
ip netns exec pc2 python3 -m http.server $PORT --bind 10.0.2.2 -d $T/www >/dev/null 2>&1 & SRV1=$!
ip netns exec pc2 python3 -m http.server 8081 --bind 10.0.2.2 -d $T/www >/dev/null 2>&1 & SRV2=$!
sleep 1
fetch() { ip netns exec pc1 python3 - "$1" "$2" <<'PY'
import sys, urllib.request
data = urllib.request.urlopen(sys.argv[1], timeout=20).read()
open(sys.argv[2], "wb").write(data)
PY
}

echo "== 1. without the secure channel, protected traffic must be BLOCKED (fail closed)"
ip netns exec dev1 scripts/device_rules.sh up lan wan $PORT >/dev/null
if timeout 6 bash -c "ip netns exec pc1 python3 -c \"import urllib.request;urllib.request.urlopen('http://10.0.2.2:$PORT/secret.txt',timeout=3)\"" >/dev/null 2>&1; then
  bad "traffic flowed although no secgw was running"; else ok "no plaintext leak while the channel is down"; fi
ip netns exec dev1 scripts/device_rules.sh down lan wan $PORT >/dev/null

echo "== 2. start devices (handshake first, then traffic)"
scripts/run_lab_devices.sh $PORT >/dev/null 2>&1 && ok "handshake done, both devices processing" || bad "devices failed to start"
ID1=$(grep -o 'id [0-9a-f]*' /tmp/secgw-lab/dev1.log | head -1); ID2=$(grep -o 'id [0-9a-f]*' /tmp/secgw-lab/dev2.log | head -1)
[ -n "$ID1" ] && [ "$ID1" = "$ID2" ] && ok "both devices report the same session ($ID1)" || bad "session ids differ ('$ID1' vs '$ID2')"

if command -v tcpdump >/dev/null; then
  ip netns exec dev1 tcpdump -ni wan -U -w $T/wan.pcap "tcp port $PORT" >/dev/null 2>&1 & TD1=$!
  ip netns exec dev1 tcpdump -ni lan -U -w $T/lan.pcap "tcp port $PORT" >/dev/null 2>&1 & TD2=$!
  sleep 1
fi

echo "== 3. protected transfers"
fetch http://10.0.2.2:$PORT/secret.txt $T/secret.out && [ "$(cat $T/secret.out)" = "$MARK" ] && ok "small file arrives intact through the tunnel" || bad "small file mismatch"
fetch http://10.0.2.2:$PORT/big.bin $T/big.out && cmp -s $T/www/big.bin $T/big.out && ok "5 MB random file arrives bit-exact (sha256 $(sha256sum $T/big.out | cut -c1-12)...)" || bad "large file mismatch"
sleep 1

echo "== 4. wire inspection"
if command -v tcpdump >/dev/null; then
  kill $TD1 $TD2 2>/dev/null; sleep 1
  grep -qa "$MARK" $T/lan.pcap && ok "control: marker visible on the host-side link" || bad "control failed: marker not seen on LAN link (capture problem)"
  grep -qa "$MARK" $T/wan.pcap && bad "PLAINTEXT marker visible between the devices!" || ok "marker NOT visible between the devices (payload encrypted)"
else echo "  (tcpdump not installed - wire inspection skipped)"; fi

echo "== 5. unselected port passes through untouched"
fetch http://10.0.2.2:8081/plain.txt $T/plain.out && [ "$(cat $T/plain.out)" = "plain traffic" ] && ok "traffic on a non-protected port still works" || bad "non-protected port broken"

echo "== 6. statistics"
kill -USR1 $(cat /tmp/secgw-lab/dev1.pid) $(cat /tmp/secgw-lab/dev2.pid); sleep 0.5
grep "stats:" /tmp/secgw-lab/dev1.log | tail -1; grep "stats:" /tmp/secgw-lab/dev2.log | tail -1
grep -q "dropped(auth)=0" <(grep "stats:" /tmp/secgw-lab/dev2.log | tail -1) && ok "no authentication failures on dev2" || bad "authentication failures on dev2"

echo; echo "RESULT: $PASS passed, $FAIL failed"; [ $FAIL -eq 0 ]
