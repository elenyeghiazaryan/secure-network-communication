#!/usr/bin/env bash
# Start secgw on dev2 (server) and dev1 (client) inside the lab and install the rules.
#   sudo scripts/run_lab_devices.sh [PORT] [PSKFILE]     (stop with: sudo scripts/stop_lab_devices.sh)
set -euo pipefail
cd "$(dirname "$0")/.."
PORT=${1:-8080}; PSK=${2:-/tmp/secgw-lab.psk}
[ -x build/secgw ] || { echo "build first: make"; exit 1; }
[ -f "$PSK" ] || { openssl rand -hex 32 > "$PSK"; chmod 600 "$PSK"; }
mkdir -p /tmp/secgw-lab
ip netns exec dev2 ./build/secgw --role server --listen 10.0.12.2 --port "$PORT" --psk-file "$PSK" -v >/tmp/secgw-lab/dev2.log 2>&1 &
echo $! > /tmp/secgw-lab/dev2.pid
ip netns exec dev1 ./build/secgw --role client --peer 10.0.12.2 --port "$PORT" --psk-file "$PSK" -v >/tmp/secgw-lab/dev1.log 2>&1 &
echo $! > /tmp/secgw-lab/dev1.pid
for i in $(seq 1 30); do
  grep -q "processing packets" /tmp/secgw-lab/dev1.log 2>/dev/null && grep -q "processing packets" /tmp/secgw-lab/dev2.log 2>/dev/null && break
  sleep 0.5
done
grep -q "processing packets" /tmp/secgw-lab/dev1.log && grep -q "processing packets" /tmp/secgw-lab/dev2.log || { echo "devices did not come up, see /tmp/secgw-lab/*.log"; exit 1; }
ip netns exec dev1 scripts/device_rules.sh up lan wan "$PORT"
ip netns exec dev2 scripts/device_rules.sh up lan wan "$PORT"
echo "secure channel up. logs: /tmp/secgw-lab/dev1.log dev2.log"
