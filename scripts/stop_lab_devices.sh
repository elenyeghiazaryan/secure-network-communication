#!/usr/bin/env bash
cd "$(dirname "$0")/.."
PORT=${1:-8080}
ip netns exec dev1 scripts/device_rules.sh down lan wan "$PORT" 2>/dev/null || true
ip netns exec dev2 scripts/device_rules.sh down lan wan "$PORT" 2>/dev/null || true
for d in dev1 dev2; do [ -f /tmp/secgw-lab/$d.pid ] && kill "$(cat /tmp/secgw-lab/$d.pid)" 2>/dev/null || true; done
rm -f /tmp/secgw-lab/*.pid
echo "devices stopped"
