#!/usr/bin/env bash
# Build the 4-node lab with Linux network namespaces (no VMs needed):
#
#  pc1 10.0.1.2 --[lan 10.0.1.1] dev1 [wan 10.0.12.1] ==== [wan 10.0.12.2] dev2 [lan 10.0.2.1]-- pc2 10.0.2.2
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }
"$(dirname "$0")/lab_teardown.sh" >/dev/null 2>&1 || true
for ns in pc1 dev1 dev2 pc2; do ip netns add $ns; ip -n $ns link set lo up; done

ip link add eth0 netns pc1  type veth peer name lan netns dev1
ip link add wan  netns dev1 type veth peer name wan netns dev2
ip link add lan  netns dev2 type veth peer name eth0 netns pc2

ip -n pc1  addr add 10.0.1.2/24  dev eth0
ip -n dev1 addr add 10.0.1.1/24  dev lan
ip -n dev1 addr add 10.0.12.1/24 dev wan
ip -n dev2 addr add 10.0.12.2/24 dev wan
ip -n dev2 addr add 10.0.2.1/24  dev lan
ip -n pc2  addr add 10.0.2.2/24  dev eth0

# PCs use MTU 1400 so that "payload + 16-byte tag" always fits the 1500-byte inter-device link
ip -n pc1 link set eth0 mtu 1400; ip -n pc2 link set eth0 mtu 1400
for pair in pc1:eth0 dev1:lan dev1:wan dev2:wan dev2:lan pc2:eth0; do
  ns=${pair%%:*}; ifc=${pair##*:}
  ip -n $ns link set $ifc up
  ip netns exec $ns ethtool -K $ifc rx off tx off gso off gro off tso off >/dev/null 2>&1 || true
done
ip -n pc1  route add default via 10.0.1.1
ip -n pc2  route add default via 10.0.2.1
ip -n dev1 route add 10.0.2.0/24 via 10.0.12.2
ip -n dev2 route add 10.0.1.0/24 via 10.0.12.1
for ns in dev1 dev2; do
  ip netns exec $ns sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
done
echo "lab ready: namespaces pc1 dev1 dev2 pc2"
