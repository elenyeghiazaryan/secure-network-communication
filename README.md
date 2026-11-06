# secgw – Secure Inline Communication Channel (Linux, C)

Prototype of a transparent, inline encryption channel between two Linux devices:

```
PC1 ──► Device1 ═══════ protected link ═══════► Device2 ──► PC2
        (encrypt TCP payload)                   (verify + decrypt, fix checksums)
```

* **Key exchange:** authenticated Diffie–Hellman (RFC 3526 group 14, 2048-bit) between Device1 and Device2, run **before** any protected data is forwarded.
* **Protection:** for each selected TCP/IPv4 packet only the **TCP payload** is encrypted with **AES-256-GCM**; the 16-byte **authentication tag is appended to the encrypted payload**. A selected empty segment carries a tag over its headers and empty plaintext.
* **No encapsulation:** original IP and TCP headers are kept (addresses, ports, seq/ack, flags, options). No UDP tunnel, no custom protocol header. Only IP total length and the IP/TCP checksums change on the wire. Each gateway reverses the kernel’s forwarding TTL decrement for selected packets.
* **Receiver:** verifies the tag, decrypts, restores the original packet, recalculates IP and TCP checksums and forwards it to the destination host.
* **Unique nonce per packet:** `nonce = 4-byte per-direction salt ‖ 64-bit packet counter`, counter incremented for every encrypted packet, separate keys per direction (details below).

Implementation: C11, OpenSSL (libcrypto) for crypto, `libnetfilter_queue` (NFQUEUE) to intercept and rewrite packets in user space.

## Repository layout

```
src/crypto.[ch]      DH (RFC 3526 #14), HKDF-SHA256, HMAC, AES-256-GCM wrappers
src/session.[ch]     key schedule, nonce construction, replay window
src/packet.[ch]      IPv4/TCP parsing, payload protect/unprotect, checksums
src/handshake.[ch]   authenticated DH handshake over a control TCP connection
src/main.c           daemon: handshake, then NFQUEUE loop
tests/               unit tests (C) + end-to-end test (namespaces)
scripts/             iptables rules, 4-node network-namespace lab
docs/DESIGN.md       protocol, packet format, security analysis
docs/TESTING.md      how everything was tested, expected output
```

## Dependencies (Debian/Ubuntu)

```bash
sudo apt install build-essential pkg-config libssl-dev libnetfilter-queue-dev \
                 iproute2 iptables ethtool python3 tcpdump openssl
```
Running the daemon needs root (or `CAP_NET_ADMIN`). `tcpdump` is optional (wire inspection in the e2e test).

## Build & test

```bash
make            # builds build/secgw
make test       # unit tests: crypto KATs, packet round trips, tamper/replay/loss, DH, handshake
sudo tests/e2e.sh   # full PC1→Dev1→Dev2→PC2 test in network namespaces
```

The included GitHub Actions workflow builds and runs both test suites on Linux. Both gateways must use the SGW2 revision of the protocol.

## Quick start – the 4-node lab (single machine)

```bash
make
sudo scripts/lab_setup.sh             # namespaces pc1, dev1, dev2, pc2 + veth links
sudo scripts/run_lab_devices.sh 8080  # starts both devices, handshake, installs iptables rules

# server on PC2, client on PC1
sudo ip netns exec pc2 python3 -m http.server 8080 --bind 10.0.2.2 &
sudo ip netns exec pc1 curl http://10.0.2.2:8080/

# watch it: plaintext on the host side, ciphertext between the devices
sudo ip netns exec dev1 tcpdump -ni lan -A tcp port 8080     # readable
sudo ip netns exec dev1 tcpdump -ni wan -A tcp port 8080     # encrypted payload (+16 bytes)
tail -f /tmp/secgw-lab/dev1.log

sudo scripts/stop_lab_devices.sh; sudo scripts/lab_teardown.sh
```
Lab addressing: `pc1 10.0.1.2 – dev1 (lan 10.0.1.1, wan 10.0.12.1) – dev2 (wan 10.0.12.2, lan 10.0.2.1) – pc2 10.0.2.2`.

## Using it on real machines

On each device (IP forwarding enabled, PCs use the device as gateway, routes between the two networks configured):

```bash
openssl rand -hex 32 > psk.key      # create ONCE, copy securely to both devices, chmod 600

# Device2 (server)
sudo ./build/secgw --role server --listen <dev2-ip> --port 8080 --psk-file psk.key -v
# Device1 (client)
sudo ./build/secgw --role client --peer <dev2-ip>   --port 8080 --psk-file psk.key -v

# on BOTH devices, after the daemon printed "processing packets":
sudo scripts/device_rules.sh up <IF_toward_host> <IF_toward_peer> 8080
```
Options: `--port` (repeatable; selects flows whose TCP src **or** dst port matches – must be identical on both devices), `--ctrl-port` (handshake, default 9000), `--queue-out/--queue-in`, `--hs-timeout`, `-v`. `kill -USR1 <pid>` prints statistics.

**MTU:** protected packets are 16 bytes longer. Keep host MTU ≤ (link MTU − 16), e.g. hosts at 1400, inter-device link 1500 (the lab does this). Offloads (`tso/gso/gro/rx/tx` checksum) are switched off by the scripts because they interfere with rewritten packets.

## How it works (short)

1. **Handshake** (control TCP connection Device1→Device2, port 9000, outside the forwarded traffic): ephemeral DH values + nonces are exchanged, both sides prove knowledge of a pre-shared key with HMAC-SHA256 over the transcript (stops man-in-the-middle), keys are derived with HKDF-SHA256. Only after success does the daemon open the NFQUEUEs. Before that, selected traffic is dropped by the kernel – **fail closed**.
2. **Send path** (queue *out*): TCP packet with payload → encrypt payload in place with AES-256-GCM, append tag, `IP total length += 16`, recompute checksums.
3. **Receive path** (queue *in*): verify tag + decrypt, remove tag, `IP total length −= 16`, recompute checksums. Packets that fail authentication, are replayed, or are too short are **dropped**.
4. TCP packets without payload (SYN/ACK/FIN) and traffic on other ports are forwarded unchanged.

### Nonce uniqueness
`nonce = salt(4) ‖ counter(8)`. Salt and key are different per direction and per session (HKDF output), the counter starts at 0 and is incremented after every encrypted packet (including retransmissions – each is a new packet and gets a new counter), and the sender refuses to encrypt after 2³² packets (session must be re-established). Because the format must not contain a custom header, the counter is not transmitted: the receiver recovers it by trial verification within a sliding window (256 ahead for loss, 256 behind for reordering; seen counters are rejected = replay protection). Immutable header fields (IPs, ports, seq, ack, flags) are authenticated as AAD, so headers cannot be altered undetected. See `docs/DESIGN.md`.

## Known limitations (prototype)
* IPv4/TCP only; IP fragments of selected flows are dropped (use MTU/MSS so none occur).
* Handshake runs once at start-up; to re-key, restart both daemons (counter limit 2³² enforced).
* Window loss tolerance is 256 packets; a longer burst loss on the inter-device link needs a restart/re-handshake.
* A failing packet costs up to 512 trial decryptions (DoS amplification) – acceptable for a lab, not for a hostile network.
* Empty-payload TCP segments (handshake/ACKs) are not authenticated; the PSK must be high-entropy (`openssl rand`).
* Both devices must use the same `--port` list.

## Authorship / originality
Written specifically for this assignment; design choices (header-bound AAD, counter-recovery window, PSK-authenticated DH, fail-closed start-up) are documented in `docs/DESIGN.md` and are the author's own.
