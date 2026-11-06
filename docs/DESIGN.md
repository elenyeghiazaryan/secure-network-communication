# Design

## 1. Topology and traffic flow
Each device has a *lan* interface (towards its host) and a *wan* interface (towards the peer). iptables `FORWARD` rules send selected TCP packets to two NFQUEUEs:

| direction | rule match | queue | action |
|---|---|---|---|
| lan → wan | tcp sport/dport ∈ ports | 0 (out) | encrypt payload |
| wan → lan | tcp sport/dport ∈ ports | 1 (in)  | verify + decrypt |

Both directions of a connection are protected (requests and replies). The handshake uses the devices' own addresses (INPUT/OUTPUT), so it never passes through `FORWARD`.

## 2. Handshake
```
C → S  "SGW1" | cnonce(32) | A = g^a mod p (256 B)
S → C  "SGW1" | snonce(32) | B = g^b mod p (256 B) | HMAC(psk, "SGW1-server" | M1 | M2body)
C → S  HMAC(psk, "SGW1-client" | M1 | M2body)
```
* Group: RFC 3526 #14 (2048-bit safe prime, g=2); private exponents 320 bits from OpenSSL's CSPRNG.
* Peer values are validated: `1 < y < p-1` and `y^((p-1)/2) = 1 (mod p)` (prime-order subgroup).
* `Z = y^x mod p` (256 B). `OKM = HKDF-SHA256(salt = cnonce‖snonce, ikm = Z, info = "SGW1 session keys")`, 80 bytes: `c2s_key(32) s2c_key(32) c2s_salt(4) s2c_salt(4) session_id(8)`.
* The PSK only authenticates (MAC) and is not mixed into the encryption keys → forward secrecy against later PSK compromise. MACs compare in constant time. A failed authentication aborts; no session exists.
* The server keeps accepting until one peer authenticates, so port scans cannot block start-up.

## 3. Packet transformation
```
before: [IPv4 hdr][TCP hdr (+options)][ payload (n bytes) ]
after : [IPv4 hdr][TCP hdr (+options)][ ciphertext (n bytes) ][ tag (16 bytes) ]
```
Changed fields: IPv4 *total length* (+16), IPv4 header checksum, TCP checksum (pseudo-header + segment). Everything else (ID, flags/DF, TTL, addresses, ports, seq, ack, window, options) is byte-identical. Decryption is the exact inverse, so the receiving host sees the original packet.

**AAD (21 bytes)** = src IP, dst IP, src port, dst port, seq, ack, TCP flags. These are immutable on the path between the devices (no NAT assumed), so any modification invalidates the tag. TTL, IP ID, checksums, window are deliberately excluded (routers/hosts legitimately change them).

## 4. Nonce management
* `nonce = salt_dir(4) ‖ counter_be64`, key and salt differ per direction ⇒ the two directions can never collide.
* Counter increments after each successful encryption (also for TCP retransmissions, which are distinct packets).
* Hard stop at 2³² packets per session (`PKT_ERR_EXHAUSTED`), well inside AES-GCM limits.
* **Counter is implicit**: nothing is added to the packet. The receiver keeps `rx_next` (highest accepted + 1) and a ring recording accepted counters. For each packet it tries `rx_next … rx_next+255` (loss) and then not-yet-seen counters `rx_next-1 … rx_next-256` (reordering); the first counter whose tag verifies is accepted. Accepted counters are recorded, so a replay finds no usable counter and is dropped. In the normal in-order case exactly one trial is needed.
* Cost of this design: a forged packet costs ≤ 512 GCM trials; loss bursts > 256 packets desynchronise the channel (restart).

## 5. Failure behaviour (fail closed)
* No handshake → NFQUEUE has no reader → kernel drops selected traffic (no `--queue-bypass`).
* Auth failure, replay, short/malformed packet, IP fragment, exhausted session → `NF_DROP`.
* Non-IPv4/non-TCP and non-selected ports → `NF_ACCEPT` unchanged. TCP segments with empty payload → unchanged.

## 6. Threat model
Protects confidentiality, integrity and replay-resistance of TCP payloads of selected flows on the inter-device link against an active network attacker who does not know the PSK. Not covered: traffic analysis (lengths, timing, headers visible), authenticity of empty-payload segments, DoS, compromise of a device, IPv6, UDP.

## 7. Why the checksum recalculation is mandatory
The tag increases the payload length, so IP total length and TCP pseudo-header length change; both checksums are recomputed on every modified packet. For packets the kernel marked "checksum offloaded" the lab scripts disable offload (`ethtool -K … tx off rx off`) so the checksum we compute is the one that goes out.
