# Testing

## Unit tests (`make test`, no root needed)
| binary | what it proves |
|---|---|
| `test_crypto` | HKDF-SHA256 = RFC 5869 test vector; AES-256-GCM = published known-answer vector; AEAD tamper detection (ciphertext, tag, AAD, nonce); DH agreement; DH rejects 0, 1, ≥p |
| `test_packet` | exact round trip for payload sizes 1…1400 with/without TCP options; plaintext absent on the wire; +16 bytes; headers preserved; checksums valid; empty TCP segments tagged and restored; untagged empty segments rejected; TTL restored; tampering with ciphertext/tag/seq/IP/port/flags rejected; truncated, forged-plaintext, too-short, wrong-key, reflected packets rejected; 3000 identical packets ⇒ 3000 distinct ciphertexts and counter == 3000; replay rejected; reorder/loss accepted; window limits; packet-limit and no-session fail closed |
| `test_handshake` | loopback handshake: both sides derive mirrored keys/salts/same session id; fresh keys every run; wrong PSK ⇒ both sides refuse, no session |

Expected tail: `ALL UNIT TESTS PASSED` (16 + 40 + 9 checks).

## End-to-end test (`sudo tests/e2e.sh`)
Builds the namespace lab and checks:
1. selected traffic is **blocked** while the daemons are not running (fail closed);
2. handshake completes and both devices report the same session id;
3. a small file and a 5 MB random file cross PC1→Dev1→Dev2→PC2 bit-exact;
4. (with tcpdump) the secret marker is visible on the host-side link but **not** between the devices, and a captured SYN keeps its TTL and gains exactly 16 bytes;
5. traffic on an unselected port passes unmodified;
6. no authentication failures were counted.

## Manual checks
* `tcpdump -ni wan -XX tcp port 8080` on dev1: headers readable, payload random, packet 16 bytes longer.
* `kill -USR1 $(cat /tmp/secgw-lab/dev1.pid)` → statistics.
* Start only one daemon / use a different `--psk-file` on each: handshake refuses ("authentication FAILED") and nothing is forwarded.
