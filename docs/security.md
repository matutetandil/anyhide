# Security Properties

Anyhide's security model is built on multiple layers that work together to provide strong encryption with plausible deniability.

## Core Security Layers

1. **Four-Factor Security**: Carrier + Passphrase + Private Key + Correct Version
2. **Never-Fail Decoder**: Always produces output - no error signals for attackers
3. **Plausible Deniability**: Wrong inputs return garbage, not errors
4. **Forward Secrecy**: Ephemeral keys protect past messages
5. **Code Splitting**: Wrong order = garbage (no error)

## Plausible Deniability

Anyhide's decoder NEVER fails. Given any combination of carrier, passphrase, and key, it always returns something. This means:

- An attacker cannot tell if they have the right passphrase
- Brute-force detection is impossible - every attempt "succeeds"
- There's no way to prove that a specific carrier contains hidden data

## Duress Password

Hide two messages in one code - reveal the decoy under coercion:

```bash
# Encode with real + decoy messages
anyhide encode -c carrier.txt \
  -m "Real secret message" -p "real-pass" \
  --decoy "Nothing important here" --decoy-pass "decoy-pass" \
  --their-key bob.pub

# Real passphrase → real message
anyhide decode --code "..." -c carrier.txt -p "real-pass" --my-key bob.key
# Output: Real secret message

# Decoy passphrase → decoy message
anyhide decode --code "..." -c carrier.txt -p "decoy-pass" --my-key bob.key
# Output: Nothing important here

# Wrong passphrase → garbage (not an error)
anyhide decode --code "..." -c carrier.txt -p "wrong-pass" --my-key bob.key
# Output: (garbage data)
```

All three outputs look identical in format. An observer cannot determine which is the "real" message.

## Code Splitting

Split a code into N parts for multi-channel delivery. ALL parts are required, in the correct order:

```bash
# Split into 3 parts
anyhide encode -c carrier.txt -m "Secret" -p "pass" --their-key bob.pub --split 3
# Output: part-1: xxx, part-2: yyy, part-3: zzz

# Decode with all parts in order
anyhide decode --parts p1.txt p2.txt p3.txt -c carrier.txt -p "pass" --my-key bob.key

# Wrong order = garbage (plausible deniability)
anyhide decode --parts p2.txt p1.txt p3.txt -c carrier.txt -p "pass" --my-key bob.key
# Returns garbage, not an error
```

## Multi-Carrier Security

Using multiple carriers concatenated in order. The order is an additional secret:

```bash
# Encode with 3 carriers - order matters!
anyhide encode -c photo.jpg -c song.mp3 -c document.pdf \
  -m "Secret message" -p "pass" --their-key bob.pub

# Wrong order = garbage (plausible deniability)
anyhide decode -c song.mp3 -c photo.jpg -c document.pdf \
  --code "..." -p "pass" --my-key bob.key
# Returns garbage, not an error
```

**Security benefit:** N carriers provide N! additional combinations:
- 2 carriers = 2 combinations
- 3 carriers = 6 combinations
- 4 carriers = 24 combinations
- 5 carriers = 120 combinations

When using multiple carriers:
- All files are read as bytes and concatenated in order
- Single text file with `-c file.txt` preserves text carrier behavior
- Multiple files always become a binary carrier

## Forward Secrecy

See [Forward Secrecy & Ratchet](ratchet.md) for details on key rotation.

## Post-Quantum Hybrid Encryption

Anyhide ships a post-quantum (PQ) hybrid track alongside the classical X25519 track. The hybrid mode combines classical Curve25519 ECDH with ML-KEM-768 (FIPS 203, formerly known as Kyber-768) so that a code remains confidential as long as **either** primitive holds — even if a future quantum computer breaks ECDH or a future cryptanalysis breaks ML-KEM.

### Threat model: harvest-now-decrypt-later

A capable adversary can record encrypted traffic today and decrypt it later when quantum computers mature. For Anyhide codes, that means an anyhide code persisted in chat logs, blockchains, or backups today could be decrypted retroactively if X25519 is broken in the future. PQ hybrid mode closes that window: the recipient's static key is hybrid, so the per-message KEM encapsulation also requires breaking ML-KEM-768 — a separate, quantum-resistant problem.

PQ hybrid does **not** address active attackers (those threats are handled by AEAD authentication, signing keys, and the never-fail decoder), only retroactive confidentiality.

### Why hybrid (and not pure PQ)

ML-KEM-768 is a young primitive. The RustCrypto `ml-kem` crate used by Anyhide (`ml-kem = "0.3.0"`) has **not** been audited. Hybrid mode mitigates this risk: the shared secret is `HKDF-SHA256(classical_ss || pq_ss)`. If ML-KEM is later broken, the X25519 leg still protects the message; if X25519 is broken by a quantum computer, the ML-KEM leg still protects the message. The combined key is at least as strong as the strongest of the two.

Code reference: `crypto/hybrid_kem.rs`, function `combine_secrets`. The combiner uses the HKDF info string `ANYHIDE-HYBRID-KEM-V1` for domain separation.

### Wire format dispatcher (v6 vs v7)

Two anyhide code formats coexist on disk:

| Format | Recipient key | Wire prefix |
|--------|---------------|-------------|
| **v6** (classical) | X25519 (`-----BEGIN ANYHIDE PUBLIC KEY-----`) | none — starts directly with the 32-byte ephemeral pubkey |
| **v7** (hybrid PQ) | X25519 + ML-KEM-768 (`-----BEGIN ANYHIDE HYBRID PUBLIC KEY-----`) | 5-byte magic: `AHV7\x01` |

The decoder sniffs the magic prefix on the post-base64 bytes (`detect_wire_format` in `crypto/mod.rs`) and routes to the matching decryption layer. Codes encoded before the PQ migration keep working byte-identically — no re-encoding required.

Collision probability between the v7 magic (`AHV7`) and the random first bytes of a v6 ephemeral pubkey is approximately 1/2^32 — statistically negligible. Even on a collision, the never-fail decoder returns garbage rather than panicking.

### Identity migration

A hybrid keypair generated via `anyhide keygen --hybrid` is a **fresh identity**, not a superset of an existing classical keypair. The X25519 component of a hybrid secret is independent of any prior classical secret the user owned. Practical consequences:

- Users migrating to PQ keep their **classical private key** on hand to decrypt pre-migration v6 codes addressed to their classical pubkey.
- Re-encoding old material under a hybrid key requires re-encoding from the original plaintext — there is no in-place upgrade path.
- The recipient's PEM file dictates the wire format. The CLI auto-detects: `anyhide encode --their-key bob.pub` produces v6 if `bob.pub` is classical or v7 if it is hybrid. No flag is needed.

Wire-format / key-flavor mismatches at decode (v6 + hybrid secret, or v7 + classical secret) flow through the never-fail decoder and yield deterministic garbage — no panics, no error signals an attacker could probe.

### Per-message overhead

Hybrid mode trades size for PQ confidentiality:

| Layer | v6 classical | v7 hybrid PQ | Overhead |
|-------|--------------|--------------|----------|
| Asymmetric prefix on a code | 32 B (X25519 pubkey) | 5 B magic + 1120 B KEM ciphertext = 1125 B | ~1.1 KB per code |
| Multi-recipient: per-recipient wrap | ~92 B | ~1.3 KB (1120 B KEM ct + identifier + AEAD tag) | ~14× |
| Identity QR code body | ~126 B | ~1310 B | ~10× (still inside QR Version 40 / EC level L) |
| `.eph` / `.eph.pub` / `.eph.key` per contact | 32 B priv + 32 B pub raw | 96 B priv + 1216 B pub raw | ~20× |

Plain text or short messages encoded with v7 will produce noticeably longer codes. For chat (where the per-message anyhide code dominates the overhead), the inflation is absorbed by the message payload.

### Chat protocol break (v1 → v2)

Unlike anyhide codes, the chat protocol forced a hard break at v2:

- Chat is RAM-only with no persisted state, so there is no historical material to preserve byte-compatibility for.
- Chat handshake migrated to a PQXDH-shape design: both sides contribute KEM entropy via `derive_master_secret(ss_resp_to_init, ss_init_to_resp)` with HKDF info `ANYHIDE-CHAT-V2-MASTER`.
- The KEM ratchet (`kem_ratchet_send` / `kem_ratchet_receive` in `chat/protocol/ratchet.rs`) replaces the classical Diffie–Hellman ratchet of v1.
- Identity Ed25519 signing keys are **not** migrated to PQ — signature authenticity is a separate threat model from harvest-now-decrypt-later confidentiality. Migrating to a PQ signature scheme (Dilithium, Falcon) is a future decision with its own tradeoffs.
- v2 peers refuse v1 connections, and vice versa, with `ChatError::VersionMismatch`. Migration UX: `anyhide keygen --hybrid -o newkey` and re-share QR with peers.

### What is *not* migrated

- **Forward-secrecy ratchet on encoded anyhide codes** (`encode --ratchet`) is rejected with `EncoderError::RatchetUnsupportedForHybrid` for hybrid recipients. The encoder's `EncodedMessage.next_keypair` is X25519-only; emitting a hybrid ephemeral here would misrepresent the ratchet shape. Classical ratchet semantics are unchanged.
- **BIP39 mnemonic backup** is classical-only. The hybrid secret is 96 bytes (32 B X25519 + 64 B ML-KEM seed), and the standard 24-word BIP39 mnemonic encodes 32-byte secrets. A 27-word or custom scheme for hybrid keys is a follow-up.
- **Ed25519 signing identities** continue as classical. Authentication of the sender does not benefit from hybrid PQ in the same way confidentiality does — a signature does not protect past messages from future cryptanalysis (it only commits the sender at signing time).

### Key code references

- `crypto/hybrid_kem.rs` — primitive, combiner, secret-key serialization
- `crypto/asymmetric.rs` — `encrypt_hybrid` / `decrypt_hybrid` (single recipient)
- `crypto/multi_recipient.rs` — `encrypt_multi_hybrid` / `decrypt_multi_hybrid` (multi-recipient, version-discriminated)
- `crypto/keys.rs` — `HybridKeyPair`, hybrid PEM encoders, `detect_key_type`
- `crypto/ephemeral_store.rs` — `*_for_contact_hybrid` parallel API for ratchet stores
- `crypto/mod.rs` — `encrypt_with_passphrase_hybrid`, `decrypt_with_passphrase_hybrid`, `detect_wire_format`, `WireFormat` enum
- `chat/protocol/handshake.rs` — PQXDH-shape handshake at chat protocol v2
- `chat/protocol/ratchet.rs` — `kem_ratchet_send` / `kem_ratchet_receive`

## Chat Security

The P2P chat uses the Double Ratchet protocol (like Signal) over Tor hidden services:

- Messages encrypted with per-message keys derived from ratchet chains
- Header encryption hides sequence numbers and DH public keys
- Carrier rotation via a separate KDF chain
- User passphrase combined with derived keys for additional entropy
- All cryptographic state is kept in RAM only and zeroized on session end
- Messages are NEVER written to disk

See [P2P Chat over Tor](chat.md) for usage details.
