# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Interactive wizard mode**: running `anyhide` without a subcommand now opens a guided TUI menu (powered by `cliclack`) covering every command surface — encode, decode, keygen, demo, chat, contacts, QR, and mnemonic flows. Subcommands continue to work exactly as before for scripting and power users; the wizard is purely a discoverable front door.
- **ANSI Shadow ASCII banner**: cyan ANYHIDE logo with the 6-dot braille mark on the left (same braille concept as the chat TUI's `⠿` icon), version and tagline below.
- **Cohesive screen flow**: each return to the home menu clears the terminal and repaints the banner, with a "Press Enter to return to menu" pause after each flow so output is readable before the next clear. Avoids the indefinite scrollback that pure prompt sequences accumulate.
- **"← Back" navigation**: every flow-level select prompt offers an explicit "← Back" option in addition to Esc/Ctrl+C — selecting it unwinds to the home menu without producing an error in the log.
- **Public demo mode** (`anyhide demo encode/decode/info`): bundles a public passphrase, a deterministic key (SHA-256 of `"ANYHIDE-PUBLIC-DEMO-KEY-V1"`), and a public text carrier so newcomers can experiment without generating an identity. Roundtrips byte-equal for plain ASCII messages. Every demo operation prints a blunt warning that the output is decodable by anyone. The wizard exposes the same flow as "Test mode (public demo)".
- New `cliclack` (0.3.x) and `console` (0.15) dependencies for prompt-style interactive UI and ANSI styling.
- New `wizard` module under `src/wizard/` (binary-only, not exposed via the library): home loop in `mod.rs`, shared input helpers in `helpers.rs`, per-command flows in `flows/{encode,decode,keygen,demo,chat,contacts,qr,mnemonic}.rs`. Each flow builds the matching `*Command` struct and calls `CommandExecutor::execute()` — no business logic is duplicated.
- New `demo` module (`src/demo.rs`, binary-only) holding the public bundle constants and the deterministic keypair derivation.

### Fixed

- Pressing Esc/Ctrl+C on the wizard home menu now exits gracefully with a "Bye!" outro instead of crashing the program with an io::Error.

## [0.15.0] - 2026-05-06

### Highlights

This release consolidates all on-disk Anyhide data under a single home directory, `~/.anyhide/`, with explicit `state/` and `cache/` separation. Previously chat profiles and Tor data were scattered across OS-specific locations, making backup, migration, and even just *finding* your identity harder than it should be. The new layout is identical across macOS, Linux, and Windows: `state/` holds your onion service keys (treat as backup material), `cache/` is safe to delete, and the `default` profile is now a real subdir like any other.

### Changed

- **Consolidated all Anyhide data under `~/.anyhide/`** (cross-platform: Unix uses `$HOME/.anyhide`, Windows uses `%USERPROFILE%\.anyhide`). Previously chat profiles and Tor data were split across OS-specific directories (`~/Library/Application Support/anyhide/` and `~/Library/Caches/anyhide/` on macOS, `~/.config/anyhide/` and `~/.local/share/anyhide/` and `~/.cache/anyhide/` on Linux). New unified layout:
  - `~/.anyhide/chat.toml` — default chat profile
  - `~/.anyhide/chat-<profile>.toml` — named chat profiles
  - `~/.anyhide/contacts.toml` — contact aliases (already used this path)
  - `~/.anyhide/contacts/` — public keys imported from chat identity QRs
  - `~/.anyhide/state/tor/<profile>/` — persistent Tor state, including onion service keys; the default profile now lives at `state/tor/default/` instead of arti's own default location
  - `~/.anyhide/cache/tor/<profile>/` — disposable Tor cache
- New `anyhide::paths` module exposes `home()`, `state_dir()`, `cache_dir()`, `tor_state_dir()`, `tor_cache_dir()`, and `imported_contacts_dir()` as the single source of truth for filesystem layout.
- `contacts::get_config_dir()` now delegates to `paths::home()`.

### Migration

This is a **breaking layout change**: existing chat identities (onion address, contacts, Tor state) will not be picked up automatically because the directories moved. To migrate:

```sh
# macOS
mv ~/Library/Application\ Support/anyhide/chat*.toml ~/.anyhide/
mv ~/Library/Application\ Support/anyhide/tor ~/.anyhide/state/tor
mv ~/Library/Caches/anyhide/tor ~/.anyhide/cache/tor

# Linux
mv ~/.config/anyhide/chat*.toml ~/.anyhide/
mv ~/.local/share/anyhide/tor ~/.anyhide/state/tor
mv ~/.cache/anyhide/tor ~/.anyhide/cache/tor
```

Or simply delete the old directories and run `anyhide chat init` again to start fresh.

### Added

- New `anyhide::paths` module: single source of truth for all filesystem paths used by Anyhide. Replaces ad-hoc `dirs::config_dir() / data_dir() / cache_dir()` calls scattered across `commands/chat.rs`, `chat/transport/tor.rs`, and `contacts/mod.rs`.

## [0.14.1] - 2026-05-06

### Fixed

- `anyhide --version` now reports the correct package version. Previously the version string in the CLI parser was a hardcoded literal (`"0.13.0"`) that drifted from `Cargo.toml` across the v0.14.0 bump, so v0.14.0 binaries identified themselves as `anyhide 0.13.0`. The CLI now derives its version from `CARGO_PKG_VERSION` at build time, so the reported version always matches `Cargo.toml`.

## [0.14.0] - 2026-05-05

### Highlights

This release adds an opt-in **post-quantum hybrid encryption** track (X25519 + ML-KEM-768) covering encoder, decoder, multi-recipient, and chat layers. Existing classical (v6) anyhide codes remain byte-identical and fully readable. The chat protocol forced a hard break to v2 — it is RAM-only with no persisted state, so the migration boundary is clean. Users who haven't migrated keep using classical keys; users who run `keygen --hybrid` get post-quantum confidentiality with no other workflow changes (encode / decode auto-detect the wire format from PEM headers).

### Added
  - Combines classical X25519 ECDH with ML-KEM-768 (FIPS 203, formerly Kyber-768)
  - Single-call API: `generate_keypair()`, `encapsulate()`, `decapsulate()`
  - HKDF-SHA256 combiner with `ANYHIDE-HYBRID-KEM-V1` info string mixes both shared secrets — security holds as long as either primitive remains secure
  - `try_decapsulate` on the PQ side rejects malformed ciphertexts explicitly instead of silently returning a pseudorandom value (implicit rejection)
  - `SharedKey` zeroizes on drop; intermediate IKM buffer in the combiner zeroizes after HKDF
  - Wire format constants exposed: `HYBRID_PUBKEY_SIZE = 1216`, `HYBRID_CT_SIZE = 1120`, `SHARED_KEY_SIZE = 32`
  - Fully serializable: `to_bytes()` / `from_bytes()` for both public keys and ciphertexts with strict length validation
  - Standalone module — not yet wired into encoder/decoder/ratchet/handshake (subsequent sessions)
  - 10 unit tests covering round-trip, wrong-key behavior, serialization, length validation, combiner determinism and divergence, and FIPS 203 size invariants

- **Hybrid asymmetric encryption** (`crypto/asymmetric.rs`)
  - `encrypt_hybrid` / `decrypt_hybrid` parallel to existing X25519-only API
  - `EncryptedDataHybrid` struct with byte-level serialization (`kem_ct (1120) || nonce (12) || aead_ct`)
  - HKDF-SHA256 with info `ANYHIDE-V3-ASYMMETRIC` derives the AEAD key from the hybrid shared secret
  - 6 unit tests: round-trip (struct + bytes), wrong-key rejection, serialization, short-input rejection, AEAD tamper detection
  - Existing X25519-only `encrypt`/`decrypt` functions left untouched for backward compatibility

- **Hybrid multi-recipient encryption** (`crypto/multi_recipient.rs`)
  - `MultiRecipientDataHybrid` struct with explicit `version: u8 = 2` discriminator
  - `RecipientKeyHybrid` per-recipient wrap: identifier is the X25519 component (32B), KEM ciphertext is the full hybrid (1120B)
  - `encrypt_multi_hybrid` / `decrypt_multi_hybrid` mirror the v1 API with `HybridPublicKey` / `HybridSecretKey`
  - HKDF-SHA256 with salt `ANYHIDE-MULTI-V2` and info `key-encryption` wraps the bulk message key per recipient
  - `from_bytes` validates the version byte — v1 bytes cannot be parsed as v2 (downgrade-attack defense at the serde layer)
  - 7 unit tests: single + 3-recipient round-trip, wrong-key, wrong-passphrase, no-recipients error, serialization, cross-version rejection
  - Existing v1 (X25519-only) struct, encrypt, and decrypt remain byte-compatible

- **Hybrid secret key serialization** (`crypto/hybrid_kem.rs`)
  - `HybridSecretKey::to_bytes()` / `from_bytes()` (96 bytes: 32B X25519 || 64B ML-KEM seed)
  - Uses ML-KEM `KeyExport` trait to round-trip through the FIPS 203 seed (`d || z`) rather than the deprecated 2,400-byte expanded form
  - `HybridKemError::InvalidSecretKey` variant for length/decode failures
  - Constants exposed: `HYBRID_SECRET_KEY_SIZE`, `CLASSICAL_SECRET_SIZE`, `PQ_SECRET_SEED_SIZE`
  - 2 additional unit tests: roundtrip recovers decapsulation, length validation

- **Hybrid keypair PEM** (`crypto/keys.rs`)
  - `HybridKeyPair` struct paralleling `KeyPair` (`generate()`, `generate_ephemeral()`, `public_key()`, `secret_key()`, `save_to_files()`, `load_from_files()`)
  - `KeyType::HybridV1` and `KeyType::EphemeralHybridV1` variants; `is_hybrid()` and `is_ephemeral_kind()` predicates
  - PEM headers: `-----BEGIN ANYHIDE HYBRID PUBLIC/PRIVATE KEY-----` and `EPHEMERAL HYBRID` variants
  - `encode_hybrid_public_key_pem` / `encode_hybrid_secret_key_pem` and matching `decode_*` and `load_*` helpers
  - `decode_public_key_pem_with_type` (classical) now refuses hybrid PEMs explicitly with a clear error instead of failing mid-base64 decode
  - `decode_hybrid_public_key_pem` (hybrid) symmetrically refuses classical PEMs
  - `detect_key_type` updated to distinguish all four variants (hybrid checked before classical because hybrid PEMs contain the `EPHEMERAL` substring)
  - 10 additional unit tests covering generation, PEM round-trip (long-term + ephemeral), file save/load, cross-type rejection, and `detect_key_type` discrimination

- **Hybrid ephemeral key store** (`crypto/ephemeral_store.rs`)
  - Parallel `_hybrid` functions for all three formats: `.eph.key` (private only), `.eph.pub` (public only), `.eph` (unified)
  - New JSON structs (`PrivateKeyEntryHybrid`, `PublicKeyEntryHybrid`, `UnifiedEntryHybrid`, `*StoreHybrid`) carry `version: u8 = 2`
  - `ContactKeysHybrid` mirrors `ContactKeys` with `HybridSecretKey` / `HybridPublicKey`
  - `generate_and_save_ephemeral_for_contact_hybrid` generates a hybrid keypair on the fly
  - All v2 functions (`*_hybrid`) probe the JSON `version` field before parsing and reject v1 stores with `EphemeralStoreError::VersionMismatch { expected: 2, found: 1 }`; v1 stores are never silently upgraded
  - File extensions are unchanged (`.eph`, `.eph.key`, `.eph.pub`) — v1 and v2 are distinguished by the embedded version field, not by filename
  - `EphemeralStoreError::HybridKemError` variant for KEM-level errors during decode
  - 9 additional unit tests covering each format round-trip, multiple contacts, public-key update, generate-and-save, contact-not-found, v2 rejecting v1, and v2 files serializing `"version": 2`

- **Hybrid PQ chat handshake protocol v2** (`chat/protocol/handshake.rs`)
  - **BREAKING**: bumped `CHAT_PROTOCOL_VERSION` from `1` to `2`. v2 peers refuse v1 connections and vice-versa — chat is RAM-only with no persisted state, so the hard break is a clean migration boundary
  - `HandshakeInit.ephemeral_public_hybrid: Vec<u8>` (1216 bytes) replaces the v1 32-byte X25519 ephemeral; `identity_public: [u8; 32]` (Ed25519 verifying key) is unchanged because authentication remains classical
  - `HandshakeResponse` adds `kem_ciphertext_to_initiator: Vec<u8>` (1120 bytes) — responder encapsulates against the initiator's hybrid eph pubkey to derive `ss_resp_to_init`
  - `HandshakeComplete` adds `kem_ciphertext_to_responder: Vec<u8>` (1120 bytes) — initiator encapsulates against the responder's hybrid eph pubkey to derive `ss_init_to_resp`
  - All new structs validate wire-size invariants on construction and via `validate()` post-deserialization; `HandshakeError::InvalidSize` and `VersionMismatch` give specific error feedback
  - KEM helper functions exposed for callers: `responder_encapsulate_to_initiator`, `initiator_decapsulate_from_responder`, `initiator_encapsulate_to_responder`, `responder_decapsulate_from_initiator`, `parse_peer_pubkey`, `parse_kem_ciphertext`
  - Two-direction KEM design ("PQXDH-shape"): both sides contribute KEM entropy; the master session secret mixes both shared secrets via `derive_master_secret(ss_resp_to_init, ss_init_to_resp)` with HKDF info `ANYHIDE-CHAT-V2-MASTER`

- **Hybrid PQ KEM ratchet** (`chat/protocol/ratchet.rs`)
  - `kem_ratchet_send` replaces `dh_ratchet`: generates a fresh `HybridKeyPair` and encapsulates against the peer's current pubkey to derive a new send chain. Returns `KemRatchetOutput { new_secret, new_public, kem_ciphertext, send_chain }`
  - `kem_ratchet_receive`: receiver decapsulates the ciphertext attached to the incoming message header to recover the same shared secret and derive the matching recv chain
  - `derive_session_keys` now takes a 32-byte master secret instead of a single DH shared secret; HKDF info binds both ephemeral pubkeys (initiator first) for transcript binding
  - `derive_master_secret(ss_resp_to_init, ss_init_to_resp)` mixes the two handshake KEM secrets into a single master via HKDF
  - `derive_handshake_carrier_key(shared_secret, responder)` derives per-direction carrier-encryption keys with domain-separated HKDF labels (`ANYHIDE-CHAT-V2-RESP-CARRIERS` / `ANYHIDE-CHAT-V2-INIT-CARRIERS`)
  - Symmetric KDF chain (`kdf_chain`), carrier chain (`advance_carrier_chain`), and per-message passphrase derivation (`derive_message_passphrase`) are unchanged from v1

- **Hybrid PQ message header** (`chat/protocol/header.rs`)
  - `MessageHeader.dh_public_hybrid: Vec<u8>` (1216 bytes) replaces v1 `dh_public: [u8; 32]`
  - `MessageHeader.kem_ciphertext: Option<Vec<u8>>` (1120 bytes when `Some`) is attached only on messages that perform a ratchet step; chain-mode messages set it to `None` to keep per-message overhead at the pubkey size
  - `encrypt_header` / `decrypt_header` validate sizes before/after AEAD; `HEADER_PUBKEY_SIZE` and `HEADER_KEM_CT_SIZE` constants exposed

- **`ChatSession` migrated to hybrid types** (`chat/session.rs`)
  - `init_as_initiator` / `init_as_responder` take `HybridSecretKey` + `HybridPublicKey` and a 32-byte master secret (from `derive_master_secret`) instead of `StaticSecret` / `PublicKey` and computing DH internally
  - Internal state uses `HybridSecretKey` / `HybridPublicKey` directly; the X25519 component (32B) of the hybrid pubkey is used as the compact identifier for skipped-message-key bookkeeping (HashMap keys stay small)
  - `pending_kem_ct` field stashes the KEM ciphertext produced by a sender-side ratchet step; consumed and attached to the next outgoing message header
  - `Drop` impl preserved: chain keys, signing key, passphrases, carriers, and skipped-key cache are zeroized; hybrid keys self-zeroize via `x25519-dalek` + `ml-kem` `zeroize` features
  - `receive_message` rejects v1 wire messages (any `version != CHAT_PROTOCOL_VERSION`) with `ChatError::VersionMismatch`
  - Per-message anyhide encoding still uses an ephemeral X25519 keypair derived from the message key — confidentiality at that layer comes from the KEM-derived chain key plus the user passphrase, not from the encoding's pubkey

- **Chat command handshake migrated** (`commands/chat.rs`)
  - All four handshake call sites (`perform_initiator_handshake`, `perform_responder_handshake`, `perform_accept_handshake`, `perform_connect_handshake`) rewritten to use hybrid KEM operations
  - Ephemeral keypair generation uses `hybrid_kem::generate_keypair()` instead of `StaticSecret::random_from_rng`
  - Carrier-encryption keys derived from KEM shared secrets (one per direction) instead of the v1 DH-then-HKDF derivation; signed handshake data binds the new pubkey + ciphertext fields
  - Bumped wire version constant in all `WireMessage::new` calls to `CHAT_PROTOCOL_VERSION` (now 2)

- **Chat identity & contact validation requires hybrid PQ keys** (`commands/chat.rs`)
  - `init_identity`, `add_contact`, and `add_contact_from_dialog` now invoke `require_hybrid_encryption_pubkey` / `require_hybrid_encryption_keypair` to validate the encryption key is hybrid before accepting it
  - Error messages on classical keys explicitly point to `anyhide keygen --hybrid -o <path>` and explain that the chat protocol now requires post-quantum hybrid keys
  - Loaders check the PEM header type rather than just the file size, so a classical PEM is rejected up front instead of failing later inside the handshake
  - Signing identity continues to use Ed25519 — only encryption migrates

- **Chat Identity QR bumped to v2** (`commands/chat.rs`)
  - `CHAT_QR_VERSION` `0x01` → `0x02`. v2 wire format: `magic(4) | version(1) | onion(56) | enc_pubkey_hybrid(1216) | sign_pubkey(32) | nick_len(1) | nick(0-63)`
  - `encode_chat_identity` / `decode_chat_identity` updated to handle 1216-byte hybrid encryption pubkey; signing pubkey unchanged at 32 bytes
  - `decode_chat_identity` validates magic + version *before* the body-size check so v1 QR codes report "Unsupported QR version (regenerate with `anyhide keygen --hybrid` and re-export)" instead of a confusing "too short" error
  - `import_qr_contact` writes the encryption pubkey using the new hybrid PEM format (`-----BEGIN ANYHIDE HYBRID PUBLIC KEY-----`)
  - Total wire size grows from ~126 bytes (v1) to ~1310 bytes (v2) — still well within QR Version 40 capacity at error correction L

- **`EphemeralContact.public_key` is now `Vec<u8>` (1216 bytes)**
  - `parse_ephemeral_from_args` accepts hybrid pubkey hex (2432 characters); rejects 32-byte (v1) hex with a clear error pointing to `--from-qr` as the recommended UX
  - The function emits a stderr note recommending `--from-qr` whenever it succeeds — typing 2432 hex chars on a CLI is impractical, QR is the path
  - `parse_ephemeral_from_qr` (preferred path) decodes hybrid pubkey directly from QR bytes — no UX change for users on this path

- **Hybrid wire format dispatcher (cripto layer)** (`crypto/mod.rs`)
  - New constants: `HYBRID_WIRE_MAGIC = b"AHV7"` (4 bytes), `HYBRID_WIRE_VERSION = 1`, `HYBRID_WIRE_PREFIX_LEN = 5`
  - Hybrid (v7) anyhide codes carry a 5-byte magic+version prefix; classical (v6) codes have no prefix and start directly with a 32-byte X25519 ephemeral pubkey. Magic chosen to make collision with the random first bytes of a v6 code statistically negligible (~1/2^32)
  - `WireFormat` enum (`ClassicalV6`, `HybridV7`) plus `detect_wire_format(ciphertext)` for sniffing the wire format without first decrypting
  - `encrypt_with_passphrase_hybrid(plaintext, passphrase, &HybridPublicKey) -> Vec<u8>` produces v7 codes by composing compress → symmetric encrypt → hybrid asymmetric encrypt → magic prefix
  - `decrypt_with_passphrase_hybrid(ciphertext, passphrase, &HybridSecretKey) -> Vec<u8>` consumes v7 codes; rejects classical inputs and unsupported version bytes explicitly
  - Hybrid keys cannot decrypt v6 codes by design — a hybrid keypair is a fresh identity, not a superset of the user's classical keypair. Users migrating to PQ keep their classical private key on hand to read pre-migration codes
  - Existing `encrypt_with_passphrase` / `decrypt_with_passphrase` (classical X25519) untouched — backward compatibility for v6 codes is preserved at the byte level
  - 8 unit tests: round-trip, magic prefix emission, format detection (v6 vs v7), short-input fallback, classical input rejection, unsupported-version rejection, wrong-secret rejection, wrong-passphrase rejection

- **Hybrid encoder / decoder entry points** (`encoder.rs`, `decoder.rs`)
  - 6 new public encoder functions (`encode_hybrid`, `encode_with_config_hybrid`, `encode_with_carrier_hybrid`, `encode_with_carrier_config_hybrid`, `encode_bytes_with_carrier_hybrid`, `encode_bytes_with_carrier_config_hybrid`) that take `&HybridPublicKey` and emit v7 wire-format codes
  - 6 new public decoder functions (`decode_hybrid`, `decode_with_config_hybrid`, `decode_with_carrier_hybrid`, `decode_with_carrier_config_hybrid`, `decode_bytes_with_carrier_hybrid`, `decode_bytes_with_carrier_config_hybrid`) that take `&HybridSecretKey` and consume v7 codes
  - Existing classical `encode*` / `decode*` functions retain their `&PublicKey` / `&StaticSecret` signatures — backward-compatible for v6 codes
  - Internal `RecipientKey<'a>` (encoder) and `DecryptionKey<'a>` (decoder) enums + `dispatch_encrypt` / `dispatch_decrypt` helpers share fragmentation / padding / signing logic between classical and hybrid paths instead of duplicating ~600 lines
  - New `EncoderError::RatchetUnsupportedForHybrid`: forward-secrecy ratchet (`config.ratchet = true`) is rejected with hybrid recipients because `EncodedMessage.next_keypair` is X25519-only and the hybrid ratchet is a follow-up. Classical ratchet semantics are unchanged
  - Wire-format mismatches (v7 code + classical secret, or v6 code + hybrid secret) decrypt to garbage via the existing never-fail decoder semantics — no panics, no leaked information
  - 4 new decoder tests + 3 new encoder tests covering: hybrid round-trip, hybrid wrong-secret garbage, classical-decoder rejecting v7 input, hybrid-decoder rejecting v6 input, v7 magic-prefix emission, v6 magic-prefix absence, hybrid-encoder rejecting `--ratchet`
  - Total tests: 388 → 395
  - All hybrid functions re-exported at the crate root in `lib.rs`

- **CLI auto-dispatch between classical and hybrid PQ at the encode / decode commands** (`commands/{encode,decode,multi_encrypt,multi_decrypt}.rs`)
  - `anyhide encode` and `anyhide decode` now sniff the recipient / user PEM header (via `detect_key_type`) and route to the matching encoder / decoder family. Classical PEMs (`BEGIN ANYHIDE PUBLIC KEY` / `PRIVATE KEY`) produce / consume v6 codes; hybrid PEMs (`BEGIN ANYHIDE HYBRID …`) produce / consume v7 codes. No flag needed for the common path
  - Verbose mode prints which flavor was loaded: `Loaded recipient's public key from <path> (classical)` or `(hybrid PQ)`
  - Encode CLI rejects `--ratchet` early with a friendly message when the recipient is a hybrid key, mirroring `EncoderError::RatchetUnsupportedForHybrid` from the lib layer
  - Wire-format / key-flavor mismatches at decode (v6 code + hybrid secret, or v7 code + classical secret) flow through the lib's never-fail decoder and yield deterministic garbage — no panics, no leaks
  - Ephemeral-store paths (`--eph-file`, `--eph-keys`/`--eph-pubs`) remain classical-only via the CLI surface; hybrid PQ ephemeral stores have a parallel API but are not yet wired into encode / decode commands
  - `anyhide multi-encrypt`: requires all `--keys` to share a flavor (all classical or all hybrid) and dispatches between `encrypt_multi` (v1) and `encrypt_multi_hybrid` (v2). Mixed-flavor lists fail fast with a clear error pointing at the first off-flavor key
  - `anyhide multi-decrypt`: auto-detects the payload flavor from its leading version byte (0x02 = hybrid v2) and the key flavor from the PEM header, requires the two to match, and dispatches to the matching decrypt family
  - 5 new integration tests under `hybrid_dispatcher` covering round-trip with a text carrier, round-trip with a binary payload, v7 magic-prefix emission, v6 magic-prefix absence, and cross-format garbage on mismatch
  - Total tests: 395 → 400, no regressions

- **`keygen --hybrid` flag** (`commands/keygen.rs`)
  - New `--hybrid` flag generates a `HybridKeyPair` (X25519 + ML-KEM-768) for encryption alongside the standard Ed25519 signing keypair
  - Required for chat protocol v2 — classical X25519 keys are no longer accepted by the chat handshake
  - Combines with `--ephemeral` for a hybrid ephemeral keypair, written either as individual files (default) or to a v2 consolidated store (see below)
  - `--show-mnemonic` works with `--hybrid`: the 96-byte hybrid secret is split into three 24-word BIP39 phrases (X25519, ML-KEM seed `d`, ML-KEM seed `z`)

- **BIP39 mnemonic backup for hybrid PQ keys** (`crypto/mnemonic.rs`, `commands/{keygen,export_mnemonic,import_mnemonic}.rs`)
  - New library helpers `hybrid_key_to_mnemonics(&[u8; 96]) -> [Vec<String>; 3]` and `mnemonics_to_hybrid_key(&[Vec<String>; 3]) -> Result<[u8; 96]>` split / reassemble the 96-byte hybrid secret across three independent 24-word BIP39 phrases. Each phrase carries its own 8-bit SHA-256 checksum, validated independently — a typo in one phrase fails fast with `MnemonicError` rather than corrupting the recovered key
  - `keygen --hybrid --show-mnemonic` prints all three phrases labeled "1/3 (X25519 component)", "2/3 (ML-KEM seed d)", "3/3 (ML-KEM seed z)" plus the Ed25519 signing phrase. Replaces the previous "not yet supported" warning
  - `export-mnemonic` detects `BEGIN ANYHIDE HYBRID PRIVATE KEY` PEMs and dispatches to the hybrid printer, emitting all three labeled phrases. Classical and signing PEMs continue to use the single-phrase path
  - `import-mnemonic --key-type hybrid` prompts the user for the three phrases in order, validates each independently, reconstructs the `HybridSecretKey` via `from_bytes`, derives the matching `HybridPublicKey`, and writes the resulting `HYBRID PRIVATE / PUBLIC KEY` PEM pair (with `chmod 600` on the secret file on Unix). Bypasses `HybridKeyPair::save_to_files` because the type has no public from-bytes constructor; the encoder helpers work directly off the secret / public keys
  - 3 new `crypto::mnemonic` unit tests covering 96-byte round-trip, independent component round-trip through the single-phrase API, and per-phrase corruption detection

- **Hybrid PQ consolidated ephemeral storage via the `keygen` CLI** (`commands/keygen.rs`)
  - `--hybrid --ephemeral --eph-keys <path> --eph-pubs <path> --contact <name>` now wires through to `save_private_key_for_contact_hybrid` / `save_public_key_for_contact_hybrid` (separate v2 stores)
  - `--hybrid --ephemeral --eph-file <path> --contact <name>` now wires through to `save_unified_keys_for_contact_hybrid` (unified v2 store). The placeholder peer pubkey is a throwaway hybrid keypair rather than zero bytes, since `HybridPublicKey::from_bytes` rejects malformed ML-KEM components
  - v2 stores embed `"version": 2` and refuse v1 files at write time with `EphemeralStoreError::VersionMismatch { expected: 2, found: 1 }` — classical and hybrid stores live in distinct paths, no in-place migration
  - v2 stores carry the `EPHEMERAL HYBRID` PEM header for printed pubkeys (vs `EPHEMERAL` for classical); peers exchange their stores out of band as before
  - The CLI surface for hybrid finally matches the classical surface: long-term, individual ephemeral, separate consolidated, and unified consolidated all work with `--hybrid`. The library API for hybrid stores existed since session 38; this commit only wires the CLI

### Dependencies

- Added `ml-kem = "0.3.0"` with `zeroize` and `getrandom` features (RustCrypto pure-Rust implementation)

## [0.13.0] - 2025-12-23

### Added

- **Multi-Contact Chat TUI Dashboard**
  - Full-featured TUI with sidebar contacts, conversation tabs, and concurrent sessions
  - `anyhide chat` (no args) launches the dashboard
  - Sidebar shows all contacts with online/offline/connecting status
  - Tab-based conversations: open multiple chats simultaneously
  - **Request/Accept Protocol**:
    - Incoming connections require manual acceptance (privacy-first)
    - Notifications separated by type: known contacts (👤) vs unknown (👻)
    - `r` to view known contact requests, `z` for unknown requests
    - `n` to view next notification, `N` to mark all as seen
    - Prevents DDoS via chat requests - you choose who to talk to
  - **Connect on-demand**: Select contact + Enter to initiate connection
  - **Add Contact dialog**: Press `+` in sidebar for multi-field form (Name, Onion, Public Key, Sign Key)
  - **Quick Ephemeral dialog**: Press `e` in sidebar to start ephemeral chat by onion address

- **UI Branding and Theming**
  - App icon `⠿` (braille 6 dots) with `⠿ anyhide` title bar and version number
  - Outer border with rounded corners (`border::ROUNDED`)
  - Consistent cyan theme color throughout all panels
  - Separator line below title bar

- **Ratatui Native Tabs Widget**
  - Active tab: cyan background, black text, bold
  - Inactive tabs: dark gray text
  - Unread badge format: ` alice (2) `
  - No brackets in tab labels (clean look)

- **Message Scrollbar**
  - Vertical scrollbar on the message area (right side)
  - Only appears when content overflows visible area
  - Symbols: `▲` (up), `▼` (down), `│` (track), `█` (thumb)
  - Position synchronized with scroll offset

- **Doom-style Command Console**
  - Drop-down overlay from top of screen (40% height)
  - Rounded border with `⠿ Console` title
  - Open with `/` (from sidebar/tabs) or `Ctrl+P` (from anywhere including input)
  - Close with `Esc`
  - Command history navigation with `↑`/`↓` arrows
  - Output scrolling with `PageUp`/`PageDown`
  - All console state securely zeroized (`console_zeroize()`) on session end
  - Available commands:
    - `/quit` (`q`, `exit`) - Quit application
    - `/close` (`c`) - Close active tab
    - `/status` (`s`) - Show session status
    - `/clear` - Clear messages or console output
    - `/requests` (`r`) - Show pending chat requests
    - `/notifications` (`n`) - Show notification count
    - `/help` (`h`, `?`) - Show commands; `/help keys` shows all keyboard shortcuts
    - `/debug` (`d`) - Show debug info (onion, contacts, sessions, Tor status)
    - `/myonion` (`me`) - Show your .onion address
    - `/who <name>` - Show a contact's .onion address

- **Enhanced Status Bar**
  - Tor connection status: `🔒 Tor ●` / `⚠ Tor ○` / `◐ Tor...`
  - Chat/hidden service status: `Chat ●` / `Chat ◐` / `Chat ○`
  - Truncated .onion address
  - Pending request indicators: `👤N` (known), `👻N` (unknown)
  - Unseen notification indicator: `🔔N`
  - Context-sensitive keyboard hints per focused panel:
    - Sidebar: `↑↓: nav | Enter: open | /: console`
    - Tabs: `←→: tabs | PgUp/Dn: scroll | /: console`
    - Input: `Enter: send | PgUp/Dn: scroll | Ctrl+P: console`
  - Temporary status messages with 5-second auto-expiry

- **Keyboard Navigation**
  - Global: `Ctrl+Q` quit, `Ctrl+P` console, `Tab`/`Shift+Tab` cycle panels
  - Global: `Ctrl+W` close tab, `Ctrl+←/→` or `Alt+←/→` switch tabs, `Alt+1-9` go to tab
  - Sidebar: `↑/↓` or `j/k` navigate, `Enter` open, `+` add, `e` ephemeral, `/` console
  - Sidebar: `r` known requests, `z` unknown requests, `n` view notification, `N` mark all seen
  - Tabs: `←/→` or `h/l` switch, `PageUp/Down` scroll 5 lines, `Ctrl+↑/↓` scroll 1 line
  - Input: `Enter` send, `PageUp/Down` scroll 5 lines, `Ctrl+↑/↓` scroll 1 line
  - Console: `↑/↓` history, `PageUp/Down` scroll output, `Esc` close

- **Ephemeral Chat Contacts**
  - Chat without saving contact to config file
  - `anyhide chat -e --onion <addr> --pubkey <hex> --sign-key <hex>` - Inline keys
  - `anyhide chat -e --from-qr <image>` - Import from QR code
  - Contact appears as `~ephemeral` in TUI
  - Ideal for one-time conversations or maximum privacy
  - Same security features as regular chat (Double Ratchet, Tor, etc.)

### Changed

- `Ctrl+C` no longer quits the application (only `Ctrl+Q` and `Esc` do)
- Contact status icons updated: `◀` for incoming request, `▶` for pending accept

### Fixed

- **Security: Complete zeroization of chat session keys on drop**
  - All sensitive key material is now properly zeroized when session ends
  - Affects: `send_chain`, `recv_chain`, `carrier_chain`, `my_dh_secret`,
    `user_passphrase`, `derived_passphrase`, `my_signing_key`
  - Note: Messages and session keys are NEVER written to disk in ANY chat mode
  - The only difference between normal and ephemeral chat is whether the
    contact identity is saved to `chat.toml`

- **Security: Console state zeroization**
  - All console input, output history, and command history are securely
    zeroized when the session ends (`console_zeroize()`)

```bash
# Ephemeral chat with inline keys
anyhide chat -e \
  --onion xyz123abc.onion \
  --pubkey 0101010101010101010101010101010101010101010101010101010101010101 \
  --sign-key 0202020202020202020202020202020202020202020202020202020202020202

# Ephemeral chat from QR code
anyhide chat -e --from-qr contact_qr.png
```

## [0.12.0] - 2025-12-19

### Added

- **Multi-Carrier Encoding**
  - Use multiple carriers concatenated in order: `-c file1 -c file2 -c file3`
  - Order matters! Different order = different carrier = garbage on decode
  - Provides N! additional security combinations (2 carriers = 2, 3 = 6, 4 = 24, 5 = 120)
  - Single carrier backwards compatible (preserves text vs binary detection)
  - Multiple carriers are always read as bytes and concatenated

```bash
# Encode with multiple carriers
anyhide encode -c photo.jpg -c song.mp3 -c doc.pdf -m "secret" -p "pass" --their-key bob.pub

# Decode with EXACT same order
anyhide decode -c photo.jpg -c song.mp3 -c doc.pdf --code "..." -p "pass" --my-key bob.key

# Wrong order = garbage (plausible deniability maintained)
anyhide decode -c song.mp3 -c photo.jpg -c doc.pdf --code "..." -p "pass" --my-key bob.key
```

- **Chat Identity QR Code**
  - Share chat identity via QR code for easy contact exchange
  - `anyhide chat export-qr -o identity.png` - Generate QR with your onion address and keys
  - `anyhide chat import-qr identity.png -n alice` - Scan QR and add contact
  - Compact binary format (~170 bytes): magic + version + onion(56) + enc_key(32) + sign_key(32) + nickname
  - Supports PNG, JPEG, GIF, BMP output formats
  - `anyhide chat me` - Display your own identity info

- **Pre-shared Carriers for Chat**
  - Optional: Use pre-shared carrier files instead of random carriers
  - `anyhide chat bob -c photo.jpg -c song.mp3` - Both parties must use same files in same order
  - Carrier files are NEVER transmitted over the network - only hash is verified
  - Files become an additional secret factor (N files = N! combinations)
  - `CarrierMode` enum: `Random` (default) vs `PreShared { hash }`
  - Hash mismatch between parties produces clear error message

### Changed

- CLI argument `-c`/`--carrier` now accepts multiple values
- `Carrier::from_files()` method added for library users

## [0.11.1] - 2025-12-18

### Fixed

- **Cross-compilation for aarch64-linux**
  - Added bundled SQLite for aarch64-linux-gnu target
  - Fixes CI build failure due to missing `libsqlite3` when cross-compiling

## [0.11.0] - 2025-12-18

### Added

- **P2P Chat over Tor**
  - Real-time encrypted chat using Tor hidden services
  - Simple command: `anyhide chat <contact>` - no server/client distinction
  - Both peers are equal: both create hidden services and race to connect
  - `anyhide chat init` - Initialize your chat identity
  - `anyhide chat add/list/show/remove` - Manage chat contacts
  - Double Ratchet protocol for forward secrecy
  - Random carrier generation at handshake time
  - Ed25519 signature verification for message authenticity
  - Bidirectional connection with `tokio::select!` - first to connect wins
  - User passphrase required for each session (combined with DH-derived keys)

- **Terminal User Interface (TUI)**
  - Visual chat interface built with ratatui
  - Three-panel layout: header (status), messages, input
  - Color-coded messages: green (you), blue (peer), yellow (system)
  - Connection status indicator with message counters
  - Character counter showing remaining chars (max 256)
  - Input limit enforced - cannot exceed max length
  - Counter turns yellow (<20 chars) and red (0 chars)
  - Scroll support for message history (Page Up/Down, Ctrl+Up/Down)
  - Chat commands: `/quit`, `/status`, `/help`, `/clear`
  - Keyboard shortcuts: Ctrl+C to quit, Enter to send

- **Async Runtime Migration**
  - Full async support using tokio runtime
  - `MessageTransport` trait converted to async
  - TCP transport migrated to `tokio::net`
  - Concurrent message handling with `tokio::select!`

- **Tor Transport (always included)**
  - `AnyhideTorClient` - Tor client wrapper using arti-client v0.37
  - `TorConnection` - Bidirectional message stream over Tor
  - `TorListener` - Accept connections on a hidden service
  - Custom .onion address generation from HsId
  - Security warnings about Arti's experimental status

- **Chat Configuration**
  - Chat contacts stored in `~/.anyhide/chat.toml`
  - Separate from regular contacts (chat requires .onion addresses)
  - Identity configuration with key paths

### Dependencies

- Added `arti-client` v0.37
- Added `tor-rtcompat` v0.37
- Added `tor-hsservice` v0.37
- Added `tor-hscrypto` v0.37
- Added `tor-cell` v0.37
- Added `futures` v0.3
- Added `async-trait` v0.1
- Added `ratatui` v0.29
- Added `crossterm` v0.28

### Security Notes

- **Arti Warning**: Arti's onion services are experimental and not as secure as C-Tor
- **Tor-Only Chat**: All chat traffic goes through Tor - no plaintext option
- **Random Carriers**: Carriers are generated with CSPRNG at handshake time
- **Forward Secrecy**: DH ratchet on direction change protects past messages

### Fixed

- **Hidden passphrase input** - Passphrase is now hidden when typing (uses rpassword)
- **Onion address checksum** - Fixed v3 .onion address generation using SHA3-256 (was incorrectly using SHA2-256)
- **Handshake data transmission** - Binary handshake data is now Base64 encoded to prevent corruption
- **Sign key path handling** - Fixed path normalization to accept both `alice` and `alice.sign.key` formats
- **Onion address available at init** - Your .onion address is now generated and saved during `chat init` (no longer requires starting a chat)
- **Message character limit** - Fixed to 256 characters (was incorrectly set to 1024)
- **Input text scrolling** - Long input text now scrolls horizontally, keeping cursor visible
- **Message text wrapping** - Long messages now wrap at word boundaries with indentation on continuation lines
- **Connection reliability** - Automatic retry on connection and handshake failures (Tor circuits can be flaky)

### Added (Post-Release Fixes)

- **Profile support for local testing** - `--profile <name>` flag allows running multiple identities on the same machine
  - Each profile gets separate config: `~/.config/anyhide/chat-<profile>.toml`
  - Each profile gets separate Tor state: `~/.local/share/anyhide/tor/<profile>/`
  - Useful for testing chat locally between two terminals
- **`chat show me` command** - View your own identity and .onion address
- **Proper Tor directory permissions** - State directories are created with 0700 permissions (required by Arti)

### Dependencies (Additional)

- Added `rpassword` v7.0 for hidden password input
- Added `sha3` v0.10 for proper onion address checksum calculation

### Examples

```bash
# Setup (one time)
anyhide keygen -o alice
anyhide keygen -o alice --signing
anyhide chat init -k alice -s alice.sign
anyhide chat add bob xyz.onion --key bob.pub --sign-key bob.sign.pub

# Start chatting
anyhide chat bob
# Enter passphrase when prompted (input is hidden)

# Local testing with profiles (two terminals on same machine)
# Terminal 1:
anyhide chat --profile alice init -k alice -s alice.sign
anyhide chat --profile alice add bob <bob.onion> --key bob.pub --sign-key bob.sign.pub
anyhide chat --profile alice bob

# Terminal 2:
anyhide chat --profile bob init -k bob -s bob.sign
anyhide chat --profile bob add alice <alice.onion> --key alice.pub --sign-key alice.sign.pub
anyhide chat --profile bob alice

# TUI Interface:
# ┌─ Anyhide Chat - bob ─────────────────────────────────┐
# │ Connected | abc123...onion | 2↑ 1↓                   │
# ├──────────────────────────────────────────────────────┤
# │                                                      │
# │  [14:32] Connected to bob                            │
# │  [14:32] Type /help for commands. Ctrl+C to quit.    │
# │  [14:33] you: Hello Bob!                             │
# │  [14:33] bob: Hi Alice!                              │
# │                                                      │
# ├─ Input ──────────────────────────────────────────────┤
# │ > your message here...                  11/256       │
# └──────────────────────────────────────────────────────┘

# Commands: /quit, /status, /help, /clear
```

## [0.10.0] - 2025-12-17

### Added

- **Mnemonic Backup (BIP39-style)**
  - Export private keys as 24-word mnemonic phrases for paper backup
  - `--show-mnemonic` flag in keygen to display backup phrases after key generation
  - `anyhide export-mnemonic <key-file>` to export existing keys
  - `anyhide import-mnemonic -o <output>` to restore keys from mnemonic (interactive)
  - `--key-type encryption|signing` to specify which key type to import
  - BIP39 English wordlist (2048 words)
  - Checksum validation to detect typos
  - Only for long-term keys (.key, .sign.key) - ephemeral keys are not supported

- **Contacts with Aliases**
  - Store contact public keys with aliases in `~/.anyhide/contacts.toml`
  - `anyhide contacts list` - show all contacts
  - `anyhide contacts add <name> <key-path>` - add a contact
  - `anyhide contacts add <name> <key-path> --signing <sign-pub>` - with signing key
  - `anyhide contacts remove <name>` - remove a contact
  - `anyhide contacts show <name>` - show contact details with fingerprint (emoji)
  - `--to <alias>` flag in encode to use contact's key instead of `--their-key`

### Library

- Export `key_to_mnemonic`, `mnemonic_to_key`, `validate_mnemonic`, `format_mnemonic`, `MnemonicError`
- Export `Contact`, `ContactsConfig`, `ContactsError`, `get_config_dir`, `resolve_contact_key`
- `KeyPair::from_secret_bytes()` to create keypair from raw bytes
- `SigningKeyPair::from_secret_bytes()` to create signing keypair from raw bytes

### Examples

```bash
# Generate keys with mnemonic backup
anyhide keygen alice --show-mnemonic
# Shows 24 words for both encryption and signing keys

# Export existing key as mnemonic
anyhide export-mnemonic alice.key
# Output: 24 words

# Restore key from mnemonic
anyhide import-mnemonic -o restored
# Prompts for 24 words, creates restored.pub + restored.key

# Restore signing key
anyhide import-mnemonic -o restored --key-type signing
# Creates restored.sign.pub + restored.sign.key

# Add contact
anyhide contacts add bob /path/to/bob.pub
anyhide contacts add bob /path/to/bob.pub --signing /path/to/bob.sign.pub

# Use contact in encode
anyhide encode -m "Hello" -c carrier.txt -p pass --to bob
# Instead of --their-key /path/to/bob.pub

# Show contact with fingerprint
anyhide contacts show bob
# Shows paths and emoji fingerprint for verification
```

## [0.9.1] - 2025-12-17

### Security

- **Fixed: Duress password now signs both messages**
  - Previously only the real message was signed, decoy had no signature
  - An attacker who knows the sender always signs could distinguish real from decoy
  - Now both real and decoy messages are signed with the same key
  - Messages are now indistinguishable based on signature presence

### Added

- Test to verify both messages are signed when using duress password with `--sign`

## [0.9.0] - 2025-12-17

### Added

- **Key Fingerprints** - Out-of-band key verification
  - `anyhide fingerprint <key-file>` command to display key fingerprints
  - Three output formats: `--format hex` (default), `--format emoji`, `--format art`
  - Hex format: SHA-256 hash in hexadecimal (64 characters)
  - Emoji format: Hash as emoji sequence (16 emojis) - easy to compare verbally
  - Art format: SSH-style randomart visual representation
  - Works with all key types: public (.pub), private (.key), signing (.sign.pub, .sign.key)

- **Duress Password (Plausible Deniability)**
  - Encode two messages with different passphrases in the same code
  - `--decoy <MESSAGE>` flag for the innocent decoy message
  - `--decoy-pass <PASS>` flag for the decoy passphrase
  - Real passphrase reveals real message, decoy passphrase reveals decoy
  - If coerced, give the decoy passphrase to reveal innocent content
  - Wrong passphrase (neither real nor decoy) returns garbage as usual

### Library

- Export `DecoyConfig` struct for library users
- New `fingerprint` command module

### Examples

```bash
# Key fingerprint verification
anyhide fingerprint alice.pub
# Output: a1b2c3d4...

anyhide fingerprint alice.pub --format emoji
# Output: 🔐🌟🎯🚀...

anyhide fingerprint alice.pub --format art
# Output: SSH-style randomart

# Duress password encoding
anyhide encode -c carrier.txt -m "Secret meeting at 3pm" -p "realpass" \
    --their-key bob.pub \
    --decoy "Happy birthday party!" --decoy-pass "innocent"

# Decode with real passphrase → "Secret meeting at 3pm"
# Decode with decoy passphrase → "Happy birthday party!"
# Decode with wrong passphrase → garbage
```

## [0.8.1] - 2025-12-17

### Added

- **Automatic Ratchet Key Management**
  - Keys now rotate automatically without manual intervention
  - `--my-key` flag for encode (auto-saves next private key after encoding)
  - `--their-key` flag for decode (auto-saves sender's next public key)
  - `--eph-file` + `--contact` for consolidated key stores

- **New CLI Parameters**
  - `--their-key <PATH>`: Specify recipient's public key (encode) or sender's public key (decode)
  - `--my-key <PATH>`: Specify your private key file for automatic ratchet updates
  - `--eph-file <PATH>`: Unified ephemeral key store file (.eph)
  - `--eph-keys <PATH>`: Separated ephemeral private keys file (.eph.key)
  - `--eph-pubs <PATH>`: Separated ephemeral public keys file (.eph.pub)
  - `--contact <NAME>`: Contact name when using ephemeral stores

- **Clean Message Output**
  - Decoded messages now show only the message content by default
  - Key rotation information only shown with `-v` (verbose) flag
  - Cleaner user experience for end users

### Deprecated

- `--key` flag (both encode and decode)
  - Use `--their-key` for encode (recipient's public key)
  - Use `--my-key` for decode (your private key)
  - Shows warning when used, still works for backwards compatibility

### Changed

- Forward secrecy ratchet is now fully automatic when using ephemeral stores
- Encode: After encoding with `--ratchet`, next keypair is saved automatically
- Decode: After decoding, sender's next public key is saved automatically
- Key rotation requires no manual copying/pasting of keys

### Examples

```bash
# Automatic ratchet with individual files
anyhide encode -c carrier.txt -m "Hello" -p "pass" \
    --their-key bob.pub --my-key alice.key --ratchet
# alice.key is automatically updated with next keypair

anyhide decode --code "..." -c carrier.txt -p "pass" \
    --my-key bob.key --their-key alice.pub
# alice.pub is automatically updated with sender's next key

# Automatic ratchet with unified store (recommended)
anyhide encode -c carrier.txt -m "Hello" -p "pass" \
    --eph-file contacts.eph --contact bob --ratchet

anyhide decode --code "..." -c carrier.txt -p "pass" \
    --eph-file contacts.eph --contact alice

# Automatic ratchet with separated stores
anyhide encode -c carrier.txt -m "Hello" -p "pass" \
    --eph-keys mykeys.eph.key --eph-pubs contacts.eph.pub --contact bob --ratchet

anyhide decode --code "..." -c carrier.txt -p "pass" \
    --eph-keys mykeys.eph.key --eph-pubs contacts.eph.pub --contact alice
```

## [0.8.0] - 2025-12-17

### Added

- **Forward Secrecy Ratchet**
  - New `--ratchet` flag in encode command enables key rotation per message
  - Each message includes sender's next public key for recipient's reply
  - Compromised keys don't expose past messages (perfect forward secrecy)
  - Works with both CLI and library usage

- **Ephemeral Key Generation**
  - New `--ephemeral` flag in keygen command generates ephemeral keys
  - Ephemeral keys use distinct PEM headers: `ANYHIDE EPHEMERAL PUBLIC/PRIVATE KEY`
  - `KeyPair::generate_ephemeral()` for library usage
  - `KeyPair::is_ephemeral()` to check key type

- **Ephemeral Key Storage Formats**
  - Three flexible storage options for ephemeral keys:
    - Individual files (like long-term keys but with ephemeral headers)
    - Separate consolidated files (`.eph.key` + `.eph.pub`)
    - Unified storage (`.eph` with both keys per contact)
  - Auto-detection of format by file extension
  - JSON-based storage for multi-contact management

- **Contact Key Management**
  - `--contact <name>` flag for keygen with consolidated storage
  - `--eph-file`, `--eph-keys`, `--eph-pubs` options for storage paths
  - Library functions: `save_unified_keys_for_contact`, `load_unified_keys_for_contact`
  - `update_unified_public_key`, `update_unified_private_key` for ratchet updates
  - `list_unified_contacts`, `list_private_key_contacts`, `list_public_key_contacts`

- **Library Exports for Ratchet**
  - All ratchet functionality available for library usage
  - `EncoderConfig.ratchet` field to enable key rotation
  - `EncodedMessage.next_keypair` returns new keypair for sender to save
  - `DecodedMessage.next_public_key` returns sender's next key for replies
  - PEM encoding functions: `encode_ephemeral_public_key_pem`, `encode_ephemeral_secret_key_pem`

### Changed

- `EncodedMessage` now includes `next_keypair: Option<KeyPair>` field
- `DecodedMessage` now includes `next_public_key: Option<Vec<u8>>` field
- `EncoderConfig` now includes `ratchet: bool` field (default: false)
- `KeyPair` now implements `Debug` (with redacted private key for security)

### Security Notes

- **Ratchet maintains plausible deniability**: Wrong inputs still return garbage, not errors
- **Long-term keys never auto-modified**: Only ephemeral keys rotate
- **Backwards compatible**: Messages without ratchet still work normally
- **Key type detection**: System distinguishes long-term from ephemeral keys by PEM headers

### Examples

```bash
# Generate ephemeral keys for a contact (unified storage)
anyhide keygen --ephemeral --contact bob --eph-file alice.eph

# Encode with forward secrecy ratchet
anyhide encode -c carrier.txt -m "secret" -p "pass" -k bob.pub --ratchet

# Decode - shows next_public_key if sender used ratchet
anyhide decode --code "..." -c carrier.txt -p "pass" -k bob.key
# Output includes: "Forward Secrecy Ratchet: Sender included their NEXT public key..."

# Library usage
let config = EncoderConfig { ratchet: true, ..Default::default() };
let encoded = encode_with_config(carrier, msg, pass, &pub_key, &config)?;
if let Some(next) = encoded.next_keypair {
    // Save next_keypair for your next message
}
```

## [0.7.1] - 2025-12-16

### Changed

- **CLI Refactored with Strategy Pattern**
  - Moved all command logic from `main.rs` to `src/commands/` module
  - Each command is now a separate file implementing `CommandExecutor` trait
  - `main.rs` reduced from ~1200 lines to ~90 lines
  - Makes adding new commands easier and improves maintainability

- **Documentation Split**
  - `README.md` is now a focused user manual
  - New `ARCHITECTURE.md` contains technical documentation for developers
  - Project structure, design patterns, and development guide moved to ARCHITECTURE.md

- **Removed Legacy "KAMO" References**
  - Updated all documentation comments to use "Anyhide" instead of "KAMO"
  - Cryptographic salts unchanged for backwards compatibility

## [0.7.0] - 2025-12-16

### Added

- **Message Signing (Ed25519)**
  - Sign messages with Ed25519 digital signatures
  - `--sign <path>` flag in encode command to sign messages
  - `--verify <path>` flag in decode command to verify signatures
  - Keygen now creates both encryption keys (.pub/.key) and signing keys (.sign.pub/.sign.key)
  - Signatures are stored inside the encrypted payload (hides sender identity)
  - Plausible deniability preserved - signature verification failure doesn't cause decode failure

- **Exact Case Preservation (char_overrides)**
  - Messages are now recovered with EXACT original case
  - System stores character overrides when carrier case differs from message
  - Enables signatures to always verify correctly
  - Example: Message "Hello" found as "hello" in carrier → char_overrides stores case differences

- **Carrier Coverage Validation**
  - New `--min-coverage` flag (0-100, default: 100)
  - At 100%: All message characters must exist exactly (same case) in carrier
  - Lower values allow encoding with char_overrides but may leak information
  - Prevents accidental encoding with incompatible carriers
  - Verbose mode shows coverage details and missing characters

- **Message Expiration**
  - New `--expires` flag to set message expiration time
  - Relative formats: `+30m` (30 minutes), `+24h` (24 hours), `+7d` (7 days), `+1w` (1 week)
  - Absolute formats: `2025-12-31` or `2025-12-31T23:59:59`
  - Expired messages return garbage (plausible deniability preserved)
  - No way to tell if message expired vs wrong inputs
  - Verbose mode shows time remaining until expiration

- **Code Splitting**
  - New `--split N` flag in encode command to split code into N parts (2-10)
  - Parts can be sent through different channels for added security
  - Parts MUST be combined in EXACT order for successful decode
  - With `--qr`: generates N separate QR images (code-1.png, code-2.png, etc.)
  - Multiple decode input methods:
    - `--code <TEXT>` - Direct base64 text
    - `--code-qr <PATH>` - Read code from QR image
    - `--code-file <PATH>` - Read code from text file
    - `--parts <FILE1> <FILE2> ...` - Combine split parts (text files or QR images)
  - Wrong order returns garbage (plausible deniability preserved)

### Security Notes

- **Maximum security (default)**: Use carriers that contain ALL characters of your message with exact case
- **Reduced security**: Lowering `--min-coverage` allows more carriers but char_overrides may reveal message patterns
- **Signature verification**: Always use `--verify` when decoding signed messages to ensure authenticity

### Examples

```bash
# Generate keys (creates both encryption and signing keys)
anyhide keygen -o alice

# Encode with signature and 7-day expiration
anyhide encode -c carrier.txt -m "Secret message" -p "pass" -k bob.pub --sign alice.sign.key --expires "+7d"

# Decode and verify
anyhide decode --code "..." -c carrier.txt -p "pass" -k bob.key --verify alice.sign.pub
# Output: Message valid for 167h 59m more

# Split code into 3 parts with QR codes
anyhide encode -c carrier.txt -m "Top secret" -p "pass" -k bob.pub --split 3 --qr code.png
# Output: code-1.png, code-2.png, code-3.png

# Decode from QR parts (order matters!)
anyhide decode --parts code-1.png code-2.png code-3.png -c carrier.txt -p "pass" -k bob.key
```

## [0.6.1] - 2025-12-15

### Fixed
- Fixed cross-compilation for Linux ARM64 by using vendored OpenSSL

## [0.6.0] - 2025-12-15 (failed release)

### Added

- **Self-Update Command**
  - New `anyhide update` command to update to the latest version
  - Automatically detects platform (Linux/macOS/Windows) and architecture (x86_64/aarch64)
  - Downloads the correct binary from GitHub Releases
  - Use `--check` to only check for updates without installing

## [0.5.3] - 2025-12-15

### Added

- **GitHub Actions Release Workflow**
  - Automated builds for Linux (x86_64, aarch64), macOS (Intel, Apple Silicon), Windows
  - Creates GitHub Release with pre-built binaries
  - Publishes to crates.io automatically on tag push

### Fixed

- Reduced keywords to 5 (crates.io limit)

## [0.5.2] - 2025-12-15

### Changed

- **Project Renamed to Anyhide**
  - Package name changed from `kamo` to `anyhide`
  - Binary renamed to `anyhide`
  - PEM headers changed to `ANYHIDE PUBLIC/PRIVATE KEY`
  - All documentation updated

### Added

- **Inline QR Code Generation**
  - New `--qr <path>` option in `encode` command
  - Generate Anyhide code and QR in one step
  - `--qr-format` option for png/svg/ascii output
  - Example: `anyhide encode -c carrier.txt -m "msg" -p "pass" -k bob.pub --qr code.png`

## [0.5.1] - 2025-12-15

### Changed

- **Universal Carrier Support**
  - ANY file can now be used as a carrier (not just text, images, or audio)
  - Works with: PDFs, videos (mp4, avi), executables, archives (zip), any binary file
  - `encode -c anyfile.xyz` produces a KAMO code (file not modified)
  - Uses byte-sequence matching for all non-text files
  - Same workflow regardless of file type

- **CLI Auto-Detection**
  - Carrier type (text/binary) auto-detected by file extension
  - Text: .txt, .md, .csv, .json, .xml, .html, .htm (substring matching)
  - Binary: ALL other files (byte-sequence matching)

### Removed

- **Legacy LSB Steganography**
  - Removed `image-hide`, `image-extract` commands
  - Removed `audio-hide`, `audio-extract` commands
  - Removed `capacity` command
  - Removed `src/stego/` module entirely
  - Removed `hound` dependency (WAV audio processing)
  - These commands modified carriers (traditional steganography)
  - Use `encode/decode -c file` instead (KAMO model - never modifies carrier)

### Added

- **Binary Message Support**
  - Hide ANY data inside carriers (not just text messages)
  - `encode --file secret.zip` to encode binary files
  - `decode -o output.bin` to extract binary data
  - KAMO code is indistinguishable (no metadata reveals if content is text/binary)
  - `encode_bytes_with_carrier()` / `decode_bytes_with_carrier()` API
  - `fragment_bytes_for_carrier()` for raw byte fragmentation
  - `DecodedBytes` struct for binary decoding results

- **Carrier Abstraction** (`src/text/carrier.rs`)
  - `Carrier` enum supporting Text and Binary variants
  - `BinaryCarrierSearch` for byte-sequence matching
  - `fragment_message_for_binary()` for adaptive text-in-binary fragmentation
  - Auto-loading with `Carrier::from_file()`

- **Generic Encoder/Decoder**
  - `encode_with_carrier()` - works with any carrier type
  - `decode_with_carrier()` - works with any carrier type
  - Unified API for text, images, and audio

### Migration from v0.5.0

The new carrier model is the recommended approach:

| v0.5.0 (LSB) | v0.5.1 (KAMO model) |
|--------------|---------------------|
| `image-hide -i img.png -o stego.png` | `encode -c img.png -m "msg"` |
| `image-extract -i stego.png` | `decode -c img.png --code "..."` |
| Modifies carrier | Never modifies carrier |
| Transmits modified file | Transmits only KAMO code |

## [0.5.0] - 2025-12-14

### Added

- **Message Compression** (`src/crypto/compression.rs`)
  - DEFLATE compression before encryption
  - Automatic: only compresses if it reduces size
  - Allows longer messages in same carrier

- **Forward Secrecy** (`src/crypto/mod.rs`)
  - Ephemeral X25519 keypairs for each message
  - Compromised long-term key doesn't expose past messages
  - Ephemeral public key included in ciphertext

- **Suffix Array** (`src/text/suffix_array.rs`)
  - O(m * log n) substring search instead of O(n * m)
  - `IndexedCarrier` for fast repeated searches
  - Unicode-aware character/byte position mapping

- **Multi-Recipient Encryption** (`src/crypto/multi_recipient.rs`)
  - Encrypt once, send to multiple recipients
  - Each recipient gets encrypted copy of symmetric key
  - Efficient: message encrypted only once

- **Image Steganography** (`src/stego/image.rs`)
  - LSB (Least Significant Bit) hiding in PNG/BMP
  - Capacity: ~3 bytes per 8 pixels
  - Survives PNG compression

- **Audio Steganography** (`src/stego/audio.rs`)
  - LSB hiding in WAV files (16-bit PCM)
  - Capacity: 1 byte per 8 samples
  - Imperceptible to human ear

- **New CLI Commands** (`src/main.rs`)
  - `image-hide` / `image-extract` - Hide/extract data in images
  - `audio-hide` / `audio-extract` - Hide/extract data in audio
  - `multi-encrypt` / `multi-decrypt` - Multi-recipient encryption
  - `capacity` - Show image/audio capacity for hiding data
  - `qr-generate` / `qr-read` - Generate and read QR codes
  - `qr-info` - Show QR code capacity analysis

- **QR Code Support** (`src/qr/`)
  - Base45 encoding for optimal QR capacity (~45% more than Base64)
  - Generate QR codes as PNG, SVG, or ASCII art
  - Read QR codes from images
  - Capacity analysis to check if data fits in QR

### Changed

- Protocol version bumped to 6
- Encryption now includes compression + forward secrecy by default

### Security

- **Forward Secrecy**: Past messages remain secure even if long-term key is compromised
- **Compression**: Reduces patterns in encrypted data
- **Multi-carrier**: Can now hide in text, images, or audio

### Migration from v0.4.1

v0.5.0 uses a different encryption format due to:
- Compression layer
- Ephemeral key prepended to ciphertext
- Protocol version 6

| v0.4.1 | v0.5.0 |
|--------|--------|
| No compression | DEFLATE compression |
| Static key exchange | Ephemeral key exchange |
| Text carrier only | Text, image, audio carriers |
| Single recipient | Multi-recipient support |
| Protocol version 5 | Protocol version 6 |

## [0.4.1] - 2025-12-14

### Changed

- **Substring Fragmentation Restored**
  - Changed from word-based back to substring-based encoding
  - Message is fragmented into variable-sized pieces (1-5 chars)
  - Fragments are found as substrings in the carrier (e.g., "ama" in "Amanda")
  - Enables cross-language encoding (Spanish carrier, English message fragments)

- **Random Position Selection**
  - Fragment positions in carrier are independent (not sequential)
  - Fragment 1 can be at end of carrier, Fragment 5 at start
  - Makes pattern analysis much harder for attackers

### Added

- **Distributed Position Selection** (`src/text/tokenize.rs`)
  - `select_distributed_position()` - Selects random occurrence from multiple matches
  - Based on passphrase + fragment index for determinism

- **Enhanced Integration Tests**
  - `test_substring_matching()` - Verifies "anda" found in "Amanda"
  - `test_cross_language()` - Tests cross-language capability

### Security

- **Enhanced Anti-Analysis**
  - Non-sequential positions make frequency analysis useless
  - Substring matching allows using any text as carrier
  - Multiple occurrences of fragments spread across carrier

### Migration from v0.4.0

v0.4.1 uses a different encoding scheme than v0.4.0:

| v0.4.0 | v0.4.1 |
|--------|--------|
| Word-based | Substring-based |
| Sequential positions possible | Random positions |
| Word index positions | Character index positions |
| Protocol version 4 | Protocol version 5 |

## [0.4.0] - 2025-12-14

### Changed

- **Word-Based Encoding**
  - Changed from character-fragment based to word-based encoding
  - Message words are matched to carrier words (case-insensitive)
  - Simpler and more robust than substring matching

- **Carrier Permutation**
  - Carrier words are now shuffled deterministically using the passphrase
  - Different passphrase = different word order in carrier
  - Provides additional layer of security (wrong passphrase = completely wrong positions)
  - Uses ChaCha20Rng seeded from HKDF-SHA256

- **Distributed Position Selection**
  - When a word appears multiple times in the carrier, positions are distributed
  - Each occurrence of a word in the message selects a different occurrence in carrier
  - Prevents simple pattern analysis ("hola hola hola" uses 3 different positions)

- **Block Padding**
  - Messages are padded to block boundaries (256 characters)
  - Minimum message size is 64 characters
  - Padding uses random words from the permuted carrier
  - Hides the actual message length from attackers
  - Encoded data includes `real_count` to extract only real words

### Added

- **New Text Processing Module** (`src/text/permute.rs`)
  - `permute_carrier()` - Shuffles carrier words deterministically
  - `find_distributed()` - Finds word positions with distribution across occurrences
  - `normalize()` - Case-insensitive word comparison

- **Block Padding Module** (`src/text/padding.rs`)
  - `calculate_padded_length()` - Computes target length for block boundary
  - `pad_message()` - Pads message with carrier words to target length

- **New Constants** (`src/lib.rs`)
  - `VERSION = 4` - Protocol version
  - `BLOCK_SIZE = 256` - Block size for padding
  - `MIN_SIZE = 64` - Minimum message size

- **Updated Data Structures**
  - `EncodedData { version, real_count, positions }` - Protocol data
  - `EncodedMessage { code, real_word_count, total_positions }` - Encoding result
  - `DecodedMessage { message, words }` - Decoding result

- **New Dependency**
  - `rand_chacha = "0.3"` for deterministic RNG

### Security

- **Four-Factor Security**
  - Carrier text (pre-shared)
  - Passphrase (determines permutation + encryption)
  - Private key (asymmetric decryption)
  - Correct protocol version

- **Enhanced Plausible Deniability**
  - Wrong passphrase produces different permutation = completely different message
  - Block padding hides message length (only block range visible)
  - Distributed selection makes pattern analysis harder

- **Anti-Analysis**
  - Repeated words in message map to different positions
  - Message length is hidden by padding
  - Word order is scrambled by permutation

### Migration from v0.3.1

v0.4 is not backwards compatible with v0.3.1 encoded messages:

| v0.3.1 | v0.4 |
|--------|------|
| Character-fragment based | Word-based |
| Substring search | Exact word match (case-insensitive) |
| No permutation | Passphrase-based carrier permutation |
| Variable fragments | Block padding |
| Positions are char indices | Positions are word indices |

## [0.3.1] - 2025-12-14

### Changed

- **Never-Fail Decoder**
  - Decoder NEVER returns an error - always produces output
  - Invalid base64 → hash-derived garbage
  - Wrong passphrase → carrier-derived fallback
  - Wrong private key → carrier-derived fallback
  - Deserialization failure → carrier-derived fallback
  - Prevents brute-force attacks and provides plausible deniability

- **Variable Fragmentation**
  - Words are fragmented into variable-sized pieces (1-5 chars)
  - Fragment sizes derived deterministically from passphrase using HKDF
  - Spaces are treated as fragment boundaries (fragments never cross word boundaries)
  - Same message + passphrase always produces same fragmentation

- **Substring Search**
  - Fragments are found as substrings in carrier (not exact word matches)
  - Case-insensitive search (message "ama" found in carrier "Amanda")
  - Character-position based (not word-index based)

### Added

- **Space Handling**
  - Spaces extracted from message, stored as metadata
  - Last fragment of each word carries space marker
  - Spaces reconstructed during decoding
  - Example: "ama parque" → fragments ["a", "ma", "par", "que"] with space after "ma"

- **Fallback Generation**
  - `generate_fallback_output()` - deterministic garbage from hash
  - `generate_fallback_from_carrier()` - pseudo-random extraction from carrier
  - Same invalid inputs always produce same garbage (deterministic)

### Security

- **Enhanced Plausible Deniability**
  - Wrong inputs produce different but valid-looking output
  - No way to distinguish "wrong passphrase" from "correct passphrase with different message"
  - Decryption failures are indistinguishable from successful decryption

- **Anti-Brute-Force**
  - Every attempt produces output (no success/fail signal)
  - Attackers cannot know when they've found the correct passphrase

## [0.3.0] - 2025-12-14

### Changed

- **Complete Architecture Overhaul: Pre-shared Carrier Model**
  - Removed all AI dependencies (Ollama, reqwest, tokio)
  - Carrier text is now pre-shared between parties, never transmitted
  - Only encrypted position codes are transmitted
  - Much simpler, faster, and works completely offline

### Removed

- **AI Module** (`src/ai/`)
  - Removed Ollama client
  - Removed carrier generation
  - Removed fragment interpretation
  - No more HTTP dependencies

- **Pattern Module** (`src/crypto/pattern.rs`)
  - Position derivation no longer needed (positions are found, not derived)

- **Complex Fragmentation** (`src/text/fragment.rs`)
  - Removed adaptive/syllable/character fragmentation
  - Simple word-based splitting is sufficient

- **Dependencies**
  - Removed `reqwest` (no HTTP needed)
  - Removed `tokio` (no async needed)
  - Removed `serde_json` (using bincode for serialization)

### Added

- **Symmetric Encryption Module** (`src/crypto/symmetric.rs`)
  - Passphrase-based encryption using HKDF + ChaCha20-Poly1305
  - Hybrid encryption: symmetric (passphrase) + asymmetric (X25519)

- **New CLI Commands**
  - `encode --carrier <file>`: Find positions in pre-shared carrier
  - `decode --code <base64> --carrier <file>`: Decrypt and extract

### Security

- **Dual-layer encryption**: Both passphrase AND private key required
- **Pre-shared carrier**: Carrier never transmitted = additional security layer
- **Wrong passphrase = decryption failure** (authenticated encryption)
- **Wrong carrier = wrong message or out-of-bounds error**

### Migration from v0.2

v0.3 is not backwards compatible with v0.2 encoded messages. The encoding format has completely changed:

| v0.2 | v0.3 |
|------|------|
| Transmits: carrier + metadata | Transmits: only encrypted code |
| AI generates carrier | User provides carrier |
| Async (tokio) | Sync |
| ~200 dependencies | ~50 dependencies |

## [0.2.1] - 2025-12-14

### Changed

- **New 3-Step Carrier Generation Strategy**
  - Step 1: AI generates base text without position constraints
  - Step 2: Post-processing inserts fragments at exact positions
  - Step 3: AI polish pass to smooth the text (with fallback to pre-polish)
  - Much more reliable than single-shot position-constrained generation

### Fixed

- **Critical bug in position derivation**
  - Encoding and decoding now use identical algorithm for position derivation
  - Positions are derived from `hash(passphrase + base_seed)` consistently
  - Plausible deniability now works correctly (wrong passphrase = different positions)

### Added

- `generate_base_text()` - Generates unconstrained base text
- `polish_carrier()` - Smooths text while preserving fragments
- `insert_fragments_at_positions()` - Deterministic fragment insertion

## [0.2.0] - 2025-12-14

### Added

- **Case Pattern Preservation**
  - Fragments are now normalized to lowercase for natural carrier embedding
  - Original case patterns are stored and restored during decoding
  - "Nos" in message appears as "nos" in carrier, but reconstructs as "Nos"

- **Adaptive Fragmentation Mode**
  - New `FragmentMode::Adaptive` (now default) that intelligently chooses fragmentation strategy per word
  - Common words (el, la, the, to, etc.) stay whole
  - Long words (5+ characters) may be split into syllables or characters
  - Deterministic: same passphrase+message always produces same fragmentation

- **Enhanced Reconstruction**
  - New `ReconstructionInfo` struct stores case patterns and fragment assembly info
  - Encoded messages now include reconstruction metadata
  - Backwards compatible with v0.1.0 message format

### Changed

- Default fragmentation mode changed from `Words` to `Adaptive`
- Fragments extracted from carrier are now always lowercase
- EncodedMessage format extended with reconstruction field

### Security

- Fragments no longer reveal case information in carrier text
- "Marta" appearing as "marta" (or "mar" + "ta") is less detectable
- Improved concealment through mixed fragmentation strategies

## [0.1.0] - 2025-12-14

### Added

- **Core Implementation**
  - Complete KAMO v0.2 specification implementation
  - CLI tool with `keygen`, `encode`, and `decode` commands
  - Support for multiple languages (es, en, fr, de, it, pt)

- **Cryptographic Module** (`src/crypto/`)
  - X25519 key pair generation with PEM format serialization
  - Hybrid encryption using X25519 + ChaCha20-Poly1305
  - HKDF-based pattern derivation for position generation
  - Deterministic AI seed generation for consistent decoy outputs

- **Text Processing Module** (`src/text/`)
  - Message fragmentation (words, syllables, characters modes)
  - Carrier text tokenization and position-based extraction
  - Carrier verification against expected fragments

- **AI Integration Module** (`src/ai/`)
  - Ollama HTTP client for local AI model interaction
  - Carrier generation with position-constrained word placement
  - Fragment interpretation for coherent message reconstruction

- **Encoder** (`src/encoder.rs`)
  - Complete encoding pipeline: fragment → pattern → AI → verify
  - Retry logic with temperature adjustment
  - Transmittable format with embedded metadata

- **Decoder** (`src/decoder.rs`)
  - Complete decoding pipeline: pattern → extract → interpret
  - Plausible deniability: never returns error for wrong passphrase
  - Deterministic decoy generation

- **CLI** (`src/main.rs`)
  - `keygen`: Generate X25519 key pairs
  - `encode`: Encode messages with stdin/file support
  - `decode`: Decode carriers with stdin/file support
  - Verbose mode for debugging

- **Testing**
  - Unit tests for all modules (39 tests)
  - Integration tests for complete workflows
  - Tests for deterministic decoy behavior

- **Documentation**
  - Comprehensive README with usage examples
  - API documentation with rustdoc
  - MIT License

### Security

- Messages require both private key AND correct passphrase to decode
- Wrong passphrase produces coherent decoy message (plausible deniability)
- Same wrong passphrase always produces same decoy (deterministic)
- No oracle attacks: decode never reveals if passphrase is correct
