# Anyhide - Architecture & Development Guide

This document provides technical documentation for developers working on Anyhide.

## Project Structure

```
anyhide/
├── src/
│   ├── main.rs              # CLI entry point, clap parsing
│   ├── lib.rs               # Public re-exports, version constants
│   │
│   ├── commands/            # CLI command implementations (Strategy pattern)
│   │   ├── mod.rs           # CommandExecutor trait definition
│   │   ├── keygen.rs        # Key pair generation command
│   │   ├── encode.rs        # Message/file encoding command
│   │   ├── decode.rs        # Message/file decoding command
│   │   ├── multi_encrypt.rs # Multi-recipient encryption
│   │   ├── multi_decrypt.rs # Multi-recipient decryption
│   │   ├── qr_generate.rs   # QR code generation
│   │   ├── qr_read.rs       # QR code reading
│   │   ├── qr_info.rs       # QR capacity analysis
│   │   └── update.rs        # Self-update command
│   │
│   ├── crypto/              # Cryptographic primitives
│   │   ├── mod.rs           # Hybrid encryption with forward secrecy
│   │   ├── keys.rs          # X25519 + Ed25519 key generation, PEM format
│   │   ├── asymmetric.rs    # X25519 + ChaCha20-Poly1305 encryption
│   │   ├── symmetric.rs     # Passphrase-based encryption (HKDF + ChaCha20)
│   │   ├── signing.rs       # Ed25519 digital signatures
│   │   ├── compression.rs   # DEFLATE message compression
│   │   ├── multi_recipient.rs # Multi-recipient encryption scheme
│   │   └── ephemeral_store.rs # Contact key management for ratchet
│   │
│   ├── text/                # Text and carrier processing
│   │   ├── mod.rs           # Module exports
│   │   ├── carrier.rs       # Universal carrier abstraction (text/binary)
│   │   ├── fragment.rs      # Adaptive message fragmentation
│   │   ├── tokenize.rs      # Carrier search utilities
│   │   ├── permute.rs       # Carrier permutation, distributed selection
│   │   ├── padding.rs       # Block padding (256-char blocks)
│   │   └── suffix_array.rs  # O(m·log n) substring search
│   │
│   ├── qr/                  # QR code support
│   │   ├── mod.rs           # Base45 encoding for QR codes
│   │   ├── generator.rs     # QR code generation (PNG/SVG/ASCII)
│   │   └── reader.rs        # QR code reading and decoding
│   │
│   ├── encoder.rs           # Encoding pipeline: fragment → find → pad → encrypt
│   └── decoder.rs           # Decoding pipeline: decrypt → extract (never fails)
│
├── tests/
│   └── integration_tests.rs # End-to-end tests
│
├── .github/
│   └── workflows/
│       └── release.yml      # CI/CD: build + publish on tag
│
├── Cargo.toml
├── LICENSE
├── README.md                # User manual
├── ARCHITECTURE.md          # This file
└── CHANGELOG.md             # Version history
```

## Design Patterns

### Strategy Pattern (Commands)

Each CLI command implements the `CommandExecutor` trait:

```rust
pub trait CommandExecutor {
    fn execute(&self) -> Result<()>;
}
```

This allows:
- Clean separation of concerns
- Easy addition of new commands
- Independent testing of each command
- Minimal `main.rs` (~90 lines)

### Never-Fail Decoder

The decoder **never returns an error**. Invalid inputs produce deterministic garbage:

```rust
// Always returns a result, never Err
fn decode(&self) -> DecodedMessage {
    // Wrong passphrase? Different fragmentation → garbage from carrier
    // Wrong carrier? Wrong positions → garbage
    // Invalid base64? Hash-derived garbage
}
```

This provides:
- Plausible deniability
- Anti-brute-force (no success/fail signal)
- Deterministic garbage (same wrong inputs = same output)

## Cryptographic Architecture

### Encryption Flow

```
Message → Compress → Sign (optional) → Symmetric Encrypt → Asymmetric Encrypt → Base64
```

1. **Compression**: DEFLATE (only if it reduces size)
2. **Signing**: Ed25519 signature of message hash (optional)
3. **Symmetric**: ChaCha20-Poly1305 with HKDF-derived key from passphrase
4. **Asymmetric**: X25519 ECDH + ChaCha20-Poly1305 with ephemeral keys

### Forward Secrecy

Each message uses an ephemeral X25519 keypair:

```rust
// Encrypt
let ephemeral = EphemeralSecret::random();
let shared = ephemeral.diffie_hellman(&recipient_public);
// Ciphertext includes ephemeral public key

// Decrypt
let shared = recipient_secret.diffie_hellman(&ephemeral_public);
```

### Forward Secrecy Ratchet

The ratchet provides key rotation per message:

```rust
// EncoderConfig with ratchet enabled
let config = EncoderConfig {
    ratchet: true,
    ..Default::default()
};

// Encode generates next keypair
let result = encode_with_config(..., &config);
// result.next_keypair contains the next public/private key pair

// EncodedData includes next_public_key
struct EncodedData {
    next_public_key: Option<Vec<u8>>,  // 32 bytes X25519 public key
    // ...
}
```

Ratchet workflow:
1. Alice encodes with `--ratchet`, generates next keypair
2. Message includes Alice's next public key (encrypted)
3. Bob decodes, receives `next_public_key` for reply
4. Bob uses that key for his reply
5. Keys rotate with each message exchange

Key types distinguished by PEM headers:
- `ANYHIDE PUBLIC KEY` / `ANYHIDE PRIVATE KEY` - Static keys
- `ANYHIDE EPHEMERAL PUBLIC KEY` / `ANYHIDE EPHEMERAL PRIVATE KEY` - Rotating keys

### Ephemeral Key Storage Formats

Three storage formats for managing contacts and their ephemeral keys:

**1. Individual PEM files** (`.pub`, `.key`)
- Standard PEM format with EPHEMERAL headers
- One file per key, like long-term keys
- Best for: simple CLI usage, single contact

**2. Separate consolidated JSON** (`.eph.key`, `.eph.pub`)
- JSON with contact → key mapping
- Separate files for private and public keys
- Best for: multiple contacts, security separation

```json
// .eph.key format
{
  "version": 1,
  "contacts": {
    "bob": { "key": "base64..." },
    "alice": { "key": "base64..." }
  }
}
```

**3. Unified JSON** (`.eph`)
- Single file with both keys per contact
- `my_private`: your key for this contact
- `their_public`: contact's current public key
- Best for: chat applications, automated ratchet

```json
// .eph format
{
  "version": 1,
  "contacts": {
    "bob": {
      "my_private": "base64...",
      "their_public": "base64..."
    }
  }
}
```

### Key Derivation

All key derivation uses HKDF-SHA256 with domain-specific salts:

```rust
const HKDF_INFO: &[u8] = b"KAMO-V3-SYMMETRIC";  // Legacy salt (DO NOT CHANGE)
const HKDF_SALT: &[u8] = b"KAMO-V3-SALT-2024";  // Legacy salt (DO NOT CHANGE)
```

**Important**: Cryptographic salts use the legacy "KAMO" prefix for backwards compatibility. Do not change these values.

### Key Format (PEM)

```
# Static keys (long-term)
-----BEGIN ANYHIDE PUBLIC KEY-----
[base64 of 32 bytes X25519 public key]
-----END ANYHIDE PUBLIC KEY-----

-----BEGIN ANYHIDE PRIVATE KEY-----
[base64 of 32 bytes X25519 secret key]
-----END ANYHIDE PRIVATE KEY-----

# Signing keys
-----BEGIN ANYHIDE SIGNING PUBLIC KEY-----
[base64 of 32 bytes Ed25519 public key]
-----END ANYHIDE SIGNING PUBLIC KEY-----

-----BEGIN ANYHIDE SIGNING KEY-----
[base64 of 32 bytes Ed25519 secret key]
-----END ANYHIDE SIGNING KEY-----

# Ephemeral keys (for ratchet)
-----BEGIN ANYHIDE EPHEMERAL PUBLIC KEY-----
[base64 of 32 bytes X25519 public key]
-----END ANYHIDE EPHEMERAL PUBLIC KEY-----

-----BEGIN ANYHIDE EPHEMERAL PRIVATE KEY-----
[base64 of 32 bytes X25519 secret key]
-----END ANYHIDE EPHEMERAL PRIVATE KEY-----
```

## Encoding Pipeline

### Fragment Generation

Messages are fragmented based on passphrase-derived sizes:

```rust
// HKDF derives fragment sizes from passphrase
let sizes = derive_fragment_sizes(passphrase, message_len);
// e.g., "hello world" → ["hel", "lo", " ", "wor", "ld"]
```

### Position Selection

Fragments are found as substrings (text) or byte sequences (binary):

```rust
// Text carrier: case-insensitive substring search
"ama" found in "Amanda" at position 2

// Binary carrier: exact byte sequence match
[0x48, 0x65] found at position 1024
```

Multiple occurrences use distributed selection (passphrase-based randomization).

### Block Padding

Messages are padded to 256-character blocks with random carrier substrings:

```rust
const BLOCK_SIZE: usize = 256;
const MIN_SIZE: usize = 64;

// "hello" (5 chars) → padded to 256 chars with carrier fragments
```

## Building & Testing

```bash
# Development
cargo build
cargo test
cargo clippy

# Release
cargo build --release

# Run specific test
cargo test test_encode_decode_roundtrip

# Generate docs
cargo doc --open
```

## Code Quality Standards

All code follows SOLID principles:

- **Single Responsibility**: Each module handles one concern
- **Open/Closed**: Extensible through traits (`CommandExecutor`, `Carrier`)
- **Liskov Substitution**: Text and Binary carriers are interchangeable
- **Interface Segregation**: Small, focused traits
- **Dependency Inversion**: Core logic uses abstractions, not concretions

## Adding a New Command

1. Create `src/commands/newcmd.rs`:

```rust
use clap::Args;
use super::CommandExecutor;

#[derive(Args, Debug)]
pub struct NewCommand {
    #[arg(short, long)]
    pub option: String,
}

impl CommandExecutor for NewCommand {
    fn execute(&self) -> Result<()> {
        // Implementation
        Ok(())
    }
}
```

2. Add to `src/commands/mod.rs`:

```rust
mod newcmd;
pub use newcmd::NewCommand;
```

3. Add to `src/main.rs` enum and match.

## CI/CD Pipeline

On tag push (`v*`):
1. Build for 5 platforms (Linux x86_64/aarch64, macOS x86_64/aarch64, Windows)
2. Create GitHub Release with binaries
3. Publish to crates.io

## Version History

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.
