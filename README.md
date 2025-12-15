# KAMO - Key Asymmetric Message Obfuscation

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org)

KAMO is an advanced steganography tool that hides messages in **any file** using hybrid encryption with forward secrecy. Unlike traditional steganography, carriers are pre-shared - only encrypted codes are transmitted.

## Overview

KAMO v0.5.1 uses a **pre-shared carrier** approach with enhanced security:

1. Both parties agree on a carrier file beforehand (ANY file: text, image, video, PDF, executable, etc.)
2. Message is **fragmented** into variable-sized pieces based on passphrase
3. Fragments are found as **substrings** (text) or **byte sequences** (binary files)
4. Positions are **randomly distributed** - not sequential (Fragment 1 can be at end, Fragment 5 at start)
5. Message is **padded** to block boundaries to hide its length
6. Positions are encrypted with passphrase (symmetric) + public key (asymmetric)
7. **Only the encrypted code is transmitted** - not the carrier

### Key Features

- **Universal Carrier Support**: Use ANY file as carrier (text, images, audio, video, PDFs, executables, etc.)
- **Binary Message Support**: Hide ANY data (text or binary files) inside carriers
- **QR Code Support**: Generate/read QR codes with Base45 encoding for optimal capacity
- **Forward Secrecy**: Ephemeral keys - compromised key doesn't expose past messages
- **Message Compression**: DEFLATE compression allows longer messages
- **Multi-Recipient**: Encrypt once for multiple recipients efficiently
- **No AI Required**: Simple, deterministic, works completely offline
- **Minimal Transmission**: Only a short base64 code is sent
- **Pre-shared Carrier**: The carrier is never transmitted, providing additional security
- **Substring Matching**: "ama" found in "Amanda" - works across languages!
- **Dual-layer Encryption**: Symmetric (passphrase) + Asymmetric (X25519)
- **Never Fails**: Decoder ALWAYS returns something - never errors (prevents brute-force)
- **Plausible Deniability**: Wrong carrier/passphrase = different message (not error)
- **Indistinguishable Codes**: KAMO code reveals nothing about content type (text vs binary)
- **Block Padding**: Message length hidden by padding to 256-char blocks
- **Random Positions**: Fragments scattered throughout carrier (non-sequential)
- **Fast Search**: Suffix array for O(m·log n) substring search

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│  ENCODE                                                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  INPUTS:                                                            │
│  ├── Carrier: "The amazing Amanda went to the park yesterday"      │
│  ├── Message: "ama park"                                           │
│  ├── Passphrase: "secret"                                          │
│  └── Recipient's public key                                         │
│                                                                     │
│  PROCESS:                                                           │
│  1. Fragment message: ["ama", "p", "ark"] (passphrase-based)       │
│  2. Find "ama" as substring → position 4 (in "amazing")            │
│  3. Find "p" at 3 positions → random select → position 31          │
│  4. Find "ark" → position 32 (in "park")                           │
│  5. Pad with random carrier substrings to 256 chars                │
│  6. Serialize: {version: 6, real_count: 3, fragments: [...]}       │
│  7. Encrypt with passphrase + public key → base64                  │
│                                                                     │
│  OUTPUT: "oaiN3zrH..." (base64 encrypted code)                     │
│                                                                     │
│  ✓ Only the code is transmitted                                    │
│  ✓ Carrier is NEVER sent                                           │
│  ✓ Positions are RANDOM (not sequential!)                          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  DECODE (NEVER FAILS)                                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  INPUTS:                                                            │
│  ├── Code: "oaiN3zrH..."                                           │
│  ├── Carrier: (same text as sender used)                           │
│  ├── Passphrase: "secret"                                          │
│  └── Recipient's private key                                        │
│                                                                     │
│  PROCESS:                                                           │
│  1. Decrypt code → {version: 6, real_count: 3, fragments: [...]}   │
│  2. Extract only first 3 fragments (real_count, ignore padding)    │
│  3. Look up chars at each position:                                │
│     pos 4, len 3 → "ama"                                           │
│     pos 31, len 1 → "p" + space marker                             │
│     pos 32, len 3 → "ark"                                          │
│  4. Concatenate: "ama park"                                        │
│                                                                     │
│  OUTPUT: "ama park"                                              │
│                                                                     │
│  ✓ NEVER returns error - wrong inputs produce garbage              │
│  ✓ Wrong passphrase? Different fragmentation → different message   │
│  ✓ Wrong carrier? Different chars at positions → garbage           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Rust 1.70 or later

### Build from Source

```bash
git clone https://github.com/matutetandil/kamo.git
cd kamo
cargo build --release
```

The binary will be available at `target/release/kamo`.

## Usage

### Generate Key Pair

```bash
# Generate keys (creates mykeys.pub and mykeys.key)
kamo keygen -o mykeys

# Share mykeys.pub with people who want to send you messages
# Keep mykeys.key secret and secure
```

### Encode a Message

```bash
# Create a carrier file (or use any existing text file)
echo "Yesterday my aunt Martha called me on the phone to tell me something" > carrier.txt

# Encode a message
kamo encode \
  --carrier carrier.txt \
  --message "Martha called" \
  --passphrase "secret123" \
  --key recipient.pub

# Output: AwNhYmNkZWZn... (encrypted code to send)
```

### Decode a Message

```bash
# Decode using the same carrier
kamo decode \
  --code "AwNhYmNkZWZn..." \
  --carrier carrier.txt \
  --passphrase "secret123" \
  --key my.key

# Output: Martha called
```

### Available Options

```
kamo keygen
  -o, --output <PATH>    Output path for keys (default: kamo)

kamo encode
  -c, --carrier <PATH>   Path to carrier file (any file type)
  -m, --message <MSG>    Text message to encode (mutually exclusive with --file)
  -f, --file <PATH>      Binary file to encode (mutually exclusive with --message)
  -p, --passphrase <PASS> Passphrase for encryption
  -k, --key <PATH>       Path to recipient's public key
  -v, --verbose          Show positions found

kamo decode
  --code <CODE>          The encrypted code to decode
  -c, --carrier <PATH>   Path to carrier file (same as encoding)
  -p, --passphrase <PASS> Passphrase for decryption
  -k, --key <PATH>       Path to your private key
  -o, --output <PATH>    Output file for decoded data (required for binary)
  -v, --verbose          Show positions and fragments

kamo multi-encrypt
  -m, --message <MSG>    Message to encrypt (or reads from stdin)
  -p, --passphrase <PASS> Passphrase for encryption
  -k, --keys <PATHS>...  Paths to recipients' public keys
  -o, --output <PATH>    Output file (prints base64 if not specified)

kamo multi-decrypt
  -i, --input <INPUT>    Encrypted data (base64 string or file path)
  -p, --passphrase <PASS> Passphrase for decryption
  -k, --key <PATH>       Path to your private key

kamo qr-generate
  -c, --code <CODE>      KAMO code (base64) - reads from stdin if not provided
  -o, --output <PATH>    Output file path (PNG, SVG, or TXT)
  -f, --format <FMT>     Output format: png (default), svg, or ascii

kamo qr-read
  -i, --input <PATH>     Path to image containing QR code
  -o, --output <PATH>    Output raw bytes to file (base64 to stdout if not specified)

kamo qr-info
  -s, --size <BYTES>     Data size in bytes
  -c, --code <CODE>      Or provide KAMO code to analyze
```

## Security Properties

1. **Four-Factor Security**: Carrier + Passphrase + Private Key + Correct Version
2. **Pre-shared Carrier**: The carrier text is never transmitted - only both parties know it
3. **Carrier Permutation**: Different passphrase = different word order = completely different message
4. **Block Padding**: Message length hidden - only block range is visible (256-char blocks)
5. **Distributed Selection**: Repeated words use different positions, preventing pattern analysis
6. **Never-Fail Decoder**: ALWAYS produces output - no error signals for attackers
7. **Anti-Brute-Force**: Cannot distinguish wrong passphrase from correct one with different message
8. **Deterministic Garbage**: Same wrong inputs always produce same output (prevents timing attacks)
9. **Plausible Deniability**: "It's just a random base64 string" - every decode attempt succeeds

## Example: Using a Public Text as Carrier

Both Alice and Bob agree to use the first paragraph of "Moby Dick" as their carrier:

```bash
# carrier.txt contains:
# "Call me Ishmael. Some years ago—never mind how long precisely—having
# little or no money in my purse, and nothing particular to interest me..."

# Alice encodes "call me"
kamo encode -c carrier.txt -m "call me" -p "melville" -k bob.pub
# Output: AxB2c3...

# Bob decodes
kamo decode --code "AxB2c3..." -c carrier.txt -p "melville" -k bob.key
# Output: call me
```

Anyone intercepting "AxB2c3..." has no idea:
- That it's a KAMO code
- What carrier was used
- What the message is

## Example: Any Binary File as Carrier

Use ANY file as a pre-shared carrier (file is never modified):

```bash
# Both Alice and Bob have the same file - can be ANYTHING:
# - An image (photo.png, image.jpg)
# - A video (movie.mp4, clip.avi)
# - A PDF document (report.pdf)
# - An executable (program.exe)
# - A compressed archive (data.zip)
# - Any other file!

# Alice encodes using a shared PDF as carrier
kamo encode -c shared_document.pdf -m "secret message" -p "passphrase" -k bob.pub
# Output: AxB2c3F4... (KAMO code - the PDF is NOT modified)

# Bob decodes using the exact same PDF
kamo decode --code "AxB2c3F4..." -c shared_document.pdf -p "passphrase" -k bob.key
# Output: secret message
```

For binary files, message fragments are searched as **byte sequences** within
the raw bytes of the file. Larger files = more byte diversity = better success rate.

## Example: Image Carrier

```bash
# Both parties have the same photo
kamo encode -c vacation_photo.jpg -m "meeting at 5pm" -p "secret" -k bob.pub
# Output: BxY4z5W6... (KAMO code)

kamo decode --code "BxY4z5W6..." -c vacation_photo.jpg -p "secret" -k bob.key
# Output: meeting at 5pm
```

## Example: Video/Audio Carrier

```bash
# Video files work great due to their size
kamo encode -c shared_video.mp4 -m "coordinates: 40.7128, -74.0060" -p "pass" -k bob.pub

# Audio files
kamo encode -c song.wav -m "the eagle has landed" -p "pass" -k bob.pub
```

## Example: Hide Binary Files

Hide ANY file (zip, image, executable, etc.) inside a carrier. The KAMO code
reveals nothing about whether the content is text or binary.

```bash
# Alice hides a secret.zip inside a shared video
kamo encode -c shared_video.mp4 --file secret.zip -p "pass" -k bob.pub
# Output: BxY4z5W6... (KAMO code - indistinguishable from text encoding)

# Bob extracts the file using -o to write raw bytes
kamo decode --code "BxY4z5W6..." -c shared_video.mp4 -p "pass" -k bob.key -o secret.zip
# Output: Decoded 15234 bytes to secret.zip

# Works with any binary data:
kamo encode -c carrier.bin --file confidential.pdf -p "pass" -k bob.pub
kamo encode -c movie.mp4 --file keys.tar.gz -p "pass" -k bob.pub
kamo encode -c image.png --file database.sqlite -p "pass" -k bob.pub
```

**Security Note:** The KAMO code format is identical for text and binary messages.
An attacker cannot determine if the hidden content is "hello world" or a 10MB file
just by looking at the code.

## Example: Multi-Recipient Encryption

Encrypt a message for multiple recipients at once:

```bash
# Encrypt for Alice, Bob, and Charlie
kamo multi-encrypt -m "Team meeting at 5pm" -p "shared_secret" \
  -k alice.pub -k bob.pub -k charlie.pub
# Output: AQMAAABhYmNkZWZn... (base64 encrypted data)

# Each recipient decrypts with their own private key
kamo multi-decrypt -i "AQMAAABhYmNkZWZn..." -p "shared_secret" -k alice.key
# Output: Team meeting at 5pm
```

## Example: QR Code Generation

Share KAMO codes via QR code for easy mobile scanning:

```bash
# Generate a KAMO code
CODE=$(kamo encode -c carrier.txt -m "secret message" -p "pass" -k bob.pub)

# Convert to QR code (uses Base45 for optimal capacity)
kamo qr-generate -c "$CODE" -o kamo_code.png
# Output: QR code generated (Version 15, ~480 chars)

# Read QR code back to KAMO code
kamo qr-read -i kamo_code.png
# Output: [base64 KAMO code]

# Check if your data fits in a QR code
kamo qr-info --size 500
# Output: Fits in QR version 17, ~750 Base45 chars
```

**Why Base45?** Standard QR codes have an alphanumeric mode that's more efficient than byte mode. Base45 uses only alphanumeric characters, providing ~45% more capacity than Base64 for QR codes.

## Project Structure

```
kamo/
├── src/
│   ├── main.rs              # CLI with clap
│   ├── lib.rs               # Public re-exports, constants
│   ├── crypto/
│   │   ├── mod.rs           # Hybrid encryption with forward secrecy
│   │   ├── keys.rs          # X25519 key generation, PEM format
│   │   ├── asymmetric.rs    # Encrypt/decrypt with X25519 + ChaCha20
│   │   ├── symmetric.rs     # Passphrase-based encryption
│   │   ├── compression.rs   # DEFLATE compression
│   │   └── multi_recipient.rs # Multi-recipient encryption
│   ├── text/
│   │   ├── mod.rs
│   │   ├── carrier.rs       # Universal carrier abstraction (text/binary)
│   │   ├── permute.rs       # Carrier permutation, distributed selection
│   │   ├── padding.rs       # Block padding
│   │   ├── fragment.rs      # Adaptive message fragmentation
│   │   ├── tokenize.rs      # Carrier search utilities
│   │   └── suffix_array.rs  # O(m·log n) substring search
│   ├── qr/
│   │   ├── mod.rs           # Base45 encoding for QR codes
│   │   ├── generator.rs     # QR code generation (PNG/SVG/ASCII)
│   │   └── reader.rs        # QR code reading and decoding
│   ├── encoder.rs           # Permute → find → pad → encrypt
│   └── decoder.rs           # Decrypt → permute → extract (never fails)
├── tests/
│   └── integration_tests.rs
├── Cargo.toml
├── LICENSE
└── README.md
```

## Cryptographic Details

- **Key Exchange**: X25519 (Curve25519)
- **Symmetric Encryption**: ChaCha20-Poly1305
- **Key Derivation**: HKDF-SHA256
- **Encryption Order**: Symmetric (passphrase) → Asymmetric (public key)

### Key Format

```
-----BEGIN KAMO PUBLIC KEY-----
[base64 of 32 bytes X25519 public key]
-----END KAMO PUBLIC KEY-----

-----BEGIN KAMO PRIVATE KEY-----
[base64 of 32 bytes X25519 secret key]
-----END KAMO PRIVATE KEY-----
```

## Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_encode_decode_roundtrip
```

## Development

### Building

```bash
cargo build           # Debug build
cargo build --release # Release build
```

### Code Quality

All code follows SOLID principles:
- Single Responsibility: Each module handles one concern
- Open/Closed: Extensible through traits and configurations
- Dependency Inversion: Core logic doesn't depend on concrete implementations

## License

MIT License - see [LICENSE](LICENSE) for details.

## Version

Current version: 0.5.1 (see [CHANGELOG.md](CHANGELOG.md))
