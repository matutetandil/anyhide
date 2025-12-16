# Anyhide - Steganography Tool for Hiding Any Data in Any File

[![Crates.io](https://img.shields.io/crates/v/anyhide.svg)](https://crates.io/crates/anyhide)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org)
[![GitHub Release](https://img.shields.io/github/v/release/matutetandil/anyhide)](https://github.com/matutetandil/anyhide/releases)

**Hide anything inside anything.** Anyhide is an advanced steganography and encryption tool that conceals any data (text, files, binaries) within any carrier file (images, videos, documents, executables) using hybrid encryption with forward secrecy and plausible deniability.

## Why Anyhide?

Traditional steganography modifies the carrier file and transmits it. Anyhide is different:

| Traditional Steganography | Anyhide |
|---------------------------|------|
| Modifies the carrier file | Never touches the carrier |
| Transmits the modified file | Transmits only a short code |
| Carrier can be analyzed | Carrier stays untouched |
| Hide text in images | Hide **anything** in **anything** |

**Use cases:**
- Hide encrypted files inside a shared video
- Conceal sensitive documents using a public PDF as carrier
- Store secrets referenced by any file both parties have
- Covert communication with plausible deniability

## Overview

Anyhide uses a **pre-shared carrier** model:

1. Both parties have the same file (ANY file: image, video, PDF, executable, text, etc.)
2. Sender hides data (text OR binary files) by finding byte patterns in the carrier
3. Only an encrypted code is transmitted - **the carrier is never sent**
4. Receiver uses the same carrier + code to extract the hidden data

```
┌─────────────────────────────────────────────────────────────┐
│  SENDER                         RECEIVER                    │
│                                                             │
│  carrier.mp4 ──┐                      ┌── carrier.mp4       │
│                │                      │   (same file)       │
│  secret.zip ───┼──► ANYHIDE CODE ────────┼──► secret.zip       │
│                │   (only this         │                     │
│  passphrase ───┘    is sent)          └── passphrase        │
│                                                             │
│  The carrier is NEVER transmitted                           │
└─────────────────────────────────────────────────────────────┘
```

## Key Features

### Hide Anything in Anything
- **Any carrier**: text, images, audio, video, PDFs, executables, archives, databases
- **Any payload**: text messages, binary files, documents, compressed archives
- **Indistinguishable**: Anyhide code reveals nothing about what's hidden (text vs 10MB file)

### Military-Grade Security
- **Dual-layer encryption**: Symmetric (ChaCha20-Poly1305) + Asymmetric (X25519)
- **Forward secrecy**: Ephemeral keys - past messages stay secure even if keys leak
- **Message signing**: Ed25519 digital signatures for sender authentication
- **Plausible deniability**: Wrong passphrase returns garbage, not an error
- **Never fails**: Decoder always returns something - prevents brute-force detection

### Practical Features
- **QR code support**: Share codes via QR with Base45 encoding
- **Multi-recipient**: Encrypt once for multiple recipients
- **Compression**: DEFLATE compression for longer messages
- **Offline**: Works completely offline, no external services
- **Fast**: Suffix array for O(m·log n) substring search

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

### From crates.io (Recommended)

```bash
cargo install anyhide
```

### Download Pre-built Binary

Download the latest release for your platform from [GitHub Releases](https://github.com/matutetandil/anyhide/releases):

- **Linux**: `anyhide-linux-x86_64` or `anyhide-linux-aarch64`
- **macOS**: `anyhide-macos-x86_64` (Intel) or `anyhide-macos-aarch64` (Apple Silicon)
- **Windows**: `anyhide-windows-x86_64.exe`

### Build from Source

```bash
git clone https://github.com/matutetandil/anyhide.git
cd anyhide
cargo build --release
```

The binary will be available at `target/release/anyhide`.

## Usage

### Generate Key Pair

```bash
# Generate keys (creates 4 files)
anyhide keygen -o mykeys
# mykeys.pub       - Encryption public key (share with senders)
# mykeys.key       - Encryption private key (keep secret)
# mykeys.sign.pub  - Signing public key (share with receivers)
# mykeys.sign.key  - Signing private key (keep secret)
```

### Encode a Message

```bash
# Create a carrier file (or use any existing text file)
echo "Yesterday my aunt Martha called me on the phone to tell me something" > carrier.txt

# Encode a message
anyhide encode \
  --carrier carrier.txt \
  --message "Martha called" \
  --passphrase "secret123" \
  --key recipient.pub

# Output: AwNhYmNkZWZn... (encrypted code to send)
```

### Decode a Message

```bash
# Decode using the same carrier
anyhide decode \
  --code "AwNhYmNkZWZn..." \
  --carrier carrier.txt \
  --passphrase "secret123" \
  --key my.key

# Output: Martha called
```

### Available Options

```
anyhide keygen
  -o, --output <PATH>    Output path for keys (default: anyhide)

anyhide encode
  -c, --carrier <PATH>   Path to carrier file (any file type)
  -m, --message <MSG>    Text message to encode (mutually exclusive with --file)
  -f, --file <PATH>      Binary file to encode (mutually exclusive with --message)
  -p, --passphrase <PASS> Passphrase for encryption
  -k, --key <PATH>       Path to recipient's public key
  --sign <PATH>          Sign message with Ed25519 signing key
  --min-coverage <0-100> Minimum carrier coverage required (default: 100)
  -v, --verbose          Show positions found
  --qr <PATH>            Generate QR code and save to file (in addition to printing code)
  --qr-format <FMT>      QR format: png (default), svg, or ascii

anyhide decode
  --code <CODE>          The encrypted code to decode
  -c, --carrier <PATH>   Path to carrier file (same as encoding)
  -p, --passphrase <PASS> Passphrase for decryption
  -k, --key <PATH>       Path to your private key
  --verify <PATH>        Verify signature with Ed25519 signing public key
  -o, --output <PATH>    Output file for decoded data (required for binary)
  -v, --verbose          Show positions and fragments

anyhide multi-encrypt
  -m, --message <MSG>    Message to encrypt (or reads from stdin)
  -p, --passphrase <PASS> Passphrase for encryption
  -k, --keys <PATHS>...  Paths to recipients' public keys
  -o, --output <PATH>    Output file (prints base64 if not specified)

anyhide multi-decrypt
  -i, --input <INPUT>    Encrypted data (base64 string or file path)
  -p, --passphrase <PASS> Passphrase for decryption
  -k, --key <PATH>       Path to your private key

anyhide qr-generate
  -c, --code <CODE>      Anyhide code (base64) - reads from stdin if not provided
  -o, --output <PATH>    Output file path (PNG, SVG, or TXT)
  -f, --format <FMT>     Output format: png (default), svg, or ascii

anyhide qr-read
  -i, --input <PATH>     Path to image containing QR code
  -o, --output <PATH>    Output raw bytes to file (base64 to stdout if not specified)

anyhide qr-info
  -s, --size <BYTES>     Data size in bytes
  -c, --code <CODE>      Or provide Anyhide code to analyze

anyhide update
  --check                Only check for updates, don't install
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
anyhide encode -c carrier.txt -m "call me" -p "melville" -k bob.pub
# Output: AxB2c3...

# Bob decodes
anyhide decode --code "AxB2c3..." -c carrier.txt -p "melville" -k bob.key
# Output: call me
```

Anyone intercepting "AxB2c3..." has no idea:
- That it's a Anyhide code
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
anyhide encode -c shared_document.pdf -m "secret message" -p "passphrase" -k bob.pub
# Output: AxB2c3F4... (Anyhide code - the PDF is NOT modified)

# Bob decodes using the exact same PDF
anyhide decode --code "AxB2c3F4..." -c shared_document.pdf -p "passphrase" -k bob.key
# Output: secret message
```

For binary files, message fragments are searched as **byte sequences** within
the raw bytes of the file. Larger files = more byte diversity = better success rate.

## Example: Image Carrier

```bash
# Both parties have the same photo
anyhide encode -c vacation_photo.jpg -m "meeting at 5pm" -p "secret" -k bob.pub
# Output: BxY4z5W6... (Anyhide code)

anyhide decode --code "BxY4z5W6..." -c vacation_photo.jpg -p "secret" -k bob.key
# Output: meeting at 5pm
```

## Example: Video/Audio Carrier

```bash
# Video files work great due to their size
anyhide encode -c shared_video.mp4 -m "coordinates: 40.7128, -74.0060" -p "pass" -k bob.pub

# Audio files
anyhide encode -c song.wav -m "the eagle has landed" -p "pass" -k bob.pub
```

## Example: Hide Binary Files

Hide ANY file (zip, image, executable, etc.) inside a carrier. The Anyhide code
reveals nothing about whether the content is text or binary.

```bash
# Alice hides a secret.zip inside a shared video
anyhide encode -c shared_video.mp4 --file secret.zip -p "pass" -k bob.pub
# Output: BxY4z5W6... (Anyhide code - indistinguishable from text encoding)

# Bob extracts the file using -o to write raw bytes
anyhide decode --code "BxY4z5W6..." -c shared_video.mp4 -p "pass" -k bob.key -o secret.zip
# Output: Decoded 15234 bytes to secret.zip

# Works with any binary data:
anyhide encode -c carrier.bin --file confidential.pdf -p "pass" -k bob.pub
anyhide encode -c movie.mp4 --file keys.tar.gz -p "pass" -k bob.pub
anyhide encode -c image.png --file database.sqlite -p "pass" -k bob.pub
```

**Security Note:** The Anyhide code format is identical for text and binary messages.
An attacker cannot determine if the hidden content is "hello world" or a 10MB file
just by looking at the code.

## Example: Multi-Recipient Encryption

Encrypt a message for multiple recipients at once:

```bash
# Encrypt for Alice, Bob, and Charlie
anyhide multi-encrypt -m "Team meeting at 5pm" -p "shared_secret" \
  -k alice.pub -k bob.pub -k charlie.pub
# Output: AQMAAABhYmNkZWZn... (base64 encrypted data)

# Each recipient decrypts with their own private key
anyhide multi-decrypt -i "AQMAAABhYmNkZWZn..." -p "shared_secret" -k alice.key
# Output: Team meeting at 5pm
```

## Example: QR Code Generation

Share Anyhide codes via QR code for easy mobile scanning:

```bash
# Generate Anyhide code + QR in one step (recommended)
anyhide encode -c carrier.txt -m "secret message" -p "pass" -k bob.pub --qr code.png
# Output: AxB2c3F4... (Anyhide code)
#         QR code saved: code.png

# Or generate QR separately from existing code
CODE=$(anyhide encode -c carrier.txt -m "secret message" -p "pass" -k bob.pub)
anyhide qr-generate -c "$CODE" -o anyhide_code.png

# Read QR code back to Anyhide code
anyhide qr-read -i anyhide_code.png
# Output: [base64 Anyhide code]

# Check if your data fits in a QR code
anyhide qr-info --size 500
# Output: Fits in QR version 17, ~750 Base45 chars
```

**Why Base45?** Standard QR codes have an alphanumeric mode that's more efficient than byte mode. Base45 uses only alphanumeric characters, providing ~45% more capacity than Base64 for QR codes.

## Example: Message Signing (Ed25519)

Sign messages to prove sender authenticity. The signature is hidden inside the encrypted payload, so receivers cannot determine if a message is signed without decrypting.

```bash
# Alice generates her keys (includes signing keys)
anyhide keygen -o alice
# Creates: alice.pub, alice.key, alice.sign.pub, alice.sign.key

# Bob generates his keys
anyhide keygen -o bob

# Alice encodes AND signs the message
anyhide encode \
  -c carrier.txt \
  -m "This message is from Alice" \
  -p "secret" \
  -k bob.pub \
  --sign alice.sign.key

# Bob decodes AND verifies the signature
anyhide decode \
  --code "..." \
  -c carrier.txt \
  -p "secret" \
  -k bob.key \
  --verify alice.sign.pub
# Output:
# Decoded message: This message is from Alice
# Signature: VALID
```

**Security properties:**
- Signature is encrypted (hidden from observers)
- Invalid signature doesn't cause decode failure (plausible deniability)
- Messages are recovered with exact original case (signatures always verify)

## Example: Carrier Coverage

By default, Anyhide requires 100% coverage: all message characters must exist exactly (same case) in the carrier. This provides maximum security.

```bash
# This works - carrier has all characters with exact case
echo "Hello World" > carrier.txt
anyhide encode -c carrier.txt -m "Hello" -p "pass" -k bob.pub
# Success: Coverage 100%

# This fails - carrier doesn't have uppercase "H"
echo "hello world" > carrier.txt
anyhide encode -c carrier.txt -m "Hello" -p "pass" -k bob.pub
# Error: Carrier coverage 80% is below required 100%

# Allow lower coverage (accepts security risk)
anyhide encode -c carrier.txt -m "Hello" -p "pass" -k bob.pub --min-coverage 80
# Warning: Coverage 80% - some characters stored in code
```

**Security note:** When coverage is below 100%, missing characters are stored as "char_overrides" in the code. An attacker analyzing multiple messages might detect patterns. Use 100% coverage for maximum security.

## Project Structure

```
anyhide/
├── src/
│   ├── main.rs              # CLI with clap
│   ├── lib.rs               # Public re-exports, constants
│   ├── crypto/
│   │   ├── mod.rs           # Hybrid encryption with forward secrecy
│   │   ├── keys.rs          # X25519 + Ed25519 key generation, PEM format
│   │   ├── asymmetric.rs    # Encrypt/decrypt with X25519 + ChaCha20
│   │   ├── symmetric.rs     # Passphrase-based encryption
│   │   ├── signing.rs       # Ed25519 digital signatures
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
- **Digital Signatures**: Ed25519
- **Key Derivation**: HKDF-SHA256
- **Encryption Order**: Symmetric (passphrase) → Asymmetric (public key)

### Key Format

```
# Encryption keys (X25519)
-----BEGIN ANYHIDE PUBLIC KEY-----
[base64 of 32 bytes X25519 public key]
-----END ANYHIDE PUBLIC KEY-----

-----BEGIN ANYHIDE PRIVATE KEY-----
[base64 of 32 bytes X25519 secret key]
-----END ANYHIDE PRIVATE KEY-----

# Signing keys (Ed25519)
-----BEGIN ANYHIDE SIGNING PUBLIC KEY-----
[base64 of 32 bytes Ed25519 public key]
-----END ANYHIDE SIGNING PUBLIC KEY-----

-----BEGIN ANYHIDE SIGNING KEY-----
[base64 of 32 bytes Ed25519 secret key]
-----END ANYHIDE SIGNING KEY-----
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

## Disclaimer

**Anyhide is provided for educational and legitimate privacy purposes only.**

This software is a tool, and like any tool, it can be used for good or bad purposes. The authors and contributors:

- **DO NOT** endorse or encourage any illegal activities
- **ARE NOT** responsible for how this software is used
- **PROVIDE** this software "as is" without warranty of any kind

**You are solely responsible for ensuring your use complies with all applicable laws and regulations in your jurisdiction.** Legitimate uses include protecting personal privacy, secure communication, research, and educational purposes.

By using Anyhide, you agree that the authors bear no liability for any misuse or damages arising from the use of this software.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Version

Current version: 0.7.0 (see [CHANGELOG.md](CHANGELOG.md))
