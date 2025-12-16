# Anyhide - Hide Anything in Anything

[![Crates.io](https://img.shields.io/crates/v/anyhide.svg)](https://crates.io/crates/anyhide)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org)
[![GitHub Release](https://img.shields.io/github/v/release/matutetandil/anyhide)](https://github.com/matutetandil/anyhide/releases)

**Hide anything inside anything.** Anyhide is an advanced steganography and encryption tool that conceals any data (text, files, binaries) within any carrier file (images, videos, documents, executables) using hybrid encryption with forward secrecy and plausible deniability.

## Why Anyhide?

Traditional steganography modifies the carrier file and transmits it. Anyhide is different:

| Traditional Steganography | Anyhide |
|---------------------------|---------|
| Modifies the carrier file | Never touches the carrier |
| Transmits the modified file | Transmits only a short code |
| Carrier can be analyzed | Carrier stays untouched |
| Hide text in images | Hide **anything** in **anything** |

**Use cases:**
- Hide encrypted files inside a shared video
- Conceal sensitive documents using a public PDF as carrier
- Store secrets referenced by any file both parties have
- Covert communication with plausible deniability

## How It Works

Anyhide uses a **pre-shared carrier** model:

1. Both parties have the same file (ANY file: image, video, PDF, text, etc.)
2. Sender hides data by finding byte patterns in the carrier
3. Only an encrypted code is transmitted - **the carrier is never sent**
4. Receiver uses the same carrier + code to extract the hidden data

```
┌─────────────────────────────────────────────────────────────┐
│  SENDER                         RECEIVER                    │
│                                                             │
│  carrier.mp4 ──┐                      ┌── carrier.mp4       │
│                │                      │   (same file)       │
│  secret.zip ───┼──► ANYHIDE CODE ─────┼──► secret.zip       │
│                │   (only this         │                     │
│  passphrase ───┘    is sent)          └── passphrase        │
│                                                             │
│  The carrier is NEVER transmitted                           │
└─────────────────────────────────────────────────────────────┘
```

## Key Features

- **Any carrier**: text, images, audio, video, PDFs, executables, archives
- **Any payload**: text messages, binary files, documents, archives
- **Dual-layer encryption**: Symmetric (ChaCha20) + Asymmetric (X25519)
- **Forward secrecy**: Past messages stay secure even if keys leak
- **Message signing**: Ed25519 signatures for sender authentication
- **Message expiration**: Auto-expiring messages
- **Code splitting**: Split codes for multi-channel delivery
- **QR code support**: Share codes via QR
- **Plausible deniability**: Wrong passphrase returns garbage, not an error
- **Never fails**: Decoder always returns something - prevents brute-force detection

## Installation

### From crates.io

```bash
cargo install anyhide
```

### Download Pre-built Binary

Download from [GitHub Releases](https://github.com/matutetandil/anyhide/releases):

- **Linux**: `anyhide-linux-x86_64` or `anyhide-linux-aarch64`
- **macOS**: `anyhide-macos-x86_64` (Intel) or `anyhide-macos-aarch64` (Apple Silicon)
- **Windows**: `anyhide-windows-x86_64.exe`

### Build from Source

```bash
git clone https://github.com/matutetandil/anyhide.git
cd anyhide
cargo build --release
```

## Quick Start

### 1. Generate Keys

```bash
anyhide keygen -o mykeys
# Creates: mykeys.pub, mykeys.key, mykeys.sign.pub, mykeys.sign.key
```

### 2. Encode a Message

```bash
# Using any text file as carrier
echo "The amazing Amanda went to the park yesterday" > carrier.txt

anyhide encode \
  -c carrier.txt \
  -m "ama park" \
  -p "secret123" \
  -k recipient.pub
# Output: AwNhYmNkZWZn... (send this code)
```

### 3. Decode a Message

```bash
anyhide decode \
  --code "AwNhYmNkZWZn..." \
  -c carrier.txt \
  -p "secret123" \
  -k recipient.key
# Output: ama park
```

## Command Reference

### Generate Keys

```bash
anyhide keygen -o <name>
# Creates 4 files:
#   <name>.pub       - Encryption public key (share with senders)
#   <name>.key       - Encryption private key (keep secret)
#   <name>.sign.pub  - Signing public key (share with receivers)
#   <name>.sign.key  - Signing private key (keep secret)
```

### Encode

```bash
anyhide encode [OPTIONS] -c <CARRIER> -p <PASSPHRASE> -k <PUBKEY>

Options:
  -c, --carrier <PATH>     Carrier file (any file type)
  -m, --message <TEXT>     Text message (or use --file for binary)
  -f, --file <PATH>        Binary file to hide
  -p, --passphrase <PASS>  Passphrase for encryption
  -k, --key <PATH>         Recipient's public key
  --sign <PATH>            Sign with Ed25519 key
  --expires <TIME>         Expiration: "+30m", "+24h", "+7d", "2025-12-31"
  --split <N>              Split into N parts (2-10)
  --qr <PATH>              Generate QR code
  --qr-format <FMT>        QR format: png, svg, ascii
  --min-coverage <0-100>   Minimum carrier coverage (default: 100)
  -v, --verbose            Show details
```

### Decode

```bash
anyhide decode [OPTIONS] -c <CARRIER> -p <PASSPHRASE> -k <PRIVKEY>

Code input (choose one):
  --code <TEXT>            Direct base64 code
  --code-qr <PATH>         Read from QR image
  --code-file <PATH>       Read from text file
  --parts <FILES>...       Combine split parts (2-10 files)

Options:
  -c, --carrier <PATH>     Carrier file (same as encoding)
  -p, --passphrase <PASS>  Passphrase for decryption
  -k, --key <PATH>         Your private key
  --verify <PATH>          Verify signature with sender's public key
  -o, --output <PATH>      Output file (required for binary)
  -v, --verbose            Show details
```

### Other Commands

```bash
anyhide multi-encrypt    # Encrypt for multiple recipients
anyhide multi-decrypt    # Decrypt multi-recipient message
anyhide qr-generate      # Generate QR from code
anyhide qr-read          # Read code from QR
anyhide qr-info          # Check QR capacity
anyhide update           # Update to latest version
```

## Examples

### Binary Files as Carrier

Use any file (video, PDF, image, executable) as carrier:

```bash
# Hide text in a shared video
anyhide encode -c shared_video.mp4 -m "secret message" -p "pass" -k bob.pub

# Hide a ZIP file inside a PDF
anyhide encode -c document.pdf --file secret.zip -p "pass" -k bob.pub

# Extract hidden file
anyhide decode --code "..." -c document.pdf -p "pass" -k bob.key -o secret.zip
```

### Message Signing

```bash
# Sign message
anyhide encode -c carrier.txt -m "From Alice" -p "pass" -k bob.pub --sign alice.sign.key

# Verify signature
anyhide decode --code "..." -c carrier.txt -p "pass" -k bob.key --verify alice.sign.pub
# Output: From Alice
# Signature: VALID
```

### Message Expiration

```bash
# Message expires in 24 hours
anyhide encode -c carrier.txt -m "Temp info" -p "pass" -k bob.pub --expires "+24h"

# After expiration: returns garbage (not an error)
```

### Code Splitting

```bash
# Split into 3 parts
anyhide encode -c carrier.txt -m "Secret" -p "pass" -k bob.pub --split 3
# Output: part-1: xxx, part-2: yyy, part-3: zzz

# Decode with all parts in order
anyhide decode --parts p1.txt p2.txt p3.txt -c carrier.txt -p "pass" -k bob.key

# Wrong order = garbage (plausible deniability)
```

### QR Codes

```bash
# Generate code + QR in one step
anyhide encode -c carrier.txt -m "Secret" -p "pass" -k bob.pub --qr code.png

# Read QR and decode
anyhide decode --code-qr code.png -c carrier.txt -p "pass" -k bob.key

# Split QR codes
anyhide encode -c carrier.txt -m "Secret" -p "pass" -k bob.pub --split 3 --qr code.png
# Creates: code-1.png, code-2.png, code-3.png
```

## Security Properties

1. **Four-Factor Security**: Carrier + Passphrase + Private Key + Correct Version
2. **Never-Fail Decoder**: Always produces output - no error signals for attackers
3. **Plausible Deniability**: Wrong inputs return garbage, not errors
4. **Forward Secrecy**: Ephemeral keys protect past messages
5. **Code Splitting**: Wrong order = garbage (no error)

## Disclaimer

**Anyhide is provided for educational and legitimate privacy purposes only.**

This software is a tool, and like any tool, it can be used for good or bad purposes. The authors:
- **DO NOT** endorse or encourage any illegal activities
- **ARE NOT** responsible for how this software is used
- **PROVIDE** this software "as is" without warranty

**You are solely responsible for ensuring your use complies with all applicable laws.**

## Documentation

- **User Manual**: This README
- **Architecture & Development**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **Version History**: [CHANGELOG.md](CHANGELOG.md)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Version

Current version: 0.7.1 (see [CHANGELOG.md](CHANGELOG.md))
