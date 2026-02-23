# Anyhide - Hide Anything in Anything

[![Crates.io](https://img.shields.io/crates/v/anyhide.svg)](https://crates.io/crates/anyhide)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org)
[![GitHub Release](https://img.shields.io/github/v/release/matutetandil/anyhide)](https://github.com/matutetandil/anyhide/releases)

**Hide anything inside anything.** Anyhide is an advanced steganography and encryption tool that conceals any data (text, files, binaries) within any carrier file(s) using hybrid encryption with forward secrecy and plausible deniability.

## Why Anyhide?

| Traditional Steganography | Anyhide |
|---------------------------|---------|
| Modifies the carrier file | Never touches the carrier |
| Transmits the modified file | Transmits only a short code |
| Carrier can be analyzed | Carrier stays untouched |
| Hide text in images | Hide **anything** in **anything** |

## How It Works

Both parties share a file (ANY file). The sender hides data by finding byte patterns in the carrier. Only an encrypted code is transmitted - **the carrier is never sent**.

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
- **Forward secrecy ratchet**: Key rotation per message
- **P2P Chat over Tor**: Real-time encrypted chat via Tor hidden services
- **Duress password**: Two messages, two passphrases - reveal the decoy under coercion
- **Multi-carrier encoding**: Multiple files as carrier, order is an additional secret
- **Message signing**: Ed25519 signatures for sender authentication
- **Code splitting**: Split codes for multi-channel delivery
- **QR code support**: Share codes via QR
- **Plausible deniability**: Wrong passphrase returns garbage, not an error
- **Never fails**: Decoder always returns something - prevents brute-force detection

## Installation

**From crates.io:**
```bash
cargo install anyhide
```

**Pre-built binary:** Download from [GitHub Releases](https://github.com/matutetandil/anyhide/releases) (Linux, macOS, Windows)

**From source:**
```bash
git clone https://github.com/matutetandil/anyhide.git && cd anyhide && cargo build --release
```

## Quick Start

```bash
# Generate keys
anyhide keygen -o mykeys

# Encode a message
anyhide encode -c carrier.txt -m "secret" -p "pass123" --their-key recipient.pub

# Decode a message
anyhide decode --code "AwNhYm..." -c carrier.txt -p "pass123" --my-key recipient.key
```

## Documentation

| Document | Description |
|----------|-------------|
| [Command Reference](docs/commands.md) | All CLI commands and options |
| [P2P Chat over Tor](docs/chat.md) | Encrypted chat setup, TUI, multi-contact dashboard |
| [Forward Secrecy & Ratchet](docs/ratchet.md) | Key rotation, ephemeral keys, library usage |
| [Security Properties](docs/security.md) | Threat model, duress password, plausible deniability |
| [Examples](docs/examples.md) | Practical usage examples |
| [Architecture](ARCHITECTURE.md) | Internal design and development guide |
| [Changelog](CHANGELOG.md) | Version history |

## Support

Anyhide is free and open source, built with passion. If you find it useful, consider buying me a coffee:

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?logo=buy-me-a-coffee&logoColor=white)](https://buymeacoffee.com/matutetandil)

## Disclaimer

**Anyhide is provided for educational and legitimate privacy purposes only.** The authors do not endorse illegal activities, are not responsible for how this software is used, and provide it "as is" without warranty. **You are solely responsible for ensuring your use complies with all applicable laws.**

## License

MIT License - see [LICENSE](LICENSE) for details.

## Version

Current version: 0.13.0 (see [CHANGELOG.md](CHANGELOG.md))
