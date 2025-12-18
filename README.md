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
- **Forward secrecy ratchet**: Key rotation per message - past messages stay secure even if keys leak
- **Ephemeral keys**: Generate rotating keys for perfect forward secrecy
- **Key fingerprints**: Verify keys out-of-band (hex, emoji, visual art)
- **Mnemonic backup**: Export/import keys as 24-word BIP39 phrases for paper backup
- **Contacts with aliases**: Save contacts in `~/.anyhide/contacts.toml`, use `--to alice`
- **P2P Chat over Tor**: Real-time encrypted chat via Tor hidden services (experimental)
- **Duress password**: Two messages, two passphrases - reveal the decoy under coercion
- **Message signing**: Ed25519 signatures for sender authentication
- **Message expiration**: Auto-expiring messages
- **Code splitting**: Split codes for multi-channel delivery
- **QR code support**: Share codes via QR
- **Plausible deniability**: Wrong passphrase returns garbage, not an error
- **Never fails**: Decoder always returns something - prevents brute-force detection
- **Library support**: Use Anyhide in your own Rust projects

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
  --their-key recipient.pub
# Output: AwNhYmNkZWZn... (send this code)
```

### 3. Decode a Message

```bash
anyhide decode \
  --code "AwNhYmNkZWZn..." \
  -c carrier.txt \
  -p "secret123" \
  --my-key recipient.key
# Output: ama park
```

## Command Reference

### Generate Keys

```bash
anyhide keygen [OPTIONS] -o <name>

Options:
  -o, --output <PATH>      Output path for keys (default: anyhide)
  --ephemeral              Generate ephemeral keys for forward secrecy
  --show-mnemonic          Show 24-word backup phrases (long-term keys only)
  --contact <NAME>         Contact name (required for consolidated storage)
  --eph-keys <PATH>        Path to .eph.key file (consolidated private keys)
  --eph-pubs <PATH>        Path to .eph.pub file (consolidated public keys)
  --eph-file <PATH>        Path to .eph file (unified storage)

# Long-term keys (default)
anyhide keygen -o mykeys

# Long-term keys with mnemonic backup phrases
anyhide keygen -o mykeys --show-mnemonic
# Shows 24-word phrases for both encryption and signing keys
# Creates: mykeys.pub, mykeys.key, mykeys.sign.pub, mykeys.sign.key

# Ephemeral keys (individual files)
anyhide keygen -o alice --ephemeral
# Creates: alice.pub, alice.key (with EPHEMERAL PEM headers)

# Ephemeral keys (consolidated separate files)
anyhide keygen --ephemeral --eph-keys keys.eph.key --eph-pubs keys.eph.pub --contact bob
# Adds/updates contact "bob" in both JSON files

# Ephemeral keys (unified file)
anyhide keygen --ephemeral --eph-file contacts.eph --contact bob
# Adds/updates contact "bob" with my_private and placeholder their_public
```

### Encode

```bash
anyhide encode [OPTIONS] -c <CARRIER> -p <PASSPHRASE>

Options:
  -c, --carrier <PATH>     Carrier file (any file type)
  -m, --message <TEXT>     Text message (or use --file for binary)
  -f, --file <PATH>        Binary file to hide
  -p, --passphrase <PASS>  Passphrase for encryption

Key options (choose one):
  --their-key <PATH>       Recipient's public key (.pub file)
  --to <ALIAS>             Contact alias (from ~/.anyhide/contacts.toml)
  --eph-file <PATH>        Unified ephemeral key store (.eph)
  --eph-keys <PATH>        Separated ephemeral private keys (.eph.key)
  --eph-pubs <PATH>        Separated ephemeral public keys (.eph.pub)
  --contact <NAME>         Contact name (required with --eph-file or --eph-keys/--eph-pubs)
  -k, --key <PATH>         [DEPRECATED] Use --their-key instead

Ratchet options:
  --ratchet                Enable forward secrecy (auto key rotation)
  --my-key <PATH>          Your private key (for auto-saving next keypair)

Duress password (plausible deniability):
  --decoy <MESSAGE>        Decoy message revealed with --decoy-pass
  --decoy-pass <PASS>      Passphrase for the decoy message

Other options:
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
anyhide decode [OPTIONS] -c <CARRIER> -p <PASSPHRASE>

Code input (choose one):
  --code <TEXT>            Direct base64 code
  --code-qr <PATH>         Read from QR image
  --code-file <PATH>       Read from text file
  --parts <FILES>...       Combine split parts (2-10 files)

Options:
  -c, --carrier <PATH>     Carrier file (same as encoding)
  -p, --passphrase <PASS>  Passphrase for decryption

Key options (choose one):
  --my-key <PATH>          Your private key (.key file)
  --eph-file <PATH>        Unified ephemeral key store (.eph)
  --eph-keys <PATH>        Separated ephemeral private keys (.eph.key)
  --eph-pubs <PATH>        Separated ephemeral public keys (.eph.pub)
  --contact <NAME>         Contact name (required with --eph-file or --eph-keys/--eph-pubs)
  -k, --key <PATH>         [DEPRECATED] Use --my-key instead

Ratchet options:
  --their-key <PATH>       Sender's public key (for auto-saving their next key)

Other options:
  --verify <PATH>          Verify signature with sender's public key
  -o, --output <PATH>      Output file (required for binary)
  -v, --verbose            Show details
```

### Fingerprint

Display a key's fingerprint for out-of-band verification (like Signal/WhatsApp).

```bash
anyhide fingerprint <KEY_PATH> [OPTIONS]

Options:
  -f, --format <FMT>     Output format: hex, emoji, art, or all (default: all)

# Show all fingerprint formats
anyhide fingerprint alice.pub

# Show only emoji fingerprint (easy to compare by phone)
anyhide fingerprint alice.pub -f emoji
```

Output example:
```
Key: alice.pub

Hex Fingerprint:
  75EC37D4 51EBEDE4 E4AA4182 FD719560
  BE3E765C CE49A772 597A0ACF 09AC05FA

Emoji Fingerprint:
  🌲 🚂 🌺 🦊 🐺 ⛵ 🏎️ 🎻

Visual Fingerprint:
  +-----------------+
  |             o .o|
  |           .o ..+|
  |          . o..oo|
  |         + o .o..|
  |        S + +.+oB|
  |         . *.+o#+|
  |        .   O+=+B|
  |         . o.Oo= |
  |          E ..*  |
  +-----------------+
```

### Mnemonic Backup

Export and import long-term keys as 24-word BIP39 phrases for paper backup.

```bash
# Export existing key to mnemonic
anyhide export-mnemonic mykeys.key
# Shows 24 words for paper backup

# Export signing key
anyhide export-mnemonic mykeys.sign.key

# Import encryption key from mnemonic (interactive)
anyhide import-mnemonic -o restored
# Enter 24 words when prompted
# Creates: restored.key, restored.pub

# Import signing key from mnemonic
anyhide import-mnemonic -o restored --key-type signing
# Creates: restored.sign.key, restored.sign.pub
```

**Important:** Mnemonic backup is only for long-term private keys (`.key`, `.sign.key`). Ephemeral keys rotate per message and should not be backed up.

### Contacts

Manage contacts with aliases to avoid typing full paths.

```bash
# Add a contact
anyhide contacts add alice /path/to/alice.pub
anyhide contacts add alice /path/to/alice.pub --signing-key /path/to/alice.sign.pub

# List all contacts
anyhide contacts list

# Show contact details with fingerprint
anyhide contacts show alice

# Remove a contact
anyhide contacts remove alice

# Use contact in encode
anyhide encode -c carrier.txt -m "Hello" -p "pass" --to alice
```

Contacts are stored in `~/.anyhide/contacts.toml`:
```toml
[contacts.alice]
public_key = "/path/to/alice.pub"
signing_key = "/path/to/alice.sign.pub"

[contacts.bob]
public_key = "/path/to/bob.pub"
```

### P2P Chat over Tor

Real-time encrypted chat using Tor hidden services. Both peers are equal - no server/client distinction.

**Security Warning:** Arti's onion services are experimental and not as secure as C-Tor. Do not use for highly sensitive communications.

**Setup (one time):**
```bash
# 1. Generate your keys (encryption + signing)
anyhide keygen -o mykeys
anyhide keygen -o mykeys --signing

# 2. Initialize your chat identity (bootstraps Tor, shows your .onion)
anyhide chat init -k mykeys -s mykeys.sign
# Output: Your .onion address: xyz123abc.onion

# 3. Add a contact (you need their .onion address and public keys)
anyhide chat add bob <bob.onion> --key bob.pub --sign-key bob.sign.pub
```

**Start chatting:**
```bash
anyhide chat bob
# Enter your passphrase when prompted (input is hidden)
```

That's it! The system will:
1. Ask for your passphrase (required for encryption, input is hidden)
2. Create your hidden service
3. Try to connect to Bob's .onion address
4. If Bob isn't online, wait for him to connect to you
5. First successful connection (incoming or outgoing) establishes the session
6. Launch the TUI (Terminal User Interface)

**TUI Interface:**
```
┌─ Anyhide Chat - bob ─────────────────────────────────┐
│ Connected | abc123...onion | 2↑ 1↓                   │
├──────────────────────────────────────────────────────┤
│                                                      │
│  [14:32] Connected to bob                            │
│  [14:32] Type /help for commands. Ctrl+C to quit.    │
│  [14:33] you: Hello Bob!                             │
│  [14:33] bob: Hey Alice! How are you?                │
│                                                      │
├─ Input ──────────────────────────────────────────────┤
│ > your message here...                  11/256       │
└──────────────────────────────────────────────────────┘
```

The counter shows `current/max` characters. Turns yellow at <20 remaining, red at 0.

**Chat management commands:**
```bash
anyhide chat init -k <keys> -s <sign>   # Initialize your identity (shows .onion)
anyhide chat add <name> <onion> ...     # Add a contact
anyhide chat list                       # List contacts
anyhide chat show <name>                # Show contact details
anyhide chat show me                    # Show your own identity and .onion
anyhide chat remove <name>              # Remove a contact
```

**Local testing with profiles:**
```bash
# Run multiple identities on the same machine (for testing)
# Terminal 1:
anyhide chat --profile alice init -k alice -s alice.sign
anyhide chat --profile alice add bob <bob.onion> --key bob.pub --sign-key bob.sign.pub
anyhide chat --profile alice bob

# Terminal 2:
anyhide chat --profile bob init -k bob -s bob.sign
anyhide chat --profile bob add alice <alice.onion> --key alice.pub --sign-key alice.sign.pub
anyhide chat --profile bob alice
```

Each profile gets separate config and Tor state directories.

**Chat session commands:**
- `/quit` or `/q` - Exit the chat
- `/status` or `/s` - Show session statistics
- `/help` or `/h` - Show available commands
- `/clear` or `/c` - Clear message history

**Keyboard shortcuts:**
- `Ctrl+C` or `Esc` - Quit
- `Enter` - Send message
- `Page Up/Down` - Scroll message history
- `Ctrl+Up/Down` - Scroll one line

**How it works:**
1. Both parties initialize with `chat init` (creates their .onion identity)
2. Exchange .onion addresses and public keys out-of-band
3. Add each other with `chat add`
4. Run `anyhide chat <contact>` - both peers create hidden services and race to connect
5. First successful connection wins, handshake establishes encrypted session
6. Messages encrypted with Double Ratchet protocol for forward secrecy

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

### Forward Secrecy Ratchet

Enable key rotation per message for perfect forward secrecy.

#### Ephemeral Key Storage Formats

Anyhide supports 3 storage formats for ephemeral keys:

**Option 1: Individual PEM files** (simple, single contact)
```bash
anyhide keygen -o alice --ephemeral
# Creates: alice.pub, alice.key (with EPHEMERAL headers)
```

**Option 2: Separate consolidated JSON files** (multiple contacts)
```bash
anyhide keygen --ephemeral --eph-keys mykeys.eph.key --eph-pubs contacts.eph.pub --contact bob
# mykeys.eph.key: JSON with your private keys for each contact
# contacts.eph.pub: JSON with each contact's public key
```

**Option 3: Unified JSON file** (recommended for chat apps)
```bash
anyhide keygen --ephemeral --eph-file contacts.eph --contact bob
# contacts.eph: JSON with both my_private and their_public per contact
```

#### Automatic Ratchet with Individual Files

```bash
# Step 1: Both parties generate ephemeral keys and exchange public keys
anyhide keygen -o alice --ephemeral   # Alice: alice.pub, alice.key
anyhide keygen -o bob --ephemeral     # Bob: bob.pub, bob.key

# Step 2: Alice sends message (keys rotate automatically)
anyhide encode -c carrier.txt -m "Hello Bob" -p "pass" \
    --their-key bob.pub --my-key alice.key --ratchet
# Output: Just the code (alice.key updated with next keypair)

# Step 3: Bob decodes (their public key updated automatically)
anyhide decode --code "..." -c carrier.txt -p "pass" \
    --my-key bob.key --their-key alice.pub
# Output: Hello Bob (alice.pub updated with her next public key)

# Step 4: Bob replies (keys rotate again)
anyhide encode -c carrier.txt -m "Hi Alice!" -p "pass" \
    --their-key alice.pub --my-key bob.key --ratchet
# Output: Just the code (bob.key updated)
```

#### Automatic Ratchet with Separated Stores

For environments where you want private keys and public keys in separate files:

```bash
# Step 1: Setup - create separated key stores
anyhide keygen --ephemeral --eph-keys alice.eph.key --eph-pubs alice.eph.pub --contact bob
anyhide keygen --ephemeral --eph-keys bob.eph.key --eph-pubs bob.eph.pub --contact alice
# Exchange initial public keys

# Step 2: Alice sends message
anyhide encode -c carrier.txt -m "Hello Bob" -p "pass" \
    --eph-keys alice.eph.key --eph-pubs alice.eph.pub --contact bob --ratchet
# Output: Just the code (alice.eph.key[bob] updated with next keypair)

# Step 3: Bob decodes
anyhide decode --code "..." -c carrier.txt -p "pass" \
    --eph-keys bob.eph.key --eph-pubs bob.eph.pub --contact alice
# Output: Hello Bob (bob.eph.pub[alice] updated with Alice's next public key)
```

#### Automatic Ratchet with Unified Store (Recommended)

```bash
# Step 1: Setup - create unified key stores for each party
anyhide keygen --ephemeral --eph-file alice.eph --contact bob
anyhide keygen --ephemeral --eph-file bob.eph --contact alice
# Exchange public keys initially

# Step 2: Alice sends message
anyhide encode -c carrier.txt -m "Hello Bob" -p "pass" \
    --eph-file alice.eph --contact bob --ratchet
# Output: Just the code (alice.eph[bob].my_private updated)

# Step 3: Bob decodes
anyhide decode --code "..." -c carrier.txt -p "pass" \
    --eph-file bob.eph --contact alice
# Output: Hello Bob (bob.eph[alice].their_public updated)

# Step 4: Bob replies
anyhide encode -c carrier.txt -m "Hi Alice!" -p "pass" \
    --eph-file bob.eph --contact alice --ratchet
# Output: Just the code (bob.eph[alice].my_private updated)
```

**Key points:**
- Messages are always clean - no key information displayed
- Keys rotate automatically after each encode/decode
- Use `-v` for verbose output if you need to see key details
- The `--key` flag is deprecated - use `--my-key` and `--their-key` instead

#### Library Usage for Chat Applications

```rust
use anyhide::{encode_with_config, decode_with_config, EncoderConfig, DecoderConfig};
use anyhide::{KeyPair, save_unified_keys_for_contact, update_unified_public_key};

// Initial setup: generate keys for Bob
let my_keypair = KeyPair::generate_ephemeral();
save_unified_keys_for_contact(
    "contacts.eph",
    "bob",
    my_keypair.secret_key(),
    &bobs_initial_public_key,
)?;

// Encode with ratchet enabled
let config = EncoderConfig { ratchet: true, ..Default::default() };
let result = encode_with_config(&carrier, "Hello!", "pass", &bobs_public_key, &config)?;

// result.next_keypair contains your NEXT key pair
// Save it for the next message you send
// result.code contains the encrypted message

// On receiving a reply, decode and get their next key
let decoded = decode_with_config(&code, &carrier, "pass", &my_secret_key, &DecoderConfig::default());
if let Some(next_key_bytes) = decoded.next_public_key {
    // Update Bob's public key for the next message
    let next_public = PublicKey::from(<[u8; 32]>::try_from(next_key_bytes)?);
    update_unified_public_key("contacts.eph", "bob", &next_public)?;
}
```

**How the ratchet works:**
1. Each message includes sender's NEXT public key
2. Recipient uses that key for the reply
3. Keys rotate with every message exchange
4. Compromised keys cannot decrypt past messages

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

Current version: 0.11.0 (see [CHANGELOG.md](CHANGELOG.md))
