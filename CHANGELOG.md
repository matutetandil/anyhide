# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
