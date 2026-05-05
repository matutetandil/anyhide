# Command Reference

Complete reference for all Anyhide CLI commands.

## Generate Keys

```bash
anyhide keygen [OPTIONS] -o <name>

Options:
  -o, --output <PATH>      Output path for keys (default: anyhide)
  --hybrid                 Generate post-quantum hybrid keys (X25519 + ML-KEM-768)
  --ephemeral              Generate ephemeral keys for forward secrecy
  --show-mnemonic          Show 24-word backup phrases (classical long-term keys only)
  --contact <NAME>         Contact name (required for consolidated storage)
  --eph-keys <PATH>        Path to .eph.key file (consolidated private keys)
  --eph-pubs <PATH>        Path to .eph.pub file (consolidated public keys)
  --eph-file <PATH>        Path to .eph file (unified storage)

# Long-term keys (default — classical X25519)
anyhide keygen -o mykeys

# Long-term hybrid post-quantum keys (X25519 + ML-KEM-768)
anyhide keygen --hybrid -o mykeys
# Required for the chat protocol (which is hybrid PQ since v0.14).
# For anyhide codes, hybrid is opt-in: encode / decode auto-detect the flavor
# from the PEM header, so no extra flags are needed at use time.
# Creates: mykeys.pub, mykeys.key (with HYBRID PEM headers), plus the
# Ed25519 mykeys.sign.pub / mykeys.sign.key signing pair.

# Long-term keys with mnemonic backup phrases (classical only)
anyhide keygen -o mykeys --show-mnemonic
# Shows 24-word phrases for both encryption and signing keys.
# Note: --show-mnemonic is silently skipped when combined with --hybrid;
# BIP39 backup for the 96-byte hybrid secret is a follow-up.

# Ephemeral keys (individual files)
anyhide keygen -o alice --ephemeral
# Creates: alice.pub, alice.key (with EPHEMERAL PEM headers)

# Ephemeral hybrid keys (individual files)
anyhide keygen --hybrid -o alice --ephemeral
# Creates: alice.pub, alice.key (with EPHEMERAL HYBRID PEM headers).

# Ephemeral keys (consolidated separate files) — classical
anyhide keygen --ephemeral --eph-keys keys.eph.key --eph-pubs keys.eph.pub --contact bob
# Adds/updates contact "bob" in both JSON files (version 1)

# Ephemeral hybrid keys (consolidated separate files) — version 2 stores
anyhide keygen --hybrid --ephemeral --eph-keys keys.eph.key --eph-pubs keys.eph.pub --contact bob
# Adds/updates contact "bob" in both JSON files with version: 2 markers.
# The store rejects writes from the classical path and vice versa, so v1
# and v2 stores live in distinct paths.

# Ephemeral keys (unified file) — classical
anyhide keygen --ephemeral --eph-file contacts.eph --contact bob
# Adds/updates contact "bob" with my_private and placeholder their_public

# Ephemeral hybrid keys (unified file) — version 2 store
anyhide keygen --hybrid --ephemeral --eph-file contacts.eph --contact bob
# Same UX as the classical unified store but with hybrid keys and version: 2.
```

## Encode

```bash
anyhide encode [OPTIONS] -c <CARRIER>... -p <PASSPHRASE>

Options:
  -c, --carriers <PATH>... Carrier file(s) - multiple files are concatenated.
                           Order matters! Wrong order = garbage (N! combinations)
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

The wire format (classical v6 vs hybrid post-quantum v7) is selected automatically
based on the recipient PEM header. A `BEGIN ANYHIDE PUBLIC KEY` produces a v6 code;
a `BEGIN ANYHIDE HYBRID PUBLIC KEY` produces a v7 code. Existing v6 codes remain
byte-identical, so peers who have not migrated to PQ keep working unchanged.

`--ratchet` is rejected for hybrid recipients (the encoder's `next_keypair` is
X25519-only). Encode without `--ratchet` for hybrid, or stick to classical keys
for ratcheted exchanges.

## Decode

```bash
anyhide decode [OPTIONS] -c <CARRIER>... -p <PASSPHRASE>

Code input (choose one):
  --code <TEXT>            Direct base64 code
  --code-qr <PATH>         Read from QR image
  --code-file <PATH>       Read from text file
  --parts <FILES>...       Combine split parts (2-10 files)

Options:
  -c, --carriers <PATH>... Carrier file(s) - EXACT same files in EXACT same order!
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

The decoder auto-detects the user's key flavor from the PEM header and the code's
wire format from its leading bytes. Mismatches (v7 code + classical secret, or v6
code + hybrid secret) flow through the never-fail decoder and yield deterministic
garbage — there is no error signal an attacker could probe to learn the format.

## Fingerprint

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

## Mnemonic Backup

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

## Contacts

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

## Other Commands

```bash
anyhide multi-encrypt    # Encrypt for multiple recipients
anyhide multi-decrypt    # Decrypt multi-recipient message
anyhide qr-generate      # Generate QR from code
anyhide qr-read          # Read code from QR
anyhide qr-info          # Check QR capacity
anyhide update           # Update to latest version
```
