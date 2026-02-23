# Forward Secrecy & Ratchet

Enable key rotation per message for perfect forward secrecy.

## Ephemeral Key Storage Formats

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

## Automatic Ratchet with Individual Files

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

## Automatic Ratchet with Separated Stores

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

## Automatic Ratchet with Unified Store (Recommended)

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

## Library Usage for Chat Applications

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

## How the Ratchet Works

1. Each message includes sender's NEXT public key
2. Recipient uses that key for the reply
3. Keys rotate with every message exchange
4. Compromised keys cannot decrypt past messages
