# Security Properties

Anyhide's security model is built on multiple layers that work together to provide strong encryption with plausible deniability.

## Core Security Layers

1. **Four-Factor Security**: Carrier + Passphrase + Private Key + Correct Version
2. **Never-Fail Decoder**: Always produces output - no error signals for attackers
3. **Plausible Deniability**: Wrong inputs return garbage, not errors
4. **Forward Secrecy**: Ephemeral keys protect past messages
5. **Code Splitting**: Wrong order = garbage (no error)

## Plausible Deniability

Anyhide's decoder NEVER fails. Given any combination of carrier, passphrase, and key, it always returns something. This means:

- An attacker cannot tell if they have the right passphrase
- Brute-force detection is impossible - every attempt "succeeds"
- There's no way to prove that a specific carrier contains hidden data

## Duress Password

Hide two messages in one code - reveal the decoy under coercion:

```bash
# Encode with real + decoy messages
anyhide encode -c carrier.txt \
  -m "Real secret message" -p "real-pass" \
  --decoy "Nothing important here" --decoy-pass "decoy-pass" \
  --their-key bob.pub

# Real passphrase → real message
anyhide decode --code "..." -c carrier.txt -p "real-pass" --my-key bob.key
# Output: Real secret message

# Decoy passphrase → decoy message
anyhide decode --code "..." -c carrier.txt -p "decoy-pass" --my-key bob.key
# Output: Nothing important here

# Wrong passphrase → garbage (not an error)
anyhide decode --code "..." -c carrier.txt -p "wrong-pass" --my-key bob.key
# Output: (garbage data)
```

All three outputs look identical in format. An observer cannot determine which is the "real" message.

## Code Splitting

Split a code into N parts for multi-channel delivery. ALL parts are required, in the correct order:

```bash
# Split into 3 parts
anyhide encode -c carrier.txt -m "Secret" -p "pass" --their-key bob.pub --split 3
# Output: part-1: xxx, part-2: yyy, part-3: zzz

# Decode with all parts in order
anyhide decode --parts p1.txt p2.txt p3.txt -c carrier.txt -p "pass" --my-key bob.key

# Wrong order = garbage (plausible deniability)
anyhide decode --parts p2.txt p1.txt p3.txt -c carrier.txt -p "pass" --my-key bob.key
# Returns garbage, not an error
```

## Multi-Carrier Security

Using multiple carriers concatenated in order. The order is an additional secret:

```bash
# Encode with 3 carriers - order matters!
anyhide encode -c photo.jpg -c song.mp3 -c document.pdf \
  -m "Secret message" -p "pass" --their-key bob.pub

# Wrong order = garbage (plausible deniability)
anyhide decode -c song.mp3 -c photo.jpg -c document.pdf \
  --code "..." -p "pass" --my-key bob.key
# Returns garbage, not an error
```

**Security benefit:** N carriers provide N! additional combinations:
- 2 carriers = 2 combinations
- 3 carriers = 6 combinations
- 4 carriers = 24 combinations
- 5 carriers = 120 combinations

When using multiple carriers:
- All files are read as bytes and concatenated in order
- Single text file with `-c file.txt` preserves text carrier behavior
- Multiple files always become a binary carrier

## Forward Secrecy

See [Forward Secrecy & Ratchet](ratchet.md) for details on key rotation.

## Chat Security

The P2P chat uses the Double Ratchet protocol (like Signal) over Tor hidden services:

- Messages encrypted with per-message keys derived from ratchet chains
- Header encryption hides sequence numbers and DH public keys
- Carrier rotation via a separate KDF chain
- User passphrase combined with derived keys for additional entropy
- All cryptographic state is kept in RAM only and zeroized on session end
- Messages are NEVER written to disk

See [P2P Chat over Tor](chat.md) for usage details.
