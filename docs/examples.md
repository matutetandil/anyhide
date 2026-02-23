# Examples

Practical examples for common Anyhide use cases.

## Binary Files as Carrier

Use any file (video, PDF, image, executable) as carrier:

```bash
# Hide text in a shared video
anyhide encode -c shared_video.mp4 -m "secret message" -p "pass" --their-key bob.pub

# Hide a ZIP file inside a PDF
anyhide encode -c document.pdf --file secret.zip -p "pass" --their-key bob.pub

# Extract hidden file
anyhide decode --code "..." -c document.pdf -p "pass" --my-key bob.key -o secret.zip
```

## Message Signing

```bash
# Sign message
anyhide encode -c carrier.txt -m "From Alice" -p "pass" --their-key bob.pub --sign alice.sign.key

# Verify signature
anyhide decode --code "..." -c carrier.txt -p "pass" --my-key bob.key --verify alice.sign.pub
# Output: From Alice
# Signature: VALID
```

## Message Expiration

```bash
# Message expires in 24 hours
anyhide encode -c carrier.txt -m "Temp info" -p "pass" --their-key bob.pub --expires "+24h"

# After expiration: returns garbage (not an error)
```

## Code Splitting

```bash
# Split into 3 parts
anyhide encode -c carrier.txt -m "Secret" -p "pass" --their-key bob.pub --split 3
# Output: part-1: xxx, part-2: yyy, part-3: zzz

# Decode with all parts in order
anyhide decode --parts p1.txt p2.txt p3.txt -c carrier.txt -p "pass" --my-key bob.key

# Wrong order = garbage (plausible deniability)
```

## QR Codes

```bash
# Generate code + QR in one step
anyhide encode -c carrier.txt -m "Secret" -p "pass" --their-key bob.pub --qr code.png

# Read QR and decode
anyhide decode --code-qr code.png -c carrier.txt -p "pass" --my-key bob.key

# Split QR codes
anyhide encode -c carrier.txt -m "Secret" -p "pass" --their-key bob.pub --split 3 --qr code.png
# Creates: code-1.png, code-2.png, code-3.png
```

## Multi-Carrier Encoding

Use multiple carriers concatenated in order. The order is an additional secret!

```bash
# Encode with 3 carriers - order matters!
anyhide encode -c photo.jpg -c song.mp3 -c document.pdf \
  -m "Secret message" -p "pass" --their-key bob.pub

# Decode with EXACT same files in EXACT same order
anyhide decode -c photo.jpg -c song.mp3 -c document.pdf \
  --code "..." -p "pass" --my-key bob.key

# Wrong order = garbage (plausible deniability)
anyhide decode -c song.mp3 -c photo.jpg -c document.pdf \
  --code "..." -p "pass" --my-key bob.key
# Returns garbage, not an error
```

## Duress Password

```bash
# Encode with real + decoy messages
anyhide encode -c carrier.txt \
  -m "Real secret" -p "real-pass" \
  --decoy "Shopping list" --decoy-pass "decoy-pass" \
  --their-key bob.pub

# Real passphrase → real message
anyhide decode --code "..." -c carrier.txt -p "real-pass" --my-key bob.key

# Decoy passphrase → decoy message (give this under coercion)
anyhide decode --code "..." -c carrier.txt -p "decoy-pass" --my-key bob.key
```

## Contact Aliases

```bash
# Save a contact
anyhide contacts add alice /path/to/alice.pub

# Encode using alias instead of path
anyhide encode -c carrier.txt -m "Hello" -p "pass" --to alice
```

## Forward Secrecy Ratchet

```bash
# Alice sends with key rotation
anyhide encode -c carrier.txt -m "Hello Bob" -p "pass" \
    --their-key bob.pub --my-key alice.key --ratchet

# Bob decodes (keys auto-update)
anyhide decode --code "..." -c carrier.txt -p "pass" \
    --my-key bob.key --their-key alice.pub
```

See [Forward Secrecy & Ratchet](ratchet.md) for detailed ratchet workflows.
