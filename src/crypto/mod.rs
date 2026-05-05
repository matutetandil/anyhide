//! Cryptographic operations for Anyhide.
//!
//! This module provides:
//! - Key generation and management (X25519)
//! - Asymmetric encryption (X25519 + ChaCha20Poly1305)
//! - Symmetric encryption with passphrase (HKDF + ChaCha20Poly1305)
//! - Hybrid encryption (symmetric + asymmetric layers)
//! - Message compression (DEFLATE)
//! - Forward secrecy with ephemeral keys
//! - Digital signatures (Ed25519)

pub mod asymmetric;
pub mod bip39_english;
pub mod compression;
pub mod ephemeral_store;
pub mod hybrid_kem;
pub mod keys;
pub mod mnemonic;
pub mod multi_recipient;
pub mod signing;
pub mod symmetric;

pub use asymmetric::{
    decrypt, decrypt_from_bytes, decrypt_hybrid, decrypt_hybrid_from_bytes, encrypt,
    encrypt_hybrid, encrypt_hybrid_to_bytes, encrypt_to_bytes, AsymmetricError, EncryptedData,
    EncryptedDataHybrid,
};
pub use compression::{compress, decompress, CompressionError};
pub use hybrid_kem::{
    decapsulate as hybrid_decapsulate, encapsulate as hybrid_encapsulate,
    generate_keypair as hybrid_generate_keypair, HybridCiphertext, HybridKemError,
    HybridPublicKey, HybridSecretKey, SharedKey as HybridSharedKey, HYBRID_CT_SIZE,
    HYBRID_PUBKEY_SIZE, HYBRID_SECRET_KEY_SIZE,
};
pub use ephemeral_store::{
    generate_and_save_ephemeral_for_contact, generate_and_save_ephemeral_for_contact_hybrid,
    list_private_key_contacts, list_private_key_contacts_hybrid, list_public_key_contacts,
    list_public_key_contacts_hybrid, list_unified_contacts, list_unified_contacts_hybrid,
    load_private_key_for_contact, load_private_key_for_contact_hybrid, load_public_key_for_contact,
    load_public_key_for_contact_hybrid, load_unified_keys_for_contact,
    load_unified_keys_for_contact_hybrid, save_private_key_for_contact,
    save_private_key_for_contact_hybrid, save_public_key_for_contact,
    save_public_key_for_contact_hybrid, save_unified_keys_for_contact,
    save_unified_keys_for_contact_hybrid, update_unified_private_key,
    update_unified_private_key_hybrid, update_unified_public_key, update_unified_public_key_hybrid,
    ContactKeys, ContactKeysHybrid, EphemeralStoreError, EphemeralStoreFormat,
};
pub use keys::{
    decode_hybrid_public_key_pem, decode_hybrid_secret_key_pem, decode_public_key_pem,
    decode_public_key_pem_with_type, decode_secret_key_pem, decode_secret_key_pem_with_type,
    detect_key_type, encode_ephemeral_public_key_pem, encode_ephemeral_secret_key_pem,
    encode_hybrid_public_key_pem, encode_hybrid_secret_key_pem, encode_public_key_pem,
    encode_public_key_pem_with_type, encode_secret_key_pem, encode_secret_key_pem_with_type,
    load_hybrid_public_key, load_hybrid_public_key_with_type, load_hybrid_secret_key,
    load_hybrid_secret_key_with_type, load_public_key, load_public_key_with_type, load_secret_key,
    load_secret_key_with_type, save_ephemeral_hybrid_private_key_pem,
    save_ephemeral_hybrid_public_key_pem, save_ephemeral_private_key_pem,
    save_ephemeral_public_key_pem, HybridKeyPair, KeyError, KeyPair, KeyType,
};
pub use multi_recipient::{
    decrypt_multi, decrypt_multi_hybrid, encrypt_multi, encrypt_multi_hybrid,
    MultiRecipientData, MultiRecipientDataHybrid, MultiRecipientError, RecipientKeyHybrid,
};
pub use signing::{
    decode_signing_key_pem, decode_verifying_key_pem, load_signing_key, load_verifying_key,
    sign_message, verify_signature, SigningError, SigningKeyPair,
};
pub use symmetric::{decrypt_symmetric, encrypt_symmetric, SymmetricError};
pub use mnemonic::{
    key_to_mnemonic, mnemonic_to_key, validate_mnemonic, format_mnemonic, MnemonicError,
};

use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

/// Errors that can occur during hybrid encryption.
#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Symmetric encryption error: {0}")]
    SymmetricError(#[from] SymmetricError),

    #[error("Asymmetric encryption error: {0}")]
    AsymmetricError(#[from] AsymmetricError),

    #[error("Compression error: {0}")]
    CompressionError(#[from] CompressionError),
}

/// Encrypts data using hybrid encryption with compression and forward secrecy:
/// 1. Compress the plaintext (DEFLATE)
/// 2. Generate ephemeral keypair for forward secrecy
/// 3. Encrypt with passphrase (symmetric)
/// 4. Encrypt with recipient's public key using ephemeral private key
/// 5. Prepend ephemeral public key to ciphertext
///
/// This provides compression, passphrase-based access control,
/// recipient authentication, AND forward secrecy.
pub fn encrypt_with_passphrase(
    plaintext: &[u8],
    passphrase: &str,
    public_key: &PublicKey,
) -> Result<Vec<u8>, EncryptionError> {
    // Step 1: Compress
    let compressed = compress(plaintext)?;

    // Step 2: Generate ephemeral keypair for forward secrecy
    let ephemeral = KeyPair::generate();

    // Step 3: Symmetric encryption with passphrase
    let symmetric_encrypted = encrypt_symmetric(&compressed, passphrase)?;

    // Step 4: Asymmetric encryption with ephemeral private key + recipient public key
    // We use the ephemeral private key instead of a static one for forward secrecy
    let asymmetric_encrypted = encrypt_to_bytes_with_ephemeral(
        &symmetric_encrypted,
        public_key,
        ephemeral.secret_key(),
    )?;

    // Step 5: Prepend ephemeral public key (32 bytes) so recipient can derive shared secret
    let mut result = Vec::with_capacity(32 + asymmetric_encrypted.len());
    result.extend_from_slice(ephemeral.public_key().as_bytes());
    result.extend(asymmetric_encrypted);

    Ok(result)
}

/// Wire-format magic prefix that identifies a hybrid post-quantum anyhide code.
///
/// Legacy classical codes (v6) begin with a 32-byte X25519 ephemeral public key,
/// which is uniformly random — collision probability for a 4-byte magic is 1/2^32.
/// New hybrid codes begin with this magic followed by a one-byte version field.
pub const HYBRID_WIRE_MAGIC: [u8; 4] = *b"AHV7";

/// Hybrid wire format version. Allows future evolution of the post-quantum scheme
/// without breaking already-emitted v7 codes.
pub const HYBRID_WIRE_VERSION: u8 = 1;

/// Length of the hybrid wire prefix (magic + version byte).
pub const HYBRID_WIRE_PREFIX_LEN: usize = HYBRID_WIRE_MAGIC.len() + 1;

/// Wire format detected on a serialized anyhide code (post-base64-decode bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireFormat {
    /// Legacy classical X25519 format. No magic prefix; the first 32 bytes are the
    /// sender's ephemeral X25519 public key. Decoded with `decrypt_with_passphrase`.
    ClassicalV6,
    /// Hybrid post-quantum format (X25519 + ML-KEM-768). Begins with `HYBRID_WIRE_MAGIC`
    /// followed by `HYBRID_WIRE_VERSION`. Decoded with `decrypt_with_passphrase_hybrid`.
    HybridV7,
}

/// Detects the wire format of a serialized anyhide code by sniffing the magic prefix.
///
/// Inputs shorter than the magic prefix or without the magic bytes are treated as
/// legacy classical codes; the legacy decoder will reject them at a deeper layer if
/// they are malformed.
pub fn detect_wire_format(ciphertext: &[u8]) -> WireFormat {
    if ciphertext.len() >= HYBRID_WIRE_PREFIX_LEN
        && ciphertext[..HYBRID_WIRE_MAGIC.len()] == HYBRID_WIRE_MAGIC
    {
        WireFormat::HybridV7
    } else {
        WireFormat::ClassicalV6
    }
}

/// Decrypts data using hybrid decryption with decompression:
/// 1. Extract ephemeral public key from ciphertext
/// 2. Decrypt with private key using ephemeral public key
/// 3. Decrypt with passphrase (symmetric)
/// 4. Decompress the plaintext
pub fn decrypt_with_passphrase(
    ciphertext: &[u8],
    passphrase: &str,
    secret_key: &StaticSecret,
) -> Result<Vec<u8>, EncryptionError> {
    if ciphertext.len() < 32 {
        return Err(EncryptionError::AsymmetricError(
            AsymmetricError::CiphertextTooShort,
        ));
    }

    // Step 1: Extract ephemeral public key (first 32 bytes)
    let ephemeral_public_bytes: [u8; 32] = ciphertext[..32]
        .try_into()
        .map_err(|_| AsymmetricError::CiphertextTooShort)?;
    let ephemeral_public = PublicKey::from(ephemeral_public_bytes);
    let encrypted_payload = &ciphertext[32..];

    // Step 2: Asymmetric decryption with our private key + ephemeral public key
    let asymmetric_decrypted =
        decrypt_from_bytes_with_ephemeral(encrypted_payload, secret_key, &ephemeral_public)?;

    // Step 3: Symmetric decryption with passphrase
    let compressed = decrypt_symmetric(&asymmetric_decrypted, passphrase)?;

    // Step 4: Decompress
    let plaintext = decompress(&compressed)?;

    Ok(plaintext)
}

/// Encrypts data using post-quantum hybrid encryption with compression:
/// 1. Compress the plaintext (DEFLATE)
/// 2. Encrypt with passphrase (symmetric)
/// 3. Encapsulate against the recipient's hybrid (X25519 + ML-KEM-768) public key
///    and AEAD-encrypt the symmetric ciphertext
/// 4. Prepend the hybrid wire prefix (`HYBRID_WIRE_MAGIC` + `HYBRID_WIRE_VERSION`)
///    so the decoder can dispatch on format without first decrypting
///
/// The output begins with `HYBRID_WIRE_MAGIC || HYBRID_WIRE_VERSION` followed by
/// the bytes returned by `encrypt_hybrid_to_bytes`. Forward secrecy at the wire
/// layer is not provided here — encoder ratchet mode (separate ephemeral keypairs
/// per message) is the mechanism for that property.
pub fn encrypt_with_passphrase_hybrid(
    plaintext: &[u8],
    passphrase: &str,
    public_key: &HybridPublicKey,
) -> Result<Vec<u8>, EncryptionError> {
    let compressed = compress(plaintext)?;
    let symmetric_encrypted = encrypt_symmetric(&compressed, passphrase)?;
    let asymmetric_encrypted = encrypt_hybrid_to_bytes(&symmetric_encrypted, public_key)?;

    let mut result = Vec::with_capacity(HYBRID_WIRE_PREFIX_LEN + asymmetric_encrypted.len());
    result.extend_from_slice(&HYBRID_WIRE_MAGIC);
    result.push(HYBRID_WIRE_VERSION);
    result.extend(asymmetric_encrypted);

    Ok(result)
}

/// Decrypts a hybrid-format anyhide code (v7) using a hybrid secret key:
/// 1. Validate the wire prefix (`HYBRID_WIRE_MAGIC` + supported version byte)
/// 2. Decapsulate the hybrid KEM ciphertext with the recipient's hybrid secret
///    and AEAD-decrypt the inner payload
/// 3. Decrypt with passphrase (symmetric)
/// 4. Decompress
///
/// Returns an error if the input is not in the hybrid wire format or carries an
/// unsupported version. Use `detect_wire_format` to dispatch between this function
/// and the classical `decrypt_with_passphrase` before calling.
pub fn decrypt_with_passphrase_hybrid(
    ciphertext: &[u8],
    passphrase: &str,
    secret_key: &HybridSecretKey,
) -> Result<Vec<u8>, EncryptionError> {
    if ciphertext.len() < HYBRID_WIRE_PREFIX_LEN
        || ciphertext[..HYBRID_WIRE_MAGIC.len()] != HYBRID_WIRE_MAGIC
    {
        return Err(EncryptionError::AsymmetricError(
            AsymmetricError::CiphertextTooShort,
        ));
    }

    let version = ciphertext[HYBRID_WIRE_MAGIC.len()];
    if version != HYBRID_WIRE_VERSION {
        return Err(EncryptionError::AsymmetricError(
            AsymmetricError::DecryptionFailed(format!(
                "Unsupported hybrid wire format version: {version} (this build supports v{HYBRID_WIRE_VERSION})"
            )),
        ));
    }

    let payload = &ciphertext[HYBRID_WIRE_PREFIX_LEN..];

    let symmetric_encrypted = decrypt_hybrid_from_bytes(payload, secret_key)?;
    let compressed = decrypt_symmetric(&symmetric_encrypted, passphrase)?;
    let plaintext = decompress(&compressed)?;

    Ok(plaintext)
}

/// Encrypts data using an ephemeral private key (for forward secrecy).
fn encrypt_to_bytes_with_ephemeral(
    plaintext: &[u8],
    recipient_public: &PublicKey,
    ephemeral_secret: &StaticSecret,
) -> Result<Vec<u8>, AsymmetricError> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    use hkdf::Hkdf;
    use rand::RngCore;
    use sha2::Sha256;

    // Derive shared secret using ECDH
    let shared_secret = ephemeral_secret.diffie_hellman(recipient_public);

    // Derive encryption key using HKDF
    let hk = Hkdf::<Sha256>::new(Some(b"KAMO-ASYM-V2"), shared_secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"encryption-key", &mut key)
        .map_err(|_| AsymmetricError::KeyDerivationFailed)?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| AsymmetricError::KeyDerivationFailed)?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AsymmetricError::EncryptionFailed(e.to_string()))?;

    // Return nonce + ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend(ciphertext);

    Ok(result)
}

/// Decrypts data using our private key and the sender's ephemeral public key.
fn decrypt_from_bytes_with_ephemeral(
    ciphertext: &[u8],
    our_secret: &StaticSecret,
    ephemeral_public: &PublicKey,
) -> Result<Vec<u8>, AsymmetricError> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    use hkdf::Hkdf;
    use sha2::Sha256;

    if ciphertext.len() < 12 {
        return Err(AsymmetricError::CiphertextTooShort);
    }

    // Derive shared secret using ECDH (same result as sender due to ECDH properties)
    let shared_secret = our_secret.diffie_hellman(ephemeral_public);

    // Derive encryption key using HKDF
    let hk = Hkdf::<Sha256>::new(Some(b"KAMO-ASYM-V2"), shared_secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"encryption-key", &mut key)
        .map_err(|_| AsymmetricError::KeyDerivationFailed)?;

    // Extract nonce and ciphertext
    let nonce = Nonce::from_slice(&ciphertext[..12]);
    let encrypted = &ciphertext[12..];

    // Decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| AsymmetricError::KeyDerivationFailed)?;

    cipher
        .decrypt(nonce, encrypted)
        .map_err(|e| AsymmetricError::DecryptionFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_encryption_roundtrip() {
        let plaintext = b"Secret message for hybrid encryption";
        let passphrase = "my_passphrase";

        let keypair = KeyPair::generate();

        let encrypted = encrypt_with_passphrase(plaintext, passphrase, keypair.public_key()).unwrap();
        let decrypted = decrypt_with_passphrase(&encrypted, passphrase, keypair.secret_key()).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hybrid_wrong_passphrase_fails() {
        let plaintext = b"Secret";
        let correct_pass = "correct";
        let wrong_pass = "wrong";

        let keypair = KeyPair::generate();

        let encrypted = encrypt_with_passphrase(plaintext, correct_pass, keypair.public_key()).unwrap();
        let result = decrypt_with_passphrase(&encrypted, wrong_pass, keypair.secret_key());

        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_wrong_key_fails() {
        let plaintext = b"Secret";
        let passphrase = "test";

        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        let encrypted = encrypt_with_passphrase(plaintext, passphrase, keypair1.public_key()).unwrap();
        let result = decrypt_with_passphrase(&encrypted, passphrase, keypair2.secret_key());

        assert!(result.is_err());
    }

    #[test]
    fn hybrid_passphrase_encryption_roundtrip() {
        let plaintext = b"Post-quantum secret message";
        let passphrase = "shared-passphrase";

        let keypair = HybridKeyPair::generate();

        let encrypted =
            encrypt_with_passphrase_hybrid(plaintext, passphrase, keypair.public_key()).unwrap();
        let decrypted =
            decrypt_with_passphrase_hybrid(&encrypted, passphrase, keypair.secret_key()).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn hybrid_wire_prefix_is_emitted() {
        let plaintext = b"prefix sniff";
        let passphrase = "p";
        let keypair = HybridKeyPair::generate();

        let encrypted =
            encrypt_with_passphrase_hybrid(plaintext, passphrase, keypair.public_key()).unwrap();

        assert!(encrypted.len() > HYBRID_WIRE_PREFIX_LEN);
        assert_eq!(&encrypted[..HYBRID_WIRE_MAGIC.len()], &HYBRID_WIRE_MAGIC);
        assert_eq!(encrypted[HYBRID_WIRE_MAGIC.len()], HYBRID_WIRE_VERSION);
    }

    #[test]
    fn detect_wire_format_distinguishes_v6_and_v7() {
        let passphrase = "p";

        let classical = KeyPair::generate();
        let v6 = encrypt_with_passphrase(b"classical", passphrase, classical.public_key()).unwrap();
        assert_eq!(detect_wire_format(&v6), WireFormat::ClassicalV6);

        let hybrid = HybridKeyPair::generate();
        let v7 = encrypt_with_passphrase_hybrid(b"hybrid", passphrase, hybrid.public_key()).unwrap();
        assert_eq!(detect_wire_format(&v7), WireFormat::HybridV7);
    }

    #[test]
    fn detect_wire_format_falls_back_to_classical_on_short_input() {
        // An empty buffer has no magic; fall back to classical so the legacy
        // decoder can produce its own length error.
        assert_eq!(detect_wire_format(&[]), WireFormat::ClassicalV6);
        assert_eq!(detect_wire_format(&[0xAB, 0xCD]), WireFormat::ClassicalV6);
    }

    #[test]
    fn hybrid_decrypt_rejects_classical_input() {
        let keypair = HybridKeyPair::generate();
        let classical = KeyPair::generate();
        let v6 = encrypt_with_passphrase(b"x", "p", classical.public_key()).unwrap();

        let result = decrypt_with_passphrase_hybrid(&v6, "p", keypair.secret_key());

        assert!(result.is_err());
    }

    #[test]
    fn hybrid_decrypt_rejects_unsupported_version() {
        let keypair = HybridKeyPair::generate();

        let mut tampered =
            encrypt_with_passphrase_hybrid(b"x", "p", keypair.public_key()).unwrap();
        // Bump the version byte to a value this build does not recognise.
        tampered[HYBRID_WIRE_MAGIC.len()] = HYBRID_WIRE_VERSION.wrapping_add(1);

        let result = decrypt_with_passphrase_hybrid(&tampered, "p", keypair.secret_key());

        assert!(result.is_err());
    }

    #[test]
    fn hybrid_decrypt_with_wrong_secret_fails() {
        let plaintext = b"x";
        let passphrase = "p";

        let keypair1 = HybridKeyPair::generate();
        let keypair2 = HybridKeyPair::generate();

        let encrypted =
            encrypt_with_passphrase_hybrid(plaintext, passphrase, keypair1.public_key()).unwrap();
        let result = decrypt_with_passphrase_hybrid(&encrypted, passphrase, keypair2.secret_key());

        assert!(result.is_err());
    }

    #[test]
    fn hybrid_decrypt_with_wrong_passphrase_fails() {
        let plaintext = b"x";
        let keypair = HybridKeyPair::generate();

        let encrypted =
            encrypt_with_passphrase_hybrid(plaintext, "correct", keypair.public_key()).unwrap();
        let result = decrypt_with_passphrase_hybrid(&encrypted, "wrong", keypair.secret_key());

        assert!(result.is_err());
    }
}
