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
pub mod compression;
pub mod ephemeral_store;
pub mod keys;
pub mod multi_recipient;
pub mod signing;
pub mod symmetric;

pub use asymmetric::{decrypt, decrypt_from_bytes, encrypt, encrypt_to_bytes, AsymmetricError, EncryptedData};
pub use compression::{compress, decompress, CompressionError};
pub use ephemeral_store::{
    load_private_key_for_contact, load_public_key_for_contact, load_unified_keys_for_contact,
    save_private_key_for_contact, save_public_key_for_contact, save_unified_keys_for_contact,
    update_unified_public_key, update_unified_private_key,
    list_private_key_contacts, list_public_key_contacts, list_unified_contacts,
    generate_and_save_ephemeral_for_contact,
    ContactKeys, EphemeralStoreError, EphemeralStoreFormat,
};
pub use keys::{
    decode_public_key_pem, decode_public_key_pem_with_type,
    decode_secret_key_pem, decode_secret_key_pem_with_type,
    detect_key_type,
    encode_ephemeral_public_key_pem, encode_ephemeral_secret_key_pem,
    encode_public_key_pem, encode_public_key_pem_with_type,
    encode_secret_key_pem, encode_secret_key_pem_with_type,
    load_public_key, load_public_key_with_type,
    load_secret_key, load_secret_key_with_type,
    KeyError, KeyPair, KeyType,
};
pub use multi_recipient::{decrypt_multi, encrypt_multi, MultiRecipientData, MultiRecipientError};
pub use signing::{
    decode_signing_key_pem, decode_verifying_key_pem, load_signing_key, load_verifying_key,
    sign_message, verify_signature, SigningError, SigningKeyPair,
};
pub use symmetric::{decrypt_symmetric, encrypt_symmetric, SymmetricError};

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
}
