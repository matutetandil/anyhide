//! Symmetric encryption with passphrase for Anyhide.
//!
//! This module provides passphrase-based symmetric encryption using:
//! - HKDF-SHA256 for key derivation from passphrase
//! - ChaCha20-Poly1305 for authenticated encryption

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use thiserror::Error;

/// HKDF info string for passphrase-based key derivation.
const HKDF_INFO: &[u8] = b"KAMO-V3-SYMMETRIC";

/// Salt for HKDF (fixed for deterministic behavior with same passphrase).
const HKDF_SALT: &[u8] = b"KAMO-V3-SALT-2024";

/// Nonce size for ChaCha20Poly1305.
const NONCE_SIZE: usize = 12;

/// Errors that can occur during symmetric encryption.
#[derive(Error, Debug)]
pub enum SymmetricError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid ciphertext: too short")]
    CiphertextTooShort,

    #[error("Key derivation failed")]
    KeyDerivationFailed,
}

/// Derives a 256-bit symmetric key from a passphrase.
fn derive_key_from_passphrase(passphrase: &str) -> Result<[u8; 32], SymmetricError> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), passphrase.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .map_err(|_| SymmetricError::KeyDerivationFailed)?;
    Ok(key)
}

/// Encrypts data using a passphrase.
///
/// The output format is: nonce (12 bytes) || ciphertext (variable, includes auth tag)
pub fn encrypt_symmetric(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, SymmetricError> {
    // Derive key from passphrase
    let key = derive_key_from_passphrase(passphrase)?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt with ChaCha20Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| SymmetricError::EncryptionFailed(e.to_string()))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| SymmetricError::EncryptionFailed(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypts data using a passphrase.
///
/// Expects input format: nonce (12 bytes) || ciphertext (variable, includes auth tag)
pub fn decrypt_symmetric(data: &[u8], passphrase: &str) -> Result<Vec<u8>, SymmetricError> {
    // Minimum: 12 (nonce) + 16 (auth tag) = 28 bytes
    if data.len() < 28 {
        return Err(SymmetricError::CiphertextTooShort);
    }

    // Extract nonce and ciphertext
    let nonce_bytes = &data[..NONCE_SIZE];
    let ciphertext = &data[NONCE_SIZE..];

    // Derive key from passphrase
    let key = derive_key_from_passphrase(passphrase)?;

    // Decrypt with ChaCha20Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| SymmetricError::DecryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| SymmetricError::DecryptionFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello, Anyhide!";
        let passphrase = "my_secret_passphrase";

        let encrypted = encrypt_symmetric(plaintext, passphrase).unwrap();
        let decrypted = decrypt_symmetric(&encrypted, passphrase).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let plaintext = b"Secret data";
        let correct_pass = "correct";
        let wrong_pass = "wrong";

        let encrypted = encrypt_symmetric(plaintext, correct_pass).unwrap();
        let result = decrypt_symmetric(&encrypted, wrong_pass);

        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let plaintext = b"";
        let passphrase = "test";

        let encrypted = encrypt_symmetric(plaintext, passphrase).unwrap();
        let decrypted = decrypt_symmetric(&encrypted, passphrase).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_ciphertext_too_short() {
        let short_data = vec![0u8; 10];
        let result = decrypt_symmetric(&short_data, "test");

        assert!(matches!(result, Err(SymmetricError::CiphertextTooShort)));
    }

    #[test]
    fn test_deterministic_key_derivation() {
        let passphrase = "test_passphrase";
        let key1 = derive_key_from_passphrase(passphrase).unwrap();
        let key2 = derive_key_from_passphrase(passphrase).unwrap();

        assert_eq!(key1, key2);
    }
}
