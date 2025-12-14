//! Cryptographic operations for KAMO.
//!
//! This module provides:
//! - Key generation and management (X25519)
//! - Asymmetric encryption (X25519 + ChaCha20Poly1305)
//! - Symmetric encryption with passphrase (HKDF + ChaCha20Poly1305)
//! - Hybrid encryption (symmetric + asymmetric layers)

pub mod asymmetric;
pub mod keys;
pub mod symmetric;

pub use asymmetric::{decrypt, decrypt_from_bytes, encrypt, encrypt_to_bytes, AsymmetricError, EncryptedData};
pub use keys::{decode_public_key_pem, decode_secret_key_pem, load_public_key, load_secret_key, KeyError, KeyPair};
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
}

/// Encrypts data using hybrid encryption:
/// 1. First encrypts with passphrase (symmetric)
/// 2. Then encrypts the result with recipient's public key (asymmetric)
///
/// This provides both passphrase-based access control and recipient authentication.
pub fn encrypt_with_passphrase(
    plaintext: &[u8],
    passphrase: &str,
    public_key: &PublicKey,
) -> Result<Vec<u8>, EncryptionError> {
    // Step 1: Symmetric encryption with passphrase
    let symmetric_encrypted = encrypt_symmetric(plaintext, passphrase)?;

    // Step 2: Asymmetric encryption with public key
    let asymmetric_encrypted = encrypt_to_bytes(&symmetric_encrypted, public_key)?;

    Ok(asymmetric_encrypted)
}

/// Decrypts data using hybrid decryption:
/// 1. First decrypts with private key (asymmetric)
/// 2. Then decrypts with passphrase (symmetric)
pub fn decrypt_with_passphrase(
    ciphertext: &[u8],
    passphrase: &str,
    secret_key: &StaticSecret,
) -> Result<Vec<u8>, EncryptionError> {
    // Step 1: Asymmetric decryption with private key
    let asymmetric_decrypted = decrypt_from_bytes(ciphertext, secret_key)?;

    // Step 2: Symmetric decryption with passphrase
    let plaintext = decrypt_symmetric(&asymmetric_decrypted, passphrase)?;

    Ok(plaintext)
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
