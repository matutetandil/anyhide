//! Asymmetric encryption using X25519 key exchange and ChaCha20Poly1305.
//!
//! This module implements hybrid encryption:
//! 1. Generate ephemeral X25519 key pair
//! 2. Perform ECDH with recipient's public key
//! 3. Derive symmetric key using HKDF
//! 4. Encrypt data with ChaCha20Poly1305

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// HKDF info string for key derivation.
const HKDF_INFO: &[u8] = b"KAMO-V2-ASYMMETRIC";

/// Nonce size for ChaCha20Poly1305.
const NONCE_SIZE: usize = 12;

/// Errors that can occur during asymmetric encryption operations.
#[derive(Error, Debug)]
pub enum AsymmetricError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid ciphertext: too short")]
    CiphertextTooShort,

    #[error("Key derivation failed")]
    KeyDerivationFailed,
}

/// Encrypted data bundle containing ephemeral public key, nonce, and ciphertext.
#[derive(Clone, Debug)]
pub struct EncryptedData {
    /// Ephemeral public key (32 bytes)
    pub ephemeral_public: [u8; 32],
    /// Nonce (12 bytes)
    pub nonce: [u8; NONCE_SIZE],
    /// Encrypted ciphertext (variable length, includes auth tag)
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Serializes the encrypted data to bytes.
    ///
    /// Format: ephemeral_public (32) || nonce (12) || ciphertext (variable)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(32 + NONCE_SIZE + self.ciphertext.len());
        result.extend_from_slice(&self.ephemeral_public);
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&self.ciphertext);
        result
    }

    /// Deserializes encrypted data from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, AsymmetricError> {
        // Minimum: 32 (public key) + 12 (nonce) + 16 (auth tag) = 60 bytes
        if data.len() < 60 {
            return Err(AsymmetricError::CiphertextTooShort);
        }

        let mut ephemeral_public = [0u8; 32];
        ephemeral_public.copy_from_slice(&data[..32]);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&data[32..32 + NONCE_SIZE]);

        let ciphertext = data[32 + NONCE_SIZE..].to_vec();

        Ok(Self {
            ephemeral_public,
            nonce,
            ciphertext,
        })
    }
}

/// Encrypts data for a recipient using their public key.
///
/// Uses X25519 ECDH to establish a shared secret, then encrypts with ChaCha20Poly1305.
pub fn encrypt(plaintext: &[u8], recipient_public: &PublicKey) -> Result<EncryptedData, AsymmetricError> {
    // Generate ephemeral key pair
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // Perform ECDH
    let shared_secret = ephemeral_secret.diffie_hellman(recipient_public);

    // Derive symmetric key using HKDF
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut symmetric_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut symmetric_key)
        .map_err(|_| AsymmetricError::KeyDerivationFailed)?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt with ChaCha20Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
        .map_err(|e| AsymmetricError::EncryptionFailed(e.to_string()))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AsymmetricError::EncryptionFailed(e.to_string()))?;

    Ok(EncryptedData {
        ephemeral_public: *ephemeral_public.as_bytes(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypts data using the recipient's secret key.
pub fn decrypt(encrypted: &EncryptedData, secret_key: &StaticSecret) -> Result<Vec<u8>, AsymmetricError> {
    // Reconstruct ephemeral public key
    let ephemeral_public = PublicKey::from(encrypted.ephemeral_public);

    // Perform ECDH
    let shared_secret = secret_key.diffie_hellman(&ephemeral_public);

    // Derive symmetric key using HKDF
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut symmetric_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut symmetric_key)
        .map_err(|_| AsymmetricError::KeyDerivationFailed)?;

    // Decrypt with ChaCha20Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
        .map_err(|e| AsymmetricError::DecryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(&encrypted.nonce);

    cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|e| AsymmetricError::DecryptionFailed(e.to_string()))
}

/// Convenience function to encrypt bytes and return serialized result.
pub fn encrypt_to_bytes(plaintext: &[u8], recipient_public: &PublicKey) -> Result<Vec<u8>, AsymmetricError> {
    let encrypted = encrypt(plaintext, recipient_public)?;
    Ok(encrypted.to_bytes())
}

/// Convenience function to decrypt from serialized bytes.
pub fn decrypt_from_bytes(data: &[u8], secret_key: &StaticSecret) -> Result<Vec<u8>, AsymmetricError> {
    let encrypted = EncryptedData::from_bytes(data)?;
    decrypt(&encrypted, secret_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyPair;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let kp = KeyPair::generate();
        let plaintext = b"Hello, KAMO!";

        let encrypted = encrypt(plaintext, kp.public_key()).unwrap();
        let decrypted = decrypt(&encrypted, kp.secret_key()).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_bytes_roundtrip() {
        let kp = KeyPair::generate();
        let plaintext = b"Secret message for steganography";

        let encrypted_bytes = encrypt_to_bytes(plaintext, kp.public_key()).unwrap();
        let decrypted = decrypt_from_bytes(&encrypted_bytes, kp.secret_key()).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_different_keys_fail_decrypt() {
        let sender_kp = KeyPair::generate();
        let wrong_kp = KeyPair::generate();
        let plaintext = b"Secret message";

        let encrypted = encrypt(plaintext, sender_kp.public_key()).unwrap();
        let result = decrypt(&encrypted, wrong_kp.secret_key());

        assert!(result.is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let kp = KeyPair::generate();
        let plaintext = b"Test data";

        let encrypted = encrypt(plaintext, kp.public_key()).unwrap();
        let bytes = encrypted.to_bytes();
        let deserialized = EncryptedData::from_bytes(&bytes).unwrap();

        assert_eq!(encrypted.ephemeral_public, deserialized.ephemeral_public);
        assert_eq!(encrypted.nonce, deserialized.nonce);
        assert_eq!(encrypted.ciphertext, deserialized.ciphertext);
    }
}
