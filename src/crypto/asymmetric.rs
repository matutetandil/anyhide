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

// ---- Hybrid post-quantum variant (X25519 + ML-KEM-768) ----

use super::hybrid_kem::{
    self, HybridCiphertext, HybridKemError, HybridPublicKey, HybridSecretKey,
    HYBRID_CT_SIZE,
};

/// HKDF info string for hybrid asymmetric encryption.
const HKDF_INFO_HYBRID: &[u8] = b"ANYHIDE-V3-ASYMMETRIC";

/// Encrypted data bundle for the hybrid PQ asymmetric scheme.
///
/// Wire format: kem_ciphertext (1120) || nonce (12) || aead_ciphertext (variable, includes auth tag).
#[derive(Clone, Debug)]
pub struct EncryptedDataHybrid {
    /// Hybrid KEM ciphertext (X25519 ephemeral pubkey + ML-KEM-768 ciphertext).
    pub kem_ciphertext: [u8; HYBRID_CT_SIZE],
    /// AEAD nonce.
    pub nonce: [u8; NONCE_SIZE],
    /// AEAD ciphertext (includes Poly1305 tag).
    pub ciphertext: Vec<u8>,
}

impl EncryptedDataHybrid {
    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_CT_SIZE + NONCE_SIZE + self.ciphertext.len());
        out.extend_from_slice(&self.kem_ciphertext);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Deserializes from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, AsymmetricError> {
        // Minimum: kem_ct + nonce + auth_tag(16)
        let min_size = HYBRID_CT_SIZE + NONCE_SIZE + 16;
        if data.len() < min_size {
            return Err(AsymmetricError::CiphertextTooShort);
        }

        let mut kem_ciphertext = [0u8; HYBRID_CT_SIZE];
        kem_ciphertext.copy_from_slice(&data[..HYBRID_CT_SIZE]);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&data[HYBRID_CT_SIZE..HYBRID_CT_SIZE + NONCE_SIZE]);

        let ciphertext = data[HYBRID_CT_SIZE + NONCE_SIZE..].to_vec();

        Ok(Self {
            kem_ciphertext,
            nonce,
            ciphertext,
        })
    }
}

impl From<HybridKemError> for AsymmetricError {
    fn from(err: HybridKemError) -> Self {
        match err {
            HybridKemError::DecapsulationFailed => {
                AsymmetricError::DecryptionFailed("Hybrid KEM decapsulation failed".to_string())
            }
            HybridKemError::KeyDerivationFailed => AsymmetricError::KeyDerivationFailed,
            HybridKemError::InvalidCiphertext
            | HybridKemError::InvalidPublicKey
            | HybridKemError::InvalidSecretKey => AsymmetricError::CiphertextTooShort,
            HybridKemError::InvalidLength { .. } => AsymmetricError::CiphertextTooShort,
        }
    }
}

/// Encrypts data for a recipient using their hybrid (X25519 + ML-KEM-768) public key.
pub fn encrypt_hybrid(
    plaintext: &[u8],
    recipient: &HybridPublicKey,
) -> Result<EncryptedDataHybrid, AsymmetricError> {
    let (kem_ct, shared) = hybrid_kem::encapsulate(recipient)?;

    let derived_key = derive_aead_key(shared.as_bytes())?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(&derived_key)
        .map_err(|e| AsymmetricError::EncryptionFailed(e.to_string()))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AsymmetricError::EncryptionFailed(e.to_string()))?;

    Ok(EncryptedDataHybrid {
        kem_ciphertext: kem_ct.to_bytes(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypts hybrid-encrypted data using the recipient's hybrid secret key.
pub fn decrypt_hybrid(
    encrypted: &EncryptedDataHybrid,
    secret: &HybridSecretKey,
) -> Result<Vec<u8>, AsymmetricError> {
    let kem_ct = HybridCiphertext::from_bytes(&encrypted.kem_ciphertext)?;
    let shared = hybrid_kem::decapsulate(secret, &kem_ct)?;

    let derived_key = derive_aead_key(shared.as_bytes())?;

    let cipher = ChaCha20Poly1305::new_from_slice(&derived_key)
        .map_err(|e| AsymmetricError::DecryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(&encrypted.nonce);

    cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|e| AsymmetricError::DecryptionFailed(e.to_string()))
}

/// Convenience helper: encrypt to bytes for the hybrid scheme.
pub fn encrypt_hybrid_to_bytes(
    plaintext: &[u8],
    recipient: &HybridPublicKey,
) -> Result<Vec<u8>, AsymmetricError> {
    Ok(encrypt_hybrid(plaintext, recipient)?.to_bytes())
}

/// Convenience helper: decrypt from serialized bytes for the hybrid scheme.
pub fn decrypt_hybrid_from_bytes(
    data: &[u8],
    secret: &HybridSecretKey,
) -> Result<Vec<u8>, AsymmetricError> {
    let encrypted = EncryptedDataHybrid::from_bytes(data)?;
    decrypt_hybrid(&encrypted, secret)
}

/// Derives a 32-byte ChaCha20Poly1305 key from a hybrid KEM shared secret.
fn derive_aead_key(shared: &[u8; 32]) -> Result<[u8; 32], AsymmetricError> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO_HYBRID, &mut key)
        .map_err(|_| AsymmetricError::KeyDerivationFailed)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyPair;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let kp = KeyPair::generate();
        let plaintext = b"Hello, Anyhide!";

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

    // ---- Hybrid PQ tests ----

    #[test]
    fn hybrid_encrypt_decrypt_roundtrip() {
        let (sk, pk) = hybrid_kem::generate_keypair();
        let plaintext = b"Post-quantum secret payload";

        let encrypted = encrypt_hybrid(plaintext, &pk).unwrap();
        let decrypted = decrypt_hybrid(&encrypted, &sk).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn hybrid_encrypt_decrypt_bytes_roundtrip() {
        let (sk, pk) = hybrid_kem::generate_keypair();
        let plaintext = b"Bytes-level hybrid roundtrip";

        let bytes = encrypt_hybrid_to_bytes(plaintext, &pk).unwrap();
        let decrypted = decrypt_hybrid_from_bytes(&bytes, &sk).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn hybrid_decrypt_with_wrong_secret_fails() {
        let (_sk_correct, pk_correct) = hybrid_kem::generate_keypair();
        let (sk_wrong, _pk_wrong) = hybrid_kem::generate_keypair();
        let plaintext = b"only the right key should open this";

        let encrypted = encrypt_hybrid(plaintext, &pk_correct).unwrap();
        let result = decrypt_hybrid(&encrypted, &sk_wrong);

        assert!(result.is_err(), "wrong key must not decrypt successfully");
    }

    #[test]
    fn hybrid_serialization_roundtrip() {
        let (_sk, pk) = hybrid_kem::generate_keypair();
        let plaintext = b"Test serialize hybrid";

        let encrypted = encrypt_hybrid(plaintext, &pk).unwrap();
        let bytes = encrypted.to_bytes();

        // wire layout: kem_ct (1120) || nonce (12) || aead_ct (>= 16 for tag)
        assert!(bytes.len() >= HYBRID_CT_SIZE + NONCE_SIZE + 16);

        let restored = EncryptedDataHybrid::from_bytes(&bytes).unwrap();
        assert_eq!(encrypted.kem_ciphertext, restored.kem_ciphertext);
        assert_eq!(encrypted.nonce, restored.nonce);
        assert_eq!(encrypted.ciphertext, restored.ciphertext);
    }

    #[test]
    fn hybrid_from_bytes_rejects_short_input() {
        let too_short = vec![0u8; HYBRID_CT_SIZE + NONCE_SIZE + 15];
        assert!(matches!(
            EncryptedDataHybrid::from_bytes(&too_short),
            Err(AsymmetricError::CiphertextTooShort)
        ));
    }

    #[test]
    fn hybrid_tampered_ciphertext_fails_authentication() {
        let (sk, pk) = hybrid_kem::generate_keypair();
        let plaintext = b"authenticated payload";

        let mut encrypted = encrypt_hybrid(plaintext, &pk).unwrap();
        let last = encrypted.ciphertext.len() - 1;
        encrypted.ciphertext[last] ^= 0x01;

        let result = decrypt_hybrid(&encrypted, &sk);
        assert!(result.is_err(), "tampered ciphertext must fail AEAD check");
    }
}
