//! Message header encryption and decryption.
//!
//! The header contains metadata like sequence number, DH public key, and carrier
//! selection. It's encrypted with the session header_key to hide this information
//! from attackers.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::chat::ChatError;

/// Message header containing metadata for decryption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageHeader {
    /// Message sequence number.
    pub seq: u32,
    /// Sender's current DH public key (for ratchet detection).
    pub dh_public: [u8; 32],
    /// Which party owns the carrier (0 = initiator, 1 = responder).
    pub carrier_owner: u8,
    /// Index into that party's carrier array.
    pub carrier_index: u16,
    /// Number of messages in the previous sending chain.
    pub prev_chain_len: u32,
}

/// Encrypt a message header with the session header key.
///
/// # Arguments
///
/// * `header` - The header to encrypt.
/// * `header_key` - The 32-byte session header key.
///
/// # Returns
///
/// A tuple of (encrypted_header, nonce) on success.
pub fn encrypt_header(
    header: &MessageHeader,
    header_key: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 12]), ChatError> {
    // Serialize header
    let header_bytes = bincode::serialize(header)
        .map_err(|e| ChatError::SerializationFailed(e.to_string()))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(header_key)
        .map_err(|e| ChatError::HeaderCryptoFailed(e.to_string()))?;

    let ciphertext = cipher
        .encrypt(nonce, header_bytes.as_ref())
        .map_err(|e| ChatError::HeaderCryptoFailed(e.to_string()))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt a message header with the session header key.
///
/// # Arguments
///
/// * `encrypted_header` - The encrypted header bytes.
/// * `nonce` - The 12-byte nonce used for encryption.
/// * `header_key` - The 32-byte session header key.
///
/// # Returns
///
/// The decrypted MessageHeader on success.
pub fn decrypt_header(
    encrypted_header: &[u8],
    nonce: &[u8; 12],
    header_key: &[u8; 32],
) -> Result<MessageHeader, ChatError> {
    let nonce = Nonce::from_slice(nonce);

    // Decrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(header_key)
        .map_err(|e| ChatError::HeaderCryptoFailed(e.to_string()))?;

    let plaintext = cipher
        .decrypt(nonce, encrypted_header)
        .map_err(|e| ChatError::HeaderCryptoFailed(e.to_string()))?;

    // Deserialize header
    let header: MessageHeader = bincode::deserialize(&plaintext)
        .map_err(|e| ChatError::SerializationFailed(e.to_string()))?;

    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_header() -> MessageHeader {
        MessageHeader {
            seq: 42,
            dh_public: [1u8; 32],
            carrier_owner: 0,
            carrier_index: 5,
            prev_chain_len: 10,
        }
    }

    #[test]
    fn test_header_roundtrip() {
        let header = make_test_header();
        let key = [99u8; 32];

        let (encrypted, nonce) = encrypt_header(&header, &key).unwrap();
        let decrypted = decrypt_header(&encrypted, &nonce, &key).unwrap();

        assert_eq!(header, decrypted);
    }

    #[test]
    fn test_header_wrong_key_fails() {
        let header = make_test_header();
        let key1 = [99u8; 32];
        let key2 = [100u8; 32];

        let (encrypted, nonce) = encrypt_header(&header, &key1).unwrap();
        let result = decrypt_header(&encrypted, &nonce, &key2);

        assert!(result.is_err());
    }

    #[test]
    fn test_header_wrong_nonce_fails() {
        let header = make_test_header();
        let key = [99u8; 32];

        let (encrypted, _nonce) = encrypt_header(&header, &key).unwrap();
        let wrong_nonce = [0u8; 12];
        let result = decrypt_header(&encrypted, &wrong_nonce, &key);

        assert!(result.is_err());
    }

    #[test]
    fn test_header_tampered_ciphertext_fails() {
        let header = make_test_header();
        let key = [99u8; 32];

        let (mut encrypted, nonce) = encrypt_header(&header, &key).unwrap();
        encrypted[0] ^= 0xFF; // Flip bits
        let result = decrypt_header(&encrypted, &nonce, &key);

        assert!(result.is_err());
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertext() {
        let header = make_test_header();
        let key = [99u8; 32];

        let (encrypted1, nonce1) = encrypt_header(&header, &key).unwrap();
        let (encrypted2, nonce2) = encrypt_header(&header, &key).unwrap();

        // Nonces should be different (random)
        assert_ne!(nonce1, nonce2);

        // Ciphertexts should be different
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same header
        let decrypted1 = decrypt_header(&encrypted1, &nonce1, &key).unwrap();
        let decrypted2 = decrypt_header(&encrypted2, &nonce2, &key).unwrap();
        assert_eq!(decrypted1, decrypted2);
    }
}
