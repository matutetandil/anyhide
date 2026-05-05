//! Message header encryption and decryption (hybrid post-quantum).
//!
//! The header contains metadata like sequence number, the sender's current
//! ratchet pubkey, and carrier selection. It's encrypted with the session
//! header_key to hide this information from passive attackers.
//!
//! In v2 the ratchet pubkey grows from 32 bytes (X25519) to 1216 bytes
//! (hybrid X25519 + ML-KEM-768) and an optional `kem_ciphertext` (1120 bytes)
//! is included only on messages that perform a ratchet step. On chain-mode
//! messages (same direction as the previous one) the ciphertext field is
//! `None` so the per-message overhead stays at the pubkey size.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::chat::ChatError;
use crate::crypto::hybrid_kem::{HYBRID_CT_SIZE, HYBRID_PUBKEY_SIZE};

/// Wire-format size of the hybrid ratchet pubkey carried in every header.
pub const HEADER_PUBKEY_SIZE: usize = HYBRID_PUBKEY_SIZE;

/// Wire-format size of the optional KEM ciphertext attached to ratchet-step messages.
pub const HEADER_KEM_CT_SIZE: usize = HYBRID_CT_SIZE;

/// Message header containing metadata for decryption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageHeader {
    /// Message sequence number.
    pub seq: u32,
    /// Sender's current hybrid ratchet public key (1216 bytes).
    ///
    /// Stored as `Vec<u8>` because bincode/serde do not derive serialization
    /// for fixed arrays larger than 32 by default. The struct enforces the
    /// expected length at construction and validation time.
    pub dh_public_hybrid: Vec<u8>,
    /// KEM ciphertext (1120 bytes) carried only when this message performs a
    /// ratchet step. Receivers detect the step by comparing `dh_public_hybrid`
    /// against the previously seen value; when a new pubkey appears, this
    /// field must be `Some` and is decapsulated to drive the new chain key.
    pub kem_ciphertext: Option<Vec<u8>>,
    /// Which party owns the carrier (0 = initiator, 1 = responder).
    pub carrier_owner: u8,
    /// Index into that party's carrier array.
    pub carrier_index: u16,
    /// Number of messages in the previous sending chain.
    pub prev_chain_len: u32,
}

impl MessageHeader {
    /// Validates wire-size invariants on a header before use.
    pub fn validate(&self) -> Result<(), ChatError> {
        if self.dh_public_hybrid.len() != HEADER_PUBKEY_SIZE {
            return Err(ChatError::SerializationFailed(format!(
                "MessageHeader.dh_public_hybrid has length {}, expected {}",
                self.dh_public_hybrid.len(),
                HEADER_PUBKEY_SIZE
            )));
        }
        if let Some(ref ct) = self.kem_ciphertext {
            if ct.len() != HEADER_KEM_CT_SIZE {
                return Err(ChatError::SerializationFailed(format!(
                    "MessageHeader.kem_ciphertext has length {}, expected {}",
                    ct.len(),
                    HEADER_KEM_CT_SIZE
                )));
            }
        }
        Ok(())
    }
}

/// Encrypts a message header with the session header key.
pub fn encrypt_header(
    header: &MessageHeader,
    header_key: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 12]), ChatError> {
    header.validate()?;

    let header_bytes = bincode::serialize(header)
        .map_err(|e| ChatError::SerializationFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(header_key)
        .map_err(|e| ChatError::HeaderCryptoFailed(e.to_string()))?;

    let ciphertext = cipher
        .encrypt(nonce, header_bytes.as_ref())
        .map_err(|e| ChatError::HeaderCryptoFailed(e.to_string()))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypts a message header with the session header key.
pub fn decrypt_header(
    encrypted_header: &[u8],
    nonce: &[u8; 12],
    header_key: &[u8; 32],
) -> Result<MessageHeader, ChatError> {
    let nonce = Nonce::from_slice(nonce);

    let cipher = ChaCha20Poly1305::new_from_slice(header_key)
        .map_err(|e| ChatError::HeaderCryptoFailed(e.to_string()))?;

    let plaintext = cipher
        .decrypt(nonce, encrypted_header)
        .map_err(|e| ChatError::HeaderCryptoFailed(e.to_string()))?;

    let header: MessageHeader = bincode::deserialize(&plaintext)
        .map_err(|e| ChatError::SerializationFailed(e.to_string()))?;

    header.validate()?;
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_header() -> MessageHeader {
        MessageHeader {
            seq: 42,
            dh_public_hybrid: vec![1u8; HEADER_PUBKEY_SIZE],
            kem_ciphertext: None,
            carrier_owner: 0,
            carrier_index: 5,
            prev_chain_len: 10,
        }
    }

    fn make_ratchet_step_header() -> MessageHeader {
        MessageHeader {
            seq: 0,
            dh_public_hybrid: vec![3u8; HEADER_PUBKEY_SIZE],
            kem_ciphertext: Some(vec![4u8; HEADER_KEM_CT_SIZE]),
            carrier_owner: 1,
            carrier_index: 0,
            prev_chain_len: 12,
        }
    }

    #[test]
    fn test_header_roundtrip_chain_mode() {
        let header = make_test_header();
        let key = [99u8; 32];

        let (encrypted, nonce) = encrypt_header(&header, &key).unwrap();
        let decrypted = decrypt_header(&encrypted, &nonce, &key).unwrap();

        assert_eq!(header, decrypted);
        assert!(decrypted.kem_ciphertext.is_none());
    }

    #[test]
    fn test_header_roundtrip_ratchet_step() {
        let header = make_ratchet_step_header();
        let key = [99u8; 32];

        let (encrypted, nonce) = encrypt_header(&header, &key).unwrap();
        let decrypted = decrypt_header(&encrypted, &nonce, &key).unwrap();

        assert_eq!(header, decrypted);
        assert!(decrypted.kem_ciphertext.is_some());
        assert_eq!(decrypted.kem_ciphertext.as_ref().unwrap().len(), HEADER_KEM_CT_SIZE);
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
        encrypted[0] ^= 0xFF;
        let result = decrypt_header(&encrypted, &nonce, &key);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_rejects_invalid_pubkey_size() {
        let bad_header = MessageHeader {
            seq: 0,
            dh_public_hybrid: vec![1u8; 32], // wrong size — must be HEADER_PUBKEY_SIZE
            kem_ciphertext: None,
            carrier_owner: 0,
            carrier_index: 0,
            prev_chain_len: 0,
        };
        let key = [0u8; 32];

        let result = encrypt_header(&bad_header, &key);
        assert!(matches!(result, Err(ChatError::SerializationFailed(_))));
    }

    #[test]
    fn test_encrypt_rejects_invalid_kem_ct_size() {
        let bad_header = MessageHeader {
            seq: 0,
            dh_public_hybrid: vec![1u8; HEADER_PUBKEY_SIZE],
            kem_ciphertext: Some(vec![2u8; 100]), // wrong size — must be HEADER_KEM_CT_SIZE
            carrier_owner: 0,
            carrier_index: 0,
            prev_chain_len: 0,
        };
        let key = [0u8; 32];

        let result = encrypt_header(&bad_header, &key);
        assert!(matches!(result, Err(ChatError::SerializationFailed(_))));
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertext() {
        let header = make_test_header();
        let key = [99u8; 32];

        let (encrypted1, nonce1) = encrypt_header(&header, &key).unwrap();
        let (encrypted2, nonce2) = encrypt_header(&header, &key).unwrap();

        assert_ne!(nonce1, nonce2);
        assert_ne!(encrypted1, encrypted2);

        let decrypted1 = decrypt_header(&encrypted1, &nonce1, &key).unwrap();
        let decrypted2 = decrypt_header(&encrypted2, &nonce2, &key).unwrap();
        assert_eq!(decrypted1, decrypted2);
    }
}
