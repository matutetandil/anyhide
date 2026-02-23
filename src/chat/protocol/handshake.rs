//! Handshake protocol for establishing a chat session.
//!
//! The handshake establishes ephemeral keys, exchanges carriers, and
//! verifies identities using Ed25519 signatures.
//!
//! ## Flow
//!
//! 1. Initiator sends `HandshakeInit` with ephemeral pubkey and proposed config
//! 2. Responder sends `HandshakeResponse` with ephemeral pubkey, agreed config, and encrypted carriers
//! 3. Initiator sends `HandshakeComplete` with encrypted carriers
//! 4. Both derive session keys from DH shared secret

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::chat::config::{ChatConfig, CHAT_PROTOCOL_VERSION};

/// Handshake initiation message (Initiator -> Responder).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeInit {
    /// Protocol version.
    pub version: u8,
    /// Ephemeral X25519 public key for this session.
    pub ephemeral_public: [u8; 32],
    /// Long-term identity public key (for verification).
    pub identity_public: [u8; 32],
    /// Proposed configuration.
    pub config: ChatConfig,
    /// Whether the initiator knows the responder (has them as a contact).
    /// Used for mutual recognition passphrase logic.
    pub i_know_you: bool,
    /// Ed25519 signature over (version || ephemeral_public || identity_public || config || i_know_you).
    pub signature: Vec<u8>,
}

impl HandshakeInit {
    /// Create a new handshake init message.
    ///
    /// # Arguments
    ///
    /// * `ephemeral_public` - Session ephemeral public key.
    /// * `identity_public` - Long-term identity public key.
    /// * `config` - Proposed session configuration.
    /// * `i_know_you` - Whether the initiator knows the responder as a contact.
    /// * `signature` - Ed25519 signature over the handshake data.
    pub fn new(
        ephemeral_public: [u8; 32],
        identity_public: [u8; 32],
        config: ChatConfig,
        i_know_you: bool,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            version: CHAT_PROTOCOL_VERSION,
            ephemeral_public,
            identity_public,
            config,
            i_know_you,
            signature,
        }
    }

    /// Get the data that was signed.
    pub fn signed_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(self.version);
        data.extend_from_slice(&self.ephemeral_public);
        data.extend_from_slice(&self.identity_public);
        data.extend_from_slice(&bincode::serialize(&self.config).unwrap());
        data.push(if self.i_know_you { 1 } else { 0 });
        data
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Handshake response message (Responder -> Initiator).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Protocol version.
    pub version: u8,
    /// Ephemeral X25519 public key for this session.
    pub ephemeral_public: [u8; 32],
    /// Long-term identity public key.
    pub identity_public: [u8; 32],
    /// Agreed configuration (may differ from proposed).
    pub config: ChatConfig,
    /// Whether the responder knows the initiator (has them as a contact).
    /// Used for mutual recognition passphrase logic.
    pub i_know_you: bool,
    /// Encrypted carriers using session key.
    pub encrypted_carriers: Vec<u8>,
    /// Ed25519 signature over (version || ephemeral_public || identity_public || config || i_know_you || hash(carriers)).
    pub signature: Vec<u8>,
}

impl HandshakeResponse {
    /// Create a new handshake response.
    ///
    /// # Arguments
    ///
    /// * `ephemeral_public` - Session ephemeral public key.
    /// * `identity_public` - Long-term identity public key.
    /// * `config` - Agreed session configuration.
    /// * `i_know_you` - Whether the responder knows the initiator as a contact.
    /// * `encrypted_carriers` - Encrypted carrier data.
    /// * `signature` - Ed25519 signature over the handshake data.
    pub fn new(
        ephemeral_public: [u8; 32],
        identity_public: [u8; 32],
        config: ChatConfig,
        i_know_you: bool,
        encrypted_carriers: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            version: CHAT_PROTOCOL_VERSION,
            ephemeral_public,
            identity_public,
            config,
            i_know_you,
            encrypted_carriers,
            signature,
        }
    }

    /// Get the data that was signed (including carrier hash).
    pub fn signed_data(&self, carrier_hash: &[u8; 32]) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(self.version);
        data.extend_from_slice(&self.ephemeral_public);
        data.extend_from_slice(&self.identity_public);
        data.extend_from_slice(&bincode::serialize(&self.config).unwrap());
        data.push(if self.i_know_you { 1 } else { 0 });
        data.extend_from_slice(carrier_hash);
        data
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Handshake completion message (Initiator -> Responder).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeComplete {
    /// Encrypted carriers from initiator.
    pub encrypted_carriers: Vec<u8>,
    /// Ed25519 signature over hash(carriers).
    pub signature: Vec<u8>,
}

impl HandshakeComplete {
    /// Create a new handshake complete message.
    pub fn new(encrypted_carriers: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            encrypted_carriers,
            signature,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Hash carriers for signing/verification.
pub fn hash_carriers(carriers: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for carrier in carriers {
        hasher.update(&(carrier.len() as u64).to_le_bytes());
        hasher.update(carrier);
    }
    hasher.finalize().into()
}

/// Encrypt carriers using ChaCha20-Poly1305.
///
/// # Arguments
///
/// * `carriers` - The carriers to encrypt.
/// * `key` - The 32-byte encryption key (derived from DH).
///
/// # Returns
///
/// The encrypted carriers blob.
pub fn encrypt_carriers(carriers: &[Vec<u8>], key: &[u8; 32]) -> Result<Vec<u8>, crate::chat::ChatError> {
    use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
    use rand::RngCore;

    // Serialize carriers
    let plaintext = bincode::serialize(carriers)
        .map_err(|e| crate::chat::ChatError::SerializationFailed(e.to_string()))?;

    // Generate nonce
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| crate::chat::ChatError::HeaderCryptoFailed(e.to_string()))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| crate::chat::ChatError::HeaderCryptoFailed(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt carriers using ChaCha20-Poly1305.
///
/// # Arguments
///
/// * `encrypted` - The encrypted carriers blob (nonce || ciphertext).
/// * `key` - The 32-byte decryption key.
///
/// # Returns
///
/// The decrypted carriers.
pub fn decrypt_carriers(encrypted: &[u8], key: &[u8; 32]) -> Result<Vec<Vec<u8>>, crate::chat::ChatError> {
    use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};

    if encrypted.len() < 12 {
        return Err(crate::chat::ChatError::HeaderCryptoFailed(
            "Encrypted carriers too short".to_string(),
        ));
    }

    // Extract nonce and ciphertext
    let nonce = Nonce::from_slice(&encrypted[..12]);
    let ciphertext = &encrypted[12..];

    // Decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| crate::chat::ChatError::HeaderCryptoFailed(e.to_string()))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| crate::chat::ChatError::HeaderCryptoFailed(e.to_string()))?;

    // Deserialize
    let carriers: Vec<Vec<u8>> = bincode::deserialize(&plaintext)
        .map_err(|e| crate::chat::ChatError::SerializationFailed(e.to_string()))?;

    Ok(carriers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_init_roundtrip() {
        let init = HandshakeInit::new(
            [1u8; 32],
            [2u8; 32],
            ChatConfig::default(),
            true, // i_know_you
            vec![3u8; 64],
        );

        let bytes = init.to_bytes().unwrap();
        let decoded = HandshakeInit::from_bytes(&bytes).unwrap();

        assert_eq!(init.version, decoded.version);
        assert_eq!(init.ephemeral_public, decoded.ephemeral_public);
        assert_eq!(init.identity_public, decoded.identity_public);
        assert_eq!(init.config, decoded.config);
        assert_eq!(init.i_know_you, decoded.i_know_you);
        assert_eq!(init.signature, decoded.signature);
    }

    #[test]
    fn test_handshake_response_roundtrip() {
        let response = HandshakeResponse::new(
            [1u8; 32],
            [2u8; 32],
            ChatConfig::default(),
            true, // i_know_you
            vec![4, 5, 6],
            vec![3u8; 64],
        );

        let bytes = response.to_bytes().unwrap();
        let decoded = HandshakeResponse::from_bytes(&bytes).unwrap();

        assert_eq!(response.version, decoded.version);
        assert_eq!(response.ephemeral_public, decoded.ephemeral_public);
        assert_eq!(response.i_know_you, decoded.i_know_you);
        assert_eq!(response.encrypted_carriers, decoded.encrypted_carriers);
    }

    #[test]
    fn test_handshake_complete_roundtrip() {
        let complete = HandshakeComplete::new(vec![7, 8, 9], vec![10u8; 64]);

        let bytes = complete.to_bytes().unwrap();
        let decoded = HandshakeComplete::from_bytes(&bytes).unwrap();

        assert_eq!(complete.encrypted_carriers, decoded.encrypted_carriers);
        assert_eq!(complete.signature, decoded.signature);
    }

    #[test]
    fn test_hash_carriers() {
        let carriers = vec![vec![1, 2, 3], vec![4, 5, 6]];

        let hash1 = hash_carriers(&carriers);
        let hash2 = hash_carriers(&carriers);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 32]);
    }

    #[test]
    fn test_hash_carriers_order_matters() {
        let carriers1 = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let carriers2 = vec![vec![4, 5, 6], vec![1, 2, 3]];

        let hash1 = hash_carriers(&carriers1);
        let hash2 = hash_carriers(&carriers2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_encrypt_decrypt_carriers() {
        let carriers = vec![vec![1, 2, 3], vec![4, 5, 6, 7, 8]];
        let key = [99u8; 32];

        let encrypted = encrypt_carriers(&carriers, &key).unwrap();
        let decrypted = decrypt_carriers(&encrypted, &key).unwrap();

        assert_eq!(carriers, decrypted);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let carriers = vec![vec![1, 2, 3]];
        let key1 = [99u8; 32];
        let key2 = [100u8; 32];

        let encrypted = encrypt_carriers(&carriers, &key1).unwrap();
        let result = decrypt_carriers(&encrypted, &key2);

        assert!(result.is_err());
    }
}
