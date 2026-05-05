//! Handshake protocol for establishing a hybrid post-quantum chat session.
//!
//! The handshake establishes ephemeral hybrid keypairs (X25519 + ML-KEM-768),
//! exchanges carriers, and verifies identities using Ed25519 signatures.
//!
//! ## Flow
//!
//! 1. Initiator sends `HandshakeInit` with hybrid ephemeral pubkey + hybrid identity pubkey
//! 2. Responder sends `HandshakeResponse` with its own hybrid ephemeral pubkey, a KEM
//!    ciphertext encapsulated against the initiator's ephemeral pubkey (giving shared
//!    secret `ss_resp_to_init`), agreed config, and encrypted carriers
//! 3. Initiator sends `HandshakeComplete` with a KEM ciphertext encapsulated against the
//!    responder's ephemeral pubkey (giving shared secret `ss_init_to_resp`) and its own
//!    encrypted carriers
//! 4. Both parties combine the two shared secrets via HKDF into a master session secret
//!    from which the session keys (header, send/recv chains, carrier chain, passphrase)
//!    are derived
//!
//! Each side encapsulates against the other so that both contribute KEM entropy — this
//! mirrors classical mutual ECDH but expressed in KEM primitives (PQXDH-shape).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::chat::config::{ChatConfig, CHAT_PROTOCOL_VERSION};
use crate::crypto::hybrid_kem::{
    self, HybridCiphertext, HybridPublicKey, HybridSecretKey, HYBRID_CT_SIZE, HYBRID_PUBKEY_SIZE,
};

/// Wire-format size of a hybrid public key (X25519 32B || ML-KEM-768 1184B).
pub const WIRE_HYBRID_PUBKEY_SIZE: usize = HYBRID_PUBKEY_SIZE;

/// Wire-format size of a hybrid KEM ciphertext (X25519 ephemeral 32B || ML-KEM-768 ct 1088B).
pub const WIRE_HYBRID_CT_SIZE: usize = HYBRID_CT_SIZE;

/// Handshake initiation message (Initiator → Responder).
///
/// At this point only the initiator has produced material; the responder will
/// reply with its own ephemeral pubkey and a KEM ciphertext.
///
/// Note: `identity_public` is the *Ed25519* verifying key (32 bytes), not a
/// hybrid encryption pubkey. Authentication uses Ed25519 signatures throughout
/// — the post-quantum migration covers confidentiality (KEM ratchet) only;
/// signature-based authentication is a separate concern, not addressed here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeInit {
    /// Protocol version (must be `CHAT_PROTOCOL_VERSION`).
    pub version: u8,
    /// Hybrid ephemeral public key for this session (1216 bytes).
    pub ephemeral_public_hybrid: Vec<u8>,
    /// Long-term Ed25519 identity public key for signature verification (32 bytes).
    pub identity_public: [u8; 32],
    /// Proposed configuration.
    pub config: ChatConfig,
    /// Whether the initiator knows the responder (has them as a contact).
    pub i_know_you: bool,
    /// Ed25519 signature over `signed_data()`.
    pub signature: Vec<u8>,
}

impl HandshakeInit {
    /// Creates a new handshake init message.
    ///
    /// Validates that the hybrid ephemeral public key has the expected wire size.
    pub fn new(
        ephemeral_public_hybrid: Vec<u8>,
        identity_public: [u8; 32],
        config: ChatConfig,
        i_know_you: bool,
        signature: Vec<u8>,
    ) -> Result<Self, HandshakeError> {
        validate_pubkey_size("ephemeral_public_hybrid", &ephemeral_public_hybrid)?;
        Ok(Self {
            version: CHAT_PROTOCOL_VERSION,
            ephemeral_public_hybrid,
            identity_public,
            config,
            i_know_you,
            signature,
        })
    }

    /// Returns the canonical bytes that must be Ed25519-signed by the initiator.
    pub fn signed_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(self.version);
        data.extend_from_slice(&self.ephemeral_public_hybrid);
        data.extend_from_slice(&self.identity_public);
        data.extend_from_slice(&bincode::serialize(&self.config).unwrap());
        data.push(if self.i_know_you { 1 } else { 0 });
        data
    }

    /// Validates the wire-size invariants on a deserialized message.
    pub fn validate(&self) -> Result<(), HandshakeError> {
        if self.version != CHAT_PROTOCOL_VERSION {
            return Err(HandshakeError::VersionMismatch {
                expected: CHAT_PROTOCOL_VERSION,
                got: self.version,
            });
        }
        validate_pubkey_size("ephemeral_public_hybrid", &self.ephemeral_public_hybrid)?;
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Handshake response message (Responder → Initiator).
///
/// The responder generates its own hybrid ephemeral keypair and encapsulates
/// against the initiator's ephemeral pubkey to derive `ss_resp_to_init`. That
/// secret is used both to encrypt the responder's carriers (via a derived
/// handshake key) and as one of the two inputs to the master session secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Protocol version (must be `CHAT_PROTOCOL_VERSION`).
    pub version: u8,
    /// Hybrid ephemeral public key for this session (1216 bytes).
    pub ephemeral_public_hybrid: Vec<u8>,
    /// Long-term Ed25519 identity public key for signature verification (32 bytes).
    pub identity_public: [u8; 32],
    /// KEM ciphertext encapsulated against the initiator's ephemeral pubkey (1120 bytes).
    pub kem_ciphertext_to_initiator: Vec<u8>,
    /// Agreed configuration (may differ from proposed).
    pub config: ChatConfig,
    /// Whether the responder knows the initiator (has them as a contact).
    pub i_know_you: bool,
    /// Encrypted carriers (key derived from `ss_resp_to_init`).
    pub encrypted_carriers: Vec<u8>,
    /// Ed25519 signature over `signed_data()`.
    pub signature: Vec<u8>,
}

impl HandshakeResponse {
    pub fn new(
        ephemeral_public_hybrid: Vec<u8>,
        identity_public: [u8; 32],
        kem_ciphertext_to_initiator: Vec<u8>,
        config: ChatConfig,
        i_know_you: bool,
        encrypted_carriers: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Self, HandshakeError> {
        validate_pubkey_size("ephemeral_public_hybrid", &ephemeral_public_hybrid)?;
        validate_ct_size("kem_ciphertext_to_initiator", &kem_ciphertext_to_initiator)?;
        Ok(Self {
            version: CHAT_PROTOCOL_VERSION,
            ephemeral_public_hybrid,
            identity_public,
            kem_ciphertext_to_initiator,
            config,
            i_know_you,
            encrypted_carriers,
            signature,
        })
    }

    /// Returns the canonical bytes that must be Ed25519-signed by the responder.
    ///
    /// Includes the carrier hash so the signature commits to the encrypted
    /// carrier blob via its plaintext digest (not the ciphertext).
    pub fn signed_data(&self, carrier_hash: &[u8; 32]) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(self.version);
        data.extend_from_slice(&self.ephemeral_public_hybrid);
        data.extend_from_slice(&self.identity_public);
        data.extend_from_slice(&self.kem_ciphertext_to_initiator);
        data.extend_from_slice(&bincode::serialize(&self.config).unwrap());
        data.push(if self.i_know_you { 1 } else { 0 });
        data.extend_from_slice(carrier_hash);
        data
    }

    pub fn validate(&self) -> Result<(), HandshakeError> {
        if self.version != CHAT_PROTOCOL_VERSION {
            return Err(HandshakeError::VersionMismatch {
                expected: CHAT_PROTOCOL_VERSION,
                got: self.version,
            });
        }
        validate_pubkey_size("ephemeral_public_hybrid", &self.ephemeral_public_hybrid)?;
        validate_ct_size("kem_ciphertext_to_initiator", &self.kem_ciphertext_to_initiator)?;
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Handshake completion message (Initiator → Responder).
///
/// The initiator encapsulates against the responder's ephemeral pubkey to
/// derive `ss_init_to_resp`. After this message, both parties hold both
/// shared secrets and can compute the master session secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeComplete {
    /// Protocol version (must be `CHAT_PROTOCOL_VERSION`).
    pub version: u8,
    /// KEM ciphertext encapsulated against the responder's ephemeral pubkey (1120 bytes).
    pub kem_ciphertext_to_responder: Vec<u8>,
    /// Encrypted carriers from initiator (key derived from `ss_init_to_resp`).
    pub encrypted_carriers: Vec<u8>,
    /// Ed25519 signature over `signed_data()`.
    pub signature: Vec<u8>,
}

impl HandshakeComplete {
    pub fn new(
        kem_ciphertext_to_responder: Vec<u8>,
        encrypted_carriers: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Self, HandshakeError> {
        validate_ct_size("kem_ciphertext_to_responder", &kem_ciphertext_to_responder)?;
        Ok(Self {
            version: CHAT_PROTOCOL_VERSION,
            kem_ciphertext_to_responder,
            encrypted_carriers,
            signature,
        })
    }

    /// Returns the canonical bytes that must be Ed25519-signed by the initiator
    /// to commit to the KEM ciphertext and the carrier-blob digest.
    pub fn signed_data(&self, carrier_hash: &[u8; 32]) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(self.version);
        data.extend_from_slice(&self.kem_ciphertext_to_responder);
        data.extend_from_slice(carrier_hash);
        data
    }

    pub fn validate(&self) -> Result<(), HandshakeError> {
        if self.version != CHAT_PROTOCOL_VERSION {
            return Err(HandshakeError::VersionMismatch {
                expected: CHAT_PROTOCOL_VERSION,
                got: self.version,
            });
        }
        validate_ct_size("kem_ciphertext_to_responder", &self.kem_ciphertext_to_responder)?;
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Errors raised when constructing or validating handshake messages.
#[derive(thiserror::Error, Debug)]
pub enum HandshakeError {
    #[error("Handshake protocol version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u8, got: u8 },

    #[error("Invalid {field} size: expected {expected}, got {got}")]
    InvalidSize {
        field: &'static str,
        expected: usize,
        got: usize,
    },
}

fn validate_pubkey_size(field: &'static str, data: &[u8]) -> Result<(), HandshakeError> {
    if data.len() != WIRE_HYBRID_PUBKEY_SIZE {
        return Err(HandshakeError::InvalidSize {
            field,
            expected: WIRE_HYBRID_PUBKEY_SIZE,
            got: data.len(),
        });
    }
    Ok(())
}

fn validate_ct_size(field: &'static str, data: &[u8]) -> Result<(), HandshakeError> {
    if data.len() != WIRE_HYBRID_CT_SIZE {
        return Err(HandshakeError::InvalidSize {
            field,
            expected: WIRE_HYBRID_CT_SIZE,
            got: data.len(),
        });
    }
    Ok(())
}

/// Hashes the carriers for signing/verification.
pub fn hash_carriers(carriers: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for carrier in carriers {
        hasher.update(&(carrier.len() as u64).to_le_bytes());
        hasher.update(carrier);
    }
    hasher.finalize().into()
}

/// Encrypts carriers using ChaCha20-Poly1305 with a 32-byte key.
///
/// The key is typically derived from one of the handshake KEM shared secrets.
pub fn encrypt_carriers(
    carriers: &[Vec<u8>],
    key: &[u8; 32],
) -> Result<Vec<u8>, crate::chat::ChatError> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    use rand::RngCore;

    let plaintext = bincode::serialize(carriers)
        .map_err(|e| crate::chat::ChatError::SerializationFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| crate::chat::ChatError::HeaderCryptoFailed(e.to_string()))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| crate::chat::ChatError::HeaderCryptoFailed(e.to_string()))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypts carriers using ChaCha20-Poly1305.
pub fn decrypt_carriers(
    encrypted: &[u8],
    key: &[u8; 32],
) -> Result<Vec<Vec<u8>>, crate::chat::ChatError> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };

    if encrypted.len() < 12 {
        return Err(crate::chat::ChatError::HeaderCryptoFailed(
            "Encrypted carriers too short".to_string(),
        ));
    }

    let nonce = Nonce::from_slice(&encrypted[..12]);
    let ciphertext = &encrypted[12..];

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| crate::chat::ChatError::HeaderCryptoFailed(e.to_string()))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| crate::chat::ChatError::HeaderCryptoFailed(e.to_string()))?;

    let carriers: Vec<Vec<u8>> = bincode::deserialize(&plaintext)
        .map_err(|e| crate::chat::ChatError::SerializationFailed(e.to_string()))?;

    Ok(carriers)
}

// ============================================================================
// KEM helpers for the handshake exchange
// ============================================================================

/// Errors produced by the handshake KEM helpers.
#[derive(thiserror::Error, Debug)]
pub enum HandshakeKemError {
    #[error("Invalid hybrid public key on the wire: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid KEM ciphertext on the wire: {0}")]
    InvalidCiphertext(String),

    #[error("KEM encapsulation failed: {0}")]
    EncapsulationFailed(String),

    #[error("KEM decapsulation failed: {0}")]
    DecapsulationFailed(String),
}

/// Decodes a peer's hybrid ephemeral public key from its wire bytes.
pub fn parse_peer_pubkey(bytes: &[u8]) -> Result<HybridPublicKey, HandshakeKemError> {
    HybridPublicKey::from_bytes(bytes)
        .map_err(|e| HandshakeKemError::InvalidPublicKey(e.to_string()))
}

/// Decodes a peer's KEM ciphertext from its wire bytes.
pub fn parse_kem_ciphertext(bytes: &[u8]) -> Result<HybridCiphertext, HandshakeKemError> {
    HybridCiphertext::from_bytes(bytes)
        .map_err(|e| HandshakeKemError::InvalidCiphertext(e.to_string()))
}

/// Responder-side KEM step: encapsulates against the initiator's ephemeral
/// pubkey to derive `ss_resp_to_init` and produce the ciphertext that goes
/// into [`HandshakeResponse`].
///
/// Returns `(kem_ciphertext, shared_secret_bytes)`. The caller pairs the
/// ciphertext with their own ephemeral pubkey when sending the response.
pub fn responder_encapsulate_to_initiator(
    init_ephemeral: &HybridPublicKey,
) -> Result<(HybridCiphertext, [u8; 32]), HandshakeKemError> {
    let (ct, shared) = hybrid_kem::encapsulate(init_ephemeral)
        .map_err(|e| HandshakeKemError::EncapsulationFailed(e.to_string()))?;
    Ok((ct, *shared.as_bytes()))
}

/// Initiator-side counterpart: decapsulates the responder's ciphertext to
/// recover the same `ss_resp_to_init` value the responder derived.
pub fn initiator_decapsulate_from_responder(
    my_secret: &HybridSecretKey,
    ciphertext: &HybridCiphertext,
) -> Result<[u8; 32], HandshakeKemError> {
    let shared = hybrid_kem::decapsulate(my_secret, ciphertext)
        .map_err(|e| HandshakeKemError::DecapsulationFailed(e.to_string()))?;
    Ok(*shared.as_bytes())
}

/// Initiator-side KEM step: encapsulates against the responder's ephemeral
/// pubkey to derive `ss_init_to_resp` for the [`HandshakeComplete`] message.
pub fn initiator_encapsulate_to_responder(
    resp_ephemeral: &HybridPublicKey,
) -> Result<(HybridCiphertext, [u8; 32]), HandshakeKemError> {
    let (ct, shared) = hybrid_kem::encapsulate(resp_ephemeral)
        .map_err(|e| HandshakeKemError::EncapsulationFailed(e.to_string()))?;
    Ok((ct, *shared.as_bytes()))
}

/// Responder-side counterpart: decapsulates the initiator's ciphertext to
/// recover `ss_init_to_resp` after receiving [`HandshakeComplete`].
pub fn responder_decapsulate_from_initiator(
    my_secret: &HybridSecretKey,
    ciphertext: &HybridCiphertext,
) -> Result<[u8; 32], HandshakeKemError> {
    let shared = hybrid_kem::decapsulate(my_secret, ciphertext)
        .map_err(|e| HandshakeKemError::DecapsulationFailed(e.to_string()))?;
    Ok(*shared.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pubkey() -> Vec<u8> {
        vec![1u8; WIRE_HYBRID_PUBKEY_SIZE]
    }

    fn dummy_ct() -> Vec<u8> {
        vec![2u8; WIRE_HYBRID_CT_SIZE]
    }

    #[test]
    fn test_handshake_init_roundtrip() {
        let init = HandshakeInit::new(
            dummy_pubkey(),
            [9u8; 32],
            ChatConfig::default(),
            true,
            vec![3u8; 64],
        )
        .unwrap();

        let bytes = init.to_bytes().unwrap();
        let decoded = HandshakeInit::from_bytes(&bytes).unwrap();

        assert_eq!(init.version, decoded.version);
        assert_eq!(init.ephemeral_public_hybrid, decoded.ephemeral_public_hybrid);
        assert_eq!(init.identity_public, decoded.identity_public);
        assert_eq!(init.config, decoded.config);
        assert_eq!(init.i_know_you, decoded.i_know_you);
        assert_eq!(init.signature, decoded.signature);

        decoded.validate().unwrap();
    }

    #[test]
    fn test_handshake_response_roundtrip() {
        let response = HandshakeResponse::new(
            dummy_pubkey(),
            [9u8; 32],
            dummy_ct(),
            ChatConfig::default(),
            true,
            vec![4, 5, 6],
            vec![3u8; 64],
        )
        .unwrap();

        let bytes = response.to_bytes().unwrap();
        let decoded = HandshakeResponse::from_bytes(&bytes).unwrap();

        assert_eq!(response.version, decoded.version);
        assert_eq!(
            response.ephemeral_public_hybrid,
            decoded.ephemeral_public_hybrid
        );
        assert_eq!(response.identity_public, decoded.identity_public);
        assert_eq!(
            response.kem_ciphertext_to_initiator,
            decoded.kem_ciphertext_to_initiator
        );
        assert_eq!(response.i_know_you, decoded.i_know_you);
        assert_eq!(response.encrypted_carriers, decoded.encrypted_carriers);

        decoded.validate().unwrap();
    }

    #[test]
    fn test_handshake_complete_roundtrip() {
        let complete = HandshakeComplete::new(dummy_ct(), vec![7, 8, 9], vec![10u8; 64]).unwrap();

        let bytes = complete.to_bytes().unwrap();
        let decoded = HandshakeComplete::from_bytes(&bytes).unwrap();

        assert_eq!(complete.kem_ciphertext_to_responder, decoded.kem_ciphertext_to_responder);
        assert_eq!(complete.encrypted_carriers, decoded.encrypted_carriers);
        assert_eq!(complete.signature, decoded.signature);

        decoded.validate().unwrap();
    }

    #[test]
    fn test_handshake_init_rejects_wrong_pubkey_size() {
        let result = HandshakeInit::new(
            vec![1u8; 32],
            [0u8; 32],
            ChatConfig::default(),
            true,
            vec![],
        );
        assert!(matches!(result, Err(HandshakeError::InvalidSize { .. })));
    }

    #[test]
    fn test_handshake_response_rejects_wrong_ct_size() {
        let result = HandshakeResponse::new(
            dummy_pubkey(),
            [0u8; 32],
            vec![2u8; 100],
            ChatConfig::default(),
            true,
            vec![],
            vec![],
        );
        assert!(matches!(result, Err(HandshakeError::InvalidSize { .. })));
    }

    #[test]
    fn test_validate_rejects_wrong_version() {
        // Build a tampered struct without using the validating constructor.
        let mut init = HandshakeInit::new(
            dummy_pubkey(),
            [0u8; 32],
            ChatConfig::default(),
            true,
            vec![],
        )
        .unwrap();
        init.version = 99;

        assert!(matches!(
            init.validate(),
            Err(HandshakeError::VersionMismatch { .. })
        ));
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
