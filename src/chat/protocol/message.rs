//! Wire message types for chat protocol.
//!
//! These types define what actually gets sent over the network.

use serde::{Deserialize, Serialize};

/// A signed message containing the plaintext and Ed25519 signature.
///
/// This is what gets encoded with anyhide steganography.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    /// The plaintext message content.
    pub content: String,
    /// Ed25519 signature over (content || seq) in bytes.
    pub signature: Vec<u8>,
}

impl SignedMessage {
    /// Create a new signed message.
    pub fn new(content: String, signature: Vec<u8>) -> Self {
        Self { content, signature }
    }

    /// Serialize to bytes for encoding.
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// A complete message as sent over the wire.
///
/// This contains the encrypted header and the anyhide code. An attacker
/// sees only random bytes (the encrypted header) and what looks like
/// a normal anyhide code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireMessage {
    /// Protocol version.
    pub version: u8,
    /// Nonce for header decryption (12 bytes).
    pub header_nonce: [u8; 12],
    /// Encrypted header (bincode serialized MessageHeader + ChaCha20Poly1305).
    pub encrypted_header: Vec<u8>,
    /// The anyhide code (message encoded with carrier-based steganography).
    pub anyhide_code: String,
}

impl WireMessage {
    /// Create a new wire message.
    pub fn new(
        version: u8,
        header_nonce: [u8; 12],
        encrypted_header: Vec<u8>,
        anyhide_code: String,
    ) -> Self {
        Self {
            version,
            header_nonce,
            encrypted_header,
            anyhide_code,
        }
    }

    /// Serialize to bytes for transport.
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_message_roundtrip() {
        let msg = SignedMessage::new("Hello, world!".to_string(), vec![1, 2, 3, 4]);

        let bytes = msg.to_bytes().unwrap();
        let decoded = SignedMessage::from_bytes(&bytes).unwrap();

        assert_eq!(msg.content, decoded.content);
        assert_eq!(msg.signature, decoded.signature);
    }

    #[test]
    fn test_wire_message_roundtrip() {
        let wire = WireMessage::new(
            1,
            [0u8; 12],
            vec![1, 2, 3, 4, 5],
            "base64encodedcode".to_string(),
        );

        let bytes = wire.to_bytes().unwrap();
        let decoded = WireMessage::from_bytes(&bytes).unwrap();

        assert_eq!(wire.version, decoded.version);
        assert_eq!(wire.header_nonce, decoded.header_nonce);
        assert_eq!(wire.encrypted_header, decoded.encrypted_header);
        assert_eq!(wire.anyhide_code, decoded.anyhide_code);
    }

    #[test]
    fn test_signed_message_empty_content() {
        let msg = SignedMessage::new(String::new(), vec![]);

        let bytes = msg.to_bytes().unwrap();
        let decoded = SignedMessage::from_bytes(&bytes).unwrap();

        assert!(decoded.content.is_empty());
        assert!(decoded.signature.is_empty());
    }

    #[test]
    fn test_wire_message_large_code() {
        let large_code = "A".repeat(10000);
        let wire = WireMessage::new(1, [0u8; 12], vec![1, 2, 3], large_code.clone());

        let bytes = wire.to_bytes().unwrap();
        let decoded = WireMessage::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.anyhide_code, large_code);
    }
}
