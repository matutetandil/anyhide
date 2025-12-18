//! Chat error types.

use thiserror::Error;

/// Errors that can occur during chat operations.
#[derive(Error, Debug)]
pub enum ChatError {
    /// Handshake failed with the given reason.
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    /// Invalid Ed25519 signature format.
    #[error("Invalid signature format")]
    InvalidSignature,

    /// Ed25519 signature verification failed.
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Session has expired.
    #[error("Session expired")]
    SessionExpired,

    /// Too many messages skipped (out-of-order limit exceeded).
    #[error("Too many skipped messages (max: {max}, requested: {requested})")]
    TooManySkipped {
        /// Maximum allowed skipped messages.
        max: usize,
        /// Number of messages requested to skip.
        requested: usize,
    },

    /// Skipped message key not found in cache.
    #[error("Skipped key not found for sequence {0}")]
    SkippedKeyNotFound(u32),

    /// Invalid carrier index.
    #[error("Invalid carrier index: owner={owner}, index={index}")]
    InvalidCarrier {
        /// Carrier owner (0 = initiator, 1 = responder).
        owner: u8,
        /// Carrier index within owner's carriers.
        index: u16,
    },

    /// Carrier extraction failed (message too long for carrier).
    #[error("Message too long for carrier capacity")]
    CarrierCapacityExceeded,

    /// Message encoding failed.
    #[error("Encoding failed: {0}")]
    EncodingFailed(String),

    /// Message decoding failed.
    #[error("Decoding failed: {0}")]
    DecodingFailed(String),

    /// Serialization failed.
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    /// Header encryption/decryption failed.
    #[error("Header crypto failed: {0}")]
    HeaderCryptoFailed(String),

    /// Transport error.
    #[error("Transport error: {0}")]
    TransportError(String),

    /// Protocol version mismatch.
    #[error("Protocol version mismatch: expected {expected}, got {got}")]
    VersionMismatch {
        /// Expected protocol version.
        expected: u8,
        /// Received protocol version.
        got: u8,
    },

    /// I/O error.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Key error.
    #[error("Key error: {0}")]
    KeyError(String),

    /// Session not initialized.
    #[error("Session not initialized")]
    SessionNotInitialized,

    /// Invalid message sequence.
    #[error("Invalid message sequence: expected {expected}, got {got}")]
    InvalidSequence {
        /// Expected sequence number.
        expected: u32,
        /// Received sequence number.
        got: u32,
    },

    /// Tor-related error.
    #[error("Tor error: {0}")]
    TorError(String),
}
