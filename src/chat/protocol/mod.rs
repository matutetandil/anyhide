//! Chat protocol types and operations.
//!
//! This module implements the Double Ratchet protocol for forward secrecy:
//!
//! - **KDF chains** for deriving per-message keys
//! - **DH ratchet** when conversation direction changes
//! - **Header encryption** to hide metadata
//! - **Handshake messages** for session establishment

mod handshake;
mod header;
mod message;
mod ratchet;

pub use handshake::{
    decrypt_carriers, encrypt_carriers, hash_carriers, HandshakeComplete, HandshakeInit,
    HandshakeResponse,
};
pub use header::{decrypt_header, encrypt_header, MessageHeader};
pub use message::{SignedMessage, WireMessage};
pub use ratchet::{
    advance_carrier_chain, derive_message_passphrase, derive_session_keys, dh_ratchet, kdf_chain,
    RatchetOutput, SessionKeys,
};
