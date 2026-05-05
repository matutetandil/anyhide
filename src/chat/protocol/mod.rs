//! Chat protocol types and operations (hybrid post-quantum, v2).
//!
//! This module implements the Double Ratchet protocol for forward secrecy
//! using hybrid X25519 + ML-KEM-768 KEM:
//!
//! - **KDF chains** for deriving per-message keys (symmetric, unchanged from v1)
//! - **KEM ratchet** when conversation direction changes (replaces v1 DH ratchet)
//! - **Header encryption** to hide metadata
//! - **Handshake messages** for session establishment via two-direction KEM exchange

mod handshake;
mod header;
mod message;
mod ratchet;

pub use handshake::{
    decrypt_carriers, encrypt_carriers, hash_carriers, initiator_decapsulate_from_responder,
    initiator_encapsulate_to_responder, parse_kem_ciphertext, parse_peer_pubkey,
    responder_decapsulate_from_initiator, responder_encapsulate_to_initiator, HandshakeComplete,
    HandshakeError, HandshakeInit, HandshakeKemError, HandshakeResponse, WIRE_HYBRID_CT_SIZE,
    WIRE_HYBRID_PUBKEY_SIZE,
};
pub use header::{decrypt_header, encrypt_header, MessageHeader, HEADER_KEM_CT_SIZE, HEADER_PUBKEY_SIZE};
pub use message::{SignedMessage, WireMessage};
pub use ratchet::{
    advance_carrier_chain, derive_handshake_carrier_key, derive_master_secret,
    derive_message_passphrase, derive_session_keys, kdf_chain, kem_ratchet_receive,
    kem_ratchet_send, KemRatchetOutput, SessionKeys,
};
