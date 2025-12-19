//! # Anyhide Chat Module
//!
//! P2P encrypted chat using Anyhide's steganographic encoding.
//!
//! This module implements a Double Ratchet protocol for forward secrecy,
//! with all session state kept in RAM and zeroized on drop.
//!
//! ## Security Model
//!
//! - **Ed25519 signatures** are the only oracle for message validity
//! - **Random carriers** generated during handshake (never reused)
//! - **All keys zeroized** on session drop
//! - **DH ratchet** on direction change for forward secrecy
//! - **Encrypted headers** hide all metadata from attackers

mod carrier;
mod config;
mod error;
pub mod protocol;
mod session;
pub mod transport;
pub mod tui;

pub use carrier::{generate_carriers, MIN_CARRIER_SIZE};
pub use config::{CarrierMode, ChatConfig};
pub use error::ChatError;
pub use protocol::{
    HandshakeComplete, HandshakeInit, HandshakeResponse, MessageHeader, SignedMessage, WireMessage,
};
pub use session::{ChatSession, Direction};
