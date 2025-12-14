//! # KAMO - Key Asymmetric Message Obfuscation
//!
//! KAMO is a steganography tool that hides messages within pre-shared carrier text.
//!
//! ## Overview
//!
//! KAMO v0.4.1 uses a pre-shared carrier approach with enhanced security:
//! - Both parties agree on a carrier text beforehand (a book, article, etc.)
//! - Message is **fragmented** into variable-sized pieces based on passphrase
//! - Fragments are found as **substrings** in the carrier (case-insensitive)
//! - Positions are **distributed** randomly across all occurrences
//! - Message is **padded** to block boundaries to hide length
//! - Positions are encrypted with passphrase (symmetric) and public key (asymmetric)
//! - Only the encrypted code is transmitted
//!
//! ## Security Model
//!
//! - **Four-factor security**: Carrier + Passphrase + Private Key + Correct Version
//! - **Substring matching**: "ama" found in "Amanda" - works across languages
//! - **Random positions**: Fragment 1 can be at end, Fragment 5 at start
//! - **Never fails**: Wrong inputs return garbage, not error
//! - **Block padding**: Message length hidden (only block range visible)
//! - **Distributed selection**: Multiple occurrences = random selection
//!
//! ## Example Usage
//!
//! ```rust
//! use kamo::crypto::KeyPair;
//! use kamo::{encode, decode};
//!
//! // Both parties have the same carrier text
//! let carrier = "Amanda fue al parque con su hermano ayer por la tarde";
//!
//! // Generate keys
//! let recipient_keys = KeyPair::generate();
//!
//! // Encode a message - fragments found as substrings
//! let encoded = encode(
//!     carrier,
//!     "ama parque",
//!     "secret_passphrase",
//!     recipient_keys.public_key()
//! ).unwrap();
//!
//! // Only encoded.code is transmitted
//! println!("Transmit this: {}", encoded.code);
//!
//! // Decode - NEVER fails, returns garbage if wrong
//! let decoded = decode(
//!     &encoded.code,
//!     carrier,
//!     "secret_passphrase",
//!     recipient_keys.secret_key()
//! );
//!
//! println!("Decoded: {}", decoded.message);
//! ```
//!
//! ## Modules
//!
//! - [`crypto`]: Cryptographic operations (key generation, encryption)
//! - [`text`]: Text processing (fragmentation, substring search, padding)
//! - [`encoder`]: Message encoding with fragments and padding
//! - [`decoder`]: Message decoding (never fails)

/// Protocol version
pub const VERSION: u8 = 5;

/// Block size for padding (in characters)
pub const BLOCK_SIZE: usize = 256;

/// Minimum message size before padding (in characters)
pub const MIN_SIZE: usize = 64;

pub mod crypto;
pub mod decoder;
pub mod encoder;
pub mod text;

// Re-export commonly used types at the crate root
pub use crypto::KeyPair;
pub use decoder::{decode, decode_with_config, DecodedMessage, DecoderConfig};
pub use encoder::{encode, encode_with_config, EncodedData, EncodedMessage, EncoderConfig, EncoderError};
pub use text::fragment::FoundFragment;
