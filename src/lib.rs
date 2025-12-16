//! # Anyhide - Hide anything in anything
//!
//! Anyhide is a steganography tool that hides messages within pre-shared carriers
//! (text, images, audio, or any file).
//!
//! ## Overview
//!
//! Anyhide uses a pre-shared carrier approach with enhanced security:
//! - Both parties agree on a carrier beforehand (text, image, or audio file)
//! - Message is **fragmented** into variable-sized pieces based on passphrase
//! - Fragments are found as **substrings** (text) or **byte sequences** (binary)
//! - Positions are **distributed** randomly across all occurrences
//! - Message is **padded** to block boundaries to hide length
//! - Positions are encrypted with passphrase (symmetric) and public key (asymmetric)
//! - Only the encrypted code is transmitted (carrier never transmitted!)
//!
//! ## Security Model
//!
//! - **Four-factor security**: Carrier + Passphrase + Private Key + Correct Version
//! - **Substring matching**: "ama" found in "Amanda" - works across languages
//! - **Random positions**: Fragment 1 can be at end, Fragment 5 at start
//! - **Never fails**: Wrong inputs return garbage, not error
//! - **Block padding**: Message length hidden (only block range visible)
//! - **Distributed selection**: Multiple occurrences = random selection
//! - **Multi-carrier**: Text, PNG/BMP images, WAV audio all supported
//!
//! ## Example Usage
//!
//! ```rust
//! use anyhide::crypto::KeyPair;
//! use anyhide::{encode, decode};
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
//! - [`text`]: Text/carrier processing (fragmentation, substring search, padding)
//! - [`encoder`]: Message encoding with fragments and padding
//! - [`decoder`]: Message decoding (never fails)
//! - [`qr`]: QR code generation and reading

/// Protocol version
pub const VERSION: u8 = 6;

/// Block size for padding (in characters)
pub const BLOCK_SIZE: usize = 256;

/// Minimum message size before padding (in characters)
pub const MIN_SIZE: usize = 64;

pub mod crypto;
pub mod decoder;
pub mod encoder;
pub mod qr;
pub mod text;

// Re-export commonly used types at the crate root
pub use crypto::{KeyPair, SigningKeyPair};
pub use decoder::{
    decode, decode_bytes_with_carrier, decode_bytes_with_carrier_config, decode_with_carrier,
    decode_with_carrier_config, decode_with_config, DecodedBytes, DecodedMessage, DecoderConfig,
};
pub use encoder::{
    encode, encode_bytes_with_carrier, encode_bytes_with_carrier_config, encode_with_carrier,
    encode_with_carrier_config, encode_with_config, EncodedData, EncodedMessage, EncoderConfig,
    EncoderError,
};
pub use qr::{decode_base45, encode_base45, generate_qr, read_qr, QrError, QrFormat};
pub use text::carrier::{fragment_bytes_for_carrier, BinaryCarrierSearch, BinaryFragment, Carrier};
pub use text::fragment::FoundFragment;
