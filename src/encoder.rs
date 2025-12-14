//! Message encoding for KAMO v0.4.1 steganography.
//!
//! This module orchestrates the encoding process:
//! 1. Fragment message into variable-sized pieces (passphrase-based)
//! 2. Find each fragment as substring in carrier (case-insensitive)
//! 3. Select positions randomly from all occurrences (distributed)
//! 4. Pad with random carrier substrings to block boundary
//! 5. Serialize with version and real_count
//! 6. Encrypt (symmetric + asymmetric)
//! 7. Return base64 code

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hkdf::Hkdf;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::PublicKey;

use crate::crypto::{encrypt_with_passphrase, EncryptionError};
use crate::text::fragment::{fragment_message_adaptive, FoundFragment};
use crate::text::tokenize::{select_distributed_position, CarrierSearch};
use crate::{BLOCK_SIZE, MIN_SIZE, VERSION};

/// HKDF salt for padding generation.
const SALT_PAD: &[u8] = b"KAMO-PAD-V5";

/// Errors that can occur during encoding.
#[derive(Error, Debug)]
pub enum EncoderError {
    #[error("Fragment '{0}' not found in carrier")]
    FragmentNotFound(String),

    #[error("Encryption error: {0}")]
    EncryptionError(#[from] EncryptionError),

    #[error("Empty message")]
    EmptyMessage,

    #[error("Empty carrier")]
    EmptyCarrier,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Data structure that gets encrypted and transmitted (v0.4.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodedData {
    /// Protocol version.
    pub version: u8,
    /// Number of real fragments in the message (before padding).
    pub real_count: u16,
    /// Found fragments with positions and space metadata.
    pub fragments: Vec<FoundFragment>,
}

/// Result of encoding a message.
#[derive(Debug, Clone)]
pub struct EncodedMessage {
    /// The encrypted code (base64) - this is what gets transmitted.
    pub code: String,
    /// Number of real fragments encoded (for debugging/info).
    pub real_fragment_count: usize,
    /// Total fragments including padding (for debugging).
    pub total_fragments: usize,
}

/// Configuration for the encoder.
#[derive(Debug, Clone)]
pub struct EncoderConfig {
    /// Whether to output verbose information.
    pub verbose: bool,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self { verbose: false }
    }
}

/// Encodes a message using v0.4.1 protocol.
///
/// # Arguments
/// * `carrier` - The pre-shared text (both parties must have this)
/// * `message` - The secret message to encode
/// * `passphrase` - Used for fragmentation, position selection, and encryption
/// * `public_key` - Recipient's public key for asymmetric encryption
///
/// # Returns
/// An `EncodedMessage` containing the encrypted code to transmit.
pub fn encode(
    carrier: &str,
    message: &str,
    passphrase: &str,
    public_key: &PublicKey,
) -> Result<EncodedMessage, EncoderError> {
    encode_with_config(carrier, message, passphrase, public_key, &EncoderConfig::default())
}

/// Encodes a message with custom configuration.
pub fn encode_with_config(
    carrier: &str,
    message: &str,
    passphrase: &str,
    public_key: &PublicKey,
    config: &EncoderConfig,
) -> Result<EncodedMessage, EncoderError> {
    // Validate inputs
    let message = message.trim();
    if message.is_empty() {
        return Err(EncoderError::EmptyMessage);
    }

    let carrier = carrier.trim();
    if carrier.is_empty() {
        return Err(EncoderError::EmptyCarrier);
    }

    // Step 1: Create carrier search helper
    let carrier_search = CarrierSearch::new(carrier);

    if carrier_search.is_empty() {
        return Err(EncoderError::EmptyCarrier);
    }

    if config.verbose {
        eprintln!("Carrier has {} characters", carrier_search.len());
    }

    // Step 2: Fragment the message ADAPTIVELY (based on what's in the carrier)
    let fragmented = fragment_message_adaptive(message, &carrier_search, passphrase);
    let real_count = fragmented.count();

    if config.verbose {
        eprintln!(
            "Fragmented into {} pieces: {:?}",
            real_count,
            fragmented.search_texts()
        );
    }

    // Step 3: Find each fragment in the carrier with distributed selection
    // Since we used adaptive fragmentation, all fragments MUST exist
    let mut found_fragments: Vec<FoundFragment> = Vec::with_capacity(real_count);

    for (i, fragment) in fragmented.fragments.iter().enumerate() {
        // Find all occurrences of this fragment
        let positions = carrier_search.find_all(&fragment.search_text);

        if positions.is_empty() {
            // This should not happen with adaptive fragmentation,
            // but handle gracefully by falling back to single chars
            return Err(EncoderError::FragmentNotFound(fragment.search_text.clone()));
        }

        // Select one position randomly based on passphrase + index
        let selected_pos = select_distributed_position(&positions, passphrase, i)
            .expect("positions is not empty");

        if config.verbose {
            eprintln!(
                "Fragment {}: '{}' found at {} positions, selected {}",
                i,
                fragment.search_text,
                positions.len(),
                selected_pos
            );
        }

        found_fragments.push(FoundFragment::new(
            selected_pos,
            fragment.search_text.chars().count(),
            fragment.space_positions.clone(),
        ));
    }

    // Step 4: Pad with random carrier substrings
    let current_size = message.len();
    let target_size = calculate_padded_length(current_size);

    if config.verbose {
        eprintln!(
            "Message size: {} chars, target: {} chars",
            current_size, target_size
        );
    }

    // Generate padding fragments from carrier
    let padding_fragments = generate_padding_fragments(
        &carrier_search,
        passphrase,
        target_size.saturating_sub(current_size),
    );

    if config.verbose {
        eprintln!("Added {} padding fragments", padding_fragments.len());
    }

    // Combine real and padding fragments
    let mut all_fragments = found_fragments;
    all_fragments.extend(padding_fragments);

    // Step 5: Create encoded data
    let data = EncodedData {
        version: VERSION,
        real_count: real_count as u16,
        fragments: all_fragments.clone(),
    };

    // Step 6: Serialize
    let serialized = bincode::serialize(&data)
        .map_err(|e| EncoderError::SerializationError(e.to_string()))?;

    if config.verbose {
        eprintln!("Serialized to {} bytes", serialized.len());
    }

    // Step 7: Encrypt (symmetric with passphrase, then asymmetric with public key)
    let encrypted = encrypt_with_passphrase(&serialized, passphrase, public_key)?;

    // Step 8: Encode to base64
    let code = BASE64.encode(&encrypted);

    Ok(EncodedMessage {
        code,
        real_fragment_count: real_count,
        total_fragments: all_fragments.len(),
    })
}

/// Calculates the padded length based on block size.
fn calculate_padded_length(message_len: usize) -> usize {
    let effective = message_len.max(MIN_SIZE);
    ((effective - 1) / BLOCK_SIZE + 1) * BLOCK_SIZE
}

/// Generates padding fragments by extracting random substrings from the carrier.
fn generate_padding_fragments(
    carrier: &CarrierSearch,
    passphrase: &str,
    approx_chars_needed: usize,
) -> Vec<FoundFragment> {
    if approx_chars_needed == 0 || carrier.is_empty() {
        return vec![];
    }

    // Derive seed for deterministic padding
    let hk = Hkdf::<Sha256>::new(Some(SALT_PAD), passphrase.as_bytes());
    let mut seed = [0u8; 32];
    hk.expand(b"padding-seed", &mut seed)
        .expect("HKDF expand should not fail");

    let mut rng = ChaCha20Rng::from_seed(seed);
    let carrier_len = carrier.len();

    let mut fragments = Vec::new();
    let mut chars_added = 0;

    while chars_added < approx_chars_needed {
        // Random position in carrier
        let pos = rng.gen_range(0..carrier_len);

        // Random length between 1 and 5
        let len = rng.gen_range(1..=5).min(carrier_len - pos);

        if len > 0 {
            fragments.push(FoundFragment::new(pos, len, vec![]));
            chars_added += len;
        }
    }

    fragments
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn test_encode_simple() {
        let carrier = "Amanda fue al parque con su hermano ayer";
        let message = "ama parque";
        let passphrase = "test123";

        let keypair = KeyPair::generate();
        let result = encode(carrier, message, passphrase, keypair.public_key());

        assert!(result.is_ok());
        let encoded = result.unwrap();
        assert!(!encoded.code.is_empty());
        // "ama parque" fragments depend on passphrase, but there will be multiple
        assert!(encoded.real_fragment_count >= 1);
    }

    #[test]
    fn test_encode_fragment_not_found() {
        let carrier = "Hola mundo";
        let message = "xyz";
        let passphrase = "test";

        let keypair = KeyPair::generate();
        let result = encode(carrier, message, passphrase, keypair.public_key());

        assert!(result.is_err());
    }

    #[test]
    fn test_encode_empty_message() {
        let carrier = "Some carrier text";
        let message = "";
        let passphrase = "test";

        let keypair = KeyPair::generate();
        let result = encode(carrier, message, passphrase, keypair.public_key());

        assert!(matches!(result, Err(EncoderError::EmptyMessage)));
    }

    #[test]
    fn test_encode_empty_carrier() {
        let carrier = "";
        let message = "Hello";
        let passphrase = "test";

        let keypair = KeyPair::generate();
        let result = encode(carrier, message, passphrase, keypair.public_key());

        assert!(matches!(result, Err(EncoderError::EmptyCarrier)));
    }

    #[test]
    fn test_encode_case_insensitive() {
        let carrier = "AMANDA FUE AL PARQUE";
        let message = "ama parque"; // lowercase
        let passphrase = "test";

        let keypair = KeyPair::generate();
        let result = encode(carrier, message, passphrase, keypair.public_key());

        assert!(result.is_ok());
    }

    #[test]
    fn test_encode_with_padding() {
        let carrier = "La casa grande tiene un jardín hermoso con flores rojas y azules";
        let passphrase = "test";

        let keypair = KeyPair::generate();

        // Short message should get padded
        let result = encode(carrier, "casa", passphrase, keypair.public_key());
        assert!(result.is_ok());
        let encoded = result.unwrap();

        // Should have padding fragments
        assert!(encoded.total_fragments > encoded.real_fragment_count);
    }

    #[test]
    fn test_encode_substring_matching() {
        // "anda" is a substring of "Amanda"
        let carrier = "Amanda camina por el parque";
        let message = "anda";
        let passphrase = "test";

        let keypair = KeyPair::generate();
        let result = encode(carrier, message, passphrase, keypair.public_key());

        assert!(result.is_ok());
    }

    #[test]
    fn test_version_in_encoded_data() {
        let carrier = "hola mundo test";
        let message = "hola";
        let passphrase = "test";

        let keypair = KeyPair::generate();
        let result = encode(carrier, message, passphrase, keypair.public_key());

        assert!(result.is_ok());
    }
}
