//! Message encoding for Anyhide steganography.
//!
//! This module orchestrates the encoding process:
//! 1. Fragment message into variable-sized pieces (passphrase-based)
//! 2. Find each fragment as substring in carrier (case-insensitive for text, byte-sequence for binary)
//! 3. Select positions randomly from all occurrences (distributed)
//! 4. Pad with random carrier substrings to block boundary
//! 5. Serialize with version and real_count
//! 6. Encrypt (symmetric + asymmetric)
//! 7. Return base64 code
//!
//! Supports both text carriers (text files, articles) and binary carriers (images, audio).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::PublicKey;

use crate::crypto::{encrypt_with_passphrase, sign_message, EncryptionError, KeyPair};
use crate::text::carrier::{fragment_bytes_for_carrier, fragment_message_for_binary, BinaryCarrierSearch, Carrier};
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

    #[error("Character '{0}' not found in carrier (neither uppercase nor lowercase)")]
    CharacterNotInCarrier(char),

    #[error("Carrier coverage too low: {0:.1}% (minimum required: {1:.1}%). {2} of {3} characters missing. Consider using a different carrier or lowering --min-coverage")]
    InsufficientCoverage(f64, f64, usize, usize),

    #[error("Encryption error: {0}")]
    EncryptionError(#[from] EncryptionError),

    #[error("Empty message")]
    EmptyMessage,

    #[error("Empty carrier")]
    EmptyCarrier,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Data structure that gets encrypted and transmitted (v0.4.1+).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodedData {
    /// Protocol version.
    pub version: u8,
    /// Number of real fragments in the message (before padding).
    pub real_count: u16,
    /// Found fragments with positions and space metadata.
    pub fragments: Vec<FoundFragment>,
    /// Ed25519 signature over the hash of the EXACT original message (64 bytes).
    /// Present only if the message was signed with --sign.
    /// The signature is always case-sensitive because char_overrides guarantee
    /// exact message recovery.
    #[serde(default)]
    pub signature: Option<Vec<u8>>,
    /// Unix timestamp when the message expires.
    /// If set and current time > expires_at, decoder returns garbage (plausible deniability).
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Next public key for forward secrecy ratchet.
    /// If present, the recipient should use this key for their reply.
    /// Only included when the sender is using ephemeral keys.
    #[serde(default)]
    pub next_public_key: Option<Vec<u8>>,
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
    /// New ephemeral keypair for forward secrecy ratchet.
    /// Present only when `ratchet: true` was set in EncoderConfig.
    /// The sender should save this keypair for the next message exchange.
    pub next_keypair: Option<KeyPair>,
}

/// Configuration for the encoder.
#[derive(Debug, Clone)]
pub struct EncoderConfig<'a> {
    /// Whether to output verbose information.
    pub verbose: bool,
    /// Optional signing key for message authentication.
    /// If provided, the message will be signed with Ed25519.
    pub signing_key: Option<&'a SigningKey>,
    /// Minimum carrier coverage required (0.0 to 1.0).
    /// 1.0 (default) = 100% of message characters must exist exactly in carrier.
    /// Lower values allow char_overrides but leak information about the message.
    pub min_coverage: f64,
    /// Optional expiration timestamp (Unix seconds).
    /// If set, the message will be unreadable after this time.
    pub expires_at: Option<u64>,
    /// Enable forward secrecy ratchet.
    /// When true, a new ephemeral keypair is generated for each message.
    /// The next_public_key is included in the encrypted data for the recipient to use
    /// in their reply, and next_keypair is returned for the sender to save.
    pub ratchet: bool,
}

impl Default for EncoderConfig<'_> {
    fn default() -> Self {
        Self {
            verbose: false,
            signing_key: None,
            min_coverage: 1.0, // 100% by default - maximum security
            expires_at: None,
            ratchet: false,
        }
    }
}

/// Calculates character overrides between extracted text and original text.
///
/// Returns a list of (position, original_char) for any characters that differ.
/// This allows the decoder to reconstruct the exact original message even when
/// the carrier has different case or characters.
fn calculate_char_overrides(extracted: &str, original: &str) -> Vec<(usize, char)> {
    let extracted_chars: Vec<char> = extracted.chars().collect();
    let original_chars: Vec<char> = original.chars().collect();
    let mut overrides = Vec::new();

    for (i, original_char) in original_chars.iter().enumerate() {
        if i < extracted_chars.len() {
            if extracted_chars[i] != *original_char {
                overrides.push((i, *original_char));
            }
        } else {
            // Original is longer - this shouldn't normally happen but handle it
            overrides.push((i, *original_char));
        }
    }

    overrides
}

/// Result of carrier coverage analysis.
#[derive(Debug)]
pub struct CoverageResult {
    /// Percentage of characters found exactly (0.0 to 1.0).
    pub coverage: f64,
    /// Total characters analyzed (non-space).
    pub total_chars: usize,
    /// Characters found exactly in carrier.
    pub found_exact: usize,
    /// Characters missing from carrier.
    pub missing_chars: Vec<char>,
}

/// Calculates what percentage of message characters exist exactly in the carrier.
///
/// This checks if each character in the message can be found exactly (same case)
/// somewhere in the carrier. Spaces are ignored.
///
/// Returns coverage as 0.0 to 1.0 (1.0 = 100% coverage, all chars found exactly).
fn calculate_carrier_coverage(message: &str, carrier: &CarrierSearch) -> CoverageResult {
    // Build a set of all characters in the carrier
    let carrier_chars: std::collections::HashSet<char> = carrier.original.chars().collect();

    let mut total_chars = 0;
    let mut found_exact = 0;
    let mut missing_chars = Vec::new();
    let mut seen_missing: std::collections::HashSet<char> = std::collections::HashSet::new();

    for ch in message.chars() {
        // Skip spaces - they're handled separately
        if ch.is_whitespace() {
            continue;
        }

        total_chars += 1;

        if carrier_chars.contains(&ch) {
            found_exact += 1;
        } else if !seen_missing.contains(&ch) {
            missing_chars.push(ch);
            seen_missing.insert(ch);
        }
    }

    let coverage = if total_chars > 0 {
        found_exact as f64 / total_chars as f64
    } else {
        1.0
    };

    CoverageResult {
        coverage,
        total_chars,
        found_exact,
        missing_chars,
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
    config: &EncoderConfig<'_>,
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

    // Step 2: Validate carrier coverage (security check)
    let coverage = calculate_carrier_coverage(message, &carrier_search);

    if config.verbose {
        eprintln!(
            "Carrier coverage: {:.1}% ({}/{} characters found exactly)",
            coverage.coverage * 100.0,
            coverage.found_exact,
            coverage.total_chars
        );
        if !coverage.missing_chars.is_empty() {
            eprintln!("Missing characters: {:?}", coverage.missing_chars);
        }
    }

    if coverage.coverage < config.min_coverage {
        return Err(EncoderError::InsufficientCoverage(
            coverage.coverage * 100.0,
            config.min_coverage * 100.0,
            coverage.total_chars - coverage.found_exact,
            coverage.total_chars,
        ));
    }

    // Step 3: Fragment the message ADAPTIVELY (based on what's in the carrier)
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
    let mut found_fragments: Vec<FoundFragment> = Vec::with_capacity(real_count);

    for (i, fragment) in fragmented.fragments.iter().enumerate() {
        // Find all occurrences of this fragment
        let positions = carrier_search.find_all(&fragment.search_text);

        if positions.is_empty() {
            // Fragment not found in carrier
            if config.min_coverage >= 1.0 {
                // With 100% coverage requirement, this is an error
                return Err(EncoderError::FragmentNotFound(fragment.search_text.clone()));
            }

            // With reduced coverage, create a "synthetic" fragment:
            // - Use position 0 as dummy position
            // - Store the ENTIRE original fragment in char_overrides
            // This allows the decoder to reconstruct the fragment from overrides alone
            let char_overrides: Vec<(usize, char)> = fragment
                .original_text
                .chars()
                .enumerate()
                .collect();

            if config.verbose {
                eprintln!(
                    "Fragment {}: '{}' NOT FOUND - using synthetic fragment with {} char_overrides",
                    i,
                    fragment.original_text,
                    char_overrides.len()
                );
            }

            found_fragments.push(FoundFragment::with_overrides(
                0, // dummy position
                fragment.search_text.chars().count(),
                fragment.space_positions.clone(),
                char_overrides,
            ));
            continue;
        }

        // Select one position randomly based on passphrase + index
        let selected_pos = select_distributed_position(&positions, passphrase, i)
            .expect("positions is not empty");

        // Extract from carrier and calculate char_overrides
        let extracted = carrier_search.extract_wrapped(selected_pos, fragment.search_text.len());
        let char_overrides = calculate_char_overrides(&extracted, &fragment.original_text);

        if config.verbose {
            eprintln!(
                "Fragment {}: '{}' (original: '{}') found at {} positions, selected {}",
                i,
                fragment.search_text,
                fragment.original_text,
                positions.len(),
                selected_pos
            );
            if !char_overrides.is_empty() {
                eprintln!("  -> char_overrides: {:?}", char_overrides);
            }
        }

        found_fragments.push(FoundFragment::with_overrides(
            selected_pos,
            fragment.search_text.chars().count(),
            fragment.space_positions.clone(),
            char_overrides,
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

    // Step 5: Optionally sign the message
    // Note: We always sign the EXACT message because char_overrides guarantees
    // exact recovery. This is the most secure approach.
    let signature = if let Some(signing_key) = config.signing_key {
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let message_hash = hasher.finalize();
        let sig = sign_message(&message_hash, signing_key);
        if config.verbose {
            eprintln!("Message signed with Ed25519 ({} bytes)", message.len());
        }
        Some(sig)
    } else {
        None
    };

    // Step 6: Generate next ephemeral keypair if ratchet is enabled
    let (next_public_key, next_keypair) = if config.ratchet {
        let new_keypair = KeyPair::generate_ephemeral();
        let public_bytes = new_keypair.public_key().as_bytes().to_vec();
        if config.verbose {
            eprintln!("Generated next ephemeral key for forward secrecy ratchet");
        }
        (Some(public_bytes), Some(new_keypair))
    } else {
        (None, None)
    };

    // Step 7: Create encoded data
    let data = EncodedData {
        version: VERSION,
        real_count: real_count as u16,
        fragments: all_fragments.clone(),
        signature,
        expires_at: config.expires_at,
        next_public_key,
    };

    // Step 8: Serialize
    let serialized = bincode::serialize(&data)
        .map_err(|e| EncoderError::SerializationError(e.to_string()))?;

    if config.verbose {
        eprintln!("Serialized to {} bytes", serialized.len());
    }

    // Step 9: Encrypt (symmetric with passphrase, then asymmetric with public key)
    let encrypted = encrypt_with_passphrase(&serialized, passphrase, public_key)?;

    // Step 10: Encode to base64
    let code = BASE64.encode(&encrypted);

    Ok(EncodedMessage {
        code,
        real_fragment_count: real_count,
        total_fragments: all_fragments.len(),
        next_keypair,
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

// ============================================================================
// Generic Carrier Support (Text + Binary)
// ============================================================================

/// Encodes a message using a generic carrier (text or binary).
///
/// This is the main entry point for encoding with any carrier type.
/// Auto-detects whether to use text or binary encoding based on the carrier.
///
/// # Arguments
/// * `carrier` - A generic carrier (text or binary)
/// * `message` - The secret message to encode
/// * `passphrase` - Used for fragmentation, position selection, and encryption
/// * `public_key` - Recipient's public key for asymmetric encryption
pub fn encode_with_carrier(
    carrier: &Carrier,
    message: &str,
    passphrase: &str,
    public_key: &PublicKey,
) -> Result<EncodedMessage, EncoderError> {
    encode_with_carrier_config(carrier, message, passphrase, public_key, &EncoderConfig::default())
}

/// Encodes a message with a generic carrier and custom configuration.
pub fn encode_with_carrier_config(
    carrier: &Carrier,
    message: &str,
    passphrase: &str,
    public_key: &PublicKey,
    config: &EncoderConfig<'_>,
) -> Result<EncodedMessage, EncoderError> {
    match carrier {
        Carrier::Text(text_carrier) => {
            encode_text_carrier(text_carrier, message, passphrase, public_key, config)
        }
        Carrier::Binary(binary_carrier) => {
            encode_binary_carrier(binary_carrier, message, passphrase, public_key, config)
        }
    }
}

/// Encodes using a text carrier (internal, reuses existing logic).
fn encode_text_carrier(
    carrier: &CarrierSearch,
    message: &str,
    passphrase: &str,
    public_key: &PublicKey,
    config: &EncoderConfig<'_>,
) -> Result<EncodedMessage, EncoderError> {
    // Validate inputs
    let message = message.trim();
    if message.is_empty() {
        return Err(EncoderError::EmptyMessage);
    }

    if carrier.is_empty() {
        return Err(EncoderError::EmptyCarrier);
    }

    if config.verbose {
        eprintln!("Text carrier has {} characters", carrier.len());
    }

    // Validate carrier coverage (security check)
    let coverage = calculate_carrier_coverage(message, carrier);

    if config.verbose {
        eprintln!(
            "Carrier coverage: {:.1}% ({}/{} characters found exactly)",
            coverage.coverage * 100.0,
            coverage.found_exact,
            coverage.total_chars
        );
        if !coverage.missing_chars.is_empty() {
            eprintln!("Missing characters: {:?}", coverage.missing_chars);
        }
    }

    if coverage.coverage < config.min_coverage {
        return Err(EncoderError::InsufficientCoverage(
            coverage.coverage * 100.0,
            config.min_coverage * 100.0,
            coverage.total_chars - coverage.found_exact,
            coverage.total_chars,
        ));
    }

    // Fragment the message adaptively
    let fragmented = fragment_message_adaptive(message, carrier, passphrase);
    let real_count = fragmented.count();

    if config.verbose {
        eprintln!(
            "Fragmented into {} pieces: {:?}",
            real_count,
            fragmented.search_texts()
        );
    }

    // Find each fragment in the carrier with distributed selection
    let mut found_fragments: Vec<FoundFragment> = Vec::with_capacity(real_count);

    for (i, fragment) in fragmented.fragments.iter().enumerate() {
        let positions = carrier.find_all(&fragment.search_text);

        if positions.is_empty() {
            // Fragment not found in carrier
            if config.min_coverage >= 1.0 {
                // With 100% coverage requirement, this is an error
                return Err(EncoderError::FragmentNotFound(fragment.search_text.clone()));
            }

            // With reduced coverage, create a "synthetic" fragment
            let char_overrides: Vec<(usize, char)> = fragment
                .original_text
                .chars()
                .enumerate()
                .collect();

            if config.verbose {
                eprintln!(
                    "Fragment {}: '{}' NOT FOUND - using synthetic fragment with {} char_overrides",
                    i,
                    fragment.original_text,
                    char_overrides.len()
                );
            }

            found_fragments.push(FoundFragment::with_overrides(
                0, // dummy position
                fragment.search_text.chars().count(),
                fragment.space_positions.clone(),
                char_overrides,
            ));
            continue;
        }

        let selected_pos = select_distributed_position(&positions, passphrase, i)
            .expect("positions is not empty");

        // Extract from carrier and calculate char_overrides
        let extracted = carrier.extract_wrapped(selected_pos, fragment.search_text.len());
        let char_overrides = calculate_char_overrides(&extracted, &fragment.original_text);

        if config.verbose {
            eprintln!(
                "Fragment {}: '{}' (original: '{}') found at {} positions, selected {}",
                i, fragment.search_text, fragment.original_text, positions.len(), selected_pos
            );
            if !char_overrides.is_empty() {
                eprintln!("  -> char_overrides: {:?}", char_overrides);
            }
        }

        found_fragments.push(FoundFragment::with_overrides(
            selected_pos,
            fragment.search_text.chars().count(),
            fragment.space_positions.clone(),
            char_overrides,
        ));
    }

    // Pad with random carrier substrings
    let current_size = message.len();
    let target_size = calculate_padded_length(current_size);
    let padding_fragments = generate_padding_fragments(
        carrier,
        passphrase,
        target_size.saturating_sub(current_size),
    );

    if config.verbose {
        eprintln!("Added {} padding fragments", padding_fragments.len());
    }

    // Combine and encrypt
    let mut all_fragments = found_fragments;
    all_fragments.extend(padding_fragments);

    // Optionally sign the message (always exact/case-sensitive with char_overrides)
    let signature = if let Some(signing_key) = config.signing_key {
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let message_hash = hasher.finalize();
        let sig = sign_message(&message_hash, signing_key);
        if config.verbose {
            eprintln!("Message signed with Ed25519 ({} bytes)", message.len());
        }
        Some(sig)
    } else {
        None
    };

    // Generate next ephemeral keypair if ratchet is enabled
    let (next_public_key, next_keypair) = if config.ratchet {
        let new_keypair = KeyPair::generate_ephemeral();
        let public_bytes = new_keypair.public_key().as_bytes().to_vec();
        if config.verbose {
            eprintln!("Generated next ephemeral key for forward secrecy ratchet");
        }
        (Some(public_bytes), Some(new_keypair))
    } else {
        (None, None)
    };

    let data = EncodedData {
        version: VERSION,
        real_count: real_count as u16,
        fragments: all_fragments.clone(),
        signature,
        expires_at: config.expires_at,
        next_public_key,
    };

    let serialized = bincode::serialize(&data)
        .map_err(|e| EncoderError::SerializationError(e.to_string()))?;

    let encrypted = encrypt_with_passphrase(&serialized, passphrase, public_key)?;
    let code = BASE64.encode(&encrypted);

    Ok(EncodedMessage {
        code,
        real_fragment_count: real_count,
        total_fragments: all_fragments.len(),
        next_keypair,
    })
}

/// Encodes using a binary carrier (images, audio, etc.).
///
/// For binary carriers, the message is converted to bytes and searched
/// as byte sequences within the carrier data.
fn encode_binary_carrier(
    carrier: &BinaryCarrierSearch,
    message: &str,
    passphrase: &str,
    public_key: &PublicKey,
    config: &EncoderConfig<'_>,
) -> Result<EncodedMessage, EncoderError> {
    // Validate inputs
    let message = message.trim();
    if message.is_empty() {
        return Err(EncoderError::EmptyMessage);
    }

    if carrier.is_empty() {
        return Err(EncoderError::EmptyCarrier);
    }

    if config.verbose {
        eprintln!("Binary carrier has {} bytes", carrier.len());
    }

    // Fragment the message for binary search
    let fragments = fragment_message_for_binary(message, carrier, passphrase);

    if fragments.is_empty() && !message.is_empty() {
        // Fragmentation failed - some bytes not found in carrier
        return Err(EncoderError::FragmentNotFound(
            "Message bytes not found in binary carrier".to_string()
        ));
    }

    let real_count = fragments.len();

    if config.verbose {
        eprintln!("Fragmented into {} byte sequences", real_count);
    }

    // Find positions for each fragment
    let mut found_fragments: Vec<FoundFragment> = Vec::with_capacity(real_count);

    for (i, fragment) in fragments.iter().enumerate() {
        let positions = carrier.find_all(&fragment.bytes);

        if positions.is_empty() {
            return Err(EncoderError::FragmentNotFound(
                format!("Byte sequence {:?} not found", fragment.bytes)
            ));
        }

        // Select one position randomly based on passphrase + index
        let selected_pos = select_distributed_position(&positions, passphrase, i)
            .expect("positions is not empty");

        if config.verbose {
            eprintln!(
                "Fragment {}: {:?} found at {} positions, selected {}",
                i, fragment.bytes, positions.len(), selected_pos
            );
        }

        // For binary, space_positions indicates word boundaries
        let space_positions = if fragment.ends_word { vec![0] } else { vec![] };

        found_fragments.push(FoundFragment::new(
            selected_pos,
            fragment.bytes.len(),
            space_positions,
        ));
    }

    // Pad with random carrier bytes
    let current_size = message.len();
    let target_size = calculate_padded_length(current_size);
    let padding_fragments = generate_padding_fragments_binary(
        carrier,
        passphrase,
        target_size.saturating_sub(current_size),
    );

    if config.verbose {
        eprintln!("Added {} padding fragments", padding_fragments.len());
    }

    // Combine and encrypt
    let mut all_fragments = found_fragments;
    all_fragments.extend(padding_fragments);

    // Optionally sign the message (always exact/case-sensitive with char_overrides)
    let signature = if let Some(signing_key) = config.signing_key {
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let message_hash = hasher.finalize();
        let sig = sign_message(&message_hash, signing_key);
        if config.verbose {
            eprintln!("Message signed with Ed25519 ({} bytes)", message.len());
        }
        Some(sig)
    } else {
        None
    };

    // Generate next ephemeral keypair if ratchet is enabled
    let (next_public_key, next_keypair) = if config.ratchet {
        let new_keypair = KeyPair::generate_ephemeral();
        let public_bytes = new_keypair.public_key().as_bytes().to_vec();
        if config.verbose {
            eprintln!("Generated next ephemeral key for forward secrecy ratchet");
        }
        (Some(public_bytes), Some(new_keypair))
    } else {
        (None, None)
    };

    let data = EncodedData {
        version: VERSION,
        real_count: real_count as u16,
        fragments: all_fragments.clone(),
        signature,
        expires_at: config.expires_at,
        next_public_key,
    };

    let serialized = bincode::serialize(&data)
        .map_err(|e| EncoderError::SerializationError(e.to_string()))?;

    let encrypted = encrypt_with_passphrase(&serialized, passphrase, public_key)?;
    let code = BASE64.encode(&encrypted);

    Ok(EncodedMessage {
        code,
        real_fragment_count: real_count,
        total_fragments: all_fragments.len(),
        next_keypair,
    })
}

/// Generates padding fragments for binary carriers.
fn generate_padding_fragments_binary(
    carrier: &BinaryCarrierSearch,
    passphrase: &str,
    approx_bytes_needed: usize,
) -> Vec<FoundFragment> {
    if approx_bytes_needed == 0 || carrier.is_empty() {
        return vec![];
    }

    // Derive seed for deterministic padding
    let hk = Hkdf::<Sha256>::new(Some(SALT_PAD), passphrase.as_bytes());
    let mut seed = [0u8; 32];
    hk.expand(b"padding-seed-binary", &mut seed)
        .expect("HKDF expand should not fail");

    let mut rng = ChaCha20Rng::from_seed(seed);
    let carrier_len = carrier.len();

    let mut fragments = Vec::new();
    let mut bytes_added = 0;

    while bytes_added < approx_bytes_needed {
        // Random position in carrier
        let pos = rng.gen_range(0..carrier_len);

        // Random length between 1 and 5
        let len = rng.gen_range(1..=5).min(carrier_len - pos);

        if len > 0 {
            fragments.push(FoundFragment::new(pos, len, vec![]));
            bytes_added += len;
        }
    }

    fragments
}

// ============================================================================
// Binary Message Support (for encoding arbitrary bytes, not just text)
// ============================================================================

/// Encodes arbitrary binary data using a carrier.
///
/// This function allows hiding any binary data (files, images, etc.) within a carrier.
/// The Anyhide code produced is indistinguishable from text message encoding.
///
/// # Arguments
/// * `carrier` - A generic carrier (must be binary for best results with binary data)
/// * `data` - The binary data to encode
/// * `passphrase` - Used for fragmentation, position selection, and encryption
/// * `public_key` - Recipient's public key for asymmetric encryption
///
/// # Example
/// ```ignore
/// let carrier = Carrier::from_file(Path::new("video.mp4"))?;
/// let secret_file = std::fs::read("secret.zip")?;
/// let encoded = encode_bytes_with_carrier(&carrier, &secret_file, "pass", &pub_key)?;
/// // encoded.code is the Anyhide code - no indication it contains binary data
/// ```
pub fn encode_bytes_with_carrier(
    carrier: &Carrier,
    data: &[u8],
    passphrase: &str,
    public_key: &PublicKey,
) -> Result<EncodedMessage, EncoderError> {
    encode_bytes_with_carrier_config(carrier, data, passphrase, public_key, &EncoderConfig::default())
}

/// Encodes binary data with custom configuration.
pub fn encode_bytes_with_carrier_config(
    carrier: &Carrier,
    data: &[u8],
    passphrase: &str,
    public_key: &PublicKey,
    config: &EncoderConfig<'_>,
) -> Result<EncodedMessage, EncoderError> {
    // Validate inputs
    if data.is_empty() {
        return Err(EncoderError::EmptyMessage);
    }

    if carrier.is_empty() {
        return Err(EncoderError::EmptyCarrier);
    }

    // For binary data, we need a binary carrier for byte-level searching
    match carrier {
        Carrier::Binary(binary_carrier) => {
            encode_bytes_binary_carrier(binary_carrier, data, passphrase, public_key, config)
        }
        Carrier::Text(text_carrier) => {
            // Convert text carrier to binary for byte-level operations
            // This allows using text files as carriers for binary messages too
            let text_bytes = text_carrier.original.as_bytes().to_vec();
            let binary_carrier = BinaryCarrierSearch::new(text_bytes);
            encode_bytes_binary_carrier(&binary_carrier, data, passphrase, public_key, config)
        }
    }
}

/// Internal: encodes binary data using a binary carrier.
fn encode_bytes_binary_carrier(
    carrier: &BinaryCarrierSearch,
    data: &[u8],
    passphrase: &str,
    public_key: &PublicKey,
    config: &EncoderConfig<'_>,
) -> Result<EncodedMessage, EncoderError> {
    if config.verbose {
        eprintln!("Binary carrier has {} bytes", carrier.len());
        eprintln!("Message has {} bytes", data.len());
    }

    // Fragment the binary data
    let fragments = fragment_bytes_for_carrier(data, carrier, passphrase);

    if fragments.is_empty() && !data.is_empty() {
        return Err(EncoderError::FragmentNotFound(
            "Message bytes not found in binary carrier".to_string(),
        ));
    }

    let real_count = fragments.len();

    if config.verbose {
        eprintln!("Fragmented into {} byte sequences", real_count);
    }

    // Find positions for each fragment
    let mut found_fragments: Vec<FoundFragment> = Vec::with_capacity(real_count);

    for (i, fragment) in fragments.iter().enumerate() {
        let positions = carrier.find_all(&fragment.bytes);

        if positions.is_empty() {
            return Err(EncoderError::FragmentNotFound(format!(
                "Byte sequence not found in carrier (fragment {})",
                i
            )));
        }

        let selected_pos =
            select_distributed_position(&positions, passphrase, i).expect("positions is not empty");

        if config.verbose {
            eprintln!(
                "Fragment {}: {} bytes found at {} positions, selected {}",
                i,
                fragment.bytes.len(),
                positions.len(),
                selected_pos
            );
        }

        // For binary data, ends_word is always false (no word boundaries)
        found_fragments.push(FoundFragment::new(
            selected_pos,
            fragment.bytes.len(),
            vec![], // No space positions for binary
        ));
    }

    // Pad with random carrier bytes
    let current_size = data.len();
    let target_size = calculate_padded_length(current_size);
    let padding_fragments =
        generate_padding_fragments_binary(carrier, passphrase, target_size.saturating_sub(current_size));

    if config.verbose {
        eprintln!("Added {} padding fragments", padding_fragments.len());
    }

    // Combine and encrypt
    let mut all_fragments = found_fragments;
    all_fragments.extend(padding_fragments);

    // Optionally sign the data (binary data is always exact)
    let signature = if let Some(signing_key) = config.signing_key {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let data_hash = hasher.finalize();
        let sig = sign_message(&data_hash, signing_key);
        if config.verbose {
            eprintln!("Data signed with Ed25519 ({} bytes)", sig.len());
        }
        Some(sig)
    } else {
        None
    };

    // Generate next ephemeral keypair if ratchet is enabled
    let (next_public_key, next_keypair) = if config.ratchet {
        let new_keypair = KeyPair::generate_ephemeral();
        let public_bytes = new_keypair.public_key().as_bytes().to_vec();
        if config.verbose {
            eprintln!("Generated next ephemeral key for forward secrecy ratchet");
        }
        (Some(public_bytes), Some(new_keypair))
    } else {
        (None, None)
    };

    let encoded_data = EncodedData {
        version: VERSION,
        real_count: real_count as u16,
        fragments: all_fragments.clone(),
        signature,
        expires_at: config.expires_at,
        next_public_key,
    };

    let serialized = bincode::serialize(&encoded_data)
        .map_err(|e| EncoderError::SerializationError(e.to_string()))?;

    let encrypted = encrypt_with_passphrase(&serialized, passphrase, public_key)?;
    let code = BASE64.encode(&encrypted);

    Ok(EncodedMessage {
        code,
        real_fragment_count: real_count,
        total_fragments: all_fragments.len(),
        next_keypair,
    })
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
    fn test_encode_exact_case_match() {
        // Carrier has all characters in correct case
        let carrier = "Amanda fue al parque hoy";
        let message = "ama parque"; // lowercase - all exist in carrier
        let passphrase = "test";

        let keypair = KeyPair::generate();
        let result = encode(carrier, message, passphrase, keypair.public_key());

        assert!(result.is_ok());
    }

    #[test]
    fn test_encode_insufficient_coverage() {
        // Carrier has only uppercase, message is lowercase
        let carrier = "AMANDA FUE AL PARQUE";
        let message = "ama parque"; // lowercase
        let passphrase = "test";

        let keypair = KeyPair::generate();
        // With default 100% coverage, this should fail
        let result = encode(carrier, message, passphrase, keypair.public_key());

        assert!(matches!(result, Err(EncoderError::InsufficientCoverage(_, _, _, _))));
    }

    #[test]
    fn test_encode_with_low_coverage() {
        // Carrier has only uppercase, message is lowercase
        let carrier = "AMANDA FUE AL PARQUE";
        let message = "ama parque"; // lowercase
        let passphrase = "test";

        let keypair = KeyPair::generate();
        // With 0% coverage requirement, this should work
        let config = EncoderConfig {
            verbose: false,
            signing_key: None,
            min_coverage: 0.0, // Allow any coverage
            expires_at: None,
            ratchet: false,
        };
        let result = encode_with_config(carrier, message, passphrase, keypair.public_key(), &config);

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
