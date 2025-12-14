//! Message decoding for KAMO v0.4.1 steganography.
//!
//! This module orchestrates the decoding process:
//! 1. Decode base64 and decrypt
//! 2. Deserialize to get fragment data
//! 3. Extract only real_count fragments (ignore padding)
//! 4. Look up characters from carrier at each position
//! 5. Reconstruct message with spaces
//!
//! CRITICAL: This decoder NEVER returns an error. If decryption fails or
//! data is invalid, it generates pseudo-random output based on the inputs.
//! This prevents brute-force attacks and provides plausible deniability.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sha2::{Digest, Sha256};
use x25519_dalek::StaticSecret;

use crate::crypto::decrypt_with_passphrase;
use crate::encoder::EncodedData;
use crate::text::tokenize::CarrierSearch;
use crate::VERSION;

/// Result of decoding a message.
/// Note: This is ALWAYS returned, even with invalid inputs.
#[derive(Debug, Clone)]
pub struct DecodedMessage {
    /// The reconstructed message.
    pub message: String,
    /// The individual fragments extracted.
    pub fragments: Vec<String>,
}

/// Configuration for the decoder.
#[derive(Debug, Clone)]
pub struct DecoderConfig {
    /// Whether to output verbose information.
    pub verbose: bool,
}

impl Default for DecoderConfig {
    fn default() -> Self {
        Self { verbose: false }
    }
}

/// Decodes an encrypted code using a pre-shared carrier.
///
/// # Important
/// This function NEVER fails. If inputs are invalid or decryption fails,
/// it returns pseudo-random garbage derived from the inputs. This is
/// intentional for security (prevents brute-force detection).
///
/// # Arguments
/// * `code` - The base64-encoded encrypted code
/// * `carrier` - The pre-shared text (must match what was used for encoding)
/// * `passphrase` - Symmetric decryption passphrase
/// * `secret_key` - Recipient's private key for asymmetric decryption
///
/// # Returns
/// A `DecodedMessage` containing the reconstructed message (or garbage).
pub fn decode(
    code: &str,
    carrier: &str,
    passphrase: &str,
    secret_key: &StaticSecret,
) -> DecodedMessage {
    decode_with_config(code, carrier, passphrase, secret_key, &DecoderConfig::default())
}

/// Decodes a message with custom configuration.
/// NEVER returns an error - always produces output.
pub fn decode_with_config(
    code: &str,
    carrier: &str,
    passphrase: &str,
    secret_key: &StaticSecret,
    config: &DecoderConfig,
) -> DecodedMessage {
    let carrier = carrier.trim();
    let carrier_search = CarrierSearch::new(carrier);

    if carrier_search.is_empty() {
        return generate_fallback_output(code, passphrase, "empty_carrier");
    }

    // Step 1: Decode base64
    let encrypted = match BASE64.decode(code.trim()) {
        Ok(data) => data,
        Err(_) => {
            if config.verbose {
                eprintln!("Base64 decode failed, generating fallback");
            }
            return generate_fallback_from_carrier(code, passphrase, &carrier_search);
        }
    };

    if config.verbose {
        eprintln!("Decoded {} bytes from base64", encrypted.len());
    }

    // Step 2: Decrypt (asymmetric then symmetric)
    let decrypted = match decrypt_with_passphrase(&encrypted, passphrase, secret_key) {
        Ok(data) => data,
        Err(_) => {
            if config.verbose {
                eprintln!("Decryption failed, generating fallback");
            }
            return generate_fallback_from_carrier(code, passphrase, &carrier_search);
        }
    };

    if config.verbose {
        eprintln!("Decrypted {} bytes", decrypted.len());
    }

    // Step 3: Deserialize
    let data: EncodedData = match bincode::deserialize(&decrypted) {
        Ok(data) => data,
        Err(_) => {
            if config.verbose {
                eprintln!("Deserialization failed, generating fallback");
            }
            return generate_fallback_from_carrier(code, passphrase, &carrier_search);
        }
    };

    if config.verbose {
        eprintln!(
            "Deserialized: version={}, real_count={}, total_fragments={}",
            data.version, data.real_count, data.fragments.len()
        );
    }

    // Step 4: Version check (soft - still return something)
    if data.version != VERSION {
        if config.verbose {
            eprintln!(
                "Version mismatch: expected {}, got {}. Attempting anyway.",
                VERSION, data.version
            );
        }
        // Continue anyway - might still work or produce garbage
    }

    // Step 5: Extract ONLY real fragments (ignore padding)
    let real_count = data.real_count as usize;
    if real_count > data.fragments.len() {
        if config.verbose {
            eprintln!("Invalid real_count, generating fallback");
        }
        return generate_fallback_from_carrier(code, passphrase, &carrier_search);
    }

    let real_fragments = &data.fragments[..real_count];

    // Step 6: Extract characters from carrier for each fragment
    let mut extracted_fragments: Vec<String> = Vec::with_capacity(real_count);
    let mut message_parts: Vec<String> = Vec::with_capacity(real_count);

    for found in real_fragments {
        // Extract characters from carrier at the stored position
        let extracted = carrier_search.extract_wrapped(
            found.position as usize,
            found.length as usize,
        );

        extracted_fragments.push(extracted.clone());

        // Add spaces based on space_positions
        let mut part = extracted;
        if !found.space_positions.is_empty() {
            // Space positions indicate where to add spaces after this fragment
            part.push(' ');
        }

        message_parts.push(part);
    }

    if config.verbose {
        eprintln!("Extracted {} fragments: {:?}", extracted_fragments.len(), extracted_fragments);
    }

    // Step 7: Join fragments into message
    let message = message_parts.concat();

    DecodedMessage {
        message,
        fragments: extracted_fragments,
    }
}

/// Generates fallback output when inputs are completely invalid.
/// Uses hash of inputs to generate deterministic garbage.
fn generate_fallback_output(code: &str, passphrase: &str, context: &str) -> DecodedMessage {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hasher.update(passphrase.as_bytes());
    hasher.update(context.as_bytes());
    let hash = hasher.finalize();

    // Generate some garbage text from hash
    let garbage: String = hash
        .iter()
        .take(16)
        .map(|b| (b'a' + (b % 26)) as char)
        .collect();

    DecodedMessage {
        message: garbage.clone(),
        fragments: vec![garbage],
    }
}

/// Generates fallback by extracting pseudo-random substrings from carrier.
fn generate_fallback_from_carrier(
    code: &str,
    passphrase: &str,
    carrier: &CarrierSearch,
) -> DecodedMessage {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hasher.update(passphrase.as_bytes());
    let hash = hasher.finalize();

    if carrier.is_empty() {
        return generate_fallback_output(code, passphrase, "empty_carrier_fallback");
    }

    let carrier_len = carrier.len();

    // Extract 3-8 fragments based on hash
    let num_fragments = 3 + (hash[0] as usize % 6);
    let mut fragments: Vec<String> = Vec::with_capacity(num_fragments);

    for i in 0..num_fragments {
        // Derive position from hash
        let pos_bytes = [hash[i * 4], hash[i * 4 + 1], hash[i * 4 + 2], hash[i * 4 + 3]];
        let pos = u32::from_le_bytes(pos_bytes) as usize % carrier_len;

        // Random length 1-5
        let len = 1 + (hash[(i * 4 + 1) % 32] as usize % 5);

        let extracted = carrier.extract_wrapped(pos, len);
        fragments.push(extracted);
    }

    let message = fragments.join(" ");

    DecodedMessage { message, fragments }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::encoder::encode;

    #[test]
    fn test_encode_decode_roundtrip() {
        let carrier = "Amanda fue al parque con su hermano ayer por la tarde";
        let message = "ama parque";
        let passphrase = "test123";

        let keypair = KeyPair::generate();

        // Encode
        let encoded = encode(carrier, message, passphrase, keypair.public_key()).unwrap();

        // Decode
        let decoded = decode(&encoded.code, carrier, passphrase, keypair.secret_key());

        // The message should match (lowercase, spaces may vary slightly)
        assert!(decoded.message.to_lowercase().contains("ama"));
        assert!(decoded.message.to_lowercase().contains("parque"));
    }

    #[test]
    fn test_wrong_passphrase_returns_garbage() {
        let carrier = "Amanda fue al parque con su hermano ayer";
        let message = "ama parque";
        let correct_passphrase = "correct";
        let wrong_passphrase = "wrong";

        let keypair = KeyPair::generate();

        // Encode with correct passphrase
        let encoded = encode(carrier, message, correct_passphrase, keypair.public_key()).unwrap();

        // Decode with wrong passphrase - should NOT fail, returns garbage
        let decoded = decode(&encoded.code, carrier, wrong_passphrase, keypair.secret_key());

        // Should return something (garbage), not error
        assert!(!decoded.message.is_empty());
    }

    #[test]
    fn test_wrong_carrier_returns_different_message() {
        let carrier_real = "Amanda fue al parque con su hermano ayer";
        let carrier_fake = "El gato negro duerme sobre la mesa azul hoy";
        let message = "ama parque";
        let passphrase = "test";

        let keypair = KeyPair::generate();

        // Encode with real carrier
        let encoded = encode(carrier_real, message, passphrase, keypair.public_key()).unwrap();

        // Decode with fake carrier - should return something, just different
        let decoded = decode(&encoded.code, carrier_fake, passphrase, keypair.secret_key());

        // Should return something, not error
        assert!(!decoded.message.is_empty());
    }

    #[test]
    fn test_wrong_private_key_returns_garbage() {
        let carrier = "Amanda fue al parque con su hermano ayer";
        let message = "ama parque";
        let passphrase = "test";

        let sender_keypair = KeyPair::generate();
        let wrong_keypair = KeyPair::generate();

        // Encode with sender's public key
        let encoded = encode(carrier, message, passphrase, sender_keypair.public_key()).unwrap();

        // Decode with wrong private key - should NOT fail
        let decoded = decode(&encoded.code, carrier, passphrase, wrong_keypair.secret_key());

        // Should return something (garbage)
        assert!(!decoded.message.is_empty());
    }

    #[test]
    fn test_empty_carrier_returns_garbage() {
        let code = "somebase64code";
        let carrier = "";
        let passphrase = "test";

        let keypair = KeyPair::generate();
        let decoded = decode(code, carrier, passphrase, keypair.secret_key());

        // Should return garbage, not error
        assert!(!decoded.message.is_empty());
    }

    #[test]
    fn test_invalid_base64_returns_garbage() {
        let code = "!!!not_valid_base64!!!";
        let carrier = "Some carrier text with words";
        let passphrase = "test";

        let keypair = KeyPair::generate();
        let decoded = decode(code, carrier, passphrase, keypair.secret_key());

        // Should return garbage, not error
        assert!(!decoded.message.is_empty());
    }

    #[test]
    fn test_deterministic_garbage() {
        let code = "invalid";
        let carrier = "Some carrier words";
        let passphrase = "test";

        let keypair = KeyPair::generate();

        let decoded1 = decode(code, carrier, passphrase, keypair.secret_key());
        let decoded2 = decode(code, carrier, passphrase, keypair.secret_key());

        // Same inputs should produce same garbage
        assert_eq!(decoded1.message, decoded2.message);
    }
}
