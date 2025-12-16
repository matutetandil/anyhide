//! Message decoding for Anyhide steganography.
//!
//! This module orchestrates the decoding process:
//! 1. Decode base64 and decrypt
//! 2. Deserialize to get fragment data
//! 3. Extract only real_count fragments (ignore padding)
//! 4. Look up data from carrier at each position (text or binary)
//! 5. Reconstruct message with spaces
//! 6. Optionally verify signature if verifying_key is provided
//!
//! CRITICAL: This decoder NEVER returns an error. If decryption fails or
//! data is invalid, it generates pseudo-random output based on the inputs.
//! This prevents brute-force attacks and provides plausible deniability.
//!
//! Supports both text carriers (text files, articles) and binary carriers (images, audio).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use x25519_dalek::StaticSecret;

use crate::crypto::{decrypt_with_passphrase, verify_signature};
use crate::encoder::EncodedData;
use crate::text::carrier::{BinaryCarrierSearch, Carrier};
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
    /// Signature verification result:
    /// - None: No signature in message OR no verifying key provided
    /// - Some(true): Signature verified successfully
    /// - Some(false): Signature verification FAILED (message may be tampered)
    pub signature_valid: Option<bool>,
}

/// Result of decoding binary data.
/// Note: This is ALWAYS returned, even with invalid inputs.
#[derive(Debug, Clone)]
pub struct DecodedBytes {
    /// The reconstructed binary data.
    pub data: Vec<u8>,
    /// The individual byte fragments extracted.
    pub fragments: Vec<Vec<u8>>,
    /// Signature verification result:
    /// - None: No signature in data OR no verifying key provided
    /// - Some(true): Signature verified successfully
    /// - Some(false): Signature verification FAILED (data may be tampered)
    pub signature_valid: Option<bool>,
}

/// Configuration for the decoder.
#[derive(Debug, Clone, Default)]
pub struct DecoderConfig<'a> {
    /// Whether to output verbose information.
    pub verbose: bool,
    /// Optional verifying key for signature verification.
    /// If provided and the message contains a signature, it will be verified.
    pub verifying_key: Option<&'a VerifyingKey>,
}

/// Verifies a signature over a message hash.
/// Returns None if no signature or no verifying key.
/// Returns Some(true) if valid, Some(false) if invalid.
///
/// Signatures are always verified over the EXACT message bytes because
/// char_overrides guarantee exact message recovery.
fn verify_message_signature(
    message: &[u8],
    signature: Option<&[u8]>,
    verifying_key: Option<&VerifyingKey>,
    verbose: bool,
) -> Option<bool> {
    match (signature, verifying_key) {
        (Some(sig), Some(key)) => {
            // Hash the exact message (char_overrides guarantee exact recovery)
            let mut hasher = Sha256::new();
            hasher.update(message);
            let message_hash = hasher.finalize();

            let result = verify_signature(&message_hash, sig, key).is_ok();
            if verbose {
                if result {
                    eprintln!("Signature verification: VALID");
                } else {
                    eprintln!("Signature verification: FAILED");
                }
            }
            Some(result)
        }
        (Some(_), None) => {
            if verbose {
                eprintln!("Message has signature but no verifying key provided");
            }
            None
        }
        (None, Some(_)) => {
            if verbose {
                eprintln!("Verifying key provided but message has no signature");
            }
            None
        }
        (None, None) => None,
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
    config: &DecoderConfig<'_>,
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
        let raw_extracted = carrier_search.extract_wrapped(
            found.position as usize,
            found.length as usize,
        );

        // Apply char_overrides to restore original case/characters
        let extracted = found.apply_overrides(&raw_extracted);

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

    // Step 8: Verify signature if present and verifying key provided
    let signature_valid = verify_message_signature(
        message.as_bytes(),
        data.signature.as_deref(),
        config.verifying_key,
        config.verbose,
    );

    DecodedMessage {
        message,
        fragments: extracted_fragments,
        signature_valid,
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
        signature_valid: None,
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

    DecodedMessage {
        message,
        fragments,
        signature_valid: None,
    }
}

// ============================================================================
// Generic Carrier Support (Text + Binary)
// ============================================================================

/// Decodes using a generic carrier (text or binary).
///
/// This is the main entry point for decoding with any carrier type.
/// NEVER fails - always returns something.
///
/// # Arguments
/// * `code` - The base64-encoded encrypted code
/// * `carrier` - A generic carrier (text or binary)
/// * `passphrase` - Symmetric decryption passphrase
/// * `secret_key` - Recipient's private key for asymmetric decryption
pub fn decode_with_carrier(
    code: &str,
    carrier: &Carrier,
    passphrase: &str,
    secret_key: &StaticSecret,
) -> DecodedMessage {
    decode_with_carrier_config(code, carrier, passphrase, secret_key, &DecoderConfig::default())
}

/// Decodes with a generic carrier and custom configuration.
/// NEVER returns an error - always produces output.
pub fn decode_with_carrier_config(
    code: &str,
    carrier: &Carrier,
    passphrase: &str,
    secret_key: &StaticSecret,
    config: &DecoderConfig<'_>,
) -> DecodedMessage {
    match carrier {
        Carrier::Text(text_carrier) => {
            decode_text_carrier(code, text_carrier, passphrase, secret_key, config)
        }
        Carrier::Binary(binary_carrier) => {
            decode_binary_carrier(code, binary_carrier, passphrase, secret_key, config)
        }
    }
}

/// Decodes using a text carrier (internal).
fn decode_text_carrier(
    code: &str,
    carrier: &CarrierSearch,
    passphrase: &str,
    secret_key: &StaticSecret,
    config: &DecoderConfig<'_>,
) -> DecodedMessage {
    if carrier.is_empty() {
        return generate_fallback_output(code, passphrase, "empty_carrier");
    }

    // Step 1: Decode base64
    let encrypted = match BASE64.decode(code.trim()) {
        Ok(data) => data,
        Err(_) => {
            if config.verbose {
                eprintln!("Base64 decode failed, generating fallback");
            }
            return generate_fallback_from_carrier(code, passphrase, carrier);
        }
    };

    if config.verbose {
        eprintln!("Decoded {} bytes from base64", encrypted.len());
    }

    // Step 2: Decrypt
    let decrypted = match decrypt_with_passphrase(&encrypted, passphrase, secret_key) {
        Ok(data) => data,
        Err(_) => {
            if config.verbose {
                eprintln!("Decryption failed, generating fallback");
            }
            return generate_fallback_from_carrier(code, passphrase, carrier);
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
            return generate_fallback_from_carrier(code, passphrase, carrier);
        }
    };

    if config.verbose {
        eprintln!(
            "Deserialized: version={}, real_count={}, total_fragments={}",
            data.version, data.real_count, data.fragments.len()
        );
    }

    // Step 4: Version check (soft)
    if data.version != VERSION && config.verbose {
        eprintln!(
            "Version mismatch: expected {}, got {}. Attempting anyway.",
            VERSION, data.version
        );
    }

    // Step 5: Extract real fragments
    let real_count = data.real_count as usize;
    if real_count > data.fragments.len() {
        if config.verbose {
            eprintln!("Invalid real_count, generating fallback");
        }
        return generate_fallback_from_carrier(code, passphrase, carrier);
    }

    let real_fragments = &data.fragments[..real_count];

    // Step 6: Extract text from carrier
    let mut extracted_fragments: Vec<String> = Vec::with_capacity(real_count);
    let mut message_parts: Vec<String> = Vec::with_capacity(real_count);

    for found in real_fragments {
        let raw_extracted = carrier.extract_wrapped(
            found.position as usize,
            found.length as usize,
        );

        // Apply char_overrides to restore original case/characters
        let extracted = found.apply_overrides(&raw_extracted);

        extracted_fragments.push(extracted.clone());

        let mut part = extracted;
        if !found.space_positions.is_empty() {
            part.push(' ');
        }

        message_parts.push(part);
    }

    if config.verbose {
        eprintln!("Extracted {} fragments: {:?}", extracted_fragments.len(), extracted_fragments);
    }

    let message = message_parts.concat();

    // Verify signature if present
    let signature_valid = verify_message_signature(
        message.as_bytes(),
        data.signature.as_deref(),
        config.verifying_key,
        config.verbose,
    );

    DecodedMessage {
        message,
        fragments: extracted_fragments,
        signature_valid,
    }
}

/// Decodes using a binary carrier.
fn decode_binary_carrier(
    code: &str,
    carrier: &BinaryCarrierSearch,
    passphrase: &str,
    secret_key: &StaticSecret,
    config: &DecoderConfig<'_>,
) -> DecodedMessage {
    if carrier.is_empty() {
        return generate_fallback_output(code, passphrase, "empty_binary_carrier");
    }

    // Step 1: Decode base64
    let encrypted = match BASE64.decode(code.trim()) {
        Ok(data) => data,
        Err(_) => {
            if config.verbose {
                eprintln!("Base64 decode failed, generating fallback");
            }
            return generate_fallback_from_binary_carrier(code, passphrase, carrier);
        }
    };

    if config.verbose {
        eprintln!("Decoded {} bytes from base64", encrypted.len());
    }

    // Step 2: Decrypt
    let decrypted = match decrypt_with_passphrase(&encrypted, passphrase, secret_key) {
        Ok(data) => data,
        Err(_) => {
            if config.verbose {
                eprintln!("Decryption failed, generating fallback");
            }
            return generate_fallback_from_binary_carrier(code, passphrase, carrier);
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
            return generate_fallback_from_binary_carrier(code, passphrase, carrier);
        }
    };

    if config.verbose {
        eprintln!(
            "Deserialized: version={}, real_count={}, total_fragments={}",
            data.version, data.real_count, data.fragments.len()
        );
    }

    // Step 4: Version check (soft)
    if data.version != VERSION && config.verbose {
        eprintln!(
            "Version mismatch: expected {}, got {}. Attempting anyway.",
            VERSION, data.version
        );
    }

    // Step 5: Extract real fragments
    let real_count = data.real_count as usize;
    if real_count > data.fragments.len() {
        if config.verbose {
            eprintln!("Invalid real_count, generating fallback");
        }
        return generate_fallback_from_binary_carrier(code, passphrase, carrier);
    }

    let real_fragments = &data.fragments[..real_count];

    // Step 6: Extract bytes from carrier and convert to string
    let mut extracted_fragments: Vec<String> = Vec::with_capacity(real_count);
    let mut message_parts: Vec<String> = Vec::with_capacity(real_count);

    for found in real_fragments {
        let bytes = carrier.extract_wrapped(
            found.position as usize,
            found.length as usize,
        );

        // Try to convert bytes to UTF-8 string
        let raw_extracted = String::from_utf8_lossy(&bytes).to_string();

        // Apply char_overrides to restore original case/characters
        let extracted = found.apply_overrides(&raw_extracted);

        extracted_fragments.push(extracted.clone());

        let mut part = extracted;
        if !found.space_positions.is_empty() {
            part.push(' ');
        }

        message_parts.push(part);
    }

    if config.verbose {
        eprintln!("Extracted {} fragments: {:?}", extracted_fragments.len(), extracted_fragments);
    }

    let message = message_parts.concat();

    // Verify signature if present
    let signature_valid = verify_message_signature(
        message.as_bytes(),
        data.signature.as_deref(),
        config.verifying_key,
        config.verbose,
    );

    DecodedMessage {
        message,
        fragments: extracted_fragments,
        signature_valid,
    }
}

/// Generates fallback by extracting pseudo-random bytes from binary carrier.
fn generate_fallback_from_binary_carrier(
    code: &str,
    passphrase: &str,
    carrier: &BinaryCarrierSearch,
) -> DecodedMessage {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hasher.update(passphrase.as_bytes());
    let hash = hasher.finalize();

    if carrier.is_empty() {
        return generate_fallback_output(code, passphrase, "empty_binary_carrier_fallback");
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

        let bytes = carrier.extract_wrapped(pos, len);
        let extracted = String::from_utf8_lossy(&bytes).to_string();
        fragments.push(extracted);
    }

    let message = fragments.join(" ");

    DecodedMessage {
        message,
        fragments,
        signature_valid: None,
    }
}

// ============================================================================
// Binary Message Decoding (for extracting arbitrary bytes, not just text)
// ============================================================================

/// Decodes arbitrary binary data from a carrier.
///
/// This function extracts raw bytes - use this when the original message was binary data.
/// NEVER fails - always returns something.
///
/// # Arguments
/// * `code` - The base64-encoded encrypted code
/// * `carrier` - A generic carrier (must match what was used for encoding)
/// * `passphrase` - Symmetric decryption passphrase
/// * `secret_key` - Recipient's private key for asymmetric decryption
///
/// # Example
/// ```ignore
/// let carrier = Carrier::from_file(Path::new("video.mp4"))?;
/// let decoded = decode_bytes_with_carrier(&code, &carrier, "pass", &secret_key);
/// std::fs::write("secret.zip", &decoded.data)?;
/// ```
pub fn decode_bytes_with_carrier(
    code: &str,
    carrier: &Carrier,
    passphrase: &str,
    secret_key: &StaticSecret,
) -> DecodedBytes {
    decode_bytes_with_carrier_config(code, carrier, passphrase, secret_key, &DecoderConfig::default())
}

/// Decodes binary data with custom configuration.
/// NEVER returns an error - always produces output.
pub fn decode_bytes_with_carrier_config(
    code: &str,
    carrier: &Carrier,
    passphrase: &str,
    secret_key: &StaticSecret,
    config: &DecoderConfig<'_>,
) -> DecodedBytes {
    // For binary decoding, we need byte-level extraction
    match carrier {
        Carrier::Binary(binary_carrier) => {
            decode_bytes_binary_carrier(code, binary_carrier, passphrase, secret_key, config)
        }
        Carrier::Text(text_carrier) => {
            // Convert text carrier to binary for byte-level operations
            let text_bytes = text_carrier.original.as_bytes().to_vec();
            let binary_carrier = BinaryCarrierSearch::new(text_bytes);
            decode_bytes_binary_carrier(code, &binary_carrier, passphrase, secret_key, config)
        }
    }
}

/// Internal: decodes binary data from a binary carrier.
fn decode_bytes_binary_carrier(
    code: &str,
    carrier: &BinaryCarrierSearch,
    passphrase: &str,
    secret_key: &StaticSecret,
    config: &DecoderConfig<'_>,
) -> DecodedBytes {
    if carrier.is_empty() {
        return generate_fallback_bytes(code, passphrase, "empty_binary_carrier");
    }

    // Step 1: Decode base64
    let encrypted = match BASE64.decode(code.trim()) {
        Ok(data) => data,
        Err(_) => {
            if config.verbose {
                eprintln!("Base64 decode failed, generating fallback");
            }
            return generate_fallback_bytes_from_carrier(code, passphrase, carrier);
        }
    };

    if config.verbose {
        eprintln!("Decoded {} bytes from base64", encrypted.len());
    }

    // Step 2: Decrypt
    let decrypted = match decrypt_with_passphrase(&encrypted, passphrase, secret_key) {
        Ok(data) => data,
        Err(_) => {
            if config.verbose {
                eprintln!("Decryption failed, generating fallback");
            }
            return generate_fallback_bytes_from_carrier(code, passphrase, carrier);
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
            return generate_fallback_bytes_from_carrier(code, passphrase, carrier);
        }
    };

    if config.verbose {
        eprintln!(
            "Deserialized: version={}, real_count={}, total_fragments={}",
            data.version, data.real_count, data.fragments.len()
        );
    }

    // Step 4: Version check (soft)
    if data.version != VERSION && config.verbose {
        eprintln!(
            "Version mismatch: expected {}, got {}. Attempting anyway.",
            VERSION, data.version
        );
    }

    // Step 5: Extract real fragments
    let real_count = data.real_count as usize;
    if real_count > data.fragments.len() {
        if config.verbose {
            eprintln!("Invalid real_count, generating fallback");
        }
        return generate_fallback_bytes_from_carrier(code, passphrase, carrier);
    }

    let real_fragments = &data.fragments[..real_count];

    // Step 6: Extract raw bytes from carrier (no string conversion)
    let mut extracted_fragments: Vec<Vec<u8>> = Vec::with_capacity(real_count);
    let mut all_bytes: Vec<u8> = Vec::new();

    for found in real_fragments {
        let bytes = carrier.extract_wrapped(found.position as usize, found.length as usize);

        extracted_fragments.push(bytes.clone());
        all_bytes.extend(bytes);
        // Note: space_positions are ignored for binary data
    }

    if config.verbose {
        eprintln!(
            "Extracted {} byte fragments, total {} bytes",
            extracted_fragments.len(),
            all_bytes.len()
        );
    }

    // Verify signature if present (for binary, we sign the raw bytes)
    let signature_valid = verify_message_signature(
        &all_bytes,
        data.signature.as_deref(),
        config.verifying_key,
        config.verbose,
    );

    DecodedBytes {
        data: all_bytes,
        fragments: extracted_fragments,
        signature_valid,
    }
}

/// Generates fallback bytes when inputs are completely invalid.
fn generate_fallback_bytes(code: &str, passphrase: &str, context: &str) -> DecodedBytes {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hasher.update(passphrase.as_bytes());
    hasher.update(context.as_bytes());
    let hash = hasher.finalize();

    // Return first 16 bytes of hash as garbage
    let garbage: Vec<u8> = hash.iter().take(16).copied().collect();

    DecodedBytes {
        data: garbage.clone(),
        fragments: vec![garbage],
        signature_valid: None,
    }
}

/// Generates fallback by extracting pseudo-random bytes from binary carrier.
fn generate_fallback_bytes_from_carrier(
    code: &str,
    passphrase: &str,
    carrier: &BinaryCarrierSearch,
) -> DecodedBytes {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hasher.update(passphrase.as_bytes());
    let hash = hasher.finalize();

    if carrier.is_empty() {
        return generate_fallback_bytes(code, passphrase, "empty_binary_carrier_fallback");
    }

    let carrier_len = carrier.len();

    // Extract 3-8 fragments based on hash
    let num_fragments = 3 + (hash[0] as usize % 6);
    let mut fragments: Vec<Vec<u8>> = Vec::with_capacity(num_fragments);
    let mut all_bytes: Vec<u8> = Vec::new();

    for i in 0..num_fragments {
        // Derive position from hash
        let pos_bytes = [hash[i * 4], hash[i * 4 + 1], hash[i * 4 + 2], hash[i * 4 + 3]];
        let pos = u32::from_le_bytes(pos_bytes) as usize % carrier_len;

        // Random length 1-5
        let len = 1 + (hash[(i * 4 + 1) % 32] as usize % 5);

        let bytes = carrier.extract_wrapped(pos, len);
        all_bytes.extend(&bytes);
        fragments.push(bytes);
    }

    DecodedBytes {
        data: all_bytes,
        fragments,
        signature_valid: None,
    }
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
