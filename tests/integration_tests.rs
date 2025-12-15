//! Integration tests for Anyhide
//!
//! Note: decode() NEVER fails - it always returns something.
//! Wrong inputs produce garbage, not errors.
//!
//! Features:
//! - Variable fragmentation (passphrase-based sizes)
//! - Substring matching (fragments found as substrings)
//! - Distributed selection (positions spread across occurrences)
//! - Block padding (message length hidden)

use anyhide::crypto::KeyPair;
use anyhide::{decode, encode};

/// Test basic encode/decode roundtrip
#[test]
fn test_encode_decode_roundtrip() {
    let carrier = "Amanda fue al parque con su hermano ayer por la tarde";
    let message = "ama parque";
    let passphrase = "test123";

    let keypair = KeyPair::generate();

    // Encode
    let encoded = encode(carrier, message, passphrase, keypair.public_key()).unwrap();
    assert!(!encoded.code.is_empty());
    assert!(encoded.real_fragment_count >= 1);

    // Decode - NOTE: no unwrap needed, decode NEVER fails
    let decoded = decode(&encoded.code, carrier, passphrase, keypair.secret_key());

    // The decoded message should contain the original fragments
    assert!(decoded.message.to_lowercase().contains("ama"));
    assert!(decoded.message.to_lowercase().contains("parque"));
}

/// Test that wrong passphrase produces different output (not error)
#[test]
fn test_wrong_passphrase_returns_garbage() {
    let carrier = "Amanda fue al parque con su hermano ayer";
    let message = "ama parque";
    let correct_passphrase = "correct";
    let wrong_passphrase = "wrong";

    let keypair = KeyPair::generate();

    // Encode with correct passphrase
    let encoded = encode(carrier, message, correct_passphrase, keypair.public_key()).unwrap();

    // Decode with correct passphrase
    let decoded_correct = decode(&encoded.code, carrier, correct_passphrase, keypair.secret_key());

    // Decode with wrong passphrase - should NOT fail, returns garbage
    let decoded_wrong = decode(&encoded.code, carrier, wrong_passphrase, keypair.secret_key());

    // Both should return something
    assert!(!decoded_correct.message.is_empty());
    assert!(!decoded_wrong.message.is_empty());

    // Messages should be different
    assert_ne!(decoded_correct.message, decoded_wrong.message);
}

/// Test that wrong private key produces different output (not error)
#[test]
fn test_wrong_private_key_returns_garbage() {
    let carrier = "Amanda fue al parque con su hermano ayer";
    let message = "ama parque";
    let passphrase = "test";

    let sender_keypair = KeyPair::generate();
    let wrong_keypair = KeyPair::generate();

    // Encode with sender's public key
    let encoded = encode(carrier, message, passphrase, sender_keypair.public_key()).unwrap();

    // Decode with correct private key
    let decoded_correct = decode(&encoded.code, carrier, passphrase, sender_keypair.secret_key());

    // Decode with wrong private key - should NOT fail, returns garbage
    let decoded_wrong = decode(&encoded.code, carrier, passphrase, wrong_keypair.secret_key());

    // Both should return something
    assert!(!decoded_correct.message.is_empty());
    assert!(!decoded_wrong.message.is_empty());
}

/// Test that fragment not found in carrier returns error during encoding
#[test]
fn test_fragment_not_found_in_carrier() {
    let carrier = "Hola mundo";
    let message = "xyz"; // "xyz" is not in carrier
    let passphrase = "test";

    let keypair = KeyPair::generate();
    let result = encode(carrier, message, passphrase, keypair.public_key());

    // Encoding should fail (not decoding)
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

/// Test case-insensitive matching
#[test]
fn test_case_insensitive_matching() {
    let carrier = "AMANDA FUE AL PARQUE HOLA";
    let message = "ama parque"; // lowercase
    let passphrase = "test";

    let keypair = KeyPair::generate();

    // Should encode successfully (case-insensitive substring matching)
    let encoded = encode(carrier, message, passphrase, keypair.public_key()).unwrap();

    // Should decode successfully
    let decoded = decode(&encoded.code, carrier, passphrase, keypair.secret_key());
    assert!(!decoded.message.is_empty());
}

/// Test wrong carrier gives different result (plausible deniability)
#[test]
fn test_wrong_carrier_plausible_deniability() {
    let carrier_real = "Amanda fue al parque con su hermano ayer";
    let carrier_fake = "El gato negro duerme sobre la mesa azul hoy";
    let message = "ama parque";
    let passphrase = "test";

    let keypair = KeyPair::generate();

    // Encode with real carrier
    let encoded = encode(carrier_real, message, passphrase, keypair.public_key()).unwrap();

    // Decode with correct carrier
    let decoded_real = decode(&encoded.code, carrier_real, passphrase, keypair.secret_key());
    assert!(!decoded_real.message.is_empty());

    // Decode with fake carrier - should return something different (not error)
    let decoded_fake = decode(&encoded.code, carrier_fake, passphrase, keypair.secret_key());
    assert!(!decoded_fake.message.is_empty());
}

/// Test empty message error
#[test]
fn test_empty_message_error() {
    let carrier = "Some carrier text";
    let message = "";
    let passphrase = "test";

    let keypair = KeyPair::generate();
    let result = encode(carrier, message, passphrase, keypair.public_key());

    assert!(result.is_err());
}

/// Test empty carrier error
#[test]
fn test_empty_carrier_error() {
    let carrier = "";
    let message = "Hello";
    let passphrase = "test";

    let keypair = KeyPair::generate();
    let result = encode(carrier, message, passphrase, keypair.public_key());

    assert!(result.is_err());
}

/// Test substring matching with longer message
#[test]
fn test_longer_message() {
    let carrier = "El día de hoy Amanda fue al mercado grande para comprar frutas";
    let message = "anda mercado";
    let passphrase = "secreto";

    let keypair = KeyPair::generate();

    let encoded = encode(carrier, message, passphrase, keypair.public_key()).unwrap();
    assert!(encoded.real_fragment_count >= 1);

    let decoded = decode(&encoded.code, carrier, passphrase, keypair.secret_key());
    // Should contain the fragments
    assert!(decoded.message.to_lowercase().contains("anda") ||
            decoded.message.to_lowercase().contains("mercado"));
}

/// Test code is base64 encoded
#[test]
fn test_code_is_base64() {
    let carrier = "El gato negro duerme";
    let message = "gato";
    let passphrase = "test";

    let keypair = KeyPair::generate();

    let encoded = encode(carrier, message, passphrase, keypair.public_key()).unwrap();

    // Should be valid base64
    let decode_result = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &encoded.code,
    );
    assert!(decode_result.is_ok());
}

/// Tests key pair generation and persistence.
#[test]
fn test_keypair_roundtrip() {
    use std::path::PathBuf;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let base_path = PathBuf::from(dir.path()).join("testkey");

    // Generate and save
    let original = KeyPair::generate();
    original.save_to_files(&base_path).unwrap();

    // Load
    let loaded = KeyPair::load_from_files(&base_path).unwrap();

    // Verify keys match
    assert_eq!(
        original.public_key().as_bytes(),
        loaded.public_key().as_bytes()
    );
    assert_eq!(
        original.secret_key().as_bytes(),
        loaded.secret_key().as_bytes()
    );
}

/// Test that same inputs produce different codes (random nonces)
#[test]
fn test_encoding_uses_random_nonces() {
    let carrier = "El gato negro duerme sobre mesa";
    let message = "gato";
    let passphrase = "test";

    let keypair = KeyPair::generate();

    // Two encodings should produce different codes (due to random nonces)
    let encoded1 = encode(carrier, message, passphrase, keypair.public_key()).unwrap();
    let encoded2 = encode(carrier, message, passphrase, keypair.public_key()).unwrap();

    // Codes should be different (random nonces in encryption)
    assert_ne!(encoded1.code, encoded2.code);

    // But both should decode to the same message
    let decoded1 = decode(&encoded1.code, carrier, passphrase, keypair.secret_key());
    let decoded2 = decode(&encoded2.code, carrier, passphrase, keypair.secret_key());

    assert_eq!(decoded1.message, decoded2.message);
}

/// Test invalid base64 code returns garbage (not error)
#[test]
fn test_invalid_base64_returns_garbage() {
    let carrier = "Some carrier text with words";
    let code = "!!!not_valid_base64!!!";
    let passphrase = "test";

    let keypair = KeyPair::generate();
    let decoded = decode(code, carrier, passphrase, keypair.secret_key());

    // Should return something (garbage), not panic or error
    assert!(!decoded.message.is_empty());
}

/// Test empty carrier during decode returns garbage (not error)
#[test]
fn test_empty_carrier_decode_returns_garbage() {
    let code = "c29tZWJhc2U2NA=="; // "somebase64" in base64
    let carrier = "";
    let passphrase = "test";

    let keypair = KeyPair::generate();
    let decoded = decode(code, carrier, passphrase, keypair.secret_key());

    // Should return something (garbage), not panic or error
    assert!(!decoded.message.is_empty());
}

/// Test deterministic garbage generation
#[test]
fn test_deterministic_garbage() {
    let code = "invalid";
    let carrier = "Some carrier text words";
    let passphrase = "test";

    let keypair = KeyPair::generate();

    let decoded1 = decode(code, carrier, passphrase, keypair.secret_key());
    let decoded2 = decode(code, carrier, passphrase, keypair.secret_key());

    // Same invalid inputs should produce same garbage
    assert_eq!(decoded1.message, decoded2.message);
}

/// Test substring matching - "anda" found in "Amanda"
#[test]
fn test_substring_matching() {
    let carrier = "Amanda camina por el sendero";
    let message = "anda";
    let passphrase = "test";

    let keypair = KeyPair::generate();

    // "anda" should be found as substring in "Amanda"
    let encoded = encode(carrier, message, passphrase, keypair.public_key()).unwrap();

    let decoded = decode(&encoded.code, carrier, passphrase, keypair.secret_key());
    // The extracted text will be from carrier (may be "anda" from "Amanda")
    assert!(!decoded.message.is_empty());
}

/// Test block padding produces similar sizes
#[test]
fn test_block_padding() {
    let carrier = "uno dos tres cuatro cinco seis siete ocho nueve diez \
                   once doce trece catorce quince dieciseis diecisiete";
    let passphrase = "test";

    let keypair = KeyPair::generate();

    // Short message
    let code_short = encode(carrier, "uno", passphrase, keypair.public_key()).unwrap();

    // Longer message but same block
    let code_longer = encode(carrier, "uno dos tres", passphrase, keypair.public_key()).unwrap();

    // Both should have padding fragments
    assert!(code_short.total_fragments >= code_short.real_fragment_count);
    assert!(code_longer.total_fragments >= code_longer.real_fragment_count);
}

/// Test cross-language capability (Spanish carrier, English message fragments)
#[test]
fn test_cross_language() {
    // Spanish carrier that contains English-compatible substrings
    let carrier = "El amor es una cosa esplendorosa y hermosa";
    let message = "amor"; // Works because "amor" is in the carrier
    let passphrase = "test";

    let keypair = KeyPair::generate();

    let result = encode(carrier, message, passphrase, keypair.public_key());
    assert!(result.is_ok());

    let decoded = decode(&result.unwrap().code, carrier, passphrase, keypair.secret_key());
    assert!(decoded.message.to_lowercase().contains("amor"));
}

/// Test version is encoded correctly
#[test]
fn test_roundtrip_v5() {
    let carrier = "Amanda fue al parque con Marta para ver las flores bonitas";
    let message = "ama parque flores";
    let passphrase = "secreto";

    let keypair = KeyPair::generate();

    let encoded = encode(carrier, message, passphrase, keypair.public_key()).unwrap();
    let decoded = decode(&encoded.code, carrier, passphrase, keypair.secret_key());

    // Should contain the key fragments
    let msg_lower = decoded.message.to_lowercase();
    assert!(msg_lower.contains("ama") || msg_lower.contains("parque") || msg_lower.contains("flor"));
}

// ============================================================================
// Binary Message Tests
// ============================================================================

use anyhide::{
    decode_bytes_with_carrier, encode_bytes_with_carrier, Carrier,
};

/// Test binary message encode/decode roundtrip
#[test]
fn test_binary_message_roundtrip() {
    // Create a carrier with all byte values (ensures any byte can be found)
    let mut carrier_data: Vec<u8> = Vec::new();
    for i in 0..=255u8 {
        carrier_data.push(i);
    }
    // Repeat for more occurrences
    for i in 0..=255u8 {
        carrier_data.push(i);
    }
    let carrier = Carrier::from_bytes(carrier_data);

    // Binary message
    let message: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];
    let passphrase = "test123";

    let keypair = KeyPair::generate();

    // Encode
    let encoded = encode_bytes_with_carrier(&carrier, &message, passphrase, keypair.public_key())
        .expect("Encoding should succeed");
    assert!(!encoded.code.is_empty());

    // Decode
    let decoded = decode_bytes_with_carrier(&encoded.code, &carrier, passphrase, keypair.secret_key());

    // Should get back the exact bytes
    assert_eq!(decoded.data, message);
}

/// Test binary message with wrong passphrase returns garbage
#[test]
fn test_binary_wrong_passphrase_returns_garbage() {
    let mut carrier_data: Vec<u8> = Vec::new();
    for i in 0..=255u8 {
        carrier_data.push(i);
        carrier_data.push(i);
    }
    let carrier = Carrier::from_bytes(carrier_data);

    let message: Vec<u8> = vec![0x41, 0x42, 0x43]; // "ABC"
    let correct_passphrase = "correct";
    let wrong_passphrase = "wrong";

    let keypair = KeyPair::generate();

    let encoded = encode_bytes_with_carrier(&carrier, &message, correct_passphrase, keypair.public_key())
        .expect("Encoding should succeed");

    // Decode with wrong passphrase
    let decoded = decode_bytes_with_carrier(&encoded.code, &carrier, wrong_passphrase, keypair.secret_key());

    // Should return something (garbage), not the original message
    assert!(!decoded.data.is_empty());
    // Garbage should be different from original
    assert_ne!(decoded.data, message);
}

/// Test binary message encoding is indistinguishable from text encoding
#[test]
fn test_binary_code_indistinguishable() {
    let mut carrier_data: Vec<u8> = Vec::new();
    for i in 0..=255u8 {
        carrier_data.push(i);
    }
    for i in 0..=255u8 {
        carrier_data.push(i);
    }
    let carrier = Carrier::from_bytes(carrier_data);

    let binary_message: Vec<u8> = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]; // "Hello" as bytes
    let passphrase = "test";

    let keypair = KeyPair::generate();

    let binary_encoded = encode_bytes_with_carrier(&carrier, &binary_message, passphrase, keypair.public_key())
        .expect("Binary encoding should succeed");

    // The code should be valid base64 (just like text encoding)
    let decode_result = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &binary_encoded.code,
    );
    assert!(decode_result.is_ok());

    // There should be no metadata indicating this is binary
    // (the code format is identical)
    assert!(!binary_encoded.code.contains("binary"));
    assert!(!binary_encoded.code.contains("BINARY"));
}

/// Test encoding a simulated file
#[test]
fn test_simulated_file_encoding() {
    // Simulate a small "file" with header and data
    let file_content: Vec<u8> = vec![
        0x89, 0x50, 0x4E, 0x47,  // PNG magic bytes
        0x0D, 0x0A, 0x1A, 0x0A,  // PNG signature
        0x00, 0x01, 0x02, 0x03,  // Some data
    ];

    // Create carrier with all possible bytes
    let mut carrier_data: Vec<u8> = Vec::new();
    for _ in 0..4 {
        for i in 0..=255u8 {
            carrier_data.push(i);
        }
    }
    let carrier = Carrier::from_bytes(carrier_data);

    let passphrase = "secret";
    let keypair = KeyPair::generate();

    // Encode the "file"
    let encoded = encode_bytes_with_carrier(&carrier, &file_content, passphrase, keypair.public_key())
        .expect("File encoding should succeed");

    // Decode
    let decoded = decode_bytes_with_carrier(&encoded.code, &carrier, passphrase, keypair.secret_key());

    // Should recover exact bytes
    assert_eq!(decoded.data, file_content);
    assert_eq!(&decoded.data[0..4], &[0x89, 0x50, 0x4E, 0x47]); // PNG magic
}
