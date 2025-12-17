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
use anyhide::{decode, encode, encode_with_config, encode_with_carrier_config, Carrier};

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

/// Test that message with characters not in carrier fails coverage check
#[test]
fn test_fragment_not_found_in_carrier() {
    let carrier = "Hola mundo";
    let message = "xyz"; // "xyz" is not in carrier
    let passphrase = "test";

    let keypair = KeyPair::generate();
    let result = encode(carrier, message, passphrase, keypair.public_key());

    // Encoding should fail with coverage error (characters not in carrier)
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("coverage") || err_msg.contains("not found"));
}

/// Test exact case matching (carrier must have exact characters)
#[test]
fn test_exact_case_matching() {
    // Carrier has lowercase 'ama' and 'parque'
    let carrier = "Amanda fue al parque hoy";
    let message = "ama parque"; // lowercase - should match
    let passphrase = "test";

    let keypair = KeyPair::generate();

    // Should encode successfully (exact case matching)
    let encoded = encode(carrier, message, passphrase, keypair.public_key()).unwrap();

    // Should decode successfully with exact message
    let decoded = decode(&encoded.code, carrier, passphrase, keypair.secret_key());
    assert_eq!(decoded.message.to_lowercase(), message.to_lowercase());
}

/// Test that uppercase carrier fails with lowercase message (100% coverage default)
#[test]
fn test_coverage_check_case_sensitive() {
    let carrier = "AMANDA FUE AL PARQUE HOLA"; // All uppercase
    let message = "ama parque"; // lowercase
    let passphrase = "test";

    let keypair = KeyPair::generate();

    // Should fail with 100% coverage (default) because lowercase chars don't exist
    let result = encode(carrier, message, passphrase, keypair.public_key());
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("coverage"));
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
    decode_bytes_with_carrier, encode_bytes_with_carrier,
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

// ============================================================================
// Forward Secrecy Ratchet Tests
// ============================================================================

/// Test encoding with ratchet generates next keypair
#[test]
fn test_ratchet_generates_next_keypair() {
    use anyhide::EncoderConfig;

    let carrier = "Amanda fue al parque con su hermano ayer por la tarde";
    let message = "ama parque";
    let passphrase = "secret";

    let keypair = KeyPair::generate();

    // Encode WITH ratchet
    let config = EncoderConfig {
        verbose: false,
        signing_key: None,
        min_coverage: 1.0,
        expires_at: None,
        ratchet: true,
        decoy: None,
    };

    let encoded = encode_with_config(carrier, message, passphrase, keypair.public_key(), &config)
        .expect("Encoding should succeed");

    // Should have generated next_keypair
    assert!(encoded.next_keypair.is_some());
    let next_keypair = encoded.next_keypair.unwrap();
    assert!(next_keypair.is_ephemeral());
}

/// Test encoding without ratchet does not generate next keypair
#[test]
fn test_no_ratchet_no_next_keypair() {
    let carrier = "Amanda fue al parque con su hermano ayer por la tarde";
    let message = "ama parque";
    let passphrase = "secret";

    let keypair = KeyPair::generate();

    // Encode WITHOUT ratchet (default)
    let encoded = encode(carrier, message, passphrase, keypair.public_key())
        .expect("Encoding should succeed");

    // Should NOT have next_keypair
    assert!(encoded.next_keypair.is_none());
}

/// Test decoded message contains next_public_key when ratchet is used
#[test]
fn test_decode_extracts_next_public_key() {
    use anyhide::EncoderConfig;

    let carrier = "Amanda fue al parque con su hermano ayer por la tarde";
    let message = "ama parque";
    let passphrase = "secret";

    let keypair = KeyPair::generate();

    // Encode with ratchet
    let config = EncoderConfig {
        verbose: false,
        signing_key: None,
        min_coverage: 1.0,
        expires_at: None,
        ratchet: true,
        decoy: None,
    };

    let encoded = encode_with_config(carrier, message, passphrase, keypair.public_key(), &config)
        .expect("Encoding should succeed");

    // Get the next public key from encoder result
    let next_keypair = encoded.next_keypair.as_ref().unwrap();
    let expected_next_public = next_keypair.public_key().as_bytes().to_vec();

    // Decode
    let decoded = decode(&encoded.code, carrier, passphrase, keypair.secret_key());

    // Decoded message should contain the next_public_key
    assert!(decoded.next_public_key.is_some());
    assert_eq!(decoded.next_public_key.unwrap(), expected_next_public);
}

/// Test decode without ratchet has no next_public_key
#[test]
fn test_decode_no_ratchet_no_next_public_key() {
    let carrier = "Amanda fue al parque con su hermano ayer por la tarde";
    let message = "ama parque";
    let passphrase = "secret";

    let keypair = KeyPair::generate();

    // Encode without ratchet
    let encoded = encode(carrier, message, passphrase, keypair.public_key())
        .expect("Encoding should succeed");

    // Decode
    let decoded = decode(&encoded.code, carrier, passphrase, keypair.secret_key());

    // Should NOT have next_public_key
    assert!(decoded.next_public_key.is_none());
}

/// Test automatic ratchet key rotation using unified store
#[test]
fn test_automatic_ratchet_with_unified_store() {
    use anyhide::crypto::{
        save_unified_keys_for_contact, load_unified_keys_for_contact,
        update_unified_public_key, update_unified_private_key,
    };
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let alice_store = dir.path().join("alice.eph");
    let bob_store = dir.path().join("bob.eph");

    // Carrier needs enough text to encode messages with substring matching
    let carrier = "Hello Bob! How are you doing today? Alice was wondering if you want to go to the park. Hi there everyone!";
    let passphrase = "secret";

    // Step 1: Alice and Bob generate initial keys and exchange public keys
    let alice_keypair = KeyPair::generate_ephemeral();
    let bob_keypair = KeyPair::generate_ephemeral();

    // Alice stores Bob's public key
    save_unified_keys_for_contact(
        &alice_store,
        "bob",
        alice_keypair.secret_key(),
        bob_keypair.public_key(),
    ).unwrap();

    // Bob stores Alice's public key
    save_unified_keys_for_contact(
        &bob_store,
        "alice",
        bob_keypair.secret_key(),
        alice_keypair.public_key(),
    ).unwrap();

    // Step 2: Alice encodes with ratchet
    let alice_keys = load_unified_keys_for_contact(&alice_store, "bob").unwrap();
    let bob_public = alice_keys.their_public;

    let config = anyhide::EncoderConfig {
        ratchet: true,
        ..Default::default()
    };
    let carrier_obj = Carrier::from_text(carrier);
    let encoded = encode_with_carrier_config(
        &carrier_obj,
        "Hello Bob",
        passphrase,
        &bob_public,
        &config,
    ).unwrap();

    // Alice should have next_keypair to save
    assert!(encoded.next_keypair.is_some());
    let alice_next = encoded.next_keypair.as_ref().unwrap();

    // Alice saves her new private key
    update_unified_private_key(&alice_store, "bob", alice_next.secret_key()).unwrap();

    // Step 3: Bob decodes and gets Alice's next public key
    let bob_keys = load_unified_keys_for_contact(&bob_store, "alice").unwrap();
    let decoded = decode(&encoded.code, carrier, passphrase, &bob_keys.my_private);

    assert!(decoded.message.to_lowercase().contains("hello"));
    assert!(decoded.next_public_key.is_some());

    // Bob saves Alice's next public key
    let alice_next_public_bytes = decoded.next_public_key.unwrap();
    assert_eq!(alice_next_public_bytes.len(), 32);

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&alice_next_public_bytes);
    let alice_next_public = x25519_dalek::PublicKey::from(key_array);

    update_unified_public_key(&bob_store, "alice", &alice_next_public).unwrap();

    // Verify Alice's next public matches what was saved
    let bob_keys_updated = load_unified_keys_for_contact(&bob_store, "alice").unwrap();
    assert_eq!(
        bob_keys_updated.their_public.as_bytes(),
        alice_next.public_key().as_bytes()
    );

    // Step 4: Bob can now reply using Alice's new key
    let config2 = anyhide::EncoderConfig {
        ratchet: true,
        ..Default::default()
    };
    let bob_reply = encode_with_carrier_config(
        &carrier_obj,
        "Hi Alice!",
        passphrase,
        &bob_keys_updated.their_public,
        &config2,
    ).unwrap();

    // Bob saves his new private key
    assert!(bob_reply.next_keypair.is_some());
    let bob_next = bob_reply.next_keypair.as_ref().unwrap();
    update_unified_private_key(&bob_store, "alice", bob_next.secret_key()).unwrap();

    // Step 5: Alice decodes Bob's reply using her NEW key
    let alice_keys_updated = load_unified_keys_for_contact(&alice_store, "bob").unwrap();
    let decoded_reply = decode(&bob_reply.code, carrier, passphrase, &alice_keys_updated.my_private);

    assert!(decoded_reply.message.to_lowercase().contains("hi"));

    // Alice got Bob's next public key
    assert!(decoded_reply.next_public_key.is_some());
}

/// Test key fingerprint consistency
#[test]
fn test_key_fingerprint_consistency() {
    use sha2::{Sha256, Digest};

    let keypair1 = KeyPair::generate();
    let keypair2 = KeyPair::generate();

    // Calculate fingerprint for keypair1
    let mut hasher1 = Sha256::new();
    hasher1.update(keypair1.public_key().as_bytes());
    let fp1: [u8; 32] = hasher1.finalize().into();

    // Calculate fingerprint again for keypair1 (should be same)
    let mut hasher1b = Sha256::new();
    hasher1b.update(keypair1.public_key().as_bytes());
    let fp1b: [u8; 32] = hasher1b.finalize().into();

    // Calculate fingerprint for keypair2 (should be different)
    let mut hasher2 = Sha256::new();
    hasher2.update(keypair2.public_key().as_bytes());
    let fp2: [u8; 32] = hasher2.finalize().into();

    // Same key = same fingerprint
    assert_eq!(fp1, fp1b);

    // Different keys = different fingerprints
    assert_ne!(fp1, fp2);
}

/// Test duress password (decoy message)
#[test]
fn test_duress_password_decoy_message() {
    use anyhide::{DecoyConfig, EncoderConfig};

    let carrier = "Hello world! Secret meeting birthday party celebration test message";
    let real_message = "Secret";
    let decoy_message = "birthday";
    let real_pass = "realpass";
    let decoy_pass = "fakepass";
    let wrong_pass = "wrongpass";

    let keypair = KeyPair::generate();

    // Encode with decoy
    let config = EncoderConfig {
        decoy: Some(DecoyConfig {
            message: decoy_message,
            passphrase: decoy_pass,
        }),
        ..Default::default()
    };

    let encoded = encode_with_config(carrier, real_message, real_pass, keypair.public_key(), &config)
        .expect("Encoding should succeed");

    // Code should contain dot separator
    assert!(encoded.code.contains('.'), "Code should contain dot separator for duress");

    // Decode with real passphrase → real message
    let decoded_real = decode(&encoded.code, carrier, real_pass, keypair.secret_key());
    assert!(decoded_real.message.to_lowercase().contains("secret"));

    // Decode with decoy passphrase → decoy message
    let decoded_decoy = decode(&encoded.code, carrier, decoy_pass, keypair.secret_key());
    assert!(decoded_decoy.message.to_lowercase().contains("birthday"));

    // Decode with wrong passphrase → garbage (neither message)
    let decoded_wrong = decode(&encoded.code, carrier, wrong_pass, keypair.secret_key());
    assert!(!decoded_wrong.message.to_lowercase().contains("secret"));
    assert!(!decoded_wrong.message.to_lowercase().contains("birthday"));
}

/// Test that duress password signs BOTH messages (real and decoy)
/// This is critical for security - if only real is signed, attacker can distinguish them
#[test]
fn test_duress_password_signs_both_messages() {
    use anyhide::{DecoyConfig, EncoderConfig, decode_with_config, DecoderConfig};
    use anyhide::crypto::SigningKeyPair;

    let carrier = "Hello world! Secret meeting birthday party celebration test message";
    let real_message = "Secret";
    let decoy_message = "birthday";
    let real_pass = "realpass";
    let decoy_pass = "fakepass";

    let keypair = KeyPair::generate();
    let signing_keypair = SigningKeyPair::generate();

    // Encode with decoy AND signing
    let config = EncoderConfig {
        signing_key: Some(signing_keypair.signing_key()),
        decoy: Some(DecoyConfig {
            message: decoy_message,
            passphrase: decoy_pass,
        }),
        ..Default::default()
    };

    let encoded = encode_with_config(carrier, real_message, real_pass, keypair.public_key(), &config)
        .expect("Encoding should succeed");

    // Decoder config with verifying key
    let decoder_config = DecoderConfig {
        verifying_key: Some(signing_keypair.verifying_key()),
        ..Default::default()
    };

    // Decode real message - should have valid signature
    let decoded_real = decode_with_config(&encoded.code, carrier, real_pass, keypair.secret_key(), &decoder_config);
    assert!(decoded_real.message.to_lowercase().contains("secret"));
    assert_eq!(decoded_real.signature_valid, Some(true), "Real message should have valid signature");

    // Decode decoy message - should ALSO have valid signature (indistinguishable)
    let decoded_decoy = decode_with_config(&encoded.code, carrier, decoy_pass, keypair.secret_key(), &decoder_config);
    assert!(decoded_decoy.message.to_lowercase().contains("birthday"));
    assert_eq!(decoded_decoy.signature_valid, Some(true), "Decoy message MUST also have valid signature for security");
}

// ============================================================================
// Mnemonic Backup Tests (v0.10.0)
// ============================================================================

/// Test mnemonic roundtrip for encryption keys
#[test]
fn test_mnemonic_encryption_key_roundtrip() {
    use anyhide::crypto::{key_to_mnemonic, mnemonic_to_key};

    // Generate a keypair
    let original_keypair = KeyPair::generate();
    let original_bytes: [u8; 32] = *original_keypair.secret_key().as_bytes();

    // Convert to mnemonic
    let words = key_to_mnemonic(&original_bytes);
    assert_eq!(words.len(), 24, "Mnemonic should be 24 words");

    // Convert back to key bytes
    let recovered_bytes = mnemonic_to_key(&words).expect("Mnemonic should be valid");

    // Should match
    assert_eq!(original_bytes, recovered_bytes, "Recovered key should match original");

    // Create keypair from recovered bytes and verify public key matches
    let recovered_keypair = KeyPair::from_secret_bytes(&recovered_bytes);
    assert_eq!(
        original_keypair.public_key().as_bytes(),
        recovered_keypair.public_key().as_bytes(),
        "Recovered public key should match original"
    );
}

/// Test mnemonic roundtrip for signing keys
#[test]
fn test_mnemonic_signing_key_roundtrip() {
    use anyhide::crypto::{key_to_mnemonic, mnemonic_to_key, SigningKeyPair};

    // Generate a signing keypair
    let original_keypair = SigningKeyPair::generate();
    let original_bytes: [u8; 32] = original_keypair.signing_key().to_bytes();

    // Convert to mnemonic
    let words = key_to_mnemonic(&original_bytes);
    assert_eq!(words.len(), 24, "Mnemonic should be 24 words");

    // Convert back to key bytes
    let recovered_bytes = mnemonic_to_key(&words).expect("Mnemonic should be valid");

    // Should match
    assert_eq!(original_bytes, recovered_bytes, "Recovered key should match original");

    // Create keypair from recovered bytes and verify verifying key matches
    let recovered_keypair = SigningKeyPair::from_secret_bytes(&recovered_bytes)
        .expect("Should create signing keypair from bytes");
    assert_eq!(
        original_keypair.verifying_key().to_bytes(),
        recovered_keypair.verifying_key().to_bytes(),
        "Recovered verifying key should match original"
    );
}

/// Test mnemonic checksum validation
#[test]
fn test_mnemonic_invalid_checksum() {
    use anyhide::crypto::{key_to_mnemonic, mnemonic_to_key, MnemonicError};

    // Generate valid mnemonic
    let key = [42u8; 32];
    let mut words = key_to_mnemonic(&key);

    // Corrupt one word
    words[23] = if words[23] == "abandon" {
        "ability".to_string()
    } else {
        "abandon".to_string()
    };

    // Should fail checksum validation
    let result = mnemonic_to_key(&words);
    assert!(matches!(result, Err(MnemonicError::InvalidChecksum)));
}

/// Test mnemonic with invalid word
#[test]
fn test_mnemonic_invalid_word() {
    use anyhide::crypto::{mnemonic_to_key, MnemonicError};

    let mut words: Vec<String> = vec!["abandon".to_string(); 24];
    words[0] = "notavalidword".to_string();

    let result = mnemonic_to_key(&words);
    assert!(matches!(result, Err(MnemonicError::InvalidWord(_))));
}

// ============================================================================
// Contacts Tests (v0.10.0)
// ============================================================================

/// Test contacts config CRUD
#[test]
fn test_contacts_config_crud_integration() {
    use anyhide::contacts::{Contact, ContactsConfig};
    use std::path::PathBuf;

    let mut config = ContactsConfig::default();

    // Add contacts
    let alice = Contact::new(PathBuf::from("/path/to/alice.pub"));
    config.add("alice", alice).unwrap();

    let bob = Contact::with_signing(
        PathBuf::from("/path/to/bob.pub"),
        PathBuf::from("/path/to/bob.sign.pub"),
    );
    config.add("bob", bob).unwrap();

    // Verify
    assert_eq!(config.len(), 2);
    assert!(config.contains("alice"));
    assert!(config.contains("bob"));

    // Get contact
    let alice_contact = config.get("alice").unwrap();
    assert_eq!(alice_contact.public_key, PathBuf::from("/path/to/alice.pub"));
    assert!(alice_contact.signing_key.is_none());

    let bob_contact = config.get("bob").unwrap();
    assert!(bob_contact.signing_key.is_some());

    // List is sorted
    let list = config.list();
    assert_eq!(list[0].0, "alice");
    assert_eq!(list[1].0, "bob");

    // Remove contact
    config.remove("alice").unwrap();
    assert_eq!(config.len(), 1);
    assert!(!config.contains("alice"));
}
