//! Block padding for KAMO v0.4.
//!
//! This module handles padding messages to block boundaries to hide
//! the actual message length from attackers.

use hkdf::Hkdf;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

use crate::{BLOCK_SIZE, MIN_SIZE};

/// HKDF salt for padding generation.
pub const SALT_PAD: &[u8] = b"KAMO-PAD-V4";

/// Calculates the padded length based on block size.
///
/// Messages are padded to multiples of BLOCK_SIZE, with a minimum of MIN_SIZE.
pub fn calculate_padded_length(message_len: usize) -> usize {
    let effective = message_len.max(MIN_SIZE);
    ((effective - 1) / BLOCK_SIZE + 1) * BLOCK_SIZE
}

/// Pads a message with words from the carrier to reach block boundary.
///
/// The padding is deterministic based on passphrase, so the same inputs
/// always produce the same padded message.
///
/// # Arguments
/// * `message` - The original message to pad
/// * `passphrase` - Used to generate deterministic padding
/// * `carrier_words` - Pool of words to use for padding
///
/// # Returns
/// The padded message with complete words (may slightly exceed block size)
pub fn pad_message(message: &str, passphrase: &str, carrier_words: &[String]) -> String {
    let target_len = calculate_padded_length(message.len());

    if message.len() >= target_len {
        return message.to_string();
    }

    if carrier_words.is_empty() {
        // Can't pad without carrier words, return original
        return message.to_string();
    }

    let mut padded = message.to_string();

    // Derive seed for deterministic padding
    let seed = derive_seed(passphrase.as_bytes(), SALT_PAD);
    let mut rng = ChaCha20Rng::from_seed(seed);

    // Add words from carrier until we reach target length
    // We keep complete words - never truncate mid-word
    while padded.len() < target_len {
        let word_idx = rng.gen_range(0..carrier_words.len());
        let word = &carrier_words[word_idx];
        padded.push(' ');
        padded.push_str(word);
    }

    // Don't truncate - keep all words complete
    padded
}

/// Derives a 32-byte seed using HKDF-SHA256.
fn derive_seed(input: &[u8], salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), input);
    let mut output = [0u8; 32];
    hk.expand(b"pad-seed", &mut output)
        .expect("HKDF expand should not fail");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_padding_size() {
        assert_eq!(calculate_padded_length(4), 256); // min 64 → 256
        assert_eq!(calculate_padded_length(64), 256);
        assert_eq!(calculate_padded_length(200), 256);
        assert_eq!(calculate_padded_length(256), 256);
        assert_eq!(calculate_padded_length(257), 512);
        assert_eq!(calculate_padded_length(600), 768);
    }

    #[test]
    fn test_pad_message_reaches_target() {
        let carrier_words: Vec<String> = vec![
            "alfa".to_string(),
            "beta".to_string(),
            "gamma".to_string(),
            "delta".to_string(),
        ];

        let message = "Hola";
        let padded = pad_message(message, "test", &carrier_words);

        // Should reach or exceed target (256) with complete words
        assert!(padded.len() >= 256);
    }

    #[test]
    fn test_pad_message_deterministic() {
        let carrier_words: Vec<String> = vec![
            "uno".to_string(),
            "dos".to_string(),
            "tres".to_string(),
        ];

        let message = "test";
        let padded1 = pad_message(message, "pass", &carrier_words);
        let padded2 = pad_message(message, "pass", &carrier_words);

        assert_eq!(padded1, padded2);
    }

    #[test]
    fn test_pad_message_different_passphrase() {
        let carrier_words: Vec<String> = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
            "e".to_string(),
        ];

        let message = "test";
        let padded1 = pad_message(message, "pass1", &carrier_words);
        let padded2 = pad_message(message, "pass2", &carrier_words);

        // Same length but different content
        assert_eq!(padded1.len(), padded2.len());
        assert_ne!(padded1, padded2);
    }

    #[test]
    fn test_pad_message_preserves_original() {
        let carrier_words: Vec<String> = vec!["x".to_string()];

        let message = "Original message";
        let padded = pad_message(message, "test", &carrier_words);

        assert!(padded.starts_with(message));
    }

    #[test]
    fn test_pad_message_uses_carrier_words() {
        let carrier_words: Vec<String> = vec![
            "alfa".to_string(),
            "beta".to_string(),
            "gamma".to_string(),
        ];

        let message = "start";
        let padded = pad_message(message, "test", &carrier_words);

        // All words after "start" should be from carrier (complete words, not truncated)
        let words: Vec<&str> = padded.split_whitespace().collect();
        for word in words.iter().skip(1) {
            let is_from_carrier = carrier_words.iter().any(|cw| cw == word);
            assert!(
                is_from_carrier,
                "Padding word '{}' not from carrier",
                word
            );
        }
    }

    #[test]
    fn test_pad_message_empty_carrier() {
        let message = "test";
        let padded = pad_message(message, "pass", &[]);

        // Without carrier words, returns original
        assert_eq!(padded, message);
    }

    #[test]
    fn test_pad_message_already_long_enough() {
        let carrier_words: Vec<String> = vec!["word".to_string()];

        let message = "a".repeat(300); // Longer than 256
        let padded = pad_message(&message, "test", &carrier_words);

        // 300 chars → target is 512, so it should pad to reach or exceed 512
        assert!(padded.len() >= 512);
    }
}
