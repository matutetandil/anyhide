//! BIP39-style mnemonic backup for Anyhide keys.
//!
//! This module provides functions to convert 32-byte keys to/from
//! 24-word mnemonic phrases for easy backup and recovery.
//!
//! # Algorithm
//!
//! 1. 32 bytes (256 bits) of key material
//! 2. SHA-256 hash of key bytes, take first 8 bits as checksum
//! 3. Total: 264 bits (256 + 8)
//! 4. Split into 24 groups of 11 bits each
//! 5. Each 11-bit value (0-2047) maps to a word in BIP39 wordlist

use sha2::{Digest, Sha256};
use thiserror::Error;

use super::bip39_english::{word_index, WORDLIST};

/// Errors that can occur when working with mnemonics.
#[derive(Error, Debug)]
pub enum MnemonicError {
    #[error("Invalid word count: expected 24 words, got {0}")]
    InvalidWordCount(usize),

    #[error("Invalid word: '{0}' is not in the BIP39 wordlist")]
    InvalidWord(String),

    #[error("Invalid checksum: the mnemonic phrase has been corrupted or mistyped")]
    InvalidChecksum,
}

/// Convert a 32-byte key to a 24-word mnemonic phrase.
///
/// # Algorithm
///
/// 1. Calculate SHA-256 checksum of key bytes
/// 2. Append first 8 bits of checksum to key (264 bits total)
/// 3. Split into 24 groups of 11 bits
/// 4. Map each 11-bit value to a word in the BIP39 wordlist
pub fn key_to_mnemonic(key_bytes: &[u8; 32]) -> Vec<String> {
    // Calculate checksum (first 8 bits of SHA-256)
    let mut hasher = Sha256::new();
    hasher.update(key_bytes);
    let checksum = hasher.finalize()[0];

    // Combine: 256 bits of key + 8 bits of checksum = 264 bits
    let mut bits = Vec::with_capacity(264);
    for byte in key_bytes {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    for i in (0..8).rev() {
        bits.push((checksum >> i) & 1);
    }

    // Split into 24 groups of 11 bits
    let mut words = Vec::with_capacity(24);
    for chunk in bits.chunks(11) {
        let mut index = 0u16;
        for (i, &bit) in chunk.iter().enumerate() {
            index |= (bit as u16) << (10 - i);
        }
        words.push(WORDLIST[index as usize].to_string());
    }

    words
}

/// Convert a 24-word mnemonic phrase back to a 32-byte key.
///
/// # Errors
///
/// Returns an error if:
/// - The word count is not exactly 24
/// - Any word is not in the BIP39 wordlist
/// - The checksum doesn't match (corrupted or mistyped)
pub fn mnemonic_to_key(words: &[String]) -> Result<[u8; 32], MnemonicError> {
    // Validate word count
    if words.len() != 24 {
        return Err(MnemonicError::InvalidWordCount(words.len()));
    }

    // Convert words to 11-bit indices
    let mut bits = Vec::with_capacity(264);
    for word in words {
        let word_lower = word.to_lowercase();
        let index = word_index(&word_lower).ok_or_else(|| MnemonicError::InvalidWord(word.clone()))?;

        // Convert index to 11 bits
        for i in (0..11).rev() {
            bits.push(((index >> i) & 1) as u8);
        }
    }

    // Extract key bytes (first 256 bits)
    let mut key_bytes = [0u8; 32];
    for (byte_idx, chunk) in bits[..256].chunks(8).enumerate() {
        let mut byte = 0u8;
        for (bit_idx, &bit) in chunk.iter().enumerate() {
            byte |= bit << (7 - bit_idx);
        }
        key_bytes[byte_idx] = byte;
    }

    // Extract checksum (last 8 bits)
    let mut stored_checksum = 0u8;
    for (i, &bit) in bits[256..264].iter().enumerate() {
        stored_checksum |= bit << (7 - i);
    }

    // Calculate expected checksum
    let mut hasher = Sha256::new();
    hasher.update(&key_bytes);
    let expected_checksum = hasher.finalize()[0];

    // Verify checksum
    if stored_checksum != expected_checksum {
        return Err(MnemonicError::InvalidChecksum);
    }

    Ok(key_bytes)
}

/// Validate a mnemonic phrase without converting it.
///
/// This is useful for checking user input before attempting conversion.
pub fn validate_mnemonic(words: &[String]) -> Result<(), MnemonicError> {
    // Just delegate to mnemonic_to_key and discard the result
    mnemonic_to_key(words)?;
    Ok(())
}

/// Format a mnemonic for display (4 words per line, numbered).
pub fn format_mnemonic(words: &[String]) -> String {
    let mut lines = Vec::new();

    for (i, chunk) in words.chunks(4).enumerate() {
        let start_num = i * 4 + 1;
        let formatted: Vec<String> = chunk
            .iter()
            .enumerate()
            .map(|(j, word)| format!("{:2}. {}", start_num + j, word))
            .collect();
        lines.push(formatted.join("  "));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_to_mnemonic_deterministic() {
        let key = [0u8; 32];
        let words1 = key_to_mnemonic(&key);
        let words2 = key_to_mnemonic(&key);
        assert_eq!(words1, words2);
        assert_eq!(words1.len(), 24);
    }

    #[test]
    fn test_mnemonic_roundtrip() {
        // Test with various keys
        let test_keys: [[u8; 32]; 3] = [
            [0u8; 32],
            [0xFF; 32],
            [
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
            ],
        ];

        for key in &test_keys {
            let words = key_to_mnemonic(key);
            let recovered = mnemonic_to_key(&words).unwrap();
            assert_eq!(&recovered, key);
        }
    }

    #[test]
    fn test_invalid_word_count() {
        let too_few: Vec<String> = vec!["abandon".to_string(); 23];
        let too_many: Vec<String> = vec!["abandon".to_string(); 25];

        assert!(matches!(
            mnemonic_to_key(&too_few),
            Err(MnemonicError::InvalidWordCount(23))
        ));
        assert!(matches!(
            mnemonic_to_key(&too_many),
            Err(MnemonicError::InvalidWordCount(25))
        ));
    }

    #[test]
    fn test_invalid_word() {
        let mut words: Vec<String> = key_to_mnemonic(&[0u8; 32]);
        words[0] = "notavalidword".to_string();

        assert!(matches!(
            mnemonic_to_key(&words),
            Err(MnemonicError::InvalidWord(_))
        ));
    }

    #[test]
    fn test_invalid_checksum() {
        let mut words = key_to_mnemonic(&[0u8; 32]);
        // Change one word to corrupt the checksum
        words[23] = if words[23] == "abandon" {
            "ability".to_string()
        } else {
            "abandon".to_string()
        };

        assert!(matches!(
            mnemonic_to_key(&words),
            Err(MnemonicError::InvalidChecksum)
        ));
    }

    #[test]
    fn test_validate_mnemonic() {
        let key = [42u8; 32];
        let words = key_to_mnemonic(&key);
        assert!(validate_mnemonic(&words).is_ok());

        let invalid: Vec<String> = vec!["invalid".to_string(); 24];
        assert!(validate_mnemonic(&invalid).is_err());
    }

    #[test]
    fn test_format_mnemonic() {
        let words: Vec<String> = (1..=24).map(|i| format!("word{}", i)).collect();
        let formatted = format_mnemonic(&words);
        assert!(formatted.contains(" 1. word1"));
        assert!(formatted.contains("24. word24"));
    }

    #[test]
    fn test_case_insensitive() {
        let key = [0u8; 32];
        let words = key_to_mnemonic(&key);

        // Convert to uppercase
        let uppercase: Vec<String> = words.iter().map(|w| w.to_uppercase()).collect();
        let recovered = mnemonic_to_key(&uppercase).unwrap();
        assert_eq!(recovered, key);

        // Mixed case
        let mixed: Vec<String> = words
            .iter()
            .enumerate()
            .map(|(i, w)| {
                if i % 2 == 0 {
                    w.to_uppercase()
                } else {
                    w.clone()
                }
            })
            .collect();
        let recovered = mnemonic_to_key(&mixed).unwrap();
        assert_eq!(recovered, key);
    }

    #[test]
    fn test_all_zeros_key() {
        // Known test vector: all zeros key
        let key = [0u8; 32];
        let words = key_to_mnemonic(&key);

        // First word should be "abandon" (index 0 for first 11 zero bits)
        assert_eq!(words[0], "abandon");
    }

    #[test]
    fn test_all_ones_key() {
        // All 0xFF key
        let key = [0xFF; 32];
        let words = key_to_mnemonic(&key);

        // First word should be "zoo" (index 2047 = 0b11111111111)
        assert_eq!(words[0], "zoo");
    }
}
