//! Carrier text search for KAMO.
//!
//! This module handles searching for fragments as substrings within
//! the carrier text. All searches are case-insensitive.
//!
//! v0.4.1: Added distributed selection for random position choice.

use hkdf::Hkdf;
use rand::SeedableRng;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

/// HKDF salt for position selection.
pub const SALT_POSITION: &[u8] = b"KAMO-POSITION-V5";

/// Normalizes text for searching (lowercase, preserves all characters).
pub fn normalize_text(text: &str) -> String {
    text.to_lowercase()
}

/// Selects one position from multiple occurrences using deterministic randomness.
///
/// This ensures that:
/// - Same passphrase + fragment_index always selects the same occurrence
/// - Different fragments select different occurrences (distributed)
/// - The selection appears random to an observer
pub fn select_distributed_position(
    positions: &[usize],
    passphrase: &str,
    fragment_index: usize,
) -> Option<usize> {
    if positions.is_empty() {
        return None;
    }

    if positions.len() == 1 {
        return Some(positions[0]);
    }

    // Derive seed from passphrase + fragment index
    let hk = Hkdf::<Sha256>::new(Some(SALT_POSITION), passphrase.as_bytes());
    let mut seed = [0u8; 32];
    let info = format!("fragment-{}", fragment_index);
    hk.expand(info.as_bytes(), &mut seed)
        .expect("HKDF expand should not fail");

    let mut rng = ChaCha20Rng::from_seed(seed);
    let idx = rng.gen_range(0..positions.len());

    Some(positions[idx])
}

/// A carrier prepared for substring searching.
#[derive(Debug, Clone)]
pub struct CarrierSearch {
    /// Original carrier text.
    pub original: String,
    /// Normalized (lowercase) carrier for searching.
    pub normalized: String,
}

impl CarrierSearch {
    /// Creates a new CarrierSearch from carrier text.
    pub fn new(carrier: &str) -> Self {
        Self {
            original: carrier.to_string(),
            normalized: normalize_text(carrier),
        }
    }

    /// Returns the length of the carrier in characters.
    pub fn len(&self) -> usize {
        self.normalized.chars().count()
    }

    /// Returns true if the carrier is empty.
    pub fn is_empty(&self) -> bool {
        self.normalized.is_empty()
    }

    /// Finds a substring in the carrier, returning its character position.
    /// Search is case-insensitive.
    pub fn find(&self, substring: &str) -> Option<usize> {
        let normalized_sub = normalize_text(substring);
        self.normalized.find(&normalized_sub).map(|byte_pos| {
            // Convert byte position to character position
            self.normalized[..byte_pos].chars().count()
        })
    }

    /// Finds all occurrences of a substring in the carrier.
    /// Returns character positions of all matches.
    pub fn find_all(&self, substring: &str) -> Vec<usize> {
        let normalized_sub = normalize_text(substring);
        let mut positions = Vec::new();
        let mut start = 0;

        while let Some(byte_pos) = self.normalized[start..].find(&normalized_sub) {
            let absolute_byte_pos = start + byte_pos;
            let char_pos = self.normalized[..absolute_byte_pos].chars().count();
            positions.push(char_pos);
            start = absolute_byte_pos + normalized_sub.len();
        }

        positions
    }

    /// Extracts a substring from the carrier at the given character position and length.
    /// Returns the original (not normalized) text.
    pub fn extract(&self, char_pos: usize, char_len: usize) -> Option<String> {
        let chars: Vec<char> = self.original.chars().collect();

        if char_pos >= chars.len() {
            return None;
        }

        let end = (char_pos + char_len).min(chars.len());
        Some(chars[char_pos..end].iter().collect())
    }

    /// Extracts with wrap-around: if position is out of bounds, uses modulo.
    /// This ensures we ALWAYS return something.
    pub fn extract_wrapped(&self, char_pos: usize, char_len: usize) -> String {
        let chars: Vec<char> = self.original.chars().collect();

        if chars.is_empty() {
            return String::new();
        }

        let actual_pos = char_pos % chars.len();
        let mut result = String::new();

        for i in 0..char_len {
            let idx = (actual_pos + i) % chars.len();
            result.push(chars[idx]);
        }

        result
    }
}

/// Finds a substring in a carrier text, returning its character position.
/// This is a convenience function that creates a CarrierSearch internally.
pub fn find_substring(carrier: &str, substring: &str) -> Option<usize> {
    CarrierSearch::new(carrier).find(substring)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_text() {
        assert_eq!(normalize_text("HoLa MuNdO"), "hola mundo");
        assert_eq!(normalize_text("ÁÉÍÓÚ"), "áéíóú");
    }

    #[test]
    fn test_carrier_search_find() {
        let carrier = CarrierSearch::new("El gato negro duerme");

        assert_eq!(carrier.find("gato"), Some(3));
        assert_eq!(carrier.find("GATO"), Some(3)); // case insensitive
        assert_eq!(carrier.find("perro"), None);
    }

    #[test]
    fn test_carrier_search_find_all() {
        let carrier = CarrierSearch::new("el gato y el perro");

        let positions = carrier.find_all("el");
        assert_eq!(positions, vec![0, 10]);
    }

    #[test]
    fn test_carrier_extract() {
        let carrier = CarrierSearch::new("Hola Mundo");

        assert_eq!(carrier.extract(0, 4), Some("Hola".to_string()));
        assert_eq!(carrier.extract(5, 5), Some("Mundo".to_string()));
        assert_eq!(carrier.extract(100, 5), None);
    }

    #[test]
    fn test_carrier_extract_wrapped() {
        let carrier = CarrierSearch::new("Hola");

        // Normal extraction
        assert_eq!(carrier.extract_wrapped(0, 2), "Ho");

        // Wrap around position
        assert_eq!(carrier.extract_wrapped(100, 2), "Ho"); // 100 % 4 = 0

        // Wrap around length
        assert_eq!(carrier.extract_wrapped(2, 4), "laHo"); // wraps around
    }

    #[test]
    fn test_find_substring_convenience() {
        let carrier = "Amanda fue al parque";

        assert_eq!(find_substring(carrier, "am"), Some(0)); // "Amanda" starts with "am"
        assert_eq!(find_substring(carrier, "parque"), Some(14));
    }

    #[test]
    fn test_unicode_positions() {
        let carrier = CarrierSearch::new("café niño");

        // "niño" starts at character position 5
        assert_eq!(carrier.find("niño"), Some(5));

        // Extract should work with unicode
        assert_eq!(carrier.extract(0, 4), Some("café".to_string()));
    }
}
