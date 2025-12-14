//! Carrier permutation and distributed position selection for KAMO v0.4.
//!
//! This module provides:
//! - Deterministic carrier permutation based on passphrase
//! - Distributed position selection across multiple occurrences

use hkdf::Hkdf;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

/// HKDF salt for carrier permutation.
pub const SALT_PERMUTE: &[u8] = b"KAMO-PERMUTE-V4";

/// HKDF salt for distributed position selection.
pub const SALT_DISTRIBUTE: &[u8] = b"KAMO-DISTRIBUTE-V4";

/// Permutes carrier words deterministically based on passphrase.
///
/// The same carrier + passphrase always produces the same permutation.
/// Different passphrases produce different permutations.
pub fn permute_carrier(carrier: &str, passphrase: &str) -> Vec<String> {
    let words: Vec<&str> = carrier.split_whitespace().collect();
    let n = words.len();

    if n == 0 {
        return vec![];
    }

    // Derive seed from passphrase
    let seed = derive_seed(passphrase.as_bytes(), SALT_PERMUTE);
    let mut rng = ChaCha20Rng::from_seed(seed);

    // Create shuffled indices
    let mut indices: Vec<usize> = (0..n).collect();
    indices.shuffle(&mut rng);

    // Return words in permuted order
    indices.iter().map(|&i| words[i].to_string()).collect()
}

/// Finds a fragment in the permuted carrier, distributing across all occurrences.
///
/// If there are multiple occurrences of the fragment, the selection is
/// deterministic based on passphrase and fragment index.
pub fn find_distributed(
    fragment: &str,
    carrier: &[String],
    passphrase: &str,
    fragment_index: usize,
) -> Option<usize> {
    // Find all occurrences
    let occurrences: Vec<usize> = carrier
        .iter()
        .enumerate()
        .filter(|(_, w)| normalize(w) == normalize(fragment))
        .map(|(i, _)| i)
        .collect();

    if occurrences.is_empty() {
        return None;
    }

    if occurrences.len() == 1 {
        return Some(occurrences[0]);
    }

    // Select deterministically based on passphrase and fragment index
    let selector_input = [passphrase.as_bytes(), &fragment_index.to_le_bytes()].concat();

    let hash = derive_seed(&selector_input, SALT_DISTRIBUTE);
    let selector = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]) as usize;

    Some(occurrences[selector % occurrences.len()])
}

/// Normalizes a word for comparison (lowercase, alphanumeric only).
pub fn normalize(word: &str) -> String {
    word.chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_lowercase()
}

/// Derives a 32-byte seed using HKDF-SHA256.
fn derive_seed(input: &[u8], salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), input);
    let mut output = [0u8; 32];
    hk.expand(b"seed", &mut output)
        .expect("HKDF expand should not fail");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permutation_deterministic() {
        let carrier = "uno dos tres cuatro cinco";
        let pass = "test123";

        let p1 = permute_carrier(carrier, pass);
        let p2 = permute_carrier(carrier, pass);

        assert_eq!(p1, p2);
    }

    #[test]
    fn test_permutation_different_passphrase() {
        let carrier = "uno dos tres cuatro cinco";

        let p1 = permute_carrier(carrier, "pass1");
        let p2 = permute_carrier(carrier, "pass2");

        assert_ne!(p1, p2);
    }

    #[test]
    fn test_permutation_contains_all_words() {
        let carrier = "uno dos tres cuatro cinco";
        let permuted = permute_carrier(carrier, "test");

        let original: Vec<&str> = carrier.split_whitespace().collect();
        assert_eq!(permuted.len(), original.len());

        // All original words should be present
        for word in original {
            assert!(permuted.contains(&word.to_string()));
        }
    }

    #[test]
    fn test_permutation_empty_carrier() {
        let permuted = permute_carrier("", "test");
        assert!(permuted.is_empty());
    }

    #[test]
    fn test_find_distributed_single_occurrence() {
        let carrier = vec![
            "uno".to_string(),
            "dos".to_string(),
            "tres".to_string(),
        ];

        let pos = find_distributed("dos", &carrier, "test", 0);
        assert_eq!(pos, Some(1));
    }

    #[test]
    fn test_find_distributed_multiple_occurrences() {
        let carrier = vec![
            "hola".to_string(),
            "mundo".to_string(),
            "hola".to_string(),
            "otra".to_string(),
            "hola".to_string(),
        ];

        // Should find one of the three "hola" positions
        let pos = find_distributed("hola", &carrier, "test", 0);
        assert!(pos.is_some());
        let p = pos.unwrap();
        assert!(p == 0 || p == 2 || p == 4);
    }

    #[test]
    fn test_find_distributed_deterministic() {
        let carrier = vec![
            "hola".to_string(),
            "mundo".to_string(),
            "hola".to_string(),
        ];

        let pos1 = find_distributed("hola", &carrier, "test", 0);
        let pos2 = find_distributed("hola", &carrier, "test", 0);

        assert_eq!(pos1, pos2);
    }

    #[test]
    fn test_find_distributed_different_index() {
        let carrier = vec![
            "a".to_string(),
            "a".to_string(),
            "a".to_string(),
            "a".to_string(),
            "a".to_string(),
        ];

        // Different fragment indices should potentially select different positions
        let positions: Vec<usize> = (0..10)
            .filter_map(|i| find_distributed("a", &carrier, "test", i))
            .collect();

        // With 5 occurrences and 10 tries, we should hit multiple positions
        let unique: std::collections::HashSet<_> = positions.iter().collect();
        assert!(unique.len() > 1, "Expected distribution across positions");
    }

    #[test]
    fn test_find_distributed_not_found() {
        let carrier = vec!["uno".to_string(), "dos".to_string()];

        let pos = find_distributed("tres", &carrier, "test", 0);
        assert_eq!(pos, None);
    }

    #[test]
    fn test_normalize() {
        assert_eq!(normalize("Hola!"), "hola");
        assert_eq!(normalize("¿Cómo?"), "cómo");
        assert_eq!(normalize("Hello, World!"), "helloworld");
    }

    #[test]
    fn test_find_distributed_case_insensitive() {
        let carrier = vec!["HOLA".to_string(), "mundo".to_string()];

        let pos = find_distributed("hola", &carrier, "test", 0);
        assert_eq!(pos, Some(0));
    }
}
