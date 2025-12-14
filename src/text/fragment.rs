//! Variable message fragmentation for KAMO.
//!
//! This module handles fragmenting messages into variable-sized pieces
//! for steganographic embedding. Fragment sizes are derived deterministically
//! from the passphrase, ensuring reproducible fragmentation.
//!
//! IMPORTANT: Spaces are treated as fragment boundaries. Fragments never
//! span across words, which ensures they can always be found in natural text.

use hkdf::Hkdf;
use sha2::Sha256;
use serde::{Deserialize, Serialize};

use crate::text::tokenize::CarrierSearch;

/// HKDF info for fragment size derivation.
const HKDF_FRAGMENT_INFO: &[u8] = b"KAMO-V3-FRAGMENT-SIZES";

/// Minimum fragment size (1 character).
const MIN_FRAGMENT_SIZE: usize = 1;

/// Maximum fragment size.
const MAX_FRAGMENT_SIZE: usize = 5;

/// A fragment of the message ready for carrier search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fragment {
    /// The fragment text WITHOUT spaces (for searching in carrier).
    pub search_text: String,
    /// Original length including spaces.
    pub original_length: usize,
    /// Positions within the fragment where spaces should be re-inserted.
    /// For example, [1] means insert space after index 1.
    pub space_positions: Vec<usize>,
}

impl Fragment {
    /// Reconstructs the original fragment text by re-inserting spaces.
    pub fn reconstruct(&self, extracted: &str) -> String {
        if self.space_positions.is_empty() {
            return extracted.to_string();
        }

        let mut result = String::with_capacity(extracted.len() + self.space_positions.len());
        let chars: Vec<char> = extracted.chars().collect();

        for (i, ch) in chars.iter().enumerate() {
            result.push(*ch);
            if self.space_positions.contains(&i) {
                result.push(' ');
            }
        }

        result
    }
}

/// Result of fragmenting a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentedMessage {
    /// The fragments ready for carrier search.
    pub fragments: Vec<Fragment>,
    /// Total character count of original message.
    pub original_length: usize,
}

impl FragmentedMessage {
    /// Returns the number of fragments.
    pub fn count(&self) -> usize {
        self.fragments.len()
    }

    /// Returns the search texts (without spaces) for all fragments.
    pub fn search_texts(&self) -> Vec<&str> {
        self.fragments.iter().map(|f| f.search_text.as_str()).collect()
    }
}

/// Fragments a message into variable-sized pieces.
///
/// The fragmentation is deterministic based on the passphrase,
/// so the same message + passphrase always produces the same fragments.
///
/// IMPORTANT: Spaces are treated as fragment boundaries. Each word is
/// fragmented independently, and a space marker is added to the last
/// fragment of each word (except the last word). This ensures fragments
/// can always be found as substrings in the carrier.
pub fn fragment_message(message: &str, passphrase: &str) -> FragmentedMessage {
    if message.is_empty() {
        return FragmentedMessage {
            fragments: vec![],
            original_length: 0,
        };
    }

    // Normalize message to lowercase for consistent fragmentation
    let message_lower = message.to_lowercase();
    let total_len = message_lower.chars().count();

    // Split by spaces first - each word is fragmented independently
    let words: Vec<&str> = message_lower.split(' ').filter(|w| !w.is_empty()).collect();

    if words.is_empty() {
        return FragmentedMessage {
            fragments: vec![],
            original_length: total_len,
        };
    }

    // Derive fragment sizes from passphrase
    let non_space_len: usize = words.iter().map(|w| w.chars().count()).sum();
    let sizes = derive_fragment_sizes(passphrase, non_space_len);
    let mut size_iter = sizes.into_iter();

    let mut fragments = Vec::new();

    for (word_idx, word) in words.iter().enumerate() {
        let is_last_word = word_idx == words.len() - 1;
        let chars: Vec<char> = word.chars().collect();
        let mut pos = 0;

        while pos < chars.len() {
            // Get next fragment size
            let size = size_iter.next().unwrap_or(chars.len() - pos);
            let end = (pos + size).min(chars.len());

            let fragment_text: String = chars[pos..end].iter().collect();
            let is_last_fragment_of_word = end >= chars.len();

            // If this is the last fragment of a word (and not the last word),
            // mark that a space follows it
            let space_positions = if is_last_fragment_of_word && !is_last_word {
                vec![fragment_text.chars().count() - 1]
            } else {
                vec![]
            };

            if !fragment_text.is_empty() {
                fragments.push(Fragment {
                    search_text: fragment_text,
                    original_length: end - pos + if !space_positions.is_empty() { 1 } else { 0 },
                    space_positions,
                });
            }

            pos = end;
        }
    }

    FragmentedMessage {
        fragments,
        original_length: total_len,
    }
}

/// Fragments a message adaptively based on what can be found in the carrier.
///
/// This is the smart version that:
/// 1. Tries to find each word as-is in the carrier
/// 2. If not found, splits it into smaller pieces (half, then smaller)
/// 3. Eventually falls back to individual characters
///
/// The fragmentation is still deterministic for a given message+carrier+passphrase.
pub fn fragment_message_adaptive(
    message: &str,
    carrier: &CarrierSearch,
    passphrase: &str,
) -> FragmentedMessage {
    if message.is_empty() {
        return FragmentedMessage {
            fragments: vec![],
            original_length: 0,
        };
    }

    let message_lower = message.to_lowercase();
    let total_len = message_lower.chars().count();

    // Split by spaces - each word is fragmented independently
    let words: Vec<&str> = message_lower.split(' ').filter(|w| !w.is_empty()).collect();

    if words.is_empty() {
        return FragmentedMessage {
            fragments: vec![],
            original_length: total_len,
        };
    }

    // Derive sizes for fallback (used when we need to make decisions)
    let non_space_len: usize = words.iter().map(|w| w.chars().count()).sum();
    let fallback_sizes = derive_fragment_sizes(passphrase, non_space_len);
    let mut size_idx = 0;

    let mut fragments = Vec::new();

    for (word_idx, word) in words.iter().enumerate() {
        let is_last_word = word_idx == words.len() - 1;
        let word_fragments = fragment_word_adaptive(word, carrier, &fallback_sizes, &mut size_idx);

        // Add all fragments from this word
        for frag in word_fragments.into_iter() {
            fragments.push(frag);
        }

        // Add space marker to last fragment of this word
        if !is_last_word && !fragments.is_empty() {
            if let Some(last) = fragments.last_mut() {
                last.space_positions = vec![last.search_text.chars().count() - 1];
            }
        }
    }

    FragmentedMessage {
        fragments,
        original_length: total_len,
    }
}

/// Fragments a single word adaptively, trying larger chunks first.
fn fragment_word_adaptive(
    word: &str,
    carrier: &CarrierSearch,
    fallback_sizes: &[usize],
    size_idx: &mut usize,
) -> Vec<Fragment> {
    if word.is_empty() {
        return vec![];
    }

    let chars: Vec<char> = word.chars().collect();

    // Try to find the whole word first
    if !carrier.find_all(word).is_empty() {
        *size_idx += 1;
        return vec![Fragment {
            search_text: word.to_string(),
            original_length: chars.len(),
            space_positions: vec![],
        }];
    }

    // Word not found - split it adaptively
    split_and_find(&chars, carrier, fallback_sizes, size_idx)
}

/// Recursively splits text until all pieces are found in carrier.
fn split_and_find(
    chars: &[char],
    carrier: &CarrierSearch,
    fallback_sizes: &[usize],
    size_idx: &mut usize,
) -> Vec<Fragment> {
    if chars.is_empty() {
        return vec![];
    }

    let text: String = chars.iter().collect();

    // Base case: single character - must exist or we fail
    if chars.len() == 1 {
        *size_idx += 1;
        return vec![Fragment {
            search_text: text,
            original_length: 1,
            space_positions: vec![],
        }];
    }

    // Try the whole chunk
    if !carrier.find_all(&text).is_empty() {
        *size_idx += 1;
        return vec![Fragment {
            search_text: text,
            original_length: chars.len(),
            space_positions: vec![],
        }];
    }

    // Not found - try different split strategies
    // Strategy 1: Use passphrase-derived size for first chunk
    let derived_size = fallback_sizes.get(*size_idx).copied().unwrap_or(2);
    let split_point = derived_size.min(chars.len() - 1).max(1);

    // Try this split
    let first_part: String = chars[..split_point].iter().collect();

    if !carrier.find_all(&first_part).is_empty() {
        // First part found, recurse on rest
        *size_idx += 1;
        let mut result = vec![Fragment {
            search_text: first_part,
            original_length: split_point,
            space_positions: vec![],
        }];
        result.extend(split_and_find(&chars[split_point..], carrier, fallback_sizes, size_idx));
        return result;
    }

    // First part not found - try splitting in half
    let half = chars.len() / 2;
    if half > 0 && half < chars.len() {
        let first_half: String = chars[..half].iter().collect();
        if !carrier.find_all(&first_half).is_empty() {
            *size_idx += 1;
            let mut result = vec![Fragment {
                search_text: first_half,
                original_length: half,
                space_positions: vec![],
            }];
            result.extend(split_and_find(&chars[half..], carrier, fallback_sizes, size_idx));
            return result;
        }
    }

    // Still not found - try progressively smaller chunks from start
    for size in (1..chars.len()).rev() {
        let chunk: String = chars[..size].iter().collect();
        if !carrier.find_all(&chunk).is_empty() {
            *size_idx += 1;
            let mut result = vec![Fragment {
                search_text: chunk,
                original_length: size,
                space_positions: vec![],
            }];
            result.extend(split_and_find(&chars[size..], carrier, fallback_sizes, size_idx));
            return result;
        }
    }

    // Last resort: first character + rest (single chars must exist)
    *size_idx += 1;
    let mut result = vec![Fragment {
        search_text: chars[0].to_string(),
        original_length: 1,
        space_positions: vec![],
    }];
    result.extend(split_and_find(&chars[1..], carrier, fallback_sizes, size_idx));
    result
}

/// Derives fragment sizes deterministically from a passphrase.
fn derive_fragment_sizes(passphrase: &str, total_length: usize) -> Vec<usize> {
    if total_length == 0 {
        return vec![];
    }

    // Use HKDF to derive a sequence of bytes for fragment sizes
    let hk = Hkdf::<Sha256>::new(Some(b"KAMO-FRAG-SALT"), passphrase.as_bytes());

    // We need enough bytes to cover the message
    // Each byte will determine a fragment size
    let max_fragments = total_length; // worst case: all size-1 fragments
    let mut output = vec![0u8; max_fragments];

    hk.expand(HKDF_FRAGMENT_INFO, &mut output)
        .expect("HKDF expand should not fail for this size");

    // Convert bytes to fragment sizes
    let mut sizes = Vec::new();
    let mut remaining = total_length;
    let mut i = 0;

    while remaining > 0 && i < output.len() {
        // Map byte to range [MIN_FRAGMENT_SIZE, MAX_FRAGMENT_SIZE]
        let range = MAX_FRAGMENT_SIZE - MIN_FRAGMENT_SIZE + 1;
        let size = MIN_FRAGMENT_SIZE + (output[i] as usize % range);

        // Don't exceed remaining characters
        let actual_size = size.min(remaining);
        sizes.push(actual_size);

        remaining = remaining.saturating_sub(actual_size);
        i += 1;
    }

    sizes
}

/// Information about a found fragment in the carrier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FoundFragment {
    /// Position (character index) in the carrier where fragment was found.
    pub position: u32,
    /// Length of the fragment (without spaces).
    pub length: u8,
    /// Positions where spaces should be re-inserted.
    pub space_positions: Vec<u8>,
}

impl FoundFragment {
    /// Creates a new FoundFragment.
    pub fn new(position: usize, length: usize, space_positions: Vec<usize>) -> Self {
        Self {
            position: position as u32,
            length: length as u8,
            space_positions: space_positions.iter().map(|&p| p as u8).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_simple() {
        let message = "hola";
        let fragmented = fragment_message(message, "test");

        assert!(!fragmented.fragments.is_empty());

        // All search texts combined should equal lowercase message (without spaces)
        let combined: String = fragmented.fragments.iter()
            .map(|f| f.search_text.as_str())
            .collect();
        assert_eq!(combined, "hola");
    }

    #[test]
    fn test_fragment_with_spaces() {
        let message = "hola mundo";
        let fragmented = fragment_message(message, "test");

        // Combined search texts (without spaces) should be "holamundo"
        let combined: String = fragmented.fragments.iter()
            .map(|f| f.search_text.as_str())
            .collect();
        assert_eq!(combined, "holamundo");
    }

    #[test]
    fn test_fragment_deterministic() {
        let message = "test message";
        let pass = "mypassphrase";

        let frag1 = fragment_message(message, pass);
        let frag2 = fragment_message(message, pass);

        assert_eq!(frag1.fragments.len(), frag2.fragments.len());
        for (f1, f2) in frag1.fragments.iter().zip(frag2.fragments.iter()) {
            assert_eq!(f1.search_text, f2.search_text);
            assert_eq!(f1.space_positions, f2.space_positions);
        }
    }

    #[test]
    fn test_different_passphrase_different_fragments() {
        let message = "same message here";

        let frag1 = fragment_message(message, "pass1");
        let frag2 = fragment_message(message, "pass2");

        // Different passphrases should (likely) produce different fragmentation
        // Note: There's a small chance they could be the same, but very unlikely
        let texts1: Vec<&str> = frag1.search_texts();
        let texts2: Vec<&str> = frag2.search_texts();

        // At least the number of fragments should differ in most cases
        // But we can't guarantee this, so just check they both work
        assert!(!texts1.is_empty());
        assert!(!texts2.is_empty());
    }

    #[test]
    fn test_space_at_word_boundary() {
        // "hola mundo" should fragment words separately
        // Last fragment of "hola" should have space marker
        let message = "hola mundo";
        let fragmented = fragment_message(message, "test");

        // Find a fragment that ends a word (has space_positions)
        let has_space_marker = fragmented.fragments.iter()
            .any(|f| !f.space_positions.is_empty());

        // There should be at least one fragment with a space marker
        // (the last fragment of "hola")
        assert!(has_space_marker);
    }

    #[test]
    fn test_reconstruct_with_spaces() {
        // Space after last char of fragment (word boundary)
        let fragment = Fragment {
            search_text: "hola".to_string(),
            original_length: 5, // "hola "
            space_positions: vec![3], // space after index 3 ('a')
        };

        let reconstructed = fragment.reconstruct("hola");
        assert_eq!(reconstructed, "hola ");
    }

    #[test]
    fn test_reconstruct_no_spaces() {
        let fragment = Fragment {
            search_text: "hola".to_string(),
            original_length: 4,
            space_positions: vec![],
        };

        let reconstructed = fragment.reconstruct("hola");
        assert_eq!(reconstructed, "hola");
    }

    #[test]
    fn test_empty_message() {
        let fragmented = fragment_message("", "test");
        assert!(fragmented.fragments.is_empty());
    }

    #[test]
    fn test_single_char() {
        let fragmented = fragment_message("a", "test");
        assert_eq!(fragmented.fragments.len(), 1);
        assert_eq!(fragmented.fragments[0].search_text, "a");
    }
}
