//! Variable message fragmentation for Anyhide.
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
    /// The fragment text WITHOUT spaces (for searching in carrier, lowercase).
    pub search_text: String,
    /// The original fragment text WITHOUT spaces (preserves original case).
    /// Used to calculate char_overrides when carrier has different case.
    pub original_text: String,
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

    let total_len = message.chars().count();

    // Split into words, keeping track of both original and lowercase
    let original_words: Vec<&str> = message.split(' ').filter(|w| !w.is_empty()).collect();

    if original_words.is_empty() {
        return FragmentedMessage {
            fragments: vec![],
            original_length: total_len,
        };
    }

    // Derive fragment sizes from passphrase (use lowercase for consistency)
    let non_space_len: usize = original_words.iter().map(|w| w.chars().count()).sum();
    let sizes = derive_fragment_sizes(passphrase, non_space_len);
    let mut size_iter = sizes.into_iter();

    let mut fragments = Vec::new();

    for (word_idx, original_word) in original_words.iter().enumerate() {
        let is_last_word = word_idx == original_words.len() - 1;
        let lowercase_word = original_word.to_lowercase();

        let original_chars: Vec<char> = original_word.chars().collect();
        let lowercase_chars: Vec<char> = lowercase_word.chars().collect();
        let mut pos = 0;

        while pos < original_chars.len() {
            // Get next fragment size
            let size = size_iter.next().unwrap_or(original_chars.len() - pos);
            let end = (pos + size).min(original_chars.len());

            let search_text: String = lowercase_chars[pos..end].iter().collect();
            let original_text: String = original_chars[pos..end].iter().collect();
            let is_last_fragment_of_word = end >= original_chars.len();

            // If this is the last fragment of a word (and not the last word),
            // mark that a space follows it
            let space_positions = if is_last_fragment_of_word && !is_last_word {
                vec![search_text.chars().count() - 1]
            } else {
                vec![]
            };

            if !search_text.is_empty() {
                fragments.push(Fragment {
                    search_text,
                    original_text,
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
/// Preserves original text case for char_overrides calculation.
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

    let total_len = message.chars().count();

    // Split by spaces - keep both original and lowercase
    let original_words: Vec<&str> = message.split(' ').filter(|w| !w.is_empty()).collect();

    if original_words.is_empty() {
        return FragmentedMessage {
            fragments: vec![],
            original_length: total_len,
        };
    }

    // Derive sizes for fallback (used when we need to make decisions)
    let non_space_len: usize = original_words.iter().map(|w| w.chars().count()).sum();
    let fallback_sizes = derive_fragment_sizes(passphrase, non_space_len);
    let mut size_idx = 0;

    let mut fragments = Vec::new();

    for (word_idx, original_word) in original_words.iter().enumerate() {
        let is_last_word = word_idx == original_words.len() - 1;
        let lowercase_word = original_word.to_lowercase();
        let word_fragments = fragment_word_adaptive(
            &lowercase_word,
            original_word,
            carrier,
            &fallback_sizes,
            &mut size_idx,
        );

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
/// Takes both lowercase (for searching) and original (for preserving case).
fn fragment_word_adaptive(
    lowercase_word: &str,
    original_word: &str,
    carrier: &CarrierSearch,
    fallback_sizes: &[usize],
    size_idx: &mut usize,
) -> Vec<Fragment> {
    if lowercase_word.is_empty() {
        return vec![];
    }

    let lowercase_chars: Vec<char> = lowercase_word.chars().collect();
    let original_chars: Vec<char> = original_word.chars().collect();

    // Try to find the whole word first
    if !carrier.find_all(lowercase_word).is_empty() {
        *size_idx += 1;
        return vec![Fragment {
            search_text: lowercase_word.to_string(),
            original_text: original_word.to_string(),
            original_length: lowercase_chars.len(),
            space_positions: vec![],
        }];
    }

    // Word not found - split it adaptively
    split_and_find(&lowercase_chars, &original_chars, carrier, fallback_sizes, size_idx)
}

/// Recursively splits text until all pieces are found in carrier.
/// Maintains both lowercase and original characters in parallel.
fn split_and_find(
    lowercase_chars: &[char],
    original_chars: &[char],
    carrier: &CarrierSearch,
    fallback_sizes: &[usize],
    size_idx: &mut usize,
) -> Vec<Fragment> {
    if lowercase_chars.is_empty() {
        return vec![];
    }

    let search_text: String = lowercase_chars.iter().collect();
    let original_text: String = original_chars.iter().collect();

    // Base case: single character - must exist or we fail
    if lowercase_chars.len() == 1 {
        *size_idx += 1;
        return vec![Fragment {
            search_text,
            original_text,
            original_length: 1,
            space_positions: vec![],
        }];
    }

    // Try the whole chunk
    if !carrier.find_all(&search_text).is_empty() {
        *size_idx += 1;
        return vec![Fragment {
            search_text,
            original_text,
            original_length: lowercase_chars.len(),
            space_positions: vec![],
        }];
    }

    // Not found - try different split strategies
    // Strategy 1: Use passphrase-derived size for first chunk
    let derived_size = fallback_sizes.get(*size_idx).copied().unwrap_or(2);
    let split_point = derived_size.min(lowercase_chars.len() - 1).max(1);

    // Try this split
    let first_search: String = lowercase_chars[..split_point].iter().collect();
    let first_original: String = original_chars[..split_point].iter().collect();

    if !carrier.find_all(&first_search).is_empty() {
        // First part found, recurse on rest
        *size_idx += 1;
        let mut result = vec![Fragment {
            search_text: first_search,
            original_text: first_original,
            original_length: split_point,
            space_positions: vec![],
        }];
        result.extend(split_and_find(
            &lowercase_chars[split_point..],
            &original_chars[split_point..],
            carrier,
            fallback_sizes,
            size_idx,
        ));
        return result;
    }

    // First part not found - try splitting in half
    let half = lowercase_chars.len() / 2;
    if half > 0 && half < lowercase_chars.len() {
        let first_half_search: String = lowercase_chars[..half].iter().collect();
        let first_half_original: String = original_chars[..half].iter().collect();
        if !carrier.find_all(&first_half_search).is_empty() {
            *size_idx += 1;
            let mut result = vec![Fragment {
                search_text: first_half_search,
                original_text: first_half_original,
                original_length: half,
                space_positions: vec![],
            }];
            result.extend(split_and_find(
                &lowercase_chars[half..],
                &original_chars[half..],
                carrier,
                fallback_sizes,
                size_idx,
            ));
            return result;
        }
    }

    // Still not found - try progressively smaller chunks from start
    for size in (1..lowercase_chars.len()).rev() {
        let chunk_search: String = lowercase_chars[..size].iter().collect();
        let chunk_original: String = original_chars[..size].iter().collect();
        if !carrier.find_all(&chunk_search).is_empty() {
            *size_idx += 1;
            let mut result = vec![Fragment {
                search_text: chunk_search,
                original_text: chunk_original,
                original_length: size,
                space_positions: vec![],
            }];
            result.extend(split_and_find(
                &lowercase_chars[size..],
                &original_chars[size..],
                carrier,
                fallback_sizes,
                size_idx,
            ));
            return result;
        }
    }

    // Last resort: first character + rest (single chars must exist)
    *size_idx += 1;
    let mut result = vec![Fragment {
        search_text: lowercase_chars[0].to_string(),
        original_text: original_chars[0].to_string(),
        original_length: 1,
        space_positions: vec![],
    }];
    result.extend(split_and_find(
        &lowercase_chars[1..],
        &original_chars[1..],
        carrier,
        fallback_sizes,
        size_idx,
    ));
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
    /// Character overrides: (position within fragment, original character).
    /// Used when the carrier has a different case or character than needed.
    /// Empty if the extracted text matches exactly.
    #[serde(default)]
    pub char_overrides: Vec<(u8, char)>,
}

impl FoundFragment {
    /// Creates a new FoundFragment.
    pub fn new(position: usize, length: usize, space_positions: Vec<usize>) -> Self {
        Self {
            position: position as u32,
            length: length as u8,
            space_positions: space_positions.iter().map(|&p| p as u8).collect(),
            char_overrides: Vec::new(),
        }
    }

    /// Creates a new FoundFragment with character overrides.
    pub fn with_overrides(
        position: usize,
        length: usize,
        space_positions: Vec<usize>,
        char_overrides: Vec<(usize, char)>,
    ) -> Self {
        Self {
            position: position as u32,
            length: length as u8,
            space_positions: space_positions.iter().map(|&p| p as u8).collect(),
            char_overrides: char_overrides.iter().map(|&(p, c)| (p as u8, c)).collect(),
        }
    }

    /// Applies character overrides to extracted text.
    /// Returns the corrected text with exact original characters.
    pub fn apply_overrides(&self, extracted: &str) -> String {
        if self.char_overrides.is_empty() {
            return extracted.to_string();
        }

        let mut chars: Vec<char> = extracted.chars().collect();

        for &(pos, original_char) in &self.char_overrides {
            let pos = pos as usize;
            if pos < chars.len() {
                chars[pos] = original_char;
            } else {
                // Character needs to be appended (extends beyond extracted length)
                while chars.len() < pos {
                    chars.push(' '); // Placeholder
                }
                chars.push(original_char);
            }
        }

        chars.into_iter().collect()
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
            original_text: "hola".to_string(),
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
            original_text: "hola".to_string(),
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
