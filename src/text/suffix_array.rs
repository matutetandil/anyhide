//! Suffix Array implementation for fast substring search.
//!
//! A suffix array provides O(m * log n) substring search where:
//! - n = length of the text
//! - m = length of the pattern
//!
//! This is much faster than naive O(n * m) search for repeated queries.

/// A suffix array with precomputed data for fast substring search.
#[derive(Debug, Clone)]
pub struct SuffixArray {
    /// The original text (lowercase for case-insensitive search).
    text: String,
    /// Sorted array of suffix starting positions.
    suffixes: Vec<usize>,
}

impl SuffixArray {
    /// Builds a suffix array from the given text.
    ///
    /// Time complexity: O(n * log^2 n) using comparison-based sorting.
    /// For most practical use cases with carriers < 100KB, this is fast enough.
    pub fn new(text: &str) -> Self {
        let text_lower = text.to_lowercase();
        let n = text_lower.len();

        if n == 0 {
            return Self {
                text: text_lower,
                suffixes: vec![],
            };
        }

        // Create all suffix indices
        let mut suffixes: Vec<usize> = (0..n).collect();

        // Sort suffixes lexicographically
        // This is O(n * log n * m) in worst case, but typically much faster
        let text_bytes = text_lower.as_bytes();
        suffixes.sort_by(|&a, &b| text_bytes[a..].cmp(&text_bytes[b..]));

        Self {
            text: text_lower,
            suffixes,
        }
    }

    /// Returns the length of the indexed text.
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Returns true if the indexed text is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Finds all occurrences of a pattern in the text.
    ///
    /// Time complexity: O(m * log n) for binary search + O(k) for collecting results,
    /// where k is the number of matches.
    ///
    /// Returns positions (byte indices) where the pattern starts.
    pub fn find_all(&self, pattern: &str) -> Vec<usize> {
        if pattern.is_empty() || self.suffixes.is_empty() {
            return vec![];
        }

        let pattern_lower = pattern.to_lowercase();
        let pattern_bytes = pattern_lower.as_bytes();
        let text_bytes = self.text.as_bytes();

        // Binary search for the range of matching suffixes
        let left = self.lower_bound(pattern_bytes, text_bytes);
        let right = self.upper_bound(pattern_bytes, text_bytes);

        if left >= right {
            return vec![];
        }

        // Collect all matching positions
        self.suffixes[left..right].to_vec()
    }

    /// Binary search for the first suffix >= pattern.
    fn lower_bound(&self, pattern: &[u8], text: &[u8]) -> usize {
        let mut lo = 0;
        let mut hi = self.suffixes.len();

        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let suffix_start = self.suffixes[mid];
            let suffix = &text[suffix_start..];

            if self.compare_prefix(suffix, pattern) < std::cmp::Ordering::Equal {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        lo
    }

    /// Binary search for the first suffix > pattern (treating pattern as prefix).
    fn upper_bound(&self, pattern: &[u8], text: &[u8]) -> usize {
        let mut lo = 0;
        let mut hi = self.suffixes.len();

        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let suffix_start = self.suffixes[mid];
            let suffix = &text[suffix_start..];

            if self.compare_prefix(suffix, pattern) <= std::cmp::Ordering::Equal {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        lo
    }

    /// Compares suffix with pattern, treating pattern as a prefix.
    /// Returns:
    /// - Less if suffix < pattern
    /// - Equal if suffix starts with pattern
    /// - Greater if suffix > pattern
    fn compare_prefix(&self, suffix: &[u8], pattern: &[u8]) -> std::cmp::Ordering {
        let len = pattern.len().min(suffix.len());

        for i in 0..len {
            match suffix[i].cmp(&pattern[i]) {
                std::cmp::Ordering::Less => return std::cmp::Ordering::Less,
                std::cmp::Ordering::Greater => return std::cmp::Ordering::Greater,
                std::cmp::Ordering::Equal => continue,
            }
        }

        // If we've compared all of pattern and they match, suffix starts with pattern
        if suffix.len() >= pattern.len() {
            std::cmp::Ordering::Equal
        } else {
            // Suffix is shorter than pattern and matches so far -> suffix < pattern
            std::cmp::Ordering::Less
        }
    }

    /// Extracts a substring at the given byte position with the given length.
    pub fn extract(&self, pos: usize, len: usize) -> Option<&str> {
        if pos >= self.text.len() {
            return None;
        }
        let end = (pos + len).min(self.text.len());
        self.text.get(pos..end)
    }

    /// Returns a reference to the indexed text.
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// An indexed carrier that uses suffix array for fast substring search.
#[derive(Debug, Clone)]
pub struct IndexedCarrier {
    /// The suffix array for the carrier.
    suffix_array: SuffixArray,
    /// Character to byte position mapping for Unicode support.
    char_to_byte: Vec<usize>,
    /// Byte to character position mapping.
    byte_to_char: Vec<usize>,
}

impl IndexedCarrier {
    /// Creates an indexed carrier from text.
    pub fn new(text: &str) -> Self {
        let text_lower = text.to_lowercase();

        // Build character <-> byte mappings for Unicode support
        let mut char_to_byte = Vec::with_capacity(text_lower.chars().count());
        let mut byte_to_char = vec![0; text_lower.len() + 1];

        for (char_idx, (byte_idx, _)) in text_lower.char_indices().enumerate() {
            char_to_byte.push(byte_idx);
            byte_to_char[byte_idx] = char_idx;
        }

        // Fill in byte_to_char for multi-byte characters
        let mut last_char_idx = 0;
        for byte_idx in 0..=text_lower.len() {
            if byte_idx < text_lower.len() {
                if text_lower.is_char_boundary(byte_idx) {
                    last_char_idx = byte_to_char[byte_idx];
                } else {
                    byte_to_char[byte_idx] = last_char_idx;
                }
            }
        }

        Self {
            suffix_array: SuffixArray::new(&text_lower),
            char_to_byte,
            byte_to_char,
        }
    }

    /// Returns the number of characters in the carrier.
    pub fn len(&self) -> usize {
        self.char_to_byte.len()
    }

    /// Returns true if the carrier is empty.
    pub fn is_empty(&self) -> bool {
        self.char_to_byte.is_empty()
    }

    /// Finds all occurrences of a pattern, returning character positions.
    pub fn find_all(&self, pattern: &str) -> Vec<usize> {
        let byte_positions = self.suffix_array.find_all(pattern);

        // Convert byte positions to character positions
        byte_positions
            .into_iter()
            .filter_map(|byte_pos| {
                if byte_pos < self.byte_to_char.len() {
                    Some(self.byte_to_char[byte_pos])
                } else {
                    None
                }
            })
            .collect()
    }

    /// Extracts text at a character position with given character length.
    pub fn extract(&self, char_pos: usize, char_len: usize) -> Option<String> {
        if char_pos >= self.char_to_byte.len() {
            return None;
        }

        let start_byte = self.char_to_byte[char_pos];
        let end_char = (char_pos + char_len).min(self.char_to_byte.len());

        let end_byte = if end_char < self.char_to_byte.len() {
            self.char_to_byte[end_char]
        } else {
            self.suffix_array.text.len()
        };

        self.suffix_array.text.get(start_byte..end_byte).map(|s| s.to_string())
    }

    /// Extracts text with wrapping (for positions near the end).
    pub fn extract_wrapped(&self, char_pos: usize, char_len: usize) -> String {
        if self.is_empty() {
            return String::new();
        }

        let pos = char_pos % self.len();
        let mut result = String::new();
        let mut remaining = char_len;
        let mut current_pos = pos;

        while remaining > 0 {
            let available = self.len() - current_pos;
            let take = remaining.min(available);

            if let Some(chunk) = self.extract(current_pos, take) {
                result.push_str(&chunk);
            }

            remaining -= take;
            current_pos = 0; // Wrap to beginning
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suffix_array_basic() {
        let sa = SuffixArray::new("banana");
        let positions = sa.find_all("ana");
        assert_eq!(positions.len(), 2);
        assert!(positions.contains(&1)); // b[ana]na
        assert!(positions.contains(&3)); // ban[ana]
    }

    #[test]
    fn test_suffix_array_case_insensitive() {
        let sa = SuffixArray::new("BANANA");
        let positions = sa.find_all("ana");
        assert_eq!(positions.len(), 2);
    }

    #[test]
    fn test_suffix_array_not_found() {
        let sa = SuffixArray::new("hello world");
        let positions = sa.find_all("xyz");
        assert!(positions.is_empty());
    }

    #[test]
    fn test_suffix_array_empty_pattern() {
        let sa = SuffixArray::new("hello");
        let positions = sa.find_all("");
        assert!(positions.is_empty());
    }

    #[test]
    fn test_suffix_array_empty_text() {
        let sa = SuffixArray::new("");
        let positions = sa.find_all("hello");
        assert!(positions.is_empty());
    }

    #[test]
    fn test_suffix_array_single_char() {
        let sa = SuffixArray::new("aaaaaa");
        let positions = sa.find_all("a");
        assert_eq!(positions.len(), 6);
    }

    #[test]
    fn test_indexed_carrier_unicode() {
        let carrier = IndexedCarrier::new("hola ñoño mundo");
        let positions = carrier.find_all("ñoño");
        assert_eq!(positions.len(), 1);
        assert_eq!(positions[0], 5); // Character position, not byte
    }

    #[test]
    fn test_indexed_carrier_extract() {
        let carrier = IndexedCarrier::new("hello world");
        let extracted = carrier.extract(0, 5);
        assert_eq!(extracted, Some("hello".to_string()));
    }

    #[test]
    fn test_indexed_carrier_extract_wrapped() {
        let carrier = IndexedCarrier::new("hello");
        let extracted = carrier.extract_wrapped(3, 4); // "lo" + "he"
        assert_eq!(extracted, "lohe");
    }
}
