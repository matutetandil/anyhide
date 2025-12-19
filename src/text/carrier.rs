//! Generic carrier abstraction for Anyhide.
//!
//! Supports both text and binary carriers (images, audio, etc.).
//! Text carriers use substring matching, binary carriers use byte-sequence matching.

use super::tokenize::CarrierSearch;

/// A carrier that can be either text or binary data.
#[derive(Debug, Clone)]
pub enum Carrier {
    /// Text carrier - uses substring matching (case-insensitive)
    Text(CarrierSearch),
    /// Binary carrier - uses byte-sequence matching
    Binary(BinaryCarrierSearch),
}

impl Carrier {
    /// Creates a text carrier from a string.
    pub fn from_text(text: &str) -> Self {
        Carrier::Text(CarrierSearch::new(text))
    }

    /// Creates a binary carrier from bytes.
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Carrier::Binary(BinaryCarrierSearch::new(data))
    }

    /// Detects carrier type from file extension and loads appropriately.
    pub fn from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match extension.as_str() {
            // Text files
            "txt" | "md" | "text" | "csv" | "json" | "xml" | "html" | "htm" => {
                let content = std::fs::read_to_string(path)?;
                Ok(Carrier::from_text(&content))
            }
            // Binary files (images, audio, etc.)
            _ => {
                let data = std::fs::read(path)?;
                Ok(Carrier::from_bytes(data))
            }
        }
    }

    /// Creates a carrier from multiple files concatenated in order.
    ///
    /// **Order matters!** Different order = different carrier = different decoding result.
    /// This provides N! additional security combinations for N carriers.
    ///
    /// - Single file: Delegates to `from_file()` (preserves text vs binary detection)
    /// - Multiple files: All read as bytes and concatenated (always binary carrier)
    pub fn from_files(paths: &[std::path::PathBuf]) -> std::io::Result<Self> {
        if paths.is_empty() {
            return Ok(Carrier::from_bytes(vec![]));
        }

        if paths.len() == 1 {
            return Self::from_file(&paths[0]);
        }

        // Multiple files: read all as bytes and concatenate in order
        let mut combined = Vec::new();
        for path in paths {
            let data = std::fs::read(path)?;
            combined.extend(data);
        }
        Ok(Carrier::from_bytes(combined))
    }

    /// Returns the length of the carrier (characters for text, bytes for binary).
    pub fn len(&self) -> usize {
        match self {
            Carrier::Text(c) => c.len(),
            Carrier::Binary(c) => c.len(),
        }
    }

    /// Returns true if the carrier is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            Carrier::Text(c) => c.is_empty(),
            Carrier::Binary(c) => c.is_empty(),
        }
    }

    /// Returns true if this is a binary carrier.
    pub fn is_binary(&self) -> bool {
        matches!(self, Carrier::Binary(_))
    }

    /// Finds all occurrences of data in the carrier.
    /// For text: searches for substring (message as string).
    /// For binary: searches for byte sequence (message as UTF-8 bytes).
    pub fn find_all(&self, data: &[u8]) -> Vec<usize> {
        match self {
            Carrier::Text(c) => {
                // Convert bytes to string for text search
                if let Ok(s) = std::str::from_utf8(data) {
                    c.find_all(s)
                } else {
                    vec![]
                }
            }
            Carrier::Binary(c) => c.find_all(data),
        }
    }

    /// Extracts data at the given position and length.
    /// For text: returns UTF-8 bytes of the extracted characters.
    /// For binary: returns the raw bytes.
    pub fn extract(&self, pos: usize, len: usize) -> Option<Vec<u8>> {
        match self {
            Carrier::Text(c) => c.extract(pos, len).map(|s| s.into_bytes()),
            Carrier::Binary(c) => c.extract(pos, len),
        }
    }

    /// Extracts with wrap-around (always returns something).
    pub fn extract_wrapped(&self, pos: usize, len: usize) -> Vec<u8> {
        match self {
            Carrier::Text(c) => c.extract_wrapped(pos, len).into_bytes(),
            Carrier::Binary(c) => c.extract_wrapped(pos, len),
        }
    }
}

/// A binary carrier prepared for byte-sequence searching.
#[derive(Debug, Clone)]
pub struct BinaryCarrierSearch {
    /// The raw binary data.
    data: Vec<u8>,
}

impl BinaryCarrierSearch {
    /// Creates a new BinaryCarrierSearch from bytes.
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Returns the length of the carrier in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the carrier is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Finds a byte sequence in the carrier, returning its position.
    pub fn find(&self, needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || needle.len() > self.data.len() {
            return None;
        }

        self.data
            .windows(needle.len())
            .position(|window| window == needle)
    }

    /// Finds all occurrences of a byte sequence in the carrier.
    pub fn find_all(&self, needle: &[u8]) -> Vec<usize> {
        if needle.is_empty() || needle.len() > self.data.len() {
            return vec![];
        }

        self.data
            .windows(needle.len())
            .enumerate()
            .filter_map(|(i, window)| if window == needle { Some(i) } else { None })
            .collect()
    }

    /// Extracts bytes at the given position and length.
    pub fn extract(&self, pos: usize, len: usize) -> Option<Vec<u8>> {
        if pos >= self.data.len() {
            return None;
        }

        let end = (pos + len).min(self.data.len());
        Some(self.data[pos..end].to_vec())
    }

    /// Extracts with wrap-around (always returns something).
    pub fn extract_wrapped(&self, pos: usize, len: usize) -> Vec<u8> {
        if self.data.is_empty() {
            return vec![];
        }

        let actual_pos = pos % self.data.len();
        let mut result = Vec::with_capacity(len);

        for i in 0..len {
            let idx = (actual_pos + i) % self.data.len();
            result.push(self.data[idx]);
        }

        result
    }

    /// Returns a reference to the underlying data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Fragment info for binary carriers.
#[derive(Debug, Clone)]
pub struct BinaryFragment {
    /// The byte sequence to search for.
    pub bytes: Vec<u8>,
    /// Whether this fragment ends a "word" (space follows in original message).
    /// Only meaningful for text messages; always false for pure binary data.
    pub ends_word: bool,
}

/// Fragments arbitrary bytes for carrier search.
/// Uses adaptive fragmentation - tries larger chunks first, falls back to single bytes.
/// This is the core function that works with raw bytes - use this for binary messages.
pub fn fragment_bytes_for_carrier(
    data: &[u8],
    carrier: &BinaryCarrierSearch,
    _passphrase: &str,
) -> Vec<BinaryFragment> {
    if data.is_empty() {
        return vec![];
    }

    let mut fragments = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        // Try progressively smaller fragments
        let mut found = false;

        // Max fragment size: 8 bytes (or remaining)
        let max_len = (data.len() - pos).min(8);

        for len in (1..=max_len).rev() {
            let fragment = &data[pos..pos + len];

            if !carrier.find_all(fragment).is_empty() {
                fragments.push(BinaryFragment {
                    bytes: fragment.to_vec(),
                    ends_word: false, // No word boundaries in binary data
                });

                pos += len;
                found = true;
                break;
            }
        }

        if !found {
            // Single byte not found - this is a problem
            // Return empty to signal failure
            return vec![];
        }
    }

    fragments
}

/// Fragments a text message for binary carrier search.
/// Wrapper around fragment_bytes_for_carrier that handles word boundaries.
pub fn fragment_message_for_binary(
    message: &str,
    carrier: &BinaryCarrierSearch,
    passphrase: &str,
) -> Vec<BinaryFragment> {
    let message_bytes = message.as_bytes();
    if message_bytes.is_empty() {
        return vec![];
    }

    // Use the core byte fragmentation
    let mut fragments = fragment_bytes_for_carrier(message_bytes, carrier, passphrase);

    // Post-process to mark word boundaries (for text reconstruction)
    let mut byte_pos = 0;
    for fragment in &mut fragments {
        let fragment_end = byte_pos + fragment.bytes.len();

        // Check if this fragment ends at a space or is followed by a space
        let ends_with_space = fragment.bytes.last() == Some(&b' ');
        let followed_by_space =
            fragment_end < message_bytes.len() && message_bytes[fragment_end] == b' ';

        fragment.ends_word = ends_with_space || followed_by_space;
        byte_pos = fragment_end;
    }

    fragments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_carrier_find() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let carrier = BinaryCarrierSearch::new(data);

        assert_eq!(carrier.find(&[3, 4, 5]), Some(2));
        assert_eq!(carrier.find(&[1, 2]), Some(0));
        assert_eq!(carrier.find(&[99, 100]), None);
    }

    #[test]
    fn test_binary_carrier_find_all() {
        let data = vec![1, 2, 1, 2, 1, 2];
        let carrier = BinaryCarrierSearch::new(data);

        let positions = carrier.find_all(&[1, 2]);
        assert_eq!(positions, vec![0, 2, 4]);
    }

    #[test]
    fn test_binary_carrier_extract() {
        let data = vec![10, 20, 30, 40, 50];
        let carrier = BinaryCarrierSearch::new(data);

        assert_eq!(carrier.extract(1, 3), Some(vec![20, 30, 40]));
        assert_eq!(carrier.extract(100, 2), None);
    }

    #[test]
    fn test_binary_carrier_extract_wrapped() {
        let data = vec![1, 2, 3, 4];
        let carrier = BinaryCarrierSearch::new(data);

        assert_eq!(carrier.extract_wrapped(0, 2), vec![1, 2]);
        assert_eq!(carrier.extract_wrapped(100, 2), vec![1, 2]); // 100 % 4 = 0
        assert_eq!(carrier.extract_wrapped(2, 4), vec![3, 4, 1, 2]); // wraps
    }

    #[test]
    fn test_carrier_enum_text() {
        let carrier = Carrier::from_text("Hello World");
        assert!(!carrier.is_binary());
        assert_eq!(carrier.len(), 11);

        let positions = carrier.find_all(b"llo");
        assert_eq!(positions, vec![2]);
    }

    #[test]
    fn test_carrier_enum_binary() {
        let carrier = Carrier::from_bytes(vec![72, 101, 108, 108, 111]); // "Hello" as bytes
        assert!(carrier.is_binary());
        assert_eq!(carrier.len(), 5);

        let positions = carrier.find_all(&[108, 108]); // "ll"
        assert_eq!(positions, vec![2]);
    }

    #[test]
    fn test_fragment_for_binary() {
        // Create a carrier with some repeated patterns
        let mut data = Vec::new();
        for i in 0..=255u8 {
            data.push(i);
        }
        // Add more data to have all byte values
        for i in 0..=255u8 {
            data.push(i);
        }

        let carrier = BinaryCarrierSearch::new(data);
        let fragments = fragment_message_for_binary("hi", &carrier, "test");

        // "hi" = [104, 105], both bytes exist in carrier
        assert!(!fragments.is_empty());
    }

    #[test]
    fn test_fragment_bytes_for_carrier() {
        // Create a carrier with all byte values
        let mut data = Vec::new();
        for i in 0..=255u8 {
            data.push(i);
        }
        for i in 0..=255u8 {
            data.push(i);
        }

        let carrier = BinaryCarrierSearch::new(data);

        // Fragment arbitrary binary data
        let binary_message = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let fragments = fragment_bytes_for_carrier(&binary_message, &carrier, "test");

        assert!(!fragments.is_empty());
        // Reconstruct the message
        let reconstructed: Vec<u8> = fragments.iter().flat_map(|f| f.bytes.clone()).collect();
        assert_eq!(reconstructed, binary_message);
    }

    #[test]
    fn test_fragment_bytes_no_word_boundaries() {
        // Binary fragments should never have ends_word set
        let mut data = Vec::new();
        for i in 0..=255u8 {
            data.push(i);
        }

        let carrier = BinaryCarrierSearch::new(data);
        let binary_message = vec![0x20, 0x41, 0x20]; // space, A, space
        let fragments = fragment_bytes_for_carrier(&binary_message, &carrier, "test");

        // All ends_word should be false for binary fragmentation
        for fragment in &fragments {
            assert!(!fragment.ends_word);
        }
    }

    #[test]
    fn test_from_files_empty() {
        let carrier = Carrier::from_files(&[]).unwrap();
        assert!(carrier.is_empty());
        assert!(carrier.is_binary());
    }

    #[test]
    fn test_from_files_single_delegates_to_from_file() {
        let dir = tempfile::tempdir().unwrap();

        // Text file
        let txt_path = dir.path().join("test.txt");
        std::fs::write(&txt_path, "Hello World").unwrap();

        let carrier = Carrier::from_files(&[txt_path]).unwrap();
        assert!(!carrier.is_binary()); // Single .txt should be text carrier
        assert_eq!(carrier.len(), 11);
    }

    #[test]
    fn test_from_files_multiple_concatenates_as_bytes() {
        let dir = tempfile::tempdir().unwrap();

        let file1 = dir.path().join("a.bin");
        let file2 = dir.path().join("b.bin");
        std::fs::write(&file1, vec![1, 2, 3]).unwrap();
        std::fs::write(&file2, vec![4, 5, 6]).unwrap();

        let carrier = Carrier::from_files(&[file1, file2]).unwrap();
        assert!(carrier.is_binary());
        assert_eq!(carrier.len(), 6); // 3 + 3 bytes

        // Verify concatenation order
        assert_eq!(carrier.extract(0, 6), Some(vec![1, 2, 3, 4, 5, 6]));
    }

    #[test]
    fn test_from_files_order_matters() {
        let dir = tempfile::tempdir().unwrap();

        let file1 = dir.path().join("first.bin");
        let file2 = dir.path().join("second.bin");
        std::fs::write(&file1, vec![0xAA, 0xBB]).unwrap();
        std::fs::write(&file2, vec![0xCC, 0xDD]).unwrap();

        let carrier_ab = Carrier::from_files(&[file1.clone(), file2.clone()]).unwrap();
        let carrier_ba = Carrier::from_files(&[file2, file1]).unwrap();

        // Different order = different carrier content
        assert_eq!(carrier_ab.extract(0, 4), Some(vec![0xAA, 0xBB, 0xCC, 0xDD]));
        assert_eq!(carrier_ba.extract(0, 4), Some(vec![0xCC, 0xDD, 0xAA, 0xBB]));
    }
}
