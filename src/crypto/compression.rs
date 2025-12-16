//! Message compression for Anyhide.
//!
//! Uses DEFLATE compression to reduce message size before encoding,
//! allowing longer messages to fit in the same carrier.

use flate2::read::{DeflateDecoder, DeflateEncoder};
use flate2::Compression;
use std::io::Read;
use thiserror::Error;

/// Compression errors.
#[derive(Error, Debug)]
pub enum CompressionError {
    #[error("Compression failed: {0}")]
    CompressionFailed(String),

    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),
}

/// Compresses data using DEFLATE algorithm.
///
/// Returns compressed bytes. If compression doesn't reduce size,
/// returns original data with a marker byte.
pub fn compress(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    if data.is_empty() {
        return Ok(vec![0u8]); // Marker: uncompressed, empty
    }

    let mut encoder = DeflateEncoder::new(data, Compression::best());
    let mut compressed = Vec::new();

    encoder
        .read_to_end(&mut compressed)
        .map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;

    // Only use compression if it actually reduces size
    // First byte is marker: 0 = uncompressed, 1 = compressed
    if compressed.len() < data.len() {
        let mut result = Vec::with_capacity(compressed.len() + 1);
        result.push(1u8); // Marker: compressed
        result.extend(compressed);
        Ok(result)
    } else {
        let mut result = Vec::with_capacity(data.len() + 1);
        result.push(0u8); // Marker: uncompressed
        result.extend(data);
        Ok(result)
    }
}

/// Decompresses data that was compressed with `compress()`.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    if data.is_empty() {
        return Err(CompressionError::DecompressionFailed(
            "Empty data".to_string(),
        ));
    }

    let marker = data[0];
    let payload = &data[1..];

    if marker == 0 {
        // Uncompressed
        Ok(payload.to_vec())
    } else if marker == 1 {
        // Compressed
        let mut decoder = DeflateDecoder::new(payload);
        let mut decompressed = Vec::new();

        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;

        Ok(decompressed)
    } else {
        Err(CompressionError::DecompressionFailed(format!(
            "Invalid marker byte: {}",
            marker
        )))
    }
}

/// Returns compression ratio (compressed_size / original_size).
/// Values < 1.0 mean compression helped.
pub fn compression_ratio(original: &[u8], compressed: &[u8]) -> f64 {
    if original.is_empty() {
        return 1.0;
    }
    compressed.len() as f64 / original.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        let data = b"Hello, this is a test message that should compress well. \
                     Hello, this is a test message that should compress well. \
                     Hello, this is a test message that should compress well.";

        let compressed = compress(data).unwrap();
        let decompressed = decompress(&compressed).unwrap();

        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_small_data() {
        // Small data might not compress well
        let data = b"Hi";
        let compressed = compress(data).unwrap();
        let decompressed = decompress(&compressed).unwrap();

        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_empty() {
        let data = b"";
        let compressed = compress(data).unwrap();
        let decompressed = decompress(&compressed).unwrap();

        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_actually_compresses() {
        // Repetitive data should compress well
        let data = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .repeat(10)
            .into_bytes();

        let compressed = compress(&data).unwrap();

        // Should be smaller (marker byte = 1 means it was compressed)
        assert_eq!(compressed[0], 1);
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn test_random_data_might_not_compress() {
        // Random data typically doesn't compress
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..100).map(|_| rng.gen()).collect();

        let compressed = compress(&data).unwrap();
        let decompressed = decompress(&compressed).unwrap();

        // Should still roundtrip correctly
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_decompression_invalid_marker() {
        let data = vec![99u8, 1, 2, 3]; // Invalid marker
        let result = decompress(&data);
        assert!(result.is_err());
    }
}
