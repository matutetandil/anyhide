//! QR code generation and reading for KAMO codes.
//!
//! Uses Base45 encoding for optimal QR code capacity.
//! Base45 is designed for QR alphanumeric mode, providing ~45% more
//! capacity than Base64 which requires QR byte mode.

mod generator;
mod reader;

pub use generator::{generate_qr, generate_qr_to_file, qr_capacity_info, QrCapacityInfo, QrConfig, QrError, QrFormat, QrOutput};
pub use reader::{read_all_qr, read_qr, read_qr_from_file};

/// Encodes binary data to Base45 string (optimized for QR codes).
///
/// Base45 uses only characters from QR alphanumeric mode:
/// 0-9, A-Z, space, $, %, *, +, -, ., /, :
pub fn encode_base45(data: &[u8]) -> String {
    base45::encode(data)
}

/// Decodes a Base45 string back to binary data.
pub fn decode_base45(encoded: &str) -> Result<Vec<u8>, QrError> {
    base45::decode(encoded).map_err(|e| QrError::Base45DecodeError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base45_roundtrip() {
        let data = b"Hello, KAMO!";
        let encoded = encode_base45(data);
        let decoded = decode_base45(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base45_binary_data() {
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let encoded = encode_base45(&data);
        let decoded = decode_base45(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base45_only_alphanumeric() {
        let data = b"Test data for QR";
        let encoded = encode_base45(data);
        // Base45 should only use: 0-9, A-Z, space, $%*+-./:
        for c in encoded.chars() {
            assert!(
                c.is_ascii_digit()
                    || c.is_ascii_uppercase()
                    || " $%*+-./:".contains(c),
                "Invalid Base45 character: {}",
                c
            );
        }
    }

    #[test]
    fn test_base45_efficiency() {
        // Base45: 2 bytes -> 3 chars, Base64: 3 bytes -> 4 chars
        // For QR alphanumeric mode, Base45 is more efficient
        let data = vec![0u8; 100];
        let base45_len = encode_base45(&data).len();
        let base64_len = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data)
            .len();

        // Base45 should be roughly 1.5x the input size
        // Base64 is roughly 1.33x but uses byte mode in QR
        assert!(base45_len <= 155); // 100 * 1.5 + overhead
        assert!(base64_len <= 140); // 100 * 1.33 + padding
    }
}
