//! QR code reading and decoding.
//!
//! Reads QR codes from images and decodes the Base45 data.

use image::DynamicImage;
use rqrr::PreparedImage;
use std::path::Path;

use super::{decode_base45, QrError};

/// Reads a QR code from an image and returns the decoded binary data.
///
/// The QR code is expected to contain Base45-encoded data.
///
/// # Arguments
/// * `image` - The image containing the QR code
///
/// # Returns
/// The decoded binary data from the QR code.
pub fn read_qr(image: &DynamicImage) -> Result<Vec<u8>, QrError> {
    // Convert to grayscale for QR detection
    let gray = image.to_luma8();

    // Prepare image for QR detection
    let mut prepared = PreparedImage::prepare(gray);

    // Find and decode QR codes
    let grids = prepared.detect_grids();

    if grids.is_empty() {
        return Err(QrError::NoQrCodeFound);
    }

    // Try to decode the first QR code found
    let (_, content) = grids[0]
        .decode()
        .map_err(|e| QrError::QrReadError(format!("Failed to decode QR: {:?}", e)))?;

    // Decode Base45 content
    decode_base45(&content)
}

/// Reads a QR code from an image file and returns the decoded binary data.
///
/// # Arguments
/// * `path` - Path to the image file containing the QR code
///
/// # Returns
/// The decoded binary data from the QR code.
pub fn read_qr_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, QrError> {
    let image = image::open(path).map_err(|e| QrError::QrReadError(e.to_string()))?;

    read_qr(&image)
}

/// Reads all QR codes from an image and returns their decoded data.
///
/// Useful when an image might contain multiple QR codes.
///
/// # Arguments
/// * `image` - The image containing QR codes
///
/// # Returns
/// Vector of decoded binary data, one per QR code found.
pub fn read_all_qr(image: &DynamicImage) -> Result<Vec<Vec<u8>>, QrError> {
    let gray = image.to_luma8();
    let mut prepared = PreparedImage::prepare(gray);
    let grids = prepared.detect_grids();

    if grids.is_empty() {
        return Err(QrError::NoQrCodeFound);
    }

    let mut results = Vec::new();

    for grid in grids {
        if let Ok((_, content)) = grid.decode() {
            if let Ok(data) = decode_base45(&content) {
                results.push(data);
            }
        }
    }

    if results.is_empty() {
        return Err(QrError::QrReadError(
            "Found QR codes but failed to decode any".to_string(),
        ));
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::super::generator::{generate_qr, QrConfig, QrFormat};
    use super::*;

    #[test]
    fn test_read_qr_roundtrip() {
        let original_data = b"Hello, Anyhide QR!";

        // Generate QR code
        let config = QrConfig {
            format: QrFormat::Png,
            module_size: 10,
            ..Default::default()
        };
        let output = generate_qr(original_data, &config).unwrap();
        let image = output.into_image().unwrap();

        // Read QR code
        let decoded = read_qr(&image).unwrap();

        assert_eq!(decoded, original_data);
    }

    #[test]
    fn test_read_qr_binary_data() {
        // Test with binary data (like a real Anyhide code)
        let original_data: Vec<u8> = (0..100).map(|i| (i * 7) as u8).collect();

        let config = QrConfig {
            format: QrFormat::Png,
            module_size: 10,
            ..Default::default()
        };
        let output = generate_qr(&original_data, &config).unwrap();
        let image = output.into_image().unwrap();

        let decoded = read_qr(&image).unwrap();

        assert_eq!(decoded, original_data);
    }

    #[test]
    fn test_read_qr_larger_data() {
        // Test with larger data (~500 bytes, typical Anyhide code size)
        let original_data: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();

        let config = QrConfig {
            format: QrFormat::Png,
            module_size: 8,
            ..Default::default()
        };
        let output = generate_qr(&original_data, &config).unwrap();
        let image = output.into_image().unwrap();

        let decoded = read_qr(&image).unwrap();

        assert_eq!(decoded, original_data);
    }
}
