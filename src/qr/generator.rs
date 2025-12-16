//! QR code generation from Anyhide codes.
//!
//! Generates QR codes using Base45 encoding for optimal capacity.

use image::{DynamicImage, Luma};
use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};
use std::path::Path;
use thiserror::Error;

use super::encode_base45;

/// Errors that can occur during QR code operations.
#[derive(Error, Debug)]
pub enum QrError {
    #[error("Data too large for QR code: {size} bytes, max ~2900 bytes")]
    DataTooLarge { size: usize },

    #[error("QR code generation failed: {0}")]
    QrGenerationError(String),

    #[error("Image save error: {0}")]
    ImageSaveError(String),

    #[error("Base45 decode error: {0}")]
    Base45DecodeError(String),

    #[error("QR code read error: {0}")]
    QrReadError(String),

    #[error("No QR code found in image")]
    NoQrCodeFound,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Output format for QR codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrFormat {
    /// PNG image (default)
    Png,
    /// SVG vector image
    Svg,
    /// ASCII art (for terminal display)
    Ascii,
}

impl Default for QrFormat {
    fn default() -> Self {
        Self::Png
    }
}

/// Configuration for QR code generation.
#[derive(Debug, Clone)]
pub struct QrConfig {
    /// Error correction level (default: Medium)
    pub ec_level: EcLevel,
    /// Module size in pixels (default: 10)
    pub module_size: u32,
    /// Quiet zone size in modules (default: 4)
    pub quiet_zone: u32,
    /// Output format
    pub format: QrFormat,
}

impl Default for QrConfig {
    fn default() -> Self {
        Self {
            ec_level: EcLevel::M,
            module_size: 10,
            quiet_zone: 4,
            format: QrFormat::Png,
        }
    }
}

/// Generates a QR code from binary data.
///
/// The data is first encoded using Base45 for optimal QR capacity,
/// then rendered as a QR code image.
///
/// # Arguments
/// * `data` - Binary data to encode (typically an Anyhide code)
/// * `config` - QR generation configuration
///
/// # Returns
/// QR code as a DynamicImage (for PNG) or String (for SVG/ASCII)
pub fn generate_qr(data: &[u8], config: &QrConfig) -> Result<QrOutput, QrError> {
    // Encode data as Base45
    let base45_data = encode_base45(data);

    // Create QR code
    let qr = QrCode::with_error_correction_level(&base45_data, config.ec_level)
        .map_err(|e| QrError::QrGenerationError(e.to_string()))?;

    match config.format {
        QrFormat::Png => {
            let image = qr
                .render::<Luma<u8>>()
                .min_dimensions(100, 100)
                .quiet_zone(config.quiet_zone > 0)
                .module_dimensions(config.module_size, config.module_size)
                .build();

            Ok(QrOutput::Image(DynamicImage::ImageLuma8(image)))
        }
        QrFormat::Svg => {
            let svg_string = qr
                .render()
                .min_dimensions(200, 200)
                .quiet_zone(config.quiet_zone > 0)
                .dark_color(svg::Color("#000000"))
                .light_color(svg::Color("#ffffff"))
                .build();

            Ok(QrOutput::Svg(svg_string))
        }
        QrFormat::Ascii => {
            let ascii = qr
                .render::<char>()
                .quiet_zone(config.quiet_zone > 0)
                .module_dimensions(2, 1)
                .build();

            Ok(QrOutput::Ascii(ascii))
        }
    }
}

/// Output from QR code generation.
pub enum QrOutput {
    /// PNG/image output
    Image(DynamicImage),
    /// SVG string output
    Svg(String),
    /// ASCII art output
    Ascii(String),
}

impl QrOutput {
    /// Returns true if this is an image output.
    pub fn is_image(&self) -> bool {
        matches!(self, QrOutput::Image(_))
    }

    /// Returns the image if this is an image output.
    pub fn into_image(self) -> Option<DynamicImage> {
        match self {
            QrOutput::Image(img) => Some(img),
            _ => None,
        }
    }

    /// Returns the string content (for SVG or ASCII).
    pub fn as_string(&self) -> Option<&str> {
        match self {
            QrOutput::Svg(s) | QrOutput::Ascii(s) => Some(s),
            _ => None,
        }
    }
}

/// Generates a QR code and saves it to a file.
///
/// # Arguments
/// * `data` - Binary data to encode
/// * `path` - Output file path
/// * `config` - QR generation configuration
pub fn generate_qr_to_file<P: AsRef<Path>>(
    data: &[u8],
    path: P,
    config: &QrConfig,
) -> Result<(), QrError> {
    let output = generate_qr(data, config)?;
    let path = path.as_ref();

    match output {
        QrOutput::Image(img) => {
            img.save(path)
                .map_err(|e| QrError::ImageSaveError(e.to_string()))?;
        }
        QrOutput::Svg(svg) => {
            std::fs::write(path, svg)?;
        }
        QrOutput::Ascii(ascii) => {
            std::fs::write(path, ascii)?;
        }
    }

    Ok(())
}

/// Returns information about QR code capacity.
pub fn qr_capacity_info(data_size: usize) -> QrCapacityInfo {
    let base45_size = (data_size * 3 + 1) / 2; // Approximate Base45 expansion

    // QR version capacities for alphanumeric mode with M error correction
    let version = if base45_size <= 20 {
        1
    } else if base45_size <= 38 {
        2
    } else if base45_size <= 61 {
        3
    } else if base45_size <= 90 {
        4
    } else if base45_size <= 122 {
        5
    } else if base45_size <= 154 {
        6
    } else if base45_size <= 178 {
        7
    } else if base45_size <= 221 {
        8
    } else if base45_size <= 262 {
        9
    } else if base45_size <= 311 {
        10
    } else if base45_size <= 535 {
        15
    } else if base45_size <= 858 {
        20
    } else if base45_size <= 1276 {
        25
    } else if base45_size <= 1782 {
        30
    } else if base45_size <= 2395 {
        35
    } else if base45_size <= 3057 {
        40
    } else {
        0 // Too large
    };

    QrCapacityInfo {
        data_bytes: data_size,
        base45_chars: base45_size,
        qr_version: version,
        fits_in_qr: version > 0,
    }
}

/// Information about QR code capacity for given data.
#[derive(Debug, Clone)]
pub struct QrCapacityInfo {
    /// Original data size in bytes
    pub data_bytes: usize,
    /// Approximate Base45 encoded size
    pub base45_chars: usize,
    /// Minimum QR version needed (1-40, 0 if too large)
    pub qr_version: u8,
    /// Whether the data fits in a standard QR code
    pub fits_in_qr: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_qr_small() {
        let data = b"Hello, Anyhide!";
        let config = QrConfig::default();
        let output = generate_qr(data, &config).unwrap();
        assert!(output.is_image());
    }

    #[test]
    fn test_generate_qr_ascii() {
        let data = b"Test";
        let config = QrConfig {
            format: QrFormat::Ascii,
            ..Default::default()
        };
        let output = generate_qr(data, &config).unwrap();
        assert!(output.as_string().is_some());
        let ascii = output.as_string().unwrap();
        assert!(ascii.contains("█") || ascii.contains("#") || ascii.contains(" "));
    }

    #[test]
    fn test_generate_qr_svg() {
        let data = b"SVG test";
        let config = QrConfig {
            format: QrFormat::Svg,
            ..Default::default()
        };
        let output = generate_qr(data, &config).unwrap();
        let svg = output.as_string().unwrap();
        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
    }

    #[test]
    fn test_qr_capacity_info() {
        let info = qr_capacity_info(100);
        assert!(info.fits_in_qr);
        assert!(info.qr_version > 0);

        let info_large = qr_capacity_info(5000);
        assert!(!info_large.fits_in_qr);
    }

    #[test]
    fn test_generate_qr_medium_data() {
        // Simulate a typical Anyhide code (~300 bytes)
        let data = vec![0u8; 300];
        let config = QrConfig::default();
        let output = generate_qr(&data, &config).unwrap();
        assert!(output.is_image());
    }
}
