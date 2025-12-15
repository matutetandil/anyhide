//! LSB (Least Significant Bit) steganography for images.
//!
//! Hides data in the least significant bits of pixel color values.
//! Supports PNG and BMP images (lossless formats only).
//!
//! Format: [4 bytes length] + [data bytes]
//! Each byte is spread across 8 pixels (1 bit per pixel channel).

use image::{DynamicImage, GenericImageView, ImageFormat};
use std::io::Cursor;
use std::path::Path;
use thiserror::Error;

/// Maximum bits per pixel channel to use for hiding data.
const BITS_PER_CHANNEL: u8 = 1;

/// Errors that can occur during image steganography.
#[derive(Error, Debug)]
pub enum ImageStegoError {
    #[error("Image too small to hide data: need {needed} bytes, have capacity for {capacity}")]
    ImageTooSmall { needed: usize, capacity: usize },

    #[error("Image load error: {0}")]
    ImageLoadError(String),

    #[error("Image save error: {0}")]
    ImageSaveError(String),

    #[error("No hidden data found in image")]
    NoDataFound,

    #[error("Invalid data format in image")]
    InvalidFormat,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Image steganography handler.
pub struct ImageStego {
    image: DynamicImage,
}

impl ImageStego {
    /// Creates a new ImageStego from a file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ImageStegoError> {
        let image = image::open(path).map_err(|e| ImageStegoError::ImageLoadError(e.to_string()))?;
        Ok(Self { image })
    }

    /// Creates a new ImageStego from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ImageStegoError> {
        let image = image::load_from_memory(bytes)
            .map_err(|e| ImageStegoError::ImageLoadError(e.to_string()))?;
        Ok(Self { image })
    }

    /// Creates a new ImageStego from a DynamicImage.
    pub fn from_image(image: DynamicImage) -> Self {
        Self { image }
    }

    /// Returns the capacity in bytes that can be hidden in this image.
    pub fn capacity(&self) -> usize {
        let (width, height) = self.image.dimensions();
        let total_pixels = (width as usize) * (height as usize);
        // 3 channels (RGB) per pixel, BITS_PER_CHANNEL bits per channel
        // 8 bits = 1 byte, so capacity = total_pixels * 3 * BITS_PER_CHANNEL / 8
        // Minus 4 bytes for the length header
        let total_bits = total_pixels * 3 * (BITS_PER_CHANNEL as usize);
        (total_bits / 8).saturating_sub(4)
    }

    /// Hides data in the image using LSB steganography.
    ///
    /// # Arguments
    /// * `data` - The data to hide
    ///
    /// # Returns
    /// A new image with the data hidden inside.
    pub fn hide(&self, data: &[u8]) -> Result<DynamicImage, ImageStegoError> {
        let capacity = self.capacity();
        if data.len() > capacity {
            return Err(ImageStegoError::ImageTooSmall {
                needed: data.len(),
                capacity,
            });
        }

        // Prepare data with length prefix
        let len_bytes = (data.len() as u32).to_le_bytes();
        let mut full_data = Vec::with_capacity(4 + data.len());
        full_data.extend_from_slice(&len_bytes);
        full_data.extend_from_slice(data);

        // Convert to RGBA for manipulation
        let mut output = self.image.to_rgba8();
        let (width, height) = output.dimensions();

        let mut bit_index = 0;
        let total_bits = full_data.len() * 8;

        'outer: for y in 0..height {
            for x in 0..width {
                if bit_index >= total_bits {
                    break 'outer;
                }

                let mut pixel = output.get_pixel(x, y).clone();

                // Modify RGB channels (not alpha)
                for channel in 0..3 {
                    if bit_index >= total_bits {
                        break;
                    }

                    let byte_idx = bit_index / 8;
                    let bit_offset = bit_index % 8;
                    let bit = (full_data[byte_idx] >> bit_offset) & 1;

                    // Clear LSB and set new bit
                    pixel.0[channel] = (pixel.0[channel] & 0xFE) | bit;
                    bit_index += 1;
                }

                output.put_pixel(x, y, pixel);
            }
        }

        Ok(DynamicImage::ImageRgba8(output))
    }

    /// Extracts hidden data from the image.
    ///
    /// # Returns
    /// The extracted data if found.
    pub fn extract(&self) -> Result<Vec<u8>, ImageStegoError> {
        let rgba = self.image.to_rgba8();
        let (width, height) = rgba.dimensions();

        // First, extract the length (4 bytes = 32 bits)
        let mut len_bytes = [0u8; 4];
        let mut bit_index = 0;

        'outer: for y in 0..height {
            for x in 0..width {
                if bit_index >= 32 {
                    break 'outer;
                }

                let pixel = rgba.get_pixel(x, y);

                for channel in 0..3 {
                    if bit_index >= 32 {
                        break;
                    }

                    let bit = pixel.0[channel] & 1;
                    let byte_idx = bit_index / 8;
                    let bit_offset = bit_index % 8;

                    len_bytes[byte_idx] |= bit << bit_offset;
                    bit_index += 1;
                }
            }
        }

        let data_len = u32::from_le_bytes(len_bytes) as usize;

        // Sanity check
        if data_len > self.capacity() {
            return Err(ImageStegoError::NoDataFound);
        }

        if data_len == 0 {
            return Ok(vec![]);
        }

        // Extract the data
        let mut data = vec![0u8; data_len];
        let total_bits = (4 + data_len) * 8;
        bit_index = 32; // Skip length bytes

        'outer2: for y in 0..height {
            for x in 0..width {
                // Skip pixels we've already processed
                let pixel_index = (y * width + x) as usize;
                let start_bit = pixel_index * 3;
                if start_bit + 3 <= 32 {
                    continue;
                }

                if bit_index >= total_bits {
                    break 'outer2;
                }

                let pixel = rgba.get_pixel(x, y);

                for channel in 0..3 {
                    // Skip bits we've already read
                    let current_bit = start_bit + channel;
                    if current_bit < 32 {
                        continue;
                    }

                    if bit_index >= total_bits {
                        break;
                    }

                    let bit = pixel.0[channel] & 1;
                    let data_bit_index = bit_index - 32;
                    let byte_idx = data_bit_index / 8;
                    let bit_offset = data_bit_index % 8;

                    if byte_idx < data.len() {
                        data[byte_idx] |= bit << bit_offset;
                    }
                    bit_index += 1;
                }
            }
        }

        Ok(data)
    }

    /// Saves the image to a file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), ImageStegoError> {
        self.image
            .save(path)
            .map_err(|e| ImageStegoError::ImageSaveError(e.to_string()))
    }

    /// Returns the image as PNG bytes.
    pub fn to_png_bytes(&self) -> Result<Vec<u8>, ImageStegoError> {
        let mut bytes = Vec::new();
        self.image
            .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .map_err(|e| ImageStegoError::ImageSaveError(e.to_string()))?;
        Ok(bytes)
    }

    /// Returns a reference to the underlying image.
    pub fn image(&self) -> &DynamicImage {
        &self.image
    }

    /// Consumes self and returns the underlying image.
    pub fn into_image(self) -> DynamicImage {
        self.image
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb};

    fn create_test_image(width: u32, height: u32) -> DynamicImage {
        let img = ImageBuffer::from_fn(width, height, |x, y| {
            Rgb([
                ((x * 17) % 256) as u8,
                ((y * 23) % 256) as u8,
                (((x + y) * 31) % 256) as u8,
            ])
        });
        DynamicImage::ImageRgb8(img)
    }

    #[test]
    fn test_capacity() {
        let image = create_test_image(100, 100);
        let stego = ImageStego::from_image(image);

        // 100x100 = 10000 pixels, 3 channels, 1 bit each = 30000 bits = 3750 bytes
        // Minus 4 for length = 3746 bytes
        assert_eq!(stego.capacity(), 3746);
    }

    #[test]
    fn test_hide_and_extract_small() {
        let image = create_test_image(100, 100);
        let stego = ImageStego::from_image(image);

        let data = b"Hello, steganography!";

        let hidden = stego.hide(data).unwrap();
        let stego2 = ImageStego::from_image(hidden);
        let extracted = stego2.extract().unwrap();

        assert_eq!(extracted, data);
    }

    #[test]
    fn test_hide_and_extract_larger() {
        let image = create_test_image(200, 200);
        let stego = ImageStego::from_image(image);

        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

        let hidden = stego.hide(&data).unwrap();
        let stego2 = ImageStego::from_image(hidden);
        let extracted = stego2.extract().unwrap();

        assert_eq!(extracted, data);
    }

    #[test]
    fn test_image_too_small() {
        let image = create_test_image(10, 10);
        let stego = ImageStego::from_image(image);

        let data = vec![0u8; 1000]; // Too much data

        let result = stego.hide(&data);
        assert!(matches!(result, Err(ImageStegoError::ImageTooSmall { .. })));
    }

    #[test]
    fn test_empty_data() {
        let image = create_test_image(100, 100);
        let stego = ImageStego::from_image(image);

        let data: &[u8] = &[];

        let hidden = stego.hide(data).unwrap();
        let stego2 = ImageStego::from_image(hidden);
        let extracted = stego2.extract().unwrap();

        assert!(extracted.is_empty());
    }

    #[test]
    fn test_png_roundtrip() {
        let image = create_test_image(100, 100);
        let stego = ImageStego::from_image(image);

        let data = b"Test PNG roundtrip";

        let hidden = stego.hide(data).unwrap();
        let stego2 = ImageStego::from_image(hidden);

        // Convert to PNG bytes and back
        let png_bytes = stego2.to_png_bytes().unwrap();
        let stego3 = ImageStego::from_bytes(&png_bytes).unwrap();
        let extracted = stego3.extract().unwrap();

        assert_eq!(extracted, data);
    }
}
