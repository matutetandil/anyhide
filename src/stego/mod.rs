//! Steganography module for hiding data in various carriers.
//!
//! Supports:
//! - Image LSB steganography (PNG, BMP)
//! - Audio LSB steganography (WAV)

pub mod image;
pub mod audio;

pub use image::{ImageStego, ImageStegoError};
pub use audio::{AudioStego, AudioStegoError};
