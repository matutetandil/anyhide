//! LSB steganography for audio files.
//!
//! Hides data in the least significant bits of audio samples.
//! Supports WAV files (uncompressed PCM).
//!
//! Format: [4 bytes length] + [data bytes]
//! Each byte is spread across 8 samples (1 bit per sample).

use hound::{SampleFormat, WavReader, WavSpec, WavWriter};
use std::io::{Cursor, Read, Seek};
use std::path::Path;
use thiserror::Error;

/// Errors that can occur during audio steganography.
#[derive(Error, Debug)]
pub enum AudioStegoError {
    #[error("Audio too short to hide data: need {needed} samples, have {available}")]
    AudioTooShort { needed: usize, available: usize },

    #[error("Audio load error: {0}")]
    AudioLoadError(String),

    #[error("Audio save error: {0}")]
    AudioSaveError(String),

    #[error("No hidden data found in audio")]
    NoDataFound,

    #[error("Unsupported audio format: {0}")]
    UnsupportedFormat(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Audio steganography handler.
pub struct AudioStego {
    /// Audio specification (sample rate, channels, etc.)
    spec: WavSpec,
    /// Audio samples (16-bit signed integers)
    samples: Vec<i16>,
}

impl AudioStego {
    /// Creates a new AudioStego from a file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, AudioStegoError> {
        let reader = WavReader::open(path)
            .map_err(|e| AudioStegoError::AudioLoadError(e.to_string()))?;

        Self::from_reader(reader)
    }

    /// Creates a new AudioStego from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AudioStegoError> {
        let cursor = Cursor::new(bytes);
        let reader = WavReader::new(cursor)
            .map_err(|e| AudioStegoError::AudioLoadError(e.to_string()))?;

        Self::from_reader(reader)
    }

    /// Creates AudioStego from a WavReader.
    fn from_reader<R: Read + Seek>(reader: WavReader<R>) -> Result<Self, AudioStegoError> {
        let spec = reader.spec();

        // We only support 16-bit PCM for simplicity
        if spec.sample_format != SampleFormat::Int || spec.bits_per_sample != 16 {
            return Err(AudioStegoError::UnsupportedFormat(format!(
                "Only 16-bit PCM WAV is supported, got {} bits {:?}",
                spec.bits_per_sample, spec.sample_format
            )));
        }

        let samples: Vec<i16> = reader
            .into_samples::<i16>()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AudioStegoError::AudioLoadError(e.to_string()))?;

        Ok(Self { spec, samples })
    }

    /// Returns the capacity in bytes that can be hidden in this audio.
    pub fn capacity(&self) -> usize {
        // 1 bit per sample, minus 4 bytes for length header
        (self.samples.len() / 8).saturating_sub(4)
    }

    /// Returns the duration in seconds.
    pub fn duration_secs(&self) -> f64 {
        let total_samples = self.samples.len() / self.spec.channels as usize;
        total_samples as f64 / self.spec.sample_rate as f64
    }

    /// Hides data in the audio using LSB steganography.
    ///
    /// # Arguments
    /// * `data` - The data to hide
    ///
    /// # Returns
    /// A new AudioStego with the data hidden inside.
    pub fn hide(&self, data: &[u8]) -> Result<Self, AudioStegoError> {
        let capacity = self.capacity();
        if data.len() > capacity {
            return Err(AudioStegoError::AudioTooShort {
                needed: (data.len() + 4) * 8,
                available: self.samples.len(),
            });
        }

        // Prepare data with length prefix
        let len_bytes = (data.len() as u32).to_le_bytes();
        let mut full_data = Vec::with_capacity(4 + data.len());
        full_data.extend_from_slice(&len_bytes);
        full_data.extend_from_slice(data);

        // Clone samples and modify
        let mut new_samples = self.samples.clone();

        for (bit_index, sample) in new_samples.iter_mut().enumerate() {
            if bit_index >= full_data.len() * 8 {
                break;
            }

            let byte_idx = bit_index / 8;
            let bit_offset = bit_index % 8;
            let bit = ((full_data[byte_idx] >> bit_offset) & 1) as i16;

            // Clear LSB and set new bit
            *sample = (*sample & !1) | bit;
        }

        Ok(Self {
            spec: self.spec,
            samples: new_samples,
        })
    }

    /// Extracts hidden data from the audio.
    ///
    /// # Returns
    /// The extracted data if found.
    pub fn extract(&self) -> Result<Vec<u8>, AudioStegoError> {
        if self.samples.len() < 32 {
            return Err(AudioStegoError::NoDataFound);
        }

        // Extract length (4 bytes = 32 bits = 32 samples)
        let mut len_bytes = [0u8; 4];
        for bit_index in 0..32 {
            let bit = (self.samples[bit_index] & 1) as u8;
            let byte_idx = bit_index / 8;
            let bit_offset = bit_index % 8;
            len_bytes[byte_idx] |= bit << bit_offset;
        }

        let data_len = u32::from_le_bytes(len_bytes) as usize;

        // Sanity check
        if data_len > self.capacity() {
            return Err(AudioStegoError::NoDataFound);
        }

        if data_len == 0 {
            return Ok(vec![]);
        }

        // Extract data
        let mut data = vec![0u8; data_len];
        let start_sample = 32;

        for bit_index in 0..(data_len * 8) {
            let sample_idx = start_sample + bit_index;
            if sample_idx >= self.samples.len() {
                break;
            }

            let bit = (self.samples[sample_idx] & 1) as u8;
            let byte_idx = bit_index / 8;
            let bit_offset = bit_index % 8;

            if byte_idx < data.len() {
                data[byte_idx] |= bit << bit_offset;
            }
        }

        Ok(data)
    }

    /// Saves the audio to a WAV file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), AudioStegoError> {
        let mut writer = WavWriter::create(path, self.spec)
            .map_err(|e| AudioStegoError::AudioSaveError(e.to_string()))?;

        for sample in &self.samples {
            writer
                .write_sample(*sample)
                .map_err(|e| AudioStegoError::AudioSaveError(e.to_string()))?;
        }

        writer
            .finalize()
            .map_err(|e| AudioStegoError::AudioSaveError(e.to_string()))?;

        Ok(())
    }

    /// Returns the audio as WAV bytes.
    pub fn to_wav_bytes(&self) -> Result<Vec<u8>, AudioStegoError> {
        let mut bytes = Vec::new();
        {
            let cursor = Cursor::new(&mut bytes);
            let mut writer = WavWriter::new(cursor, self.spec)
                .map_err(|e| AudioStegoError::AudioSaveError(e.to_string()))?;

            for sample in &self.samples {
                writer
                    .write_sample(*sample)
                    .map_err(|e| AudioStegoError::AudioSaveError(e.to_string()))?;
            }

            writer
                .finalize()
                .map_err(|e| AudioStegoError::AudioSaveError(e.to_string()))?;
        }
        Ok(bytes)
    }

    /// Returns the audio specification.
    pub fn spec(&self) -> &WavSpec {
        &self.spec
    }

    /// Returns the number of samples.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }
}

/// Creates a simple test WAV audio.
#[cfg(test)]
fn create_test_audio(sample_count: usize) -> AudioStego {
    let spec = WavSpec {
        channels: 1,
        sample_rate: 44100,
        bits_per_sample: 16,
        sample_format: SampleFormat::Int,
    };

    // Generate a simple sine wave
    let samples: Vec<i16> = (0..sample_count)
        .map(|i| {
            let t = i as f64 / 44100.0;
            let freq = 440.0; // A4 note
            (f64::sin(2.0 * std::f64::consts::PI * freq * t) * 16000.0) as i16
        })
        .collect();

    AudioStego { spec, samples }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capacity() {
        let audio = create_test_audio(10000);
        // 10000 samples / 8 bits per byte - 4 bytes header = 1246 bytes
        assert_eq!(audio.capacity(), 1246);
    }

    #[test]
    fn test_hide_and_extract_small() {
        let audio = create_test_audio(10000);
        let data = b"Hello, audio steganography!";

        let hidden = audio.hide(data).unwrap();
        let extracted = hidden.extract().unwrap();

        assert_eq!(extracted, data);
    }

    #[test]
    fn test_hide_and_extract_larger() {
        let audio = create_test_audio(100000);
        let data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();

        let hidden = audio.hide(&data).unwrap();
        let extracted = hidden.extract().unwrap();

        assert_eq!(extracted, data);
    }

    #[test]
    fn test_audio_too_short() {
        let audio = create_test_audio(100);
        let data = vec![0u8; 1000];

        let result = audio.hide(&data);
        assert!(matches!(result, Err(AudioStegoError::AudioTooShort { .. })));
    }

    #[test]
    fn test_empty_data() {
        let audio = create_test_audio(10000);
        let data: &[u8] = &[];

        let hidden = audio.hide(data).unwrap();
        let extracted = hidden.extract().unwrap();

        assert!(extracted.is_empty());
    }

    #[test]
    fn test_wav_roundtrip() {
        let audio = create_test_audio(10000);
        let data = b"Test WAV roundtrip";

        let hidden = audio.hide(data).unwrap();

        // Convert to WAV bytes and back
        let wav_bytes = hidden.to_wav_bytes().unwrap();
        let loaded = AudioStego::from_bytes(&wav_bytes).unwrap();
        let extracted = loaded.extract().unwrap();

        assert_eq!(extracted, data);
    }
}
