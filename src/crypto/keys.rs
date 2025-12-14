//! Key generation and management for KAMO.
//!
//! This module handles X25519 key pair generation and PEM format serialization.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

/// PEM header for KAMO public keys.
const PUBLIC_KEY_HEADER: &str = "-----BEGIN KAMO PUBLIC KEY-----";
const PUBLIC_KEY_FOOTER: &str = "-----END KAMO PUBLIC KEY-----";

/// PEM header for KAMO private keys.
const PRIVATE_KEY_HEADER: &str = "-----BEGIN KAMO PRIVATE KEY-----";
const PRIVATE_KEY_FOOTER: &str = "-----END KAMO PRIVATE KEY-----";

/// Errors that can occur during key operations.
#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Invalid PEM format: {0}")]
    InvalidPemFormat(String),

    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// A KAMO key pair containing both public and private keys.
#[derive(Clone)]
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    /// Generates a new random key pair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Returns the public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Returns the secret key.
    pub fn secret_key(&self) -> &StaticSecret {
        &self.secret
    }

    /// Consumes the key pair and returns the secret key.
    pub fn into_secret_key(self) -> StaticSecret {
        self.secret
    }

    /// Saves the key pair to files.
    ///
    /// Creates `{base_path}.pub` for public key and `{base_path}.key` for private key.
    pub fn save_to_files(&self, base_path: &Path) -> Result<(), KeyError> {
        let pub_path = base_path.with_extension("pub");
        let key_path = base_path.with_extension("key");

        let pub_pem = encode_public_key_pem(&self.public);
        let key_pem = encode_secret_key_pem(&self.secret);

        fs::write(&pub_path, pub_pem)?;
        fs::write(&key_path, key_pem)?;

        // Set restrictive permissions on private key (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&key_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&key_path, perms)?;
        }

        Ok(())
    }

    /// Loads a key pair from files.
    pub fn load_from_files(base_path: &Path) -> Result<Self, KeyError> {
        let pub_path = base_path.with_extension("pub");
        let key_path = base_path.with_extension("key");

        let public = load_public_key(&pub_path)?;
        let secret = load_secret_key(&key_path)?;

        Ok(Self { secret, public })
    }
}

/// Encodes a public key to PEM format.
pub fn encode_public_key_pem(key: &PublicKey) -> String {
    let encoded = BASE64.encode(key.as_bytes());
    format!("{}\n{}\n{}\n", PUBLIC_KEY_HEADER, encoded, PUBLIC_KEY_FOOTER)
}

/// Encodes a secret key to PEM format.
pub fn encode_secret_key_pem(key: &StaticSecret) -> String {
    let encoded = BASE64.encode(key.as_bytes());
    format!(
        "{}\n{}\n{}\n",
        PRIVATE_KEY_HEADER, encoded, PRIVATE_KEY_FOOTER
    )
}

/// Loads a public key from a PEM file.
pub fn load_public_key(path: &Path) -> Result<PublicKey, KeyError> {
    let content = fs::read_to_string(path)?;
    decode_public_key_pem(&content)
}

/// Loads a secret key from a PEM file.
pub fn load_secret_key(path: &Path) -> Result<StaticSecret, KeyError> {
    let content = fs::read_to_string(path)?;
    decode_secret_key_pem(&content)
}

/// Decodes a public key from PEM format.
pub fn decode_public_key_pem(pem: &str) -> Result<PublicKey, KeyError> {
    let base64_content = extract_pem_content(pem, PUBLIC_KEY_HEADER, PUBLIC_KEY_FOOTER)?;
    let bytes = BASE64.decode(base64_content.trim())?;

    if bytes.len() != 32 {
        return Err(KeyError::InvalidKeyLength {
            expected: 32,
            got: bytes.len(),
        });
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Ok(PublicKey::from(key_bytes))
}

/// Decodes a secret key from PEM format.
pub fn decode_secret_key_pem(pem: &str) -> Result<StaticSecret, KeyError> {
    let base64_content = extract_pem_content(pem, PRIVATE_KEY_HEADER, PRIVATE_KEY_FOOTER)?;
    let bytes = BASE64.decode(base64_content.trim())?;

    if bytes.len() != 32 {
        return Err(KeyError::InvalidKeyLength {
            expected: 32,
            got: bytes.len(),
        });
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Ok(StaticSecret::from(key_bytes))
}

/// Extracts the base64 content from a PEM string.
fn extract_pem_content<'a>(
    pem: &'a str,
    header: &str,
    footer: &str,
) -> Result<&'a str, KeyError> {
    let start = pem
        .find(header)
        .ok_or_else(|| KeyError::InvalidPemFormat("Missing header".to_string()))?
        + header.len();

    let end = pem
        .find(footer)
        .ok_or_else(|| KeyError::InvalidPemFormat("Missing footer".to_string()))?;

    if start >= end {
        return Err(KeyError::InvalidPemFormat(
            "Header must come before footer".to_string(),
        ));
    }

    Ok(pem[start..end].trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_key_generation() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();

        // Keys should be different
        assert_ne!(kp1.public_key().as_bytes(), kp2.public_key().as_bytes());
    }

    #[test]
    fn test_pem_roundtrip_public() {
        let kp = KeyPair::generate();
        let pem = encode_public_key_pem(kp.public_key());
        let decoded = decode_public_key_pem(&pem).unwrap();

        assert_eq!(kp.public_key().as_bytes(), decoded.as_bytes());
    }

    #[test]
    fn test_pem_roundtrip_secret() {
        let kp = KeyPair::generate();
        let pem = encode_secret_key_pem(kp.secret_key());
        let decoded = decode_secret_key_pem(&pem).unwrap();

        assert_eq!(kp.secret_key().as_bytes(), decoded.as_bytes());
    }

    #[test]
    fn test_save_and_load_files() {
        let dir = tempdir().unwrap();
        let base_path = dir.path().join("testkey");

        let kp = KeyPair::generate();
        kp.save_to_files(&base_path).unwrap();

        let loaded = KeyPair::load_from_files(&base_path).unwrap();

        assert_eq!(
            kp.public_key().as_bytes(),
            loaded.public_key().as_bytes()
        );
        assert_eq!(
            kp.secret_key().as_bytes(),
            loaded.secret_key().as_bytes()
        );
    }
}
