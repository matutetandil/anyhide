//! Key generation and management for Anyhide.
//!
//! This module handles X25519 key pair generation and PEM format serialization.
//! Supports both long-term keys and ephemeral keys for forward secrecy.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

// ============================================================================
// PEM Headers - Long-term keys
// ============================================================================

/// PEM header for Anyhide public keys.
const PUBLIC_KEY_HEADER: &str = "-----BEGIN ANYHIDE PUBLIC KEY-----";
const PUBLIC_KEY_FOOTER: &str = "-----END ANYHIDE PUBLIC KEY-----";

/// PEM header for Anyhide private keys.
const PRIVATE_KEY_HEADER: &str = "-----BEGIN ANYHIDE PRIVATE KEY-----";
const PRIVATE_KEY_FOOTER: &str = "-----END ANYHIDE PRIVATE KEY-----";

// ============================================================================
// PEM Headers - Ephemeral keys (for forward secrecy ratchet)
// ============================================================================

/// PEM header for Anyhide ephemeral public keys.
const EPHEMERAL_PUBLIC_KEY_HEADER: &str = "-----BEGIN ANYHIDE EPHEMERAL PUBLIC KEY-----";
const EPHEMERAL_PUBLIC_KEY_FOOTER: &str = "-----END ANYHIDE EPHEMERAL PUBLIC KEY-----";

/// PEM header for Anyhide ephemeral private keys.
const EPHEMERAL_PRIVATE_KEY_HEADER: &str = "-----BEGIN ANYHIDE EPHEMERAL PRIVATE KEY-----";
const EPHEMERAL_PRIVATE_KEY_FOOTER: &str = "-----END ANYHIDE EPHEMERAL PRIVATE KEY-----";

// ============================================================================
// Key Type
// ============================================================================

/// Represents the type of key (long-term or ephemeral).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Long-term key that never changes automatically.
    LongTerm,
    /// Ephemeral key that rotates with each message for forward secrecy.
    Ephemeral,
}

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

/// An Anyhide key pair containing both public and private keys.
#[derive(Clone)]
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
    key_type: KeyType,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't expose private key in debug output for security
        f.debug_struct("KeyPair")
            .field("public", &BASE64.encode(self.public.as_bytes()))
            .field("key_type", &self.key_type)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl KeyPair {
    /// Generates a new random long-term key pair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret,
            public,
            key_type: KeyType::LongTerm,
        }
    }

    /// Generates a new random ephemeral key pair for forward secrecy.
    pub fn generate_ephemeral() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret,
            public,
            key_type: KeyType::Ephemeral,
        }
    }

    /// Returns the key type (long-term or ephemeral).
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Returns true if this is an ephemeral key.
    pub fn is_ephemeral(&self) -> bool {
        self.key_type == KeyType::Ephemeral
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
    /// Uses appropriate PEM headers based on key type (long-term or ephemeral).
    pub fn save_to_files(&self, base_path: &Path) -> Result<(), KeyError> {
        let pub_path = base_path.with_extension("pub");
        let key_path = base_path.with_extension("key");

        let pub_pem = encode_public_key_pem_with_type(&self.public, self.key_type);
        let key_pem = encode_secret_key_pem_with_type(&self.secret, self.key_type);

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

    /// Loads a key pair from files, automatically detecting key type from PEM headers.
    pub fn load_from_files(base_path: &Path) -> Result<Self, KeyError> {
        let pub_path = base_path.with_extension("pub");
        let key_path = base_path.with_extension("key");

        let (public, pub_type) = load_public_key_with_type(&pub_path)?;
        let (secret, key_type) = load_secret_key_with_type(&key_path)?;

        // Both files should have the same key type
        if pub_type != key_type {
            return Err(KeyError::InvalidPemFormat(
                "Public and private key types don't match".to_string(),
            ));
        }

        Ok(Self {
            secret,
            public,
            key_type,
        })
    }
}

/// Encodes a public key to PEM format (long-term key).
pub fn encode_public_key_pem(key: &PublicKey) -> String {
    encode_public_key_pem_with_type(key, KeyType::LongTerm)
}

/// Encodes a secret key to PEM format (long-term key).
pub fn encode_secret_key_pem(key: &StaticSecret) -> String {
    encode_secret_key_pem_with_type(key, KeyType::LongTerm)
}

/// Encodes a public key to PEM format with specified key type.
pub fn encode_public_key_pem_with_type(key: &PublicKey, key_type: KeyType) -> String {
    let encoded = BASE64.encode(key.as_bytes());
    let (header, footer) = match key_type {
        KeyType::LongTerm => (PUBLIC_KEY_HEADER, PUBLIC_KEY_FOOTER),
        KeyType::Ephemeral => (EPHEMERAL_PUBLIC_KEY_HEADER, EPHEMERAL_PUBLIC_KEY_FOOTER),
    };
    format!("{}\n{}\n{}\n", header, encoded, footer)
}

/// Encodes a secret key to PEM format with specified key type.
pub fn encode_secret_key_pem_with_type(key: &StaticSecret, key_type: KeyType) -> String {
    let encoded = BASE64.encode(key.as_bytes());
    let (header, footer) = match key_type {
        KeyType::LongTerm => (PRIVATE_KEY_HEADER, PRIVATE_KEY_FOOTER),
        KeyType::Ephemeral => (EPHEMERAL_PRIVATE_KEY_HEADER, EPHEMERAL_PRIVATE_KEY_FOOTER),
    };
    format!("{}\n{}\n{}\n", header, encoded, footer)
}

/// Encodes a public key to ephemeral PEM format.
pub fn encode_ephemeral_public_key_pem(key: &PublicKey) -> String {
    encode_public_key_pem_with_type(key, KeyType::Ephemeral)
}

/// Encodes a secret key to ephemeral PEM format.
pub fn encode_ephemeral_secret_key_pem(key: &StaticSecret) -> String {
    encode_secret_key_pem_with_type(key, KeyType::Ephemeral)
}

/// Loads a public key from a PEM file.
pub fn load_public_key(path: &Path) -> Result<PublicKey, KeyError> {
    let (key, _key_type) = load_public_key_with_type(path)?;
    Ok(key)
}

/// Loads a secret key from a PEM file.
pub fn load_secret_key(path: &Path) -> Result<StaticSecret, KeyError> {
    let (key, _key_type) = load_secret_key_with_type(path)?;
    Ok(key)
}

/// Loads a public key from a PEM file, returning both key and detected type.
pub fn load_public_key_with_type(path: &Path) -> Result<(PublicKey, KeyType), KeyError> {
    let content = fs::read_to_string(path)?;
    decode_public_key_pem_with_type(&content)
}

/// Loads a secret key from a PEM file, returning both key and detected type.
pub fn load_secret_key_with_type(path: &Path) -> Result<(StaticSecret, KeyType), KeyError> {
    let content = fs::read_to_string(path)?;
    decode_secret_key_pem_with_type(&content)
}

/// Decodes a public key from PEM format (long-term only, for backwards compatibility).
pub fn decode_public_key_pem(pem: &str) -> Result<PublicKey, KeyError> {
    let (key, _key_type) = decode_public_key_pem_with_type(pem)?;
    Ok(key)
}

/// Decodes a secret key from PEM format (long-term only, for backwards compatibility).
pub fn decode_secret_key_pem(pem: &str) -> Result<StaticSecret, KeyError> {
    let (key, _key_type) = decode_secret_key_pem_with_type(pem)?;
    Ok(key)
}

/// Decodes a public key from PEM format, detecting key type automatically.
pub fn decode_public_key_pem_with_type(pem: &str) -> Result<(PublicKey, KeyType), KeyError> {
    // Try ephemeral first, then long-term
    let (base64_content, key_type) =
        if pem.contains(EPHEMERAL_PUBLIC_KEY_HEADER) {
            (
                extract_pem_content(pem, EPHEMERAL_PUBLIC_KEY_HEADER, EPHEMERAL_PUBLIC_KEY_FOOTER)?,
                KeyType::Ephemeral,
            )
        } else if pem.contains(PUBLIC_KEY_HEADER) {
            (
                extract_pem_content(pem, PUBLIC_KEY_HEADER, PUBLIC_KEY_FOOTER)?,
                KeyType::LongTerm,
            )
        } else {
            return Err(KeyError::InvalidPemFormat(
                "No valid public key header found".to_string(),
            ));
        };

    let bytes = BASE64.decode(base64_content.trim())?;

    if bytes.len() != 32 {
        return Err(KeyError::InvalidKeyLength {
            expected: 32,
            got: bytes.len(),
        });
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Ok((PublicKey::from(key_bytes), key_type))
}

/// Decodes a secret key from PEM format, detecting key type automatically.
pub fn decode_secret_key_pem_with_type(pem: &str) -> Result<(StaticSecret, KeyType), KeyError> {
    // Try ephemeral first, then long-term
    let (base64_content, key_type) =
        if pem.contains(EPHEMERAL_PRIVATE_KEY_HEADER) {
            (
                extract_pem_content(pem, EPHEMERAL_PRIVATE_KEY_HEADER, EPHEMERAL_PRIVATE_KEY_FOOTER)?,
                KeyType::Ephemeral,
            )
        } else if pem.contains(PRIVATE_KEY_HEADER) {
            (
                extract_pem_content(pem, PRIVATE_KEY_HEADER, PRIVATE_KEY_FOOTER)?,
                KeyType::LongTerm,
            )
        } else {
            return Err(KeyError::InvalidPemFormat(
                "No valid private key header found".to_string(),
            ));
        };

    let bytes = BASE64.decode(base64_content.trim())?;

    if bytes.len() != 32 {
        return Err(KeyError::InvalidKeyLength {
            expected: 32,
            got: bytes.len(),
        });
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Ok((StaticSecret::from(key_bytes), key_type))
}

/// Detects the key type from a PEM string without fully parsing it.
pub fn detect_key_type(pem: &str) -> Option<KeyType> {
    if pem.contains("EPHEMERAL") {
        Some(KeyType::Ephemeral)
    } else if pem.contains("ANYHIDE") {
        Some(KeyType::LongTerm)
    } else {
        None
    }
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
        // Should be long-term by default
        assert_eq!(kp1.key_type(), KeyType::LongTerm);
        assert!(!kp1.is_ephemeral());
    }

    #[test]
    fn test_ephemeral_key_generation() {
        let kp1 = KeyPair::generate_ephemeral();
        let kp2 = KeyPair::generate_ephemeral();

        // Keys should be different
        assert_ne!(kp1.public_key().as_bytes(), kp2.public_key().as_bytes());
        // Should be ephemeral
        assert_eq!(kp1.key_type(), KeyType::Ephemeral);
        assert!(kp1.is_ephemeral());
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
    fn test_ephemeral_pem_roundtrip_public() {
        let kp = KeyPair::generate_ephemeral();
        let pem = encode_ephemeral_public_key_pem(kp.public_key());

        // Check header is correct
        assert!(pem.contains("EPHEMERAL PUBLIC KEY"));

        let (decoded, key_type) = decode_public_key_pem_with_type(&pem).unwrap();
        assert_eq!(kp.public_key().as_bytes(), decoded.as_bytes());
        assert_eq!(key_type, KeyType::Ephemeral);
    }

    #[test]
    fn test_ephemeral_pem_roundtrip_secret() {
        let kp = KeyPair::generate_ephemeral();
        let pem = encode_ephemeral_secret_key_pem(kp.secret_key());

        // Check header is correct
        assert!(pem.contains("EPHEMERAL PRIVATE KEY"));

        let (decoded, key_type) = decode_secret_key_pem_with_type(&pem).unwrap();
        assert_eq!(kp.secret_key().as_bytes(), decoded.as_bytes());
        assert_eq!(key_type, KeyType::Ephemeral);
    }

    #[test]
    fn test_detect_key_type() {
        let long_term = KeyPair::generate();
        let ephemeral = KeyPair::generate_ephemeral();

        let lt_pem = encode_public_key_pem(long_term.public_key());
        let eph_pem = encode_ephemeral_public_key_pem(ephemeral.public_key());

        assert_eq!(detect_key_type(&lt_pem), Some(KeyType::LongTerm));
        assert_eq!(detect_key_type(&eph_pem), Some(KeyType::Ephemeral));
        assert_eq!(detect_key_type("garbage"), None);
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
        assert_eq!(loaded.key_type(), KeyType::LongTerm);
    }

    #[test]
    fn test_save_and_load_ephemeral_files() {
        let dir = tempdir().unwrap();
        let base_path = dir.path().join("ephemeral_key");

        let kp = KeyPair::generate_ephemeral();
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
        assert_eq!(loaded.key_type(), KeyType::Ephemeral);
        assert!(loaded.is_ephemeral());
    }

    #[test]
    fn test_long_term_pem_headers() {
        let kp = KeyPair::generate();
        let pub_pem = encode_public_key_pem(kp.public_key());
        let key_pem = encode_secret_key_pem(kp.secret_key());

        assert!(pub_pem.contains("-----BEGIN ANYHIDE PUBLIC KEY-----"));
        assert!(pub_pem.contains("-----END ANYHIDE PUBLIC KEY-----"));
        assert!(!pub_pem.contains("EPHEMERAL"));

        assert!(key_pem.contains("-----BEGIN ANYHIDE PRIVATE KEY-----"));
        assert!(key_pem.contains("-----END ANYHIDE PRIVATE KEY-----"));
        assert!(!key_pem.contains("EPHEMERAL"));
    }

    #[test]
    fn test_ephemeral_pem_headers() {
        let kp = KeyPair::generate_ephemeral();
        let pub_pem = encode_public_key_pem_with_type(kp.public_key(), KeyType::Ephemeral);
        let key_pem = encode_secret_key_pem_with_type(kp.secret_key(), KeyType::Ephemeral);

        assert!(pub_pem.contains("-----BEGIN ANYHIDE EPHEMERAL PUBLIC KEY-----"));
        assert!(pub_pem.contains("-----END ANYHIDE EPHEMERAL PUBLIC KEY-----"));

        assert!(key_pem.contains("-----BEGIN ANYHIDE EPHEMERAL PRIVATE KEY-----"));
        assert!(key_pem.contains("-----END ANYHIDE EPHEMERAL PRIVATE KEY-----"));
    }
}
