//! Key generation and management for Anyhide.
//!
//! This module handles X25519 key pair generation and PEM format serialization.
//! Supports both long-term keys and ephemeral keys for forward secrecy, and a
//! parallel hybrid post-quantum keypair (`HybridKeyPair`) combining X25519 and
//! ML-KEM-768 for harvest-now-decrypt-later resistance.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use super::hybrid_kem::{
    self, HybridKemError, HybridPublicKey, HybridSecretKey, HYBRID_PUBKEY_SIZE,
    HYBRID_SECRET_KEY_SIZE,
};

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
// PEM Headers - Hybrid post-quantum keys (X25519 + ML-KEM-768)
// ============================================================================

/// PEM header for Anyhide long-term hybrid public keys.
const HYBRID_PUBLIC_KEY_HEADER: &str = "-----BEGIN ANYHIDE HYBRID PUBLIC KEY-----";
const HYBRID_PUBLIC_KEY_FOOTER: &str = "-----END ANYHIDE HYBRID PUBLIC KEY-----";

/// PEM header for Anyhide long-term hybrid private keys.
const HYBRID_PRIVATE_KEY_HEADER: &str = "-----BEGIN ANYHIDE HYBRID PRIVATE KEY-----";
const HYBRID_PRIVATE_KEY_FOOTER: &str = "-----END ANYHIDE HYBRID PRIVATE KEY-----";

/// PEM header for Anyhide ephemeral hybrid public keys.
const EPHEMERAL_HYBRID_PUBLIC_KEY_HEADER: &str =
    "-----BEGIN ANYHIDE EPHEMERAL HYBRID PUBLIC KEY-----";
const EPHEMERAL_HYBRID_PUBLIC_KEY_FOOTER: &str =
    "-----END ANYHIDE EPHEMERAL HYBRID PUBLIC KEY-----";

/// PEM header for Anyhide ephemeral hybrid private keys.
const EPHEMERAL_HYBRID_PRIVATE_KEY_HEADER: &str =
    "-----BEGIN ANYHIDE EPHEMERAL HYBRID PRIVATE KEY-----";
const EPHEMERAL_HYBRID_PRIVATE_KEY_FOOTER: &str =
    "-----END ANYHIDE EPHEMERAL HYBRID PRIVATE KEY-----";

// ============================================================================
// Key Type
// ============================================================================

/// Represents the type of key (long-term, ephemeral, or hybrid post-quantum variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Long-term classical X25519 key that never changes automatically.
    LongTerm,
    /// Ephemeral classical X25519 key that rotates with each message for forward secrecy.
    Ephemeral,
    /// Long-term hybrid post-quantum key (X25519 + ML-KEM-768).
    HybridV1,
    /// Ephemeral hybrid post-quantum key (X25519 + ML-KEM-768) for forward secrecy.
    EphemeralHybridV1,
}

impl KeyType {
    /// Returns true if this key type is a hybrid post-quantum variant.
    pub fn is_hybrid(self) -> bool {
        matches!(self, KeyType::HybridV1 | KeyType::EphemeralHybridV1)
    }

    /// Returns true if this key type is ephemeral (rotates per message).
    pub fn is_ephemeral_kind(self) -> bool {
        matches!(self, KeyType::Ephemeral | KeyType::EphemeralHybridV1)
    }
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

    #[error("Hybrid KEM error: {0}")]
    HybridKemError(#[from] HybridKemError),
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

    /// Creates a key pair from raw secret bytes (for mnemonic import).
    ///
    /// The public key is derived from the secret key.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let secret = StaticSecret::from(*bytes);
        let public = PublicKey::from(&secret);
        Self {
            secret,
            public,
            key_type: KeyType::LongTerm,
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

/// Encodes a classical X25519 public key to PEM format with specified key type.
///
/// Panics if `key_type` is a hybrid variant — use [`encode_hybrid_public_key_pem`]
/// for hybrid keys (the bytes representation is different).
pub fn encode_public_key_pem_with_type(key: &PublicKey, key_type: KeyType) -> String {
    let encoded = BASE64.encode(key.as_bytes());
    let (header, footer) = match key_type {
        KeyType::LongTerm => (PUBLIC_KEY_HEADER, PUBLIC_KEY_FOOTER),
        KeyType::Ephemeral => (EPHEMERAL_PUBLIC_KEY_HEADER, EPHEMERAL_PUBLIC_KEY_FOOTER),
        KeyType::HybridV1 | KeyType::EphemeralHybridV1 => panic!(
            "encode_public_key_pem_with_type called with hybrid type; use encode_hybrid_public_key_pem"
        ),
    };
    format!("{}\n{}\n{}\n", header, encoded, footer)
}

/// Encodes a classical X25519 secret key to PEM format with specified key type.
///
/// Panics if `key_type` is a hybrid variant — use [`encode_hybrid_secret_key_pem`]
/// for hybrid keys.
pub fn encode_secret_key_pem_with_type(key: &StaticSecret, key_type: KeyType) -> String {
    let encoded = BASE64.encode(key.as_bytes());
    let (header, footer) = match key_type {
        KeyType::LongTerm => (PRIVATE_KEY_HEADER, PRIVATE_KEY_FOOTER),
        KeyType::Ephemeral => (EPHEMERAL_PRIVATE_KEY_HEADER, EPHEMERAL_PRIVATE_KEY_FOOTER),
        KeyType::HybridV1 | KeyType::EphemeralHybridV1 => panic!(
            "encode_secret_key_pem_with_type called with hybrid type; use encode_hybrid_secret_key_pem"
        ),
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

/// Saves an ephemeral private key to a PEM file.
pub fn save_ephemeral_private_key_pem(key: &StaticSecret, path: &Path) -> Result<(), KeyError> {
    let pem = encode_ephemeral_secret_key_pem(key);
    fs::write(path, pem)?;

    // Set restrictive permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Saves an ephemeral public key to a PEM file.
pub fn save_ephemeral_public_key_pem(key: &PublicKey, path: &Path) -> Result<(), KeyError> {
    let pem = encode_ephemeral_public_key_pem(key);
    fs::write(path, pem)?;
    Ok(())
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

/// Decodes a classical X25519 public key from PEM format, detecting key type automatically.
///
/// Returns an error if the PEM is hybrid — hybrid PEMs must be loaded via
/// [`decode_hybrid_public_key_pem`] because their byte format is different.
pub fn decode_public_key_pem_with_type(pem: &str) -> Result<(PublicKey, KeyType), KeyError> {
    // Reject hybrid PEMs explicitly so callers see a clear error instead of
    // a misleading "invalid key length" from base64 decoding 1216 bytes.
    if pem.contains(EPHEMERAL_HYBRID_PUBLIC_KEY_HEADER) || pem.contains(HYBRID_PUBLIC_KEY_HEADER) {
        return Err(KeyError::InvalidPemFormat(
            "PEM is a hybrid public key; use decode_hybrid_public_key_pem".to_string(),
        ));
    }

    // Try ephemeral first, then long-term. The hybrid check above ensures we
    // do not accidentally match the classical "EPHEMERAL PUBLIC KEY" substring
    // inside an "EPHEMERAL HYBRID PUBLIC KEY" header.
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

/// Decodes a classical X25519 secret key from PEM format, detecting key type automatically.
///
/// Returns an error if the PEM is hybrid — hybrid PEMs must be loaded via
/// [`decode_hybrid_secret_key_pem`] because their byte format is different.
pub fn decode_secret_key_pem_with_type(pem: &str) -> Result<(StaticSecret, KeyType), KeyError> {
    if pem.contains(EPHEMERAL_HYBRID_PRIVATE_KEY_HEADER)
        || pem.contains(HYBRID_PRIVATE_KEY_HEADER)
    {
        return Err(KeyError::InvalidPemFormat(
            "PEM is a hybrid private key; use decode_hybrid_secret_key_pem".to_string(),
        ));
    }

    // Try ephemeral first, then long-term.
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
///
/// Checks hybrid headers before classical ones because hybrid PEMs also
/// contain the substrings "EPHEMERAL" and "ANYHIDE".
pub fn detect_key_type(pem: &str) -> Option<KeyType> {
    let is_hybrid = pem.contains("HYBRID");
    let is_ephemeral = pem.contains("EPHEMERAL");
    let is_anyhide = pem.contains("ANYHIDE");

    match (is_anyhide, is_hybrid, is_ephemeral) {
        (true, true, true) => Some(KeyType::EphemeralHybridV1),
        (true, true, false) => Some(KeyType::HybridV1),
        (true, false, true) => Some(KeyType::Ephemeral),
        (true, false, false) => Some(KeyType::LongTerm),
        _ => None,
    }
}

// ============================================================================
// Hybrid post-quantum keypair (X25519 + ML-KEM-768)
// ============================================================================

/// A hybrid post-quantum key pair combining X25519 ECDH and ML-KEM-768.
///
/// Mirrors the [`KeyPair`] API but operates on [`HybridSecretKey`] /
/// [`HybridPublicKey`] (defined in [`super::hybrid_kem`]). Like `KeyPair`,
/// it can be either long-term ([`KeyType::HybridV1`]) or ephemeral
/// ([`KeyType::EphemeralHybridV1`]).
pub struct HybridKeyPair {
    secret: HybridSecretKey,
    public: HybridPublicKey,
    key_type: KeyType,
}

impl std::fmt::Debug for HybridKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridKeyPair")
            .field("public", &BASE64.encode(self.public.to_bytes()))
            .field("key_type", &self.key_type)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl HybridKeyPair {
    /// Generates a new long-term hybrid keypair.
    pub fn generate() -> Self {
        let (secret, public) = hybrid_kem::generate_keypair();
        Self {
            secret,
            public,
            key_type: KeyType::HybridV1,
        }
    }

    /// Generates a new ephemeral hybrid keypair for forward secrecy.
    pub fn generate_ephemeral() -> Self {
        let (secret, public) = hybrid_kem::generate_keypair();
        Self {
            secret,
            public,
            key_type: KeyType::EphemeralHybridV1,
        }
    }

    /// Returns the key type (`HybridV1` or `EphemeralHybridV1`).
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Returns true if this is an ephemeral hybrid keypair.
    pub fn is_ephemeral(&self) -> bool {
        self.key_type == KeyType::EphemeralHybridV1
    }

    /// Returns the hybrid public key.
    pub fn public_key(&self) -> &HybridPublicKey {
        &self.public
    }

    /// Returns the hybrid secret key.
    pub fn secret_key(&self) -> &HybridSecretKey {
        &self.secret
    }

    /// Consumes the keypair and returns the secret key.
    pub fn into_secret_key(self) -> HybridSecretKey {
        self.secret
    }

    /// Saves the hybrid keypair to `{base_path}.pub` and `{base_path}.key`.
    ///
    /// Uses hybrid PEM headers; restrictive permissions (0o600) on the private
    /// key on Unix.
    pub fn save_to_files(&self, base_path: &Path) -> Result<(), KeyError> {
        let pub_path = base_path.with_extension("pub");
        let key_path = base_path.with_extension("key");

        let pub_pem = encode_hybrid_public_key_pem(&self.public, self.key_type)?;
        let key_pem = encode_hybrid_secret_key_pem(&self.secret, self.key_type)?;

        fs::write(&pub_path, pub_pem)?;
        fs::write(&key_path, key_pem)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&key_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&key_path, perms)?;
        }

        Ok(())
    }

    /// Loads a hybrid keypair from `{base_path}.pub` and `{base_path}.key`.
    ///
    /// Validates that both files use the same hybrid key type.
    pub fn load_from_files(base_path: &Path) -> Result<Self, KeyError> {
        let pub_path = base_path.with_extension("pub");
        let key_path = base_path.with_extension("key");

        let (public, pub_type) = load_hybrid_public_key_with_type(&pub_path)?;
        let (secret, key_type) = load_hybrid_secret_key_with_type(&key_path)?;

        if pub_type != key_type {
            return Err(KeyError::InvalidPemFormat(
                "Hybrid public and private key types don't match".to_string(),
            ));
        }

        Ok(Self {
            secret,
            public,
            key_type,
        })
    }
}

/// Encodes a hybrid public key to PEM format.
///
/// Returns an error if `key_type` is not a hybrid variant.
pub fn encode_hybrid_public_key_pem(
    key: &HybridPublicKey,
    key_type: KeyType,
) -> Result<String, KeyError> {
    let (header, footer) = match key_type {
        KeyType::HybridV1 => (HYBRID_PUBLIC_KEY_HEADER, HYBRID_PUBLIC_KEY_FOOTER),
        KeyType::EphemeralHybridV1 => (
            EPHEMERAL_HYBRID_PUBLIC_KEY_HEADER,
            EPHEMERAL_HYBRID_PUBLIC_KEY_FOOTER,
        ),
        _ => {
            return Err(KeyError::InvalidPemFormat(
                "encode_hybrid_public_key_pem requires a hybrid KeyType".to_string(),
            ));
        }
    };
    let encoded = BASE64.encode(key.to_bytes());
    Ok(format!("{}\n{}\n{}\n", header, encoded, footer))
}

/// Encodes a hybrid secret key to PEM format.
///
/// Returns an error if `key_type` is not a hybrid variant.
pub fn encode_hybrid_secret_key_pem(
    key: &HybridSecretKey,
    key_type: KeyType,
) -> Result<String, KeyError> {
    let (header, footer) = match key_type {
        KeyType::HybridV1 => (HYBRID_PRIVATE_KEY_HEADER, HYBRID_PRIVATE_KEY_FOOTER),
        KeyType::EphemeralHybridV1 => (
            EPHEMERAL_HYBRID_PRIVATE_KEY_HEADER,
            EPHEMERAL_HYBRID_PRIVATE_KEY_FOOTER,
        ),
        _ => {
            return Err(KeyError::InvalidPemFormat(
                "encode_hybrid_secret_key_pem requires a hybrid KeyType".to_string(),
            ));
        }
    };
    let encoded = BASE64.encode(key.to_bytes());
    Ok(format!("{}\n{}\n{}\n", header, encoded, footer))
}

/// Decodes a hybrid public key from PEM format, detecting whether it is long-term or ephemeral.
pub fn decode_hybrid_public_key_pem(pem: &str) -> Result<(HybridPublicKey, KeyType), KeyError> {
    let (base64_content, key_type) = if pem.contains(EPHEMERAL_HYBRID_PUBLIC_KEY_HEADER) {
        (
            extract_pem_content(
                pem,
                EPHEMERAL_HYBRID_PUBLIC_KEY_HEADER,
                EPHEMERAL_HYBRID_PUBLIC_KEY_FOOTER,
            )?,
            KeyType::EphemeralHybridV1,
        )
    } else if pem.contains(HYBRID_PUBLIC_KEY_HEADER) {
        (
            extract_pem_content(pem, HYBRID_PUBLIC_KEY_HEADER, HYBRID_PUBLIC_KEY_FOOTER)?,
            KeyType::HybridV1,
        )
    } else {
        return Err(KeyError::InvalidPemFormat(
            "No valid hybrid public key header found".to_string(),
        ));
    };

    let bytes = BASE64.decode(base64_content.trim())?;
    if bytes.len() != HYBRID_PUBKEY_SIZE {
        return Err(KeyError::InvalidKeyLength {
            expected: HYBRID_PUBKEY_SIZE,
            got: bytes.len(),
        });
    }

    let public = HybridPublicKey::from_bytes(&bytes)?;
    Ok((public, key_type))
}

/// Decodes a hybrid secret key from PEM format, detecting whether it is long-term or ephemeral.
pub fn decode_hybrid_secret_key_pem(pem: &str) -> Result<(HybridSecretKey, KeyType), KeyError> {
    let (base64_content, key_type) = if pem.contains(EPHEMERAL_HYBRID_PRIVATE_KEY_HEADER) {
        (
            extract_pem_content(
                pem,
                EPHEMERAL_HYBRID_PRIVATE_KEY_HEADER,
                EPHEMERAL_HYBRID_PRIVATE_KEY_FOOTER,
            )?,
            KeyType::EphemeralHybridV1,
        )
    } else if pem.contains(HYBRID_PRIVATE_KEY_HEADER) {
        (
            extract_pem_content(pem, HYBRID_PRIVATE_KEY_HEADER, HYBRID_PRIVATE_KEY_FOOTER)?,
            KeyType::HybridV1,
        )
    } else {
        return Err(KeyError::InvalidPemFormat(
            "No valid hybrid private key header found".to_string(),
        ));
    };

    let bytes = BASE64.decode(base64_content.trim())?;
    if bytes.len() != HYBRID_SECRET_KEY_SIZE {
        return Err(KeyError::InvalidKeyLength {
            expected: HYBRID_SECRET_KEY_SIZE,
            got: bytes.len(),
        });
    }

    let secret = HybridSecretKey::from_bytes(&bytes)?;
    Ok((secret, key_type))
}

/// Loads a hybrid public key from a PEM file, returning the key and detected type.
pub fn load_hybrid_public_key_with_type(
    path: &Path,
) -> Result<(HybridPublicKey, KeyType), KeyError> {
    let content = fs::read_to_string(path)?;
    decode_hybrid_public_key_pem(&content)
}

/// Loads a hybrid secret key from a PEM file, returning the key and detected type.
pub fn load_hybrid_secret_key_with_type(
    path: &Path,
) -> Result<(HybridSecretKey, KeyType), KeyError> {
    let content = fs::read_to_string(path)?;
    decode_hybrid_secret_key_pem(&content)
}

/// Loads a hybrid public key from a PEM file (type info discarded).
pub fn load_hybrid_public_key(path: &Path) -> Result<HybridPublicKey, KeyError> {
    let (key, _) = load_hybrid_public_key_with_type(path)?;
    Ok(key)
}

/// Loads a hybrid secret key from a PEM file (type info discarded).
pub fn load_hybrid_secret_key(path: &Path) -> Result<HybridSecretKey, KeyError> {
    let (key, _) = load_hybrid_secret_key_with_type(path)?;
    Ok(key)
}

/// Saves an ephemeral hybrid private key to a PEM file with restrictive permissions.
pub fn save_ephemeral_hybrid_private_key_pem(
    key: &HybridSecretKey,
    path: &Path,
) -> Result<(), KeyError> {
    let pem = encode_hybrid_secret_key_pem(key, KeyType::EphemeralHybridV1)?;
    fs::write(path, pem)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Saves an ephemeral hybrid public key to a PEM file.
pub fn save_ephemeral_hybrid_public_key_pem(
    key: &HybridPublicKey,
    path: &Path,
) -> Result<(), KeyError> {
    let pem = encode_hybrid_public_key_pem(key, KeyType::EphemeralHybridV1)?;
    fs::write(path, pem)?;
    Ok(())
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

    // ========================================================================
    // Hybrid keypair tests
    // ========================================================================

    #[test]
    fn test_hybrid_keypair_generate_long_term() {
        let kp = HybridKeyPair::generate();
        assert_eq!(kp.key_type(), KeyType::HybridV1);
        assert!(!kp.is_ephemeral());
        assert!(kp.key_type().is_hybrid());
    }

    #[test]
    fn test_hybrid_keypair_generate_ephemeral() {
        let kp = HybridKeyPair::generate_ephemeral();
        assert_eq!(kp.key_type(), KeyType::EphemeralHybridV1);
        assert!(kp.is_ephemeral());
        assert!(kp.key_type().is_hybrid());
        assert!(kp.key_type().is_ephemeral_kind());
    }

    #[test]
    fn test_hybrid_pem_roundtrip_public() {
        let kp = HybridKeyPair::generate();
        let pem = encode_hybrid_public_key_pem(kp.public_key(), kp.key_type()).unwrap();

        assert!(pem.contains("-----BEGIN ANYHIDE HYBRID PUBLIC KEY-----"));

        let (decoded, key_type) = decode_hybrid_public_key_pem(&pem).unwrap();
        assert_eq!(decoded.to_bytes(), kp.public_key().to_bytes());
        assert_eq!(key_type, KeyType::HybridV1);
    }

    #[test]
    fn test_hybrid_pem_roundtrip_secret_recovers_decapsulation() {
        let kp = HybridKeyPair::generate();
        let pem = encode_hybrid_secret_key_pem(kp.secret_key(), kp.key_type()).unwrap();

        assert!(pem.contains("-----BEGIN ANYHIDE HYBRID PRIVATE KEY-----"));

        let (decoded, key_type) = decode_hybrid_secret_key_pem(&pem).unwrap();
        assert_eq!(key_type, KeyType::HybridV1);
        // Decoded secret derives the same public key
        assert_eq!(decoded.public_key().to_bytes(), kp.public_key().to_bytes());
    }

    #[test]
    fn test_ephemeral_hybrid_pem_roundtrip() {
        let kp = HybridKeyPair::generate_ephemeral();
        let pub_pem = encode_hybrid_public_key_pem(kp.public_key(), kp.key_type()).unwrap();
        let key_pem = encode_hybrid_secret_key_pem(kp.secret_key(), kp.key_type()).unwrap();

        assert!(pub_pem.contains("EPHEMERAL HYBRID PUBLIC"));
        assert!(key_pem.contains("EPHEMERAL HYBRID PRIVATE"));

        let (_, pub_type) = decode_hybrid_public_key_pem(&pub_pem).unwrap();
        let (_, sec_type) = decode_hybrid_secret_key_pem(&key_pem).unwrap();

        assert_eq!(pub_type, KeyType::EphemeralHybridV1);
        assert_eq!(sec_type, KeyType::EphemeralHybridV1);
    }

    #[test]
    fn test_hybrid_save_and_load_files() {
        let dir = tempdir().unwrap();
        let base_path = dir.path().join("hybrid_key");

        let kp = HybridKeyPair::generate();
        kp.save_to_files(&base_path).unwrap();

        let loaded = HybridKeyPair::load_from_files(&base_path).unwrap();

        assert_eq!(
            kp.public_key().to_bytes(),
            loaded.public_key().to_bytes()
        );
        // Verify secret key works by deriving the public key
        assert_eq!(
            loaded.secret_key().public_key().to_bytes(),
            kp.public_key().to_bytes()
        );
        assert_eq!(loaded.key_type(), KeyType::HybridV1);
    }

    #[test]
    fn test_hybrid_save_and_load_ephemeral_files() {
        let dir = tempdir().unwrap();
        let base_path = dir.path().join("eph_hybrid_key");

        let kp = HybridKeyPair::generate_ephemeral();
        kp.save_to_files(&base_path).unwrap();

        let loaded = HybridKeyPair::load_from_files(&base_path).unwrap();
        assert_eq!(loaded.key_type(), KeyType::EphemeralHybridV1);
        assert!(loaded.is_ephemeral());
    }

    #[test]
    fn test_detect_key_type_distinguishes_hybrid() {
        let classical = KeyPair::generate();
        let classical_eph = KeyPair::generate_ephemeral();
        let hybrid = HybridKeyPair::generate();
        let hybrid_eph = HybridKeyPair::generate_ephemeral();

        let classical_pem = encode_public_key_pem(classical.public_key());
        let classical_eph_pem = encode_ephemeral_public_key_pem(classical_eph.public_key());
        let hybrid_pem = encode_hybrid_public_key_pem(hybrid.public_key(), hybrid.key_type()).unwrap();
        let hybrid_eph_pem =
            encode_hybrid_public_key_pem(hybrid_eph.public_key(), hybrid_eph.key_type()).unwrap();

        assert_eq!(detect_key_type(&classical_pem), Some(KeyType::LongTerm));
        assert_eq!(detect_key_type(&classical_eph_pem), Some(KeyType::Ephemeral));
        assert_eq!(detect_key_type(&hybrid_pem), Some(KeyType::HybridV1));
        assert_eq!(
            detect_key_type(&hybrid_eph_pem),
            Some(KeyType::EphemeralHybridV1)
        );
    }

    #[test]
    fn test_classical_decoder_rejects_hybrid_pem() {
        let hybrid = HybridKeyPair::generate();
        let pem = encode_hybrid_public_key_pem(hybrid.public_key(), hybrid.key_type()).unwrap();

        // Classical decoder must refuse hybrid PEMs explicitly rather than
        // fail mid-base64-decode with a misleading error.
        let result = decode_public_key_pem_with_type(&pem);
        assert!(matches!(result, Err(KeyError::InvalidPemFormat(_))));
    }

    #[test]
    fn test_hybrid_decoder_rejects_classical_pem() {
        let classical = KeyPair::generate();
        let pem = encode_public_key_pem(classical.public_key());

        let result = decode_hybrid_public_key_pem(&pem);
        assert!(matches!(result, Err(KeyError::InvalidPemFormat(_))));
    }

    #[test]
    fn test_hybrid_encoder_rejects_non_hybrid_keytype() {
        let hybrid = HybridKeyPair::generate();
        let result = encode_hybrid_public_key_pem(hybrid.public_key(), KeyType::LongTerm);
        assert!(matches!(result, Err(KeyError::InvalidPemFormat(_))));
    }
}
