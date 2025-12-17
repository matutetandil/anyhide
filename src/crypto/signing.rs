//! Digital signature operations using Ed25519.
//!
//! This module provides message signing and verification using Ed25519,
//! which is separate from the X25519 encryption keys for security best practices.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;
use thiserror::Error;

/// PEM header for Anyhide signing public keys.
const SIGNING_PUBLIC_KEY_HEADER: &str = "-----BEGIN ANYHIDE SIGNING PUBLIC KEY-----";
const SIGNING_PUBLIC_KEY_FOOTER: &str = "-----END ANYHIDE SIGNING PUBLIC KEY-----";

/// PEM header for Anyhide signing private keys.
const SIGNING_PRIVATE_KEY_HEADER: &str = "-----BEGIN ANYHIDE SIGNING PRIVATE KEY-----";
const SIGNING_PRIVATE_KEY_FOOTER: &str = "-----END ANYHIDE SIGNING PRIVATE KEY-----";

/// Errors that can occur during signing operations.
#[derive(Error, Debug)]
pub enum SigningError {
    #[error("Invalid PEM format: {0}")]
    InvalidPemFormat(String),

    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Invalid signature format")]
    InvalidSignature,

    #[error("Invalid signing key")]
    InvalidSigningKey,

    #[error("Invalid verifying key")]
    InvalidVerifyingKey,
}

/// An Ed25519 key pair for signing and verifying messages.
#[derive(Clone)]
pub struct SigningKeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl SigningKeyPair {
    /// Generates a new random signing key pair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Creates a signing key pair from raw secret bytes (for mnemonic import).
    ///
    /// The verifying (public) key is derived from the signing (private) key.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, SigningError> {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Returns the verifying (public) key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Returns the signing (private) key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Signs a message and returns the signature bytes.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    /// Saves the signing key pair to files.
    ///
    /// Creates `{base_path}.sign.pub` for public key and `{base_path}.sign.key` for private key.
    pub fn save_to_files(&self, base_path: &Path) -> Result<(), SigningError> {
        let pub_path = add_sign_extension(base_path, "pub");
        let key_path = add_sign_extension(base_path, "key");

        let pub_pem = encode_verifying_key_pem(&self.verifying_key);
        let key_pem = encode_signing_key_pem(&self.signing_key);

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

    /// Loads a signing key pair from files.
    pub fn load_from_files(base_path: &Path) -> Result<Self, SigningError> {
        let pub_path = add_sign_extension(base_path, "pub");
        let key_path = add_sign_extension(base_path, "key");

        let verifying_key = load_verifying_key(&pub_path)?;
        let signing_key = load_signing_key(&key_path)?;

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }
}

/// Helper to create paths like "alice.sign.pub" from "alice"
fn add_sign_extension(base_path: &Path, ext: &str) -> std::path::PathBuf {
    let mut path = base_path.as_os_str().to_os_string();
    path.push(".sign.");
    path.push(ext);
    std::path::PathBuf::from(path)
}

/// Signs a message with the given signing key.
pub fn sign_message(message: &[u8], signing_key: &SigningKey) -> Vec<u8> {
    let signature = signing_key.sign(message);
    signature.to_bytes().to_vec()
}

/// Verifies a signature against a message using the given verifying key.
pub fn verify_signature(
    message: &[u8],
    signature_bytes: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<(), SigningError> {
    if signature_bytes.len() != 64 {
        return Err(SigningError::InvalidSignature);
    }

    let sig_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| SigningError::InvalidSignature)?;

    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(message, &signature)
        .map_err(|_| SigningError::VerificationFailed)
}

/// Encodes a verifying (public) key to PEM format.
pub fn encode_verifying_key_pem(key: &VerifyingKey) -> String {
    let encoded = BASE64.encode(key.as_bytes());
    format!(
        "{}\n{}\n{}\n",
        SIGNING_PUBLIC_KEY_HEADER, encoded, SIGNING_PUBLIC_KEY_FOOTER
    )
}

/// Encodes a signing (private) key to PEM format.
pub fn encode_signing_key_pem(key: &SigningKey) -> String {
    let encoded = BASE64.encode(key.to_bytes());
    format!(
        "{}\n{}\n{}\n",
        SIGNING_PRIVATE_KEY_HEADER, encoded, SIGNING_PRIVATE_KEY_FOOTER
    )
}

/// Loads a verifying (public) key from a PEM file.
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey, SigningError> {
    let content = fs::read_to_string(path)?;
    decode_verifying_key_pem(&content)
}

/// Loads a signing (private) key from a PEM file.
pub fn load_signing_key(path: &Path) -> Result<SigningKey, SigningError> {
    let content = fs::read_to_string(path)?;
    decode_signing_key_pem(&content)
}

/// Decodes a verifying (public) key from PEM format.
pub fn decode_verifying_key_pem(pem: &str) -> Result<VerifyingKey, SigningError> {
    let base64_content =
        extract_pem_content(pem, SIGNING_PUBLIC_KEY_HEADER, SIGNING_PUBLIC_KEY_FOOTER)?;
    let bytes = BASE64.decode(base64_content.trim())?;

    if bytes.len() != 32 {
        return Err(SigningError::InvalidKeyLength {
            expected: 32,
            got: bytes.len(),
        });
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);

    VerifyingKey::from_bytes(&key_bytes).map_err(|_| SigningError::InvalidVerifyingKey)
}

/// Decodes a signing (private) key from PEM format.
pub fn decode_signing_key_pem(pem: &str) -> Result<SigningKey, SigningError> {
    let base64_content =
        extract_pem_content(pem, SIGNING_PRIVATE_KEY_HEADER, SIGNING_PRIVATE_KEY_FOOTER)?;
    let bytes = BASE64.decode(base64_content.trim())?;

    if bytes.len() != 32 {
        return Err(SigningError::InvalidKeyLength {
            expected: 32,
            got: bytes.len(),
        });
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);

    Ok(SigningKey::from_bytes(&key_bytes))
}

/// Extracts the base64 content from a PEM string.
fn extract_pem_content<'a>(
    pem: &'a str,
    header: &str,
    footer: &str,
) -> Result<&'a str, SigningError> {
    let start = pem
        .find(header)
        .ok_or_else(|| SigningError::InvalidPemFormat("Missing header".to_string()))?
        + header.len();

    let end = pem
        .find(footer)
        .ok_or_else(|| SigningError::InvalidPemFormat("Missing footer".to_string()))?;

    if start >= end {
        return Err(SigningError::InvalidPemFormat(
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
    fn test_signing_key_generation() {
        let kp1 = SigningKeyPair::generate();
        let kp2 = SigningKeyPair::generate();

        // Keys should be different
        assert_ne!(
            kp1.verifying_key().as_bytes(),
            kp2.verifying_key().as_bytes()
        );
    }

    #[test]
    fn test_sign_and_verify() {
        let kp = SigningKeyPair::generate();
        let message = b"Hello, World!";

        let signature = kp.sign(message);
        let result = verify_signature(message, &signature, kp.verifying_key());

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let kp = SigningKeyPair::generate();
        let message = b"Hello, World!";
        let wrong_message = b"Wrong message";

        let signature = kp.sign(message);
        let result = verify_signature(wrong_message, &signature, kp.verifying_key());

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let kp1 = SigningKeyPair::generate();
        let kp2 = SigningKeyPair::generate();
        let message = b"Hello, World!";

        let signature = kp1.sign(message);
        let result = verify_signature(message, &signature, kp2.verifying_key());

        assert!(result.is_err());
    }

    #[test]
    fn test_pem_roundtrip_verifying() {
        let kp = SigningKeyPair::generate();
        let pem = encode_verifying_key_pem(kp.verifying_key());
        let decoded = decode_verifying_key_pem(&pem).unwrap();

        assert_eq!(kp.verifying_key().as_bytes(), decoded.as_bytes());
    }

    #[test]
    fn test_pem_roundtrip_signing() {
        let kp = SigningKeyPair::generate();
        let pem = encode_signing_key_pem(kp.signing_key());
        let decoded = decode_signing_key_pem(&pem).unwrap();

        assert_eq!(kp.signing_key().to_bytes(), decoded.to_bytes());
    }

    #[test]
    fn test_save_and_load_files() {
        let dir = tempdir().unwrap();
        let base_path = dir.path().join("testkey");

        let kp = SigningKeyPair::generate();
        kp.save_to_files(&base_path).unwrap();

        let loaded = SigningKeyPair::load_from_files(&base_path).unwrap();

        assert_eq!(
            kp.verifying_key().as_bytes(),
            loaded.verifying_key().as_bytes()
        );
        assert_eq!(kp.signing_key().to_bytes(), loaded.signing_key().to_bytes());
    }

    #[test]
    fn test_sign_verify_with_loaded_keys() {
        let dir = tempdir().unwrap();
        let base_path = dir.path().join("testkey");

        let kp = SigningKeyPair::generate();
        kp.save_to_files(&base_path).unwrap();

        let message = b"Secret message to sign";
        let signature = kp.sign(message);

        // Load only the verifying key and verify
        let verifying_key = load_verifying_key(&add_sign_extension(&base_path, "pub")).unwrap();
        let result = verify_signature(message, &signature, &verifying_key);

        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_signature_length() {
        let kp = SigningKeyPair::generate();
        let message = b"Hello";
        let bad_signature = vec![0u8; 32]; // Wrong length

        let result = verify_signature(message, &bad_signature, kp.verifying_key());
        assert!(matches!(result, Err(SigningError::InvalidSignature)));
    }
}
