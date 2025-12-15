//! Multi-recipient encryption for KAMO.
//!
//! Allows encrypting a message for multiple recipients efficiently:
//! 1. Generate a random symmetric key
//! 2. Encrypt the message once with the symmetric key
//! 3. Encrypt the symmetric key for each recipient's public key
//! 4. Recipients can decrypt the symmetric key with their private key
//!
//! This is more efficient than encrypting the entire message for each recipient.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use super::compression::{compress, decompress};
use super::symmetric::{encrypt_symmetric, decrypt_symmetric};
use super::KeyPair;

/// HKDF salt for multi-recipient encryption.
const SALT_MULTI: &[u8] = b"KAMO-MULTI-V1";

/// Errors for multi-recipient operations.
#[derive(Error, Debug)]
pub enum MultiRecipientError {
    #[error("No recipients specified")]
    NoRecipients,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Compression failed: {0}")]
    CompressionFailed(String),

    #[error("Invalid data format")]
    InvalidFormat,

    #[error("Recipient not found in encrypted data")]
    RecipientNotFound,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// An encrypted key for a single recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientKey {
    /// Recipient's public key (to identify which key to use).
    pub recipient_public: [u8; 32],
    /// Ephemeral public key used for this recipient.
    pub ephemeral_public: [u8; 32],
    /// Encrypted symmetric key (nonce + ciphertext).
    pub encrypted_key: Vec<u8>,
}

/// Multi-recipient encrypted data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiRecipientData {
    /// Protocol version.
    pub version: u8,
    /// Encrypted keys for each recipient.
    pub recipient_keys: Vec<RecipientKey>,
    /// Nonce for the message encryption.
    pub message_nonce: [u8; 12],
    /// The encrypted message (same for all recipients).
    pub encrypted_message: Vec<u8>,
}

impl MultiRecipientData {
    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MultiRecipientError> {
        bincode::serialize(self)
            .map_err(|e| MultiRecipientError::SerializationError(e.to_string()))
    }

    /// Deserializes from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, MultiRecipientError> {
        bincode::deserialize(data)
            .map_err(|e| MultiRecipientError::SerializationError(e.to_string()))
    }
}

/// Encrypts data for multiple recipients.
///
/// The message is compressed, then encrypted once with a random key.
/// The random key is then encrypted for each recipient's public key.
///
/// # Arguments
/// * `plaintext` - The data to encrypt
/// * `passphrase` - Additional passphrase protection
/// * `recipients` - Public keys of all recipients
///
/// # Returns
/// `MultiRecipientData` containing the encrypted message and keys for all recipients.
pub fn encrypt_multi(
    plaintext: &[u8],
    passphrase: &str,
    recipients: &[PublicKey],
) -> Result<MultiRecipientData, MultiRecipientError> {
    if recipients.is_empty() {
        return Err(MultiRecipientError::NoRecipients);
    }

    // Step 1: Compress the plaintext
    let compressed = compress(plaintext)
        .map_err(|e| MultiRecipientError::CompressionFailed(e.to_string()))?;

    // Step 2: Encrypt with passphrase first (symmetric)
    let passphrase_encrypted = encrypt_symmetric(&compressed, passphrase)
        .map_err(|e| MultiRecipientError::EncryptionFailed(e.to_string()))?;

    // Step 3: Generate random symmetric key for the message
    let mut message_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut message_key);

    // Step 4: Encrypt the message with the random key
    let mut message_nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut message_nonce);

    let cipher = ChaCha20Poly1305::new_from_slice(&message_key)
        .map_err(|_| MultiRecipientError::EncryptionFailed("Invalid key".to_string()))?;

    let encrypted_message = cipher
        .encrypt(Nonce::from_slice(&message_nonce), passphrase_encrypted.as_ref())
        .map_err(|e| MultiRecipientError::EncryptionFailed(e.to_string()))?;

    // Step 5: Encrypt the message key for each recipient
    let mut recipient_keys = Vec::with_capacity(recipients.len());

    for recipient_public in recipients {
        let encrypted_key = encrypt_key_for_recipient(&message_key, recipient_public)?;
        recipient_keys.push(encrypted_key);
    }

    Ok(MultiRecipientData {
        version: 1,
        recipient_keys,
        message_nonce,
        encrypted_message,
    })
}

/// Decrypts data as one of the recipients.
///
/// # Arguments
/// * `data` - The multi-recipient encrypted data
/// * `passphrase` - The passphrase used during encryption
/// * `secret_key` - The recipient's private key
///
/// # Returns
/// The decrypted plaintext if successful.
pub fn decrypt_multi(
    data: &MultiRecipientData,
    passphrase: &str,
    secret_key: &StaticSecret,
) -> Result<Vec<u8>, MultiRecipientError> {
    // Calculate our public key to find the right encrypted key
    let our_public = PublicKey::from(secret_key);

    // Step 1: Find our encrypted key
    let our_key_data = data
        .recipient_keys
        .iter()
        .find(|rk| rk.recipient_public == *our_public.as_bytes())
        .ok_or(MultiRecipientError::RecipientNotFound)?;

    // Step 2: Decrypt the message key
    let message_key = decrypt_key_for_recipient(our_key_data, secret_key)?;

    // Step 3: Decrypt the message
    let cipher = ChaCha20Poly1305::new_from_slice(&message_key)
        .map_err(|_| MultiRecipientError::DecryptionFailed("Invalid key".to_string()))?;

    let passphrase_encrypted = cipher
        .decrypt(
            Nonce::from_slice(&data.message_nonce),
            data.encrypted_message.as_ref(),
        )
        .map_err(|e| MultiRecipientError::DecryptionFailed(e.to_string()))?;

    // Step 4: Decrypt with passphrase
    let compressed = decrypt_symmetric(&passphrase_encrypted, passphrase)
        .map_err(|e| MultiRecipientError::DecryptionFailed(e.to_string()))?;

    // Step 5: Decompress
    let plaintext = decompress(&compressed)
        .map_err(|e| MultiRecipientError::CompressionFailed(e.to_string()))?;

    Ok(plaintext)
}

/// Encrypts a symmetric key for a single recipient.
fn encrypt_key_for_recipient(
    message_key: &[u8; 32],
    recipient_public: &PublicKey,
) -> Result<RecipientKey, MultiRecipientError> {
    // Generate ephemeral keypair
    let ephemeral = KeyPair::generate();

    // Derive shared secret via ECDH
    let shared_secret = ephemeral.secret_key().diffie_hellman(recipient_public);

    // Derive encryption key using HKDF
    let hk = Hkdf::<Sha256>::new(Some(SALT_MULTI), shared_secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"key-encryption", &mut key)
        .map_err(|_| MultiRecipientError::EncryptionFailed("HKDF failed".to_string()))?;

    // Encrypt the message key
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| MultiRecipientError::EncryptionFailed("Invalid key".to_string()))?;

    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), message_key.as_ref())
        .map_err(|e| MultiRecipientError::EncryptionFailed(e.to_string()))?;

    // Combine nonce + ciphertext
    let mut encrypted_key = Vec::with_capacity(12 + encrypted.len());
    encrypted_key.extend_from_slice(&nonce_bytes);
    encrypted_key.extend(encrypted);

    Ok(RecipientKey {
        recipient_public: *recipient_public.as_bytes(),
        ephemeral_public: *ephemeral.public_key().as_bytes(),
        encrypted_key,
    })
}

/// Decrypts a symmetric key using our private key.
fn decrypt_key_for_recipient(
    recipient_key: &RecipientKey,
    secret_key: &StaticSecret,
) -> Result<[u8; 32], MultiRecipientError> {
    if recipient_key.encrypted_key.len() < 12 {
        return Err(MultiRecipientError::InvalidFormat);
    }

    // Reconstruct ephemeral public key
    let ephemeral_public = PublicKey::from(recipient_key.ephemeral_public);

    // Derive shared secret via ECDH
    let shared_secret = secret_key.diffie_hellman(&ephemeral_public);

    // Derive encryption key using HKDF
    let hk = Hkdf::<Sha256>::new(Some(SALT_MULTI), shared_secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"key-encryption", &mut key)
        .map_err(|_| MultiRecipientError::DecryptionFailed("HKDF failed".to_string()))?;

    // Extract nonce and ciphertext
    let nonce = Nonce::from_slice(&recipient_key.encrypted_key[..12]);
    let ciphertext = &recipient_key.encrypted_key[12..];

    // Decrypt the message key
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| MultiRecipientError::DecryptionFailed("Invalid key".to_string()))?;

    let decrypted = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| MultiRecipientError::DecryptionFailed(e.to_string()))?;

    if decrypted.len() != 32 {
        return Err(MultiRecipientError::InvalidFormat);
    }

    let mut message_key = [0u8; 32];
    message_key.copy_from_slice(&decrypted);

    Ok(message_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_recipient_single() {
        let recipient = KeyPair::generate();
        let plaintext = b"Hello, multi-recipient world!";
        let passphrase = "test_pass";

        let encrypted = encrypt_multi(plaintext, passphrase, &[*recipient.public_key()]).unwrap();
        let decrypted = decrypt_multi(&encrypted, passphrase, recipient.secret_key()).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_multi_recipient_multiple() {
        let recipient1 = KeyPair::generate();
        let recipient2 = KeyPair::generate();
        let recipient3 = KeyPair::generate();

        let plaintext = b"Secret message for three people";
        let passphrase = "shared_secret";

        let encrypted = encrypt_multi(
            plaintext,
            passphrase,
            &[
                *recipient1.public_key(),
                *recipient2.public_key(),
                *recipient3.public_key(),
            ],
        )
        .unwrap();

        // All three should be able to decrypt
        let decrypted1 = decrypt_multi(&encrypted, passphrase, recipient1.secret_key()).unwrap();
        let decrypted2 = decrypt_multi(&encrypted, passphrase, recipient2.secret_key()).unwrap();
        let decrypted3 = decrypt_multi(&encrypted, passphrase, recipient3.secret_key()).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted1.as_slice());
        assert_eq!(plaintext.as_slice(), decrypted2.as_slice());
        assert_eq!(plaintext.as_slice(), decrypted3.as_slice());
    }

    #[test]
    fn test_multi_recipient_wrong_key() {
        let recipient = KeyPair::generate();
        let wrong_key = KeyPair::generate();

        let plaintext = b"Secret";
        let passphrase = "test";

        let encrypted = encrypt_multi(plaintext, passphrase, &[*recipient.public_key()]).unwrap();
        let result = decrypt_multi(&encrypted, passphrase, wrong_key.secret_key());

        assert!(result.is_err());
    }

    #[test]
    fn test_multi_recipient_wrong_passphrase() {
        let recipient = KeyPair::generate();
        let plaintext = b"Secret";

        let encrypted =
            encrypt_multi(plaintext, "correct", &[*recipient.public_key()]).unwrap();
        let result = decrypt_multi(&encrypted, "wrong", recipient.secret_key());

        assert!(result.is_err());
    }

    #[test]
    fn test_multi_recipient_no_recipients() {
        let plaintext = b"Secret";
        let result = encrypt_multi(plaintext, "test", &[]);

        assert!(matches!(result, Err(MultiRecipientError::NoRecipients)));
    }

    #[test]
    fn test_multi_recipient_serialization() {
        let recipient = KeyPair::generate();
        let plaintext = b"Test serialization";
        let passphrase = "test";

        let encrypted = encrypt_multi(plaintext, passphrase, &[*recipient.public_key()]).unwrap();

        // Serialize and deserialize
        let bytes = encrypted.to_bytes().unwrap();
        let deserialized = MultiRecipientData::from_bytes(&bytes).unwrap();

        // Should still decrypt correctly
        let decrypted = decrypt_multi(&deserialized, passphrase, recipient.secret_key()).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
