//! Ephemeral key storage for managing multiple contacts with forward secrecy.
//!
//! This module provides three storage formats for ephemeral keys:
//! - `.eph.key`: Only private keys, indexed by contact name
//! - `.eph.pub`: Only public keys, indexed by contact name
//! - `.eph`: Unified format with both private and public keys per contact

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use super::keys::KeyPair;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

/// Errors that can occur during ephemeral store operations.
#[derive(Error, Debug)]
pub enum EphemeralStoreError {
    #[error("Contact not found: {0}")]
    ContactNotFound(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Invalid key data: {0}")]
    InvalidKeyData(String),

    #[error("File format not supported: {0}")]
    UnsupportedFormat(String),
}

// ============================================================================
// Serializable structures for JSON storage
// ============================================================================

/// A single contact's private key entry.
#[derive(Serialize, Deserialize, Clone)]
struct PrivateKeyEntry {
    /// Base64-encoded private key bytes
    key: String,
}

/// A single contact's public key entry.
#[derive(Serialize, Deserialize, Clone)]
struct PublicKeyEntry {
    /// Base64-encoded public key bytes
    key: String,
}

/// A single contact's full entry (both keys).
#[derive(Serialize, Deserialize, Clone)]
struct UnifiedEntry {
    /// Base64-encoded private key bytes (my key for this contact)
    my_private: String,
    /// Base64-encoded public key bytes (their key)
    their_public: String,
}

/// Storage for private keys only (.eph.key format).
#[derive(Serialize, Deserialize, Default)]
struct PrivateKeyStore {
    /// Version of the store format
    version: u8,
    /// Map of contact name to private key
    contacts: HashMap<String, PrivateKeyEntry>,
}

/// Storage for public keys only (.eph.pub format).
#[derive(Serialize, Deserialize, Default)]
struct PublicKeyStore {
    /// Version of the store format
    version: u8,
    /// Map of contact name to public key
    contacts: HashMap<String, PublicKeyEntry>,
}

/// Unified storage for both keys (.eph format).
#[derive(Serialize, Deserialize, Default)]
struct UnifiedStore {
    /// Version of the store format
    version: u8,
    /// Map of contact name to key pair
    contacts: HashMap<String, UnifiedEntry>,
}

const STORE_VERSION: u8 = 1;

// ============================================================================
// Public API
// ============================================================================

/// Detects the ephemeral store format from a file path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EphemeralStoreFormat {
    /// `.eph.key` - Only private keys
    PrivateOnly,
    /// `.eph.pub` - Only public keys
    PublicOnly,
    /// `.eph` - Unified format
    Unified,
}

impl EphemeralStoreFormat {
    /// Detects format from file path extension.
    pub fn from_path(path: &Path) -> Option<Self> {
        let path_str = path.to_string_lossy();
        if path_str.ends_with(".eph.key") {
            Some(Self::PrivateOnly)
        } else if path_str.ends_with(".eph.pub") {
            Some(Self::PublicOnly)
        } else if path_str.ends_with(".eph") {
            Some(Self::Unified)
        } else {
            None
        }
    }
}

// ============================================================================
// Private Key Store (.eph.key)
// ============================================================================

/// Loads a private key for a contact from a .eph.key file.
pub fn load_private_key_for_contact(
    path: &Path,
    contact: &str,
) -> Result<StaticSecret, EphemeralStoreError> {
    let content = fs::read_to_string(path)?;
    let store: PrivateKeyStore = serde_json::from_str(&content)?;

    let entry = store
        .contacts
        .get(contact)
        .ok_or_else(|| EphemeralStoreError::ContactNotFound(contact.to_string()))?;

    decode_private_key(&entry.key)
}

/// Saves or updates a private key for a contact in a .eph.key file.
pub fn save_private_key_for_contact(
    path: &Path,
    contact: &str,
    key: &StaticSecret,
) -> Result<(), EphemeralStoreError> {
    let mut store = if path.exists() {
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content)?
    } else {
        PrivateKeyStore {
            version: STORE_VERSION,
            contacts: HashMap::new(),
        }
    };

    store.contacts.insert(
        contact.to_string(),
        PrivateKeyEntry {
            key: BASE64.encode(key.as_bytes()),
        },
    );

    let content = serde_json::to_string_pretty(&store)?;
    fs::write(path, content)?;

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

/// Lists all contacts in a .eph.key file.
pub fn list_private_key_contacts(path: &Path) -> Result<Vec<String>, EphemeralStoreError> {
    let content = fs::read_to_string(path)?;
    let store: PrivateKeyStore = serde_json::from_str(&content)?;
    Ok(store.contacts.keys().cloned().collect())
}

// ============================================================================
// Public Key Store (.eph.pub)
// ============================================================================

/// Loads a public key for a contact from a .eph.pub file.
pub fn load_public_key_for_contact(
    path: &Path,
    contact: &str,
) -> Result<PublicKey, EphemeralStoreError> {
    let content = fs::read_to_string(path)?;
    let store: PublicKeyStore = serde_json::from_str(&content)?;

    let entry = store
        .contacts
        .get(contact)
        .ok_or_else(|| EphemeralStoreError::ContactNotFound(contact.to_string()))?;

    decode_public_key(&entry.key)
}

/// Saves or updates a public key for a contact in a .eph.pub file.
pub fn save_public_key_for_contact(
    path: &Path,
    contact: &str,
    key: &PublicKey,
) -> Result<(), EphemeralStoreError> {
    let mut store = if path.exists() {
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content)?
    } else {
        PublicKeyStore {
            version: STORE_VERSION,
            contacts: HashMap::new(),
        }
    };

    store.contacts.insert(
        contact.to_string(),
        PublicKeyEntry {
            key: BASE64.encode(key.as_bytes()),
        },
    );

    let content = serde_json::to_string_pretty(&store)?;
    fs::write(path, content)?;

    Ok(())
}

/// Lists all contacts in a .eph.pub file.
pub fn list_public_key_contacts(path: &Path) -> Result<Vec<String>, EphemeralStoreError> {
    let content = fs::read_to_string(path)?;
    let store: PublicKeyStore = serde_json::from_str(&content)?;
    Ok(store.contacts.keys().cloned().collect())
}

// ============================================================================
// Unified Store (.eph)
// ============================================================================

/// A contact's key pair from unified storage.
pub struct ContactKeys {
    /// My private key for this contact
    pub my_private: StaticSecret,
    /// Their public key
    pub their_public: PublicKey,
}

/// Loads keys for a contact from a .eph file.
pub fn load_unified_keys_for_contact(
    path: &Path,
    contact: &str,
) -> Result<ContactKeys, EphemeralStoreError> {
    let content = fs::read_to_string(path)?;
    let store: UnifiedStore = serde_json::from_str(&content)?;

    let entry = store
        .contacts
        .get(contact)
        .ok_or_else(|| EphemeralStoreError::ContactNotFound(contact.to_string()))?;

    Ok(ContactKeys {
        my_private: decode_private_key(&entry.my_private)?,
        their_public: decode_public_key(&entry.their_public)?,
    })
}

/// Saves or updates keys for a contact in a .eph file.
pub fn save_unified_keys_for_contact(
    path: &Path,
    contact: &str,
    my_private: &StaticSecret,
    their_public: &PublicKey,
) -> Result<(), EphemeralStoreError> {
    let mut store = if path.exists() {
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content)?
    } else {
        UnifiedStore {
            version: STORE_VERSION,
            contacts: HashMap::new(),
        }
    };

    store.contacts.insert(
        contact.to_string(),
        UnifiedEntry {
            my_private: BASE64.encode(my_private.as_bytes()),
            their_public: BASE64.encode(their_public.as_bytes()),
        },
    );

    let content = serde_json::to_string_pretty(&store)?;
    fs::write(path, content)?;

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

/// Updates only the public key for a contact in a .eph file.
pub fn update_unified_public_key(
    path: &Path,
    contact: &str,
    their_public: &PublicKey,
) -> Result<(), EphemeralStoreError> {
    let content = fs::read_to_string(path)?;
    let mut store: UnifiedStore = serde_json::from_str(&content)?;

    let entry = store
        .contacts
        .get_mut(contact)
        .ok_or_else(|| EphemeralStoreError::ContactNotFound(contact.to_string()))?;

    entry.their_public = BASE64.encode(their_public.as_bytes());

    let content = serde_json::to_string_pretty(&store)?;
    fs::write(path, content)?;

    Ok(())
}

/// Updates only the private key for a contact in a .eph file.
pub fn update_unified_private_key(
    path: &Path,
    contact: &str,
    my_private: &StaticSecret,
) -> Result<(), EphemeralStoreError> {
    let content = fs::read_to_string(path)?;
    let mut store: UnifiedStore = serde_json::from_str(&content)?;

    let entry = store
        .contacts
        .get_mut(contact)
        .ok_or_else(|| EphemeralStoreError::ContactNotFound(contact.to_string()))?;

    entry.my_private = BASE64.encode(my_private.as_bytes());

    let content = serde_json::to_string_pretty(&store)?;
    fs::write(path, content)?;

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

/// Lists all contacts in a .eph file.
pub fn list_unified_contacts(path: &Path) -> Result<Vec<String>, EphemeralStoreError> {
    let content = fs::read_to_string(path)?;
    let store: UnifiedStore = serde_json::from_str(&content)?;
    Ok(store.contacts.keys().cloned().collect())
}

/// Generates a new ephemeral key pair and saves it to a .eph file for a contact.
/// Also returns the public key so it can be shared with the contact.
pub fn generate_and_save_ephemeral_for_contact(
    path: &Path,
    contact: &str,
    their_public: &PublicKey,
) -> Result<PublicKey, EphemeralStoreError> {
    let keypair = KeyPair::generate_ephemeral();
    let my_public = *keypair.public_key();

    save_unified_keys_for_contact(path, contact, keypair.secret_key(), their_public)?;

    Ok(my_public)
}

// ============================================================================
// Helper functions
// ============================================================================

fn decode_private_key(base64_key: &str) -> Result<StaticSecret, EphemeralStoreError> {
    let bytes = BASE64
        .decode(base64_key)
        .map_err(|e| EphemeralStoreError::InvalidKeyData(e.to_string()))?;

    if bytes.len() != 32 {
        return Err(EphemeralStoreError::InvalidKeyData(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Ok(StaticSecret::from(key_bytes))
}

fn decode_public_key(base64_key: &str) -> Result<PublicKey, EphemeralStoreError> {
    let bytes = BASE64
        .decode(base64_key)
        .map_err(|e| EphemeralStoreError::InvalidKeyData(e.to_string()))?;

    if bytes.len() != 32 {
        return Err(EphemeralStoreError::InvalidKeyData(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Ok(PublicKey::from(key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_ephemeral_store_format_detection() {
        assert_eq!(
            EphemeralStoreFormat::from_path(Path::new("alice.eph.key")),
            Some(EphemeralStoreFormat::PrivateOnly)
        );
        assert_eq!(
            EphemeralStoreFormat::from_path(Path::new("alice.eph.pub")),
            Some(EphemeralStoreFormat::PublicOnly)
        );
        assert_eq!(
            EphemeralStoreFormat::from_path(Path::new("alice.eph")),
            Some(EphemeralStoreFormat::Unified)
        );
        assert_eq!(
            EphemeralStoreFormat::from_path(Path::new("alice.pub")),
            None
        );
    }

    #[test]
    fn test_private_key_store_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.eph.key");

        let keypair = KeyPair::generate_ephemeral();

        save_private_key_for_contact(&path, "bob", keypair.secret_key()).unwrap();
        let loaded = load_private_key_for_contact(&path, "bob").unwrap();

        assert_eq!(keypair.secret_key().as_bytes(), loaded.as_bytes());
    }

    #[test]
    fn test_public_key_store_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.eph.pub");

        let keypair = KeyPair::generate_ephemeral();

        save_public_key_for_contact(&path, "bob", keypair.public_key()).unwrap();
        let loaded = load_public_key_for_contact(&path, "bob").unwrap();

        assert_eq!(keypair.public_key().as_bytes(), loaded.as_bytes());
    }

    #[test]
    fn test_unified_store_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.eph");

        let my_keypair = KeyPair::generate_ephemeral();
        let their_keypair = KeyPair::generate_ephemeral();

        save_unified_keys_for_contact(
            &path,
            "bob",
            my_keypair.secret_key(),
            their_keypair.public_key(),
        )
        .unwrap();

        let loaded = load_unified_keys_for_contact(&path, "bob").unwrap();

        assert_eq!(my_keypair.secret_key().as_bytes(), loaded.my_private.as_bytes());
        assert_eq!(their_keypair.public_key().as_bytes(), loaded.their_public.as_bytes());
    }

    #[test]
    fn test_multiple_contacts() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.eph");

        let bob_my = KeyPair::generate_ephemeral();
        let bob_their = KeyPair::generate_ephemeral();
        let alice_my = KeyPair::generate_ephemeral();
        let alice_their = KeyPair::generate_ephemeral();

        save_unified_keys_for_contact(&path, "bob", bob_my.secret_key(), bob_their.public_key()).unwrap();
        save_unified_keys_for_contact(&path, "alice", alice_my.secret_key(), alice_their.public_key()).unwrap();

        let contacts = list_unified_contacts(&path).unwrap();
        assert_eq!(contacts.len(), 2);
        assert!(contacts.contains(&"bob".to_string()));
        assert!(contacts.contains(&"alice".to_string()));

        let bob_loaded = load_unified_keys_for_contact(&path, "bob").unwrap();
        let alice_loaded = load_unified_keys_for_contact(&path, "alice").unwrap();

        assert_eq!(bob_my.secret_key().as_bytes(), bob_loaded.my_private.as_bytes());
        assert_eq!(alice_my.secret_key().as_bytes(), alice_loaded.my_private.as_bytes());
    }

    #[test]
    fn test_update_public_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.eph");

        let my_keypair = KeyPair::generate_ephemeral();
        let their_old = KeyPair::generate_ephemeral();
        let their_new = KeyPair::generate_ephemeral();

        save_unified_keys_for_contact(&path, "bob", my_keypair.secret_key(), their_old.public_key()).unwrap();
        update_unified_public_key(&path, "bob", their_new.public_key()).unwrap();

        let loaded = load_unified_keys_for_contact(&path, "bob").unwrap();

        // Private key unchanged
        assert_eq!(my_keypair.secret_key().as_bytes(), loaded.my_private.as_bytes());
        // Public key updated
        assert_eq!(their_new.public_key().as_bytes(), loaded.their_public.as_bytes());
    }

    #[test]
    fn test_contact_not_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.eph");

        let my_keypair = KeyPair::generate_ephemeral();
        let their_keypair = KeyPair::generate_ephemeral();

        save_unified_keys_for_contact(&path, "bob", my_keypair.secret_key(), their_keypair.public_key()).unwrap();

        let result = load_unified_keys_for_contact(&path, "alice");
        assert!(matches!(result, Err(EphemeralStoreError::ContactNotFound(_))));
    }
}
