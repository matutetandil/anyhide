//! Ephemeral key storage for managing multiple contacts with forward secrecy.
//!
//! This module provides three storage formats for ephemeral keys:
//! - `.eph.key`: Only private keys, indexed by contact name
//! - `.eph.pub`: Only public keys, indexed by contact name
//! - `.eph`: Unified format with both private and public keys per contact
//!
//! Each format has a parallel hybrid post-quantum variant (`*_hybrid` functions)
//! that stores hybrid keypairs (X25519 + ML-KEM-768). Hybrid stores use a
//! `version: 2` discriminator and refuse to load v1 stores; v1 functions in
//! turn refuse to load v2 stores. Files written by either family must be
//! managed by their respective functions — they share file extensions but
//! never share contents.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use super::hybrid_kem::{HybridPublicKey, HybridSecretKey, HYBRID_PUBKEY_SIZE, HYBRID_SECRET_KEY_SIZE};
use super::keys::{HybridKeyPair, KeyPair};
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

    #[error("Store version mismatch: expected {expected}, found {found}")]
    VersionMismatch { expected: u8, found: u8 },

    #[error("Hybrid KEM error: {0}")]
    HybridKemError(#[from] super::hybrid_kem::HybridKemError),
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

/// Version discriminator for hybrid post-quantum stores.
const STORE_VERSION_HYBRID: u8 = 2;

// ============================================================================
// Hybrid serializable structures (parallel to v1, version=2)
// ============================================================================

/// A single contact's hybrid private key entry.
#[derive(Serialize, Deserialize, Clone)]
struct PrivateKeyEntryHybrid {
    /// Base64-encoded hybrid private key bytes (96B: X25519 || ML-KEM seed)
    key: String,
}

/// A single contact's hybrid public key entry.
#[derive(Serialize, Deserialize, Clone)]
struct PublicKeyEntryHybrid {
    /// Base64-encoded hybrid public key bytes (1216B: X25519 || ML-KEM ek)
    key: String,
}

/// A single contact's full hybrid entry.
#[derive(Serialize, Deserialize, Clone)]
struct UnifiedEntryHybrid {
    /// Base64-encoded hybrid private key bytes (my key for this contact)
    my_private: String,
    /// Base64-encoded hybrid public key bytes (their key)
    their_public: String,
}

/// Hybrid storage for private keys only (.eph.key format, version 2).
#[derive(Serialize, Deserialize)]
struct PrivateKeyStoreHybrid {
    version: u8,
    contacts: HashMap<String, PrivateKeyEntryHybrid>,
}

/// Hybrid storage for public keys only (.eph.pub format, version 2).
#[derive(Serialize, Deserialize)]
struct PublicKeyStoreHybrid {
    version: u8,
    contacts: HashMap<String, PublicKeyEntryHybrid>,
}

/// Hybrid unified storage for both keys (.eph format, version 2).
#[derive(Serialize, Deserialize)]
struct UnifiedStoreHybrid {
    version: u8,
    contacts: HashMap<String, UnifiedEntryHybrid>,
}

/// Reads the `version` field from a JSON store file without committing to a
/// particular schema. Returns `None` if the file is empty or missing.
fn peek_store_version(path: &Path) -> Result<Option<u8>, EphemeralStoreError> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path)?;
    if content.trim().is_empty() {
        return Ok(None);
    }

    #[derive(Deserialize)]
    struct VersionProbe {
        version: u8,
    }

    let probe: VersionProbe = serde_json::from_str(&content)?;
    Ok(Some(probe.version))
}

/// Validates that a store file at `path` is either absent or carries the
/// expected version. Used by both v1 and v2 loaders to refuse cross-version
/// reads explicitly instead of producing misleading "invalid key length"
/// errors after a base64 decode.
fn require_store_version(path: &Path, expected: u8) -> Result<(), EphemeralStoreError> {
    if let Some(found) = peek_store_version(path)? {
        if found != expected {
            return Err(EphemeralStoreError::VersionMismatch { expected, found });
        }
    }
    Ok(())
}

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

// ============================================================================
// Hybrid Private Key Store (.eph.key, version 2)
// ============================================================================

/// Loads a hybrid private key for a contact from a v2 .eph.key file.
pub fn load_private_key_for_contact_hybrid(
    path: &Path,
    contact: &str,
) -> Result<HybridSecretKey, EphemeralStoreError> {
    require_store_version(path, STORE_VERSION_HYBRID)?;
    let content = fs::read_to_string(path)?;
    let store: PrivateKeyStoreHybrid = serde_json::from_str(&content)?;

    let entry = store
        .contacts
        .get(contact)
        .ok_or_else(|| EphemeralStoreError::ContactNotFound(contact.to_string()))?;

    decode_hybrid_private_key(&entry.key)
}

/// Saves or updates a hybrid private key for a contact in a v2 .eph.key file.
pub fn save_private_key_for_contact_hybrid(
    path: &Path,
    contact: &str,
    key: &HybridSecretKey,
) -> Result<(), EphemeralStoreError> {
    require_store_version(path, STORE_VERSION_HYBRID)?;

    let mut store = if path.exists() {
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content)?
    } else {
        PrivateKeyStoreHybrid {
            version: STORE_VERSION_HYBRID,
            contacts: HashMap::new(),
        }
    };

    store.contacts.insert(
        contact.to_string(),
        PrivateKeyEntryHybrid {
            key: BASE64.encode(key.to_bytes()),
        },
    );

    let content = serde_json::to_string_pretty(&store)?;
    fs::write(path, content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Lists all contacts in a v2 .eph.key file.
pub fn list_private_key_contacts_hybrid(path: &Path) -> Result<Vec<String>, EphemeralStoreError> {
    require_store_version(path, STORE_VERSION_HYBRID)?;
    let content = fs::read_to_string(path)?;
    let store: PrivateKeyStoreHybrid = serde_json::from_str(&content)?;
    Ok(store.contacts.keys().cloned().collect())
}

// ============================================================================
// Hybrid Public Key Store (.eph.pub, version 2)
// ============================================================================

/// Loads a hybrid public key for a contact from a v2 .eph.pub file.
pub fn load_public_key_for_contact_hybrid(
    path: &Path,
    contact: &str,
) -> Result<HybridPublicKey, EphemeralStoreError> {
    require_store_version(path, STORE_VERSION_HYBRID)?;
    let content = fs::read_to_string(path)?;
    let store: PublicKeyStoreHybrid = serde_json::from_str(&content)?;

    let entry = store
        .contacts
        .get(contact)
        .ok_or_else(|| EphemeralStoreError::ContactNotFound(contact.to_string()))?;

    decode_hybrid_public_key(&entry.key)
}

/// Saves or updates a hybrid public key for a contact in a v2 .eph.pub file.
pub fn save_public_key_for_contact_hybrid(
    path: &Path,
    contact: &str,
    key: &HybridPublicKey,
) -> Result<(), EphemeralStoreError> {
    require_store_version(path, STORE_VERSION_HYBRID)?;

    let mut store = if path.exists() {
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content)?
    } else {
        PublicKeyStoreHybrid {
            version: STORE_VERSION_HYBRID,
            contacts: HashMap::new(),
        }
    };

    store.contacts.insert(
        contact.to_string(),
        PublicKeyEntryHybrid {
            key: BASE64.encode(key.to_bytes()),
        },
    );

    let content = serde_json::to_string_pretty(&store)?;
    fs::write(path, content)?;

    Ok(())
}

/// Lists all contacts in a v2 .eph.pub file.
pub fn list_public_key_contacts_hybrid(path: &Path) -> Result<Vec<String>, EphemeralStoreError> {
    require_store_version(path, STORE_VERSION_HYBRID)?;
    let content = fs::read_to_string(path)?;
    let store: PublicKeyStoreHybrid = serde_json::from_str(&content)?;
    Ok(store.contacts.keys().cloned().collect())
}

// ============================================================================
// Hybrid Unified Store (.eph, version 2)
// ============================================================================

/// A contact's hybrid keypair from unified storage.
pub struct ContactKeysHybrid {
    /// My hybrid private key for this contact
    pub my_private: HybridSecretKey,
    /// Their hybrid public key
    pub their_public: HybridPublicKey,
}

/// Loads hybrid keys for a contact from a v2 .eph file.
pub fn load_unified_keys_for_contact_hybrid(
    path: &Path,
    contact: &str,
) -> Result<ContactKeysHybrid, EphemeralStoreError> {
    require_store_version(path, STORE_VERSION_HYBRID)?;
    let content = fs::read_to_string(path)?;
    let store: UnifiedStoreHybrid = serde_json::from_str(&content)?;

    let entry = store
        .contacts
        .get(contact)
        .ok_or_else(|| EphemeralStoreError::ContactNotFound(contact.to_string()))?;

    Ok(ContactKeysHybrid {
        my_private: decode_hybrid_private_key(&entry.my_private)?,
        their_public: decode_hybrid_public_key(&entry.their_public)?,
    })
}

/// Saves or updates hybrid keys for a contact in a v2 .eph file.
pub fn save_unified_keys_for_contact_hybrid(
    path: &Path,
    contact: &str,
    my_private: &HybridSecretKey,
    their_public: &HybridPublicKey,
) -> Result<(), EphemeralStoreError> {
    require_store_version(path, STORE_VERSION_HYBRID)?;

    let mut store = if path.exists() {
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content)?
    } else {
        UnifiedStoreHybrid {
            version: STORE_VERSION_HYBRID,
            contacts: HashMap::new(),
        }
    };

    store.contacts.insert(
        contact.to_string(),
        UnifiedEntryHybrid {
            my_private: BASE64.encode(my_private.to_bytes()),
            their_public: BASE64.encode(their_public.to_bytes()),
        },
    );

    let content = serde_json::to_string_pretty(&store)?;
    fs::write(path, content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Updates only the hybrid public key for a contact in a v2 .eph file.
pub fn update_unified_public_key_hybrid(
    path: &Path,
    contact: &str,
    their_public: &HybridPublicKey,
) -> Result<(), EphemeralStoreError> {
    require_store_version(path, STORE_VERSION_HYBRID)?;
    let content = fs::read_to_string(path)?;
    let mut store: UnifiedStoreHybrid = serde_json::from_str(&content)?;

    let entry = store
        .contacts
        .get_mut(contact)
        .ok_or_else(|| EphemeralStoreError::ContactNotFound(contact.to_string()))?;

    entry.their_public = BASE64.encode(their_public.to_bytes());

    let content = serde_json::to_string_pretty(&store)?;
    fs::write(path, content)?;

    Ok(())
}

/// Updates only the hybrid private key for a contact in a v2 .eph file.
pub fn update_unified_private_key_hybrid(
    path: &Path,
    contact: &str,
    my_private: &HybridSecretKey,
) -> Result<(), EphemeralStoreError> {
    require_store_version(path, STORE_VERSION_HYBRID)?;
    let content = fs::read_to_string(path)?;
    let mut store: UnifiedStoreHybrid = serde_json::from_str(&content)?;

    let entry = store
        .contacts
        .get_mut(contact)
        .ok_or_else(|| EphemeralStoreError::ContactNotFound(contact.to_string()))?;

    entry.my_private = BASE64.encode(my_private.to_bytes());

    let content = serde_json::to_string_pretty(&store)?;
    fs::write(path, content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Lists all contacts in a v2 .eph file.
pub fn list_unified_contacts_hybrid(path: &Path) -> Result<Vec<String>, EphemeralStoreError> {
    require_store_version(path, STORE_VERSION_HYBRID)?;
    let content = fs::read_to_string(path)?;
    let store: UnifiedStoreHybrid = serde_json::from_str(&content)?;
    Ok(store.contacts.keys().cloned().collect())
}

/// Generates a new hybrid ephemeral keypair and saves it to a v2 .eph file
/// for a contact. Returns the public key so it can be shared with the contact.
pub fn generate_and_save_ephemeral_for_contact_hybrid(
    path: &Path,
    contact: &str,
    their_public: &HybridPublicKey,
) -> Result<HybridPublicKey, EphemeralStoreError> {
    let keypair = HybridKeyPair::generate_ephemeral();
    let my_public = keypair.public_key().clone();

    save_unified_keys_for_contact_hybrid(path, contact, keypair.secret_key(), their_public)?;

    Ok(my_public)
}

// ============================================================================
// Helper functions (hybrid)
// ============================================================================

fn decode_hybrid_private_key(base64_key: &str) -> Result<HybridSecretKey, EphemeralStoreError> {
    let bytes = BASE64
        .decode(base64_key)
        .map_err(|e| EphemeralStoreError::InvalidKeyData(e.to_string()))?;

    if bytes.len() != HYBRID_SECRET_KEY_SIZE {
        return Err(EphemeralStoreError::InvalidKeyData(format!(
            "Expected {} bytes for hybrid secret key, got {}",
            HYBRID_SECRET_KEY_SIZE,
            bytes.len()
        )));
    }

    HybridSecretKey::from_bytes(&bytes).map_err(EphemeralStoreError::HybridKemError)
}

fn decode_hybrid_public_key(base64_key: &str) -> Result<HybridPublicKey, EphemeralStoreError> {
    let bytes = BASE64
        .decode(base64_key)
        .map_err(|e| EphemeralStoreError::InvalidKeyData(e.to_string()))?;

    if bytes.len() != HYBRID_PUBKEY_SIZE {
        return Err(EphemeralStoreError::InvalidKeyData(format!(
            "Expected {} bytes for hybrid public key, got {}",
            HYBRID_PUBKEY_SIZE,
            bytes.len()
        )));
    }

    HybridPublicKey::from_bytes(&bytes).map_err(EphemeralStoreError::HybridKemError)
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

    // ========================================================================
    // Hybrid store tests (version 2)
    // ========================================================================

    use crate::crypto::hybrid_kem::{decapsulate, encapsulate};

    #[test]
    fn test_hybrid_private_key_store_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_hybrid.eph.key");

        let kp = HybridKeyPair::generate_ephemeral();
        let original_pub = kp.public_key().to_bytes();

        save_private_key_for_contact_hybrid(&path, "bob", kp.secret_key()).unwrap();
        let loaded = load_private_key_for_contact_hybrid(&path, "bob").unwrap();

        // Loaded secret derives the same public key
        assert_eq!(loaded.public_key().to_bytes(), original_pub);

        // Loaded secret can decapsulate
        let (ct, sender_key) = encapsulate(kp.public_key()).unwrap();
        let recovered = decapsulate(&loaded, &ct).unwrap();
        assert_eq!(sender_key.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn test_hybrid_public_key_store_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_hybrid.eph.pub");

        let kp = HybridKeyPair::generate_ephemeral();
        save_public_key_for_contact_hybrid(&path, "bob", kp.public_key()).unwrap();
        let loaded = load_public_key_for_contact_hybrid(&path, "bob").unwrap();

        assert_eq!(loaded.to_bytes(), kp.public_key().to_bytes());
    }

    #[test]
    fn test_hybrid_unified_store_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_hybrid.eph");

        let mine = HybridKeyPair::generate_ephemeral();
        let theirs = HybridKeyPair::generate_ephemeral();

        save_unified_keys_for_contact_hybrid(
            &path,
            "bob",
            mine.secret_key(),
            theirs.public_key(),
        )
        .unwrap();

        let loaded = load_unified_keys_for_contact_hybrid(&path, "bob").unwrap();

        assert_eq!(
            loaded.my_private.public_key().to_bytes(),
            mine.public_key().to_bytes()
        );
        assert_eq!(loaded.their_public.to_bytes(), theirs.public_key().to_bytes());
    }

    #[test]
    fn test_hybrid_multiple_contacts() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_hybrid.eph");

        let bob_my = HybridKeyPair::generate_ephemeral();
        let bob_their = HybridKeyPair::generate_ephemeral();
        let alice_my = HybridKeyPair::generate_ephemeral();
        let alice_their = HybridKeyPair::generate_ephemeral();

        save_unified_keys_for_contact_hybrid(&path, "bob", bob_my.secret_key(), bob_their.public_key()).unwrap();
        save_unified_keys_for_contact_hybrid(&path, "alice", alice_my.secret_key(), alice_their.public_key()).unwrap();

        let contacts = list_unified_contacts_hybrid(&path).unwrap();
        assert_eq!(contacts.len(), 2);
        assert!(contacts.contains(&"bob".to_string()));
        assert!(contacts.contains(&"alice".to_string()));

        let bob_loaded = load_unified_keys_for_contact_hybrid(&path, "bob").unwrap();
        let alice_loaded = load_unified_keys_for_contact_hybrid(&path, "alice").unwrap();

        assert_eq!(bob_loaded.my_private.public_key().to_bytes(), bob_my.public_key().to_bytes());
        assert_eq!(alice_loaded.my_private.public_key().to_bytes(), alice_my.public_key().to_bytes());
    }

    #[test]
    fn test_hybrid_update_public_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_hybrid.eph");

        let mine = HybridKeyPair::generate_ephemeral();
        let their_old = HybridKeyPair::generate_ephemeral();
        let their_new = HybridKeyPair::generate_ephemeral();

        save_unified_keys_for_contact_hybrid(&path, "bob", mine.secret_key(), their_old.public_key()).unwrap();
        update_unified_public_key_hybrid(&path, "bob", their_new.public_key()).unwrap();

        let loaded = load_unified_keys_for_contact_hybrid(&path, "bob").unwrap();
        assert_eq!(loaded.my_private.public_key().to_bytes(), mine.public_key().to_bytes());
        assert_eq!(loaded.their_public.to_bytes(), their_new.public_key().to_bytes());
    }

    #[test]
    fn test_hybrid_generate_and_save_ephemeral() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_hybrid.eph");

        let theirs = HybridKeyPair::generate_ephemeral();
        let my_pub = generate_and_save_ephemeral_for_contact_hybrid(
            &path,
            "bob",
            theirs.public_key(),
        )
        .unwrap();

        let loaded = load_unified_keys_for_contact_hybrid(&path, "bob").unwrap();
        assert_eq!(loaded.my_private.public_key().to_bytes(), my_pub.to_bytes());
        assert_eq!(loaded.their_public.to_bytes(), theirs.public_key().to_bytes());
    }

    #[test]
    fn test_hybrid_contact_not_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_hybrid.eph");

        let mine = HybridKeyPair::generate_ephemeral();
        let theirs = HybridKeyPair::generate_ephemeral();

        save_unified_keys_for_contact_hybrid(&path, "bob", mine.secret_key(), theirs.public_key()).unwrap();

        let result = load_unified_keys_for_contact_hybrid(&path, "alice");
        assert!(matches!(result, Err(EphemeralStoreError::ContactNotFound(_))));
    }

    #[test]
    fn test_v2_loader_rejects_v1_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v1.eph");

        // Create a v1 store
        let mine = KeyPair::generate_ephemeral();
        let theirs = KeyPair::generate_ephemeral();
        save_unified_keys_for_contact(&path, "bob", mine.secret_key(), theirs.public_key()).unwrap();

        // v2 loader must reject it explicitly
        let result = load_unified_keys_for_contact_hybrid(&path, "bob");
        assert!(matches!(
            result,
            Err(EphemeralStoreError::VersionMismatch { expected: 2, found: 1 })
        ));

        // v2 saver must also reject mid-write so we don't corrupt the v1 store
        let hyb = HybridKeyPair::generate_ephemeral();
        let result = save_unified_keys_for_contact_hybrid(&path, "alice", hyb.secret_key(), hyb.public_key());
        assert!(matches!(
            result,
            Err(EphemeralStoreError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn test_v2_files_use_version_2_in_serialized_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_hybrid.eph");

        let mine = HybridKeyPair::generate_ephemeral();
        let theirs = HybridKeyPair::generate_ephemeral();
        save_unified_keys_for_contact_hybrid(&path, "bob", mine.secret_key(), theirs.public_key()).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"version\": 2"));
    }
}
