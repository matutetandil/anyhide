//! Contact management for Anyhide.
//!
//! This module provides functionality for managing contacts with aliases,
//! stored in `~/.anyhide/contacts.toml`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur when managing contacts.
#[derive(Error, Debug)]
pub enum ContactsError {
    #[error("Contact not found: {0}")]
    NotFound(String),

    #[error("Contact already exists: {0}")]
    AlreadyExists(String),

    #[error("Config directory not found. Unable to determine home directory.")]
    NoConfigDir,

    #[error("Invalid key file: {0}")]
    InvalidKeyFile(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    TomlParseError(#[from] toml::de::Error),

    #[error("TOML serialize error: {0}")]
    TomlSerializeError(#[from] toml::ser::Error),
}

/// A contact with their public key paths.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Contact {
    /// Path to the contact's public encryption key (.pub)
    pub public_key: PathBuf,

    /// Path to the contact's public signing key (.sign.pub), optional
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<PathBuf>,
}

impl Contact {
    /// Create a new contact with just a public key.
    pub fn new(public_key: PathBuf) -> Self {
        Self {
            public_key,
            signing_key: None,
        }
    }

    /// Create a new contact with both encryption and signing keys.
    pub fn with_signing(public_key: PathBuf, signing_key: PathBuf) -> Self {
        Self {
            public_key,
            signing_key: Some(signing_key),
        }
    }
}

/// The contacts configuration stored in TOML format.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ContactsConfig {
    /// Map of contact names to their information.
    #[serde(default)]
    pub contacts: HashMap<String, Contact>,
}

impl ContactsConfig {
    /// Load the contacts configuration from the default location.
    ///
    /// Creates an empty config if the file doesn't exist.
    pub fn load() -> Result<Self, ContactsError> {
        let path = Self::config_path()?;

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&path)?;
        let config: ContactsConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save the contacts configuration to the default location.
    ///
    /// Creates the config directory if it doesn't exist.
    pub fn save(&self) -> Result<(), ContactsError> {
        let path = Self::config_path()?;

        // Ensure the directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)?;
        fs::write(&path, content)?;

        // Set restrictive permissions on config file (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&path, perms)?;
        }

        Ok(())
    }

    /// Get the path to the contacts configuration file.
    pub fn config_path() -> Result<PathBuf, ContactsError> {
        let config_dir = get_config_dir()?;
        Ok(config_dir.join("contacts.toml"))
    }

    /// Add a new contact.
    ///
    /// Returns an error if the contact already exists.
    pub fn add(&mut self, name: &str, contact: Contact) -> Result<(), ContactsError> {
        if self.contacts.contains_key(name) {
            return Err(ContactsError::AlreadyExists(name.to_string()));
        }
        self.contacts.insert(name.to_string(), contact);
        Ok(())
    }

    /// Update an existing contact or add a new one.
    pub fn upsert(&mut self, name: &str, contact: Contact) {
        self.contacts.insert(name.to_string(), contact);
    }

    /// Remove a contact by name.
    ///
    /// Returns an error if the contact doesn't exist.
    pub fn remove(&mut self, name: &str) -> Result<Contact, ContactsError> {
        self.contacts
            .remove(name)
            .ok_or_else(|| ContactsError::NotFound(name.to_string()))
    }

    /// Get a contact by name.
    pub fn get(&self, name: &str) -> Option<&Contact> {
        self.contacts.get(name)
    }

    /// List all contacts sorted by name.
    pub fn list(&self) -> Vec<(&str, &Contact)> {
        let mut contacts: Vec<_> = self.contacts.iter().map(|(k, v)| (k.as_str(), v)).collect();
        contacts.sort_by(|a, b| a.0.cmp(b.0));
        contacts
    }

    /// Check if a contact exists.
    pub fn contains(&self, name: &str) -> bool {
        self.contacts.contains_key(name)
    }

    /// Get the number of contacts.
    pub fn len(&self) -> usize {
        self.contacts.len()
    }

    /// Check if there are no contacts.
    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }
}

/// Get the Anyhide config directory.
///
/// Returns `~/.anyhide` on Unix or `%APPDATA%\anyhide` on Windows.
pub fn get_config_dir() -> Result<PathBuf, ContactsError> {
    dirs::home_dir()
        .map(|home| home.join(".anyhide"))
        .ok_or(ContactsError::NoConfigDir)
}

/// Resolve a contact alias or path to an actual key path.
///
/// If the input looks like a path (contains `/` or `\`), returns it as-is.
/// Otherwise, treats it as a contact alias and looks it up.
pub fn resolve_contact_key(name_or_path: &str) -> Result<PathBuf, ContactsError> {
    // If it looks like a path, return as-is
    if name_or_path.contains('/') || name_or_path.contains('\\') || name_or_path.contains('.') {
        return Ok(PathBuf::from(name_or_path));
    }

    // Otherwise, look up as a contact alias
    let config = ContactsConfig::load()?;
    let contact = config
        .get(name_or_path)
        .ok_or_else(|| ContactsError::NotFound(name_or_path.to_string()))?;

    Ok(contact.public_key.clone())
}

/// Resolve a contact's signing key.
pub fn resolve_contact_signing_key(name: &str) -> Result<Option<PathBuf>, ContactsError> {
    let config = ContactsConfig::load()?;
    let contact = config
        .get(name)
        .ok_or_else(|| ContactsError::NotFound(name.to_string()))?;

    Ok(contact.signing_key.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_test_config() -> (TempDir, PathBuf) {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("contacts.toml");
        (temp_dir, config_path)
    }

    #[test]
    fn test_contact_creation() {
        let contact = Contact::new(PathBuf::from("/path/to/alice.pub"));
        assert_eq!(contact.public_key, PathBuf::from("/path/to/alice.pub"));
        assert!(contact.signing_key.is_none());

        let contact_with_signing = Contact::with_signing(
            PathBuf::from("/path/to/bob.pub"),
            PathBuf::from("/path/to/bob.sign.pub"),
        );
        assert_eq!(contact_with_signing.public_key, PathBuf::from("/path/to/bob.pub"));
        assert_eq!(
            contact_with_signing.signing_key,
            Some(PathBuf::from("/path/to/bob.sign.pub"))
        );
    }

    #[test]
    fn test_contacts_config_crud() {
        let mut config = ContactsConfig::default();

        // Add contact
        let alice = Contact::new(PathBuf::from("/path/to/alice.pub"));
        config.add("alice", alice.clone()).unwrap();
        assert!(config.contains("alice"));
        assert_eq!(config.len(), 1);

        // Get contact
        let retrieved = config.get("alice").unwrap();
        assert_eq!(retrieved.public_key, alice.public_key);

        // Add duplicate should fail
        let result = config.add("alice", Contact::new(PathBuf::from("/other/path.pub")));
        assert!(matches!(result, Err(ContactsError::AlreadyExists(_))));

        // Upsert should work
        let updated = Contact::new(PathBuf::from("/updated/alice.pub"));
        config.upsert("alice", updated);
        assert_eq!(
            config.get("alice").unwrap().public_key,
            PathBuf::from("/updated/alice.pub")
        );

        // Add another contact
        let bob = Contact::with_signing(
            PathBuf::from("/path/to/bob.pub"),
            PathBuf::from("/path/to/bob.sign.pub"),
        );
        config.add("bob", bob).unwrap();
        assert_eq!(config.len(), 2);

        // List contacts (should be sorted)
        let list = config.list();
        assert_eq!(list[0].0, "alice");
        assert_eq!(list[1].0, "bob");

        // Remove contact
        let removed = config.remove("alice").unwrap();
        assert_eq!(removed.public_key, PathBuf::from("/updated/alice.pub"));
        assert!(!config.contains("alice"));
        assert_eq!(config.len(), 1);

        // Remove non-existent should fail
        let result = config.remove("charlie");
        assert!(matches!(result, Err(ContactsError::NotFound(_))));
    }

    #[test]
    fn test_toml_serialization() {
        let mut config = ContactsConfig::default();
        config
            .add("alice", Contact::new(PathBuf::from("/path/to/alice.pub")))
            .unwrap();
        config
            .add(
                "bob",
                Contact::with_signing(
                    PathBuf::from("/path/to/bob.pub"),
                    PathBuf::from("/path/to/bob.sign.pub"),
                ),
            )
            .unwrap();

        // Serialize
        let toml_str = toml::to_string_pretty(&config).unwrap();
        assert!(toml_str.contains("[contacts.alice]"));
        assert!(toml_str.contains("[contacts.bob]"));
        assert!(toml_str.contains("signing_key"));

        // Deserialize
        let loaded: ContactsConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains("alice"));
        assert!(loaded.contains("bob"));
        assert!(loaded.get("bob").unwrap().signing_key.is_some());
    }

    #[test]
    fn test_empty_config() {
        let config = ContactsConfig::default();
        assert!(config.is_empty());
        assert_eq!(config.len(), 0);
        assert!(config.list().is_empty());
    }

    #[test]
    fn test_resolve_path_vs_alias() {
        // Paths should be returned as-is
        assert_eq!(
            resolve_contact_key("/path/to/key.pub").unwrap(),
            PathBuf::from("/path/to/key.pub")
        );
        assert_eq!(
            resolve_contact_key("./relative/key.pub").unwrap(),
            PathBuf::from("./relative/key.pub")
        );
        assert_eq!(
            resolve_contact_key("key.pub").unwrap(),
            PathBuf::from("key.pub")
        );
    }
}
