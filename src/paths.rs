//! Centralized filesystem paths for Anyhide.
//!
//! All Anyhide data lives under a single home directory:
//!
//! - Unix: `~/.anyhide`
//! - Windows: `%USERPROFILE%\.anyhide`
//!
//! Layout:
//!
//! ```text
//! ~/.anyhide/
//! ├── chat.toml              # default chat profile (identity + contacts)
//! ├── chat-<profile>.toml    # named chat profiles
//! ├── contacts.toml          # contact aliases used by encode/decode
//! ├── contacts/              # public keys imported from chat identity QR codes
//! ├── state/                 # persistent state (DO NOT DELETE — onion service keys)
//! │   └── tor/<profile>/
//! └── cache/                 # disposable cache (Tor directory, descriptors)
//!     └── tor/<profile>/
//! ```

use std::path::PathBuf;

/// Errors raised when resolving Anyhide paths.
#[derive(thiserror::Error, Debug)]
pub enum PathsError {
    #[error("Home directory not found. Set $HOME (Unix) or %USERPROFILE% (Windows).")]
    NoHomeDir,
}

/// The Anyhide home directory: `~/.anyhide`.
pub fn home() -> Result<PathBuf, PathsError> {
    dirs::home_dir()
        .map(|h| h.join(".anyhide"))
        .ok_or(PathsError::NoHomeDir)
}

/// Persistent state directory: `~/.anyhide/state`.
///
/// Contains data that must survive across runs (e.g., Tor onion service keys).
/// **Do not delete** without losing identity.
pub fn state_dir() -> Result<PathBuf, PathsError> {
    home().map(|h| h.join("state"))
}

/// Disposable cache directory: `~/.anyhide/cache`.
///
/// Safe to delete; will be repopulated as needed.
pub fn cache_dir() -> Result<PathBuf, PathsError> {
    home().map(|h| h.join("cache"))
}

/// Tor state directory for a given profile: `~/.anyhide/state/tor/<profile>`.
pub fn tor_state_dir(profile: &str) -> Result<PathBuf, PathsError> {
    state_dir().map(|s| s.join("tor").join(profile))
}

/// Tor cache directory for a given profile: `~/.anyhide/cache/tor/<profile>`.
pub fn tor_cache_dir(profile: &str) -> Result<PathBuf, PathsError> {
    cache_dir().map(|c| c.join("tor").join(profile))
}

/// Directory holding public keys imported from chat identity QR codes:
/// `~/.anyhide/contacts`.
pub fn imported_contacts_dir() -> Result<PathBuf, PathsError> {
    home().map(|h| h.join("contacts"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_ends_with_dot_anyhide() {
        let path = home().expect("home dir resolvable in test env");
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), ".anyhide");
    }

    #[test]
    fn state_and_cache_are_under_home() {
        let h = home().unwrap();
        assert_eq!(state_dir().unwrap(), h.join("state"));
        assert_eq!(cache_dir().unwrap(), h.join("cache"));
    }

    #[test]
    fn tor_dirs_are_profile_scoped() {
        let h = home().unwrap();
        assert_eq!(tor_state_dir("alice").unwrap(), h.join("state/tor/alice"));
        assert_eq!(tor_cache_dir("bob").unwrap(), h.join("cache/tor/bob"));
    }
}
