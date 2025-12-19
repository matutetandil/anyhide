//! Chat configuration.

use serde::{Deserialize, Serialize};

/// Protocol version for chat messages.
pub const CHAT_PROTOCOL_VERSION: u8 = 1;

/// Carrier mode for chat sessions.
///
/// Determines how carriers are obtained for steganographic encoding:
/// - `Random`: Generate random carriers during handshake (default, carriers exchanged)
/// - `PreShared`: Use pre-shared carrier files (carriers NOT exchanged, only hash verified)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CarrierMode {
    /// Generate random carriers during handshake.
    /// Each party generates carriers and exchanges them encrypted.
    Random,

    /// Use pre-shared carrier files.
    /// Both parties must have the same files in the same order.
    /// Only the hash is exchanged for verification.
    PreShared {
        /// SHA-256 hash of concatenated carrier data.
        hash: [u8; 32],
    },
}

impl Default for CarrierMode {
    fn default() -> Self {
        Self::Random
    }
}

/// Default number of carriers per party.
pub const DEFAULT_CARRIERS_PER_PARTY: usize = 10;

/// Default carrier size in bytes.
pub const DEFAULT_CARRIER_SIZE: usize = 4096;

/// Default maximum message length (256 chars for steganographic efficiency).
pub const DEFAULT_MAX_MESSAGE_LEN: usize = 256;

/// Default maximum number of skipped messages to cache keys for.
pub const DEFAULT_MAX_SKIP: usize = 100;

/// Default session timeout in seconds.
pub const DEFAULT_SESSION_TIMEOUT_SECS: u64 = 3600;

/// Configuration for a chat session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatConfig {
    /// Number of carriers each party contributes.
    pub carriers_per_party: usize,

    /// Size of each carrier in bytes.
    pub carrier_size: usize,

    /// Maximum message length in characters.
    pub max_message_len: usize,

    /// Maximum number of skipped messages to cache keys for.
    pub max_skip: usize,

    /// Session timeout in seconds.
    pub session_timeout_secs: u64,

    /// Carrier mode (random vs pre-shared).
    pub carrier_mode: CarrierMode,
}

impl Default for ChatConfig {
    fn default() -> Self {
        Self {
            carriers_per_party: DEFAULT_CARRIERS_PER_PARTY,
            carrier_size: DEFAULT_CARRIER_SIZE,
            max_message_len: DEFAULT_MAX_MESSAGE_LEN,
            max_skip: DEFAULT_MAX_SKIP,
            session_timeout_secs: DEFAULT_SESSION_TIMEOUT_SECS,
            carrier_mode: CarrierMode::default(),
        }
    }
}

impl ChatConfig {
    /// Create a new config with custom values.
    pub fn new(
        carriers_per_party: usize,
        carrier_size: usize,
        max_message_len: usize,
        max_skip: usize,
        session_timeout_secs: u64,
    ) -> Self {
        Self {
            carriers_per_party,
            carrier_size,
            max_message_len,
            max_skip,
            session_timeout_secs,
            carrier_mode: CarrierMode::default(),
        }
    }

    /// Create a config with pre-shared carriers.
    pub fn with_preshared_carriers(carriers_hash: [u8; 32]) -> Self {
        Self {
            carrier_mode: CarrierMode::PreShared { hash: carriers_hash },
            ..Default::default()
        }
    }

    /// Negotiate config between two parties.
    ///
    /// For numeric values, takes the minimum.
    /// For carrier mode, requires both parties to agree (same mode and hash).
    ///
    /// Returns `None` if carrier modes are incompatible.
    pub fn negotiate(&self, other: &Self) -> Option<Self> {
        // Check carrier mode compatibility
        let carrier_mode = match (&self.carrier_mode, &other.carrier_mode) {
            (CarrierMode::Random, CarrierMode::Random) => CarrierMode::Random,
            (CarrierMode::PreShared { hash: h1 }, CarrierMode::PreShared { hash: h2 }) => {
                if h1 == h2 {
                    CarrierMode::PreShared { hash: *h1 }
                } else {
                    return None; // Hash mismatch
                }
            }
            _ => return None, // Mode mismatch (one Random, one PreShared)
        };

        Some(Self {
            carriers_per_party: self.carriers_per_party.min(other.carriers_per_party),
            carrier_size: self.carrier_size.min(other.carrier_size),
            max_message_len: self.max_message_len.min(other.max_message_len),
            max_skip: self.max_skip.min(other.max_skip),
            session_timeout_secs: self.session_timeout_secs.min(other.session_timeout_secs),
            carrier_mode,
        })
    }

    /// Check if using pre-shared carriers.
    pub fn is_preshared(&self) -> bool {
        matches!(self.carrier_mode, CarrierMode::PreShared { .. })
    }

    /// Total number of carriers in session (both parties combined).
    pub fn total_carriers(&self) -> usize {
        self.carriers_per_party * 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ChatConfig::default();
        assert_eq!(config.carriers_per_party, DEFAULT_CARRIERS_PER_PARTY);
        assert_eq!(config.carrier_size, DEFAULT_CARRIER_SIZE);
        assert_eq!(config.max_message_len, DEFAULT_MAX_MESSAGE_LEN);
        assert_eq!(config.max_skip, DEFAULT_MAX_SKIP);
        assert_eq!(config.session_timeout_secs, DEFAULT_SESSION_TIMEOUT_SECS);
        assert_eq!(config.carrier_mode, CarrierMode::Random);
    }

    #[test]
    fn test_negotiate_takes_minimum() {
        let config_a = ChatConfig::new(10, 4096, 256, 100, 3600);
        let config_b = ChatConfig::new(5, 8192, 128, 200, 1800);

        let negotiated = config_a.negotiate(&config_b).unwrap();

        assert_eq!(negotiated.carriers_per_party, 5);
        assert_eq!(negotiated.carrier_size, 4096);
        assert_eq!(negotiated.max_message_len, 128);
        assert_eq!(negotiated.max_skip, 100);
        assert_eq!(negotiated.session_timeout_secs, 1800);
        assert_eq!(negotiated.carrier_mode, CarrierMode::Random);
    }

    #[test]
    fn test_total_carriers() {
        let config = ChatConfig::new(10, 4096, 1024, 100, 3600);
        assert_eq!(config.total_carriers(), 20);
    }

    #[test]
    fn test_preshared_config() {
        let hash = [0xAA; 32];
        let config = ChatConfig::with_preshared_carriers(hash);
        assert!(config.is_preshared());
        assert_eq!(config.carrier_mode, CarrierMode::PreShared { hash });
    }

    #[test]
    fn test_negotiate_preshared_same_hash() {
        let hash = [0xBB; 32];
        let config_a = ChatConfig::with_preshared_carriers(hash);
        let config_b = ChatConfig::with_preshared_carriers(hash);

        let negotiated = config_a.negotiate(&config_b);
        assert!(negotiated.is_some());
        assert_eq!(negotiated.unwrap().carrier_mode, CarrierMode::PreShared { hash });
    }

    #[test]
    fn test_negotiate_preshared_different_hash() {
        let hash_a = [0xAA; 32];
        let hash_b = [0xBB; 32];
        let config_a = ChatConfig::with_preshared_carriers(hash_a);
        let config_b = ChatConfig::with_preshared_carriers(hash_b);

        let negotiated = config_a.negotiate(&config_b);
        assert!(negotiated.is_none()); // Hash mismatch
    }

    #[test]
    fn test_negotiate_mode_mismatch() {
        let config_random = ChatConfig::default();
        let config_preshared = ChatConfig::with_preshared_carriers([0xCC; 32]);

        // Random vs PreShared should fail
        assert!(config_random.negotiate(&config_preshared).is_none());
        assert!(config_preshared.negotiate(&config_random).is_none());
    }
}
