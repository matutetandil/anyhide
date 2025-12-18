//! Chat configuration.

use serde::{Deserialize, Serialize};

/// Protocol version for chat messages.
pub const CHAT_PROTOCOL_VERSION: u8 = 1;

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
}

impl Default for ChatConfig {
    fn default() -> Self {
        Self {
            carriers_per_party: DEFAULT_CARRIERS_PER_PARTY,
            carrier_size: DEFAULT_CARRIER_SIZE,
            max_message_len: DEFAULT_MAX_MESSAGE_LEN,
            max_skip: DEFAULT_MAX_SKIP,
            session_timeout_secs: DEFAULT_SESSION_TIMEOUT_SECS,
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
        }
    }

    /// Negotiate config between two parties (take minimum of each value).
    pub fn negotiate(&self, other: &Self) -> Self {
        Self {
            carriers_per_party: self.carriers_per_party.min(other.carriers_per_party),
            carrier_size: self.carrier_size.min(other.carrier_size),
            max_message_len: self.max_message_len.min(other.max_message_len),
            max_skip: self.max_skip.min(other.max_skip),
            session_timeout_secs: self.session_timeout_secs.min(other.session_timeout_secs),
        }
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
    }

    #[test]
    fn test_negotiate_takes_minimum() {
        let config_a = ChatConfig::new(10, 4096, 256, 100, 3600);
        let config_b = ChatConfig::new(5, 8192, 128, 200, 1800);

        let negotiated = config_a.negotiate(&config_b);

        assert_eq!(negotiated.carriers_per_party, 5);
        assert_eq!(negotiated.carrier_size, 4096);
        assert_eq!(negotiated.max_message_len, 128);
        assert_eq!(negotiated.max_skip, 100);
        assert_eq!(negotiated.session_timeout_secs, 1800);
    }

    #[test]
    fn test_total_carriers() {
        let config = ChatConfig::new(10, 4096, 1024, 100, 3600);
        assert_eq!(config.total_carriers(), 20);
    }
}
