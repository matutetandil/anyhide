//! Tor transport for anonymous chat connections.
//!
//! This module provides Tor-based transport using arti-client.
//! Supports both connecting to .onion addresses and hosting hidden services.
//!
//! **SECURITY WARNING**: Arti's onion services are experimental and not as
//! secure as C-Tor. Do not use for highly sensitive communications.
//! See: https://gitlab.torproject.org/tpo/core/arti/-/wikis/Onion-Services

use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use arti_client::config::TorClientConfigBuilder;
use arti_client::{DataStream, TorClient, TorClientConfig};
use tor_cell::relaycell::msg::Connected;
use tor_hscrypto::pk::HsId;
use tor_hsservice::{
    config::OnionServiceConfigBuilder, status::State as HsState, HsNickname, RendRequest,
    RunningOnionService,
};
use tor_rtcompat::PreferredRuntime;

// Re-export HsState for external use
pub use tor_hsservice::status::State as OnionServiceState;

use crate::chat::error::ChatError;
use crate::chat::protocol::WireMessage;
use crate::chat::transport::MessageTransport;

/// Convert an HsId to its .onion address string.
fn hsid_to_onion_address(hsid: &HsId) -> String {
    // HsId is a 32-byte ed25519 public key
    // The .onion address is: base32(PUBKEY | CHECKSUM | VERSION)
    // where CHECKSUM = SHA3_256(".onion checksum" | PUBKEY | VERSION)[:2]
    // and VERSION = 0x03

    use sha3::{Digest, Sha3_256};

    let pubkey: &[u8; 32] = hsid.as_ref();
    let version: u8 = 0x03;

    // Calculate checksum using SHA3-256 (required by Tor v3 spec)
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([version]);
    let checksum = hasher.finalize();

    // Combine: pubkey (32) + checksum (2) + version (1) = 35 bytes
    let mut combined = [0u8; 35];
    combined[..32].copy_from_slice(pubkey);
    combined[32..34].copy_from_slice(&checksum[..2]);
    combined[34] = version;

    // Base32 encode (lowercase, no padding)
    let encoded = base32_encode(&combined);
    format!("{}.onion", encoded.to_lowercase())
}

/// Simple base32 encoder (RFC 4648).
fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();

    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for &byte in data {
        buffer = (buffer << 8) | (byte as u64);
        bits_left += 8;

        while bits_left >= 5 {
            bits_left -= 5;
            let idx = ((buffer >> bits_left) & 0x1f) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }

    if bits_left > 0 {
        let idx = ((buffer << (5 - bits_left)) & 0x1f) as usize;
        result.push(ALPHABET[idx] as char);
    }

    result
}

/// Wrapper around arti's TorClient for managing Tor connections.
#[derive(Clone)]
pub struct AnyhideTorClient {
    client: TorClient<PreferredRuntime>,
}

impl AnyhideTorClient {
    /// Create and bootstrap a new Tor client.
    ///
    /// This will download the Tor consensus and establish circuits,
    /// which may take some time on first run (typically 30-60 seconds).
    ///
    /// If `profile` is provided, uses separate state/cache directories for that profile.
    pub async fn new() -> Result<Self, ChatError> {
        Self::with_profile(None).await
    }

    /// Create and bootstrap a new Tor client with a specific profile.
    ///
    /// Each profile gets its own state and cache directories, allowing
    /// multiple identities to run on the same machine.
    pub async fn with_profile(profile: Option<&str>) -> Result<Self, ChatError> {
        let config = match profile {
            Some(name) => {
                // Get base directories
                let data_dir = dirs::data_dir()
                    .or_else(|| dirs::home_dir().map(|h| h.join(".local/share")))
                    .ok_or_else(|| ChatError::TorError("Could not find data directory".into()))?;

                let cache_dir = dirs::cache_dir()
                    .or_else(|| dirs::home_dir().map(|h| h.join(".cache")))
                    .ok_or_else(|| ChatError::TorError("Could not find cache directory".into()))?;

                // Create profile-specific directories
                let state_dir = data_dir.join("anyhide").join("tor").join(name);
                let cache_path = cache_dir.join("anyhide").join("tor").join(name);

                // Create directories if they don't exist with proper permissions (0700)
                std::fs::create_dir_all(&state_dir).map_err(|e| {
                    ChatError::TorError(format!("Failed to create state dir: {}", e))
                })?;
                std::fs::create_dir_all(&cache_path).map_err(|e| {
                    ChatError::TorError(format!("Failed to create cache dir: {}", e))
                })?;

                // Set restrictive permissions (required by Arti for security)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o700);
                    std::fs::set_permissions(&state_dir, perms.clone()).map_err(|e| {
                        ChatError::TorError(format!("Failed to set state dir permissions: {}", e))
                    })?;
                    std::fs::set_permissions(&cache_path, perms).map_err(|e| {
                        ChatError::TorError(format!("Failed to set cache dir permissions: {}", e))
                    })?;
                }

                TorClientConfigBuilder::from_directories(state_dir, cache_path)
                    .build()
                    .map_err(|e| ChatError::TorError(format!("Failed to build config: {}", e)))?
            }
            None => TorClientConfig::default(),
        };

        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| ChatError::TorError(format!("Failed to bootstrap Tor client: {}", e)))?;

        Ok(Self { client })
    }

    /// Connect to an onion address (e.g., "xyz123abc.onion:port").
    pub async fn connect(&self, onion_addr: &str) -> Result<TorConnection, ChatError> {
        let stream = self
            .client
            .connect(onion_addr)
            .await
            .map_err(|e| {
                ChatError::TorError(format!("Failed to connect to {}: {}", onion_addr, e))
            })?;

        Ok(TorConnection::new(stream, onion_addr.to_string()))
    }

    /// Launch a hidden service and return a listener.
    ///
    /// **WARNING**: Arti onion services are experimental and less secure than C-Tor.
    pub async fn listen(&self, nickname: &str) -> Result<TorListener, ChatError> {
        let hs_nickname = HsNickname::new(nickname.to_string()).map_err(|e| {
            ChatError::TorError(format!("Invalid nickname '{}': {}", nickname, e))
        })?;

        // Build onion service config
        let hs_config = OnionServiceConfigBuilder::default()
            .nickname(hs_nickname)
            .build()
            .map_err(|e| {
                ChatError::TorError(format!("Failed to build onion service config: {}", e))
            })?;

        // Launch the onion service
        let (service, rend_requests) = self
            .client
            .launch_onion_service(hs_config)
            .map_err(|e| ChatError::TorError(format!("Failed to launch onion service: {}", e)))?
            .ok_or_else(|| ChatError::TorError("Onion service disabled in config".to_string()))?;

        // Get the onion address
        let onion_addr = service
            .onion_address()
            .map(|hsid| hsid_to_onion_address(&hsid))
            .unwrap_or_else(|| "generating...".to_string());

        Ok(TorListener {
            service,
            rend_requests: Box::pin(rend_requests),
            onion_addr,
        })
    }

    /// Get the underlying TorClient for advanced usage.
    pub fn inner(&self) -> &TorClient<PreferredRuntime> {
        &self.client
    }
}

/// A Tor connection to a remote peer.
pub struct TorConnection {
    stream: DataStream,
    peer_addr: String,
}

impl TorConnection {
    /// Create a new TorConnection from a DataStream.
    pub fn new(stream: DataStream, peer_addr: String) -> Self {
        Self { stream, peer_addr }
    }
}

#[async_trait]
impl MessageTransport for TorConnection {
    async fn send(&mut self, message: &WireMessage) -> Result<(), ChatError> {
        let data = message
            .to_bytes()
            .map_err(|e| ChatError::SerializationFailed(e.to_string()))?;

        // Write length prefix
        let len = data.len() as u32;
        self.stream.write_all(&len.to_le_bytes()).await?;
        self.stream.write_all(&data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<WireMessage, ChatError> {
        // Read length prefix
        let mut len_bytes = [0u8; 4];
        self.stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        // Sanity check: max 10MB
        if len > 10 * 1024 * 1024 {
            return Err(ChatError::TransportError(format!(
                "Message too large: {} bytes",
                len
            )));
        }

        let mut data = vec![0u8; len];
        self.stream.read_exact(&mut data).await?;
        WireMessage::from_bytes(&data).map_err(|e| ChatError::SerializationFailed(e.to_string()))
    }

    async fn close(&mut self) -> Result<(), ChatError> {
        self.stream.flush().await?;
        Ok(())
    }

    fn peer_addr(&self) -> Result<String, ChatError> {
        Ok(self.peer_addr.clone())
    }
}

/// A Tor listener for accepting incoming connections on a hidden service.
pub struct TorListener {
    service: Arc<RunningOnionService>,
    rend_requests: std::pin::Pin<Box<dyn futures::Stream<Item = RendRequest> + Send>>,
    onion_addr: String,
}

/// Handle for checking the status of a running onion service.
/// Can be cloned and used from any task.
#[derive(Clone)]
pub struct OnionServiceHandle {
    service: Arc<RunningOnionService>,
    onion_addr: String,
}

impl OnionServiceHandle {
    /// Get the .onion address of this hidden service.
    pub fn onion_addr(&self) -> &str {
        &self.onion_addr
    }

    /// Get the current state of the hidden service.
    pub fn state(&self) -> HsState {
        self.service.status().state()
    }

    /// Check if the hidden service is published and reachable.
    pub fn is_published(&self) -> bool {
        matches!(
            self.state(),
            HsState::Running | HsState::DegradedReachable
        )
    }

    /// Check if the hidden service is still bootstrapping.
    pub fn is_bootstrapping(&self) -> bool {
        matches!(self.state(), HsState::Bootstrapping)
    }
}

impl TorListener {
    /// Get a handle for checking the service status.
    /// The handle can be cloned and used from any task.
    pub fn handle(&self) -> OnionServiceHandle {
        OnionServiceHandle {
            service: self.service.clone(),
            onion_addr: self.onion_addr.clone(),
        }
    }

    /// Get the .onion address of this hidden service.
    pub fn onion_addr(&self) -> &str {
        &self.onion_addr
    }

    /// Get the current state of the hidden service.
    ///
    /// Returns the high-level operational state:
    /// - `Bootstrapping` - Building intro points and publishing descriptor
    /// - `Running` - Fully reachable, descriptor published
    /// - `DegradedReachable` - Reachable but with issues
    /// - `DegradedUnreachable` - Descriptor upload failed
    /// - `Recovering` - Trying to recover from a problem
    /// - `Broken` - Failed to start or maintain the service
    pub fn state(&self) -> HsState {
        self.service.status().state()
    }

    /// Check if the hidden service is published and reachable.
    ///
    /// Returns true when the service is in `Running` or `DegradedReachable` state,
    /// meaning clients can potentially connect.
    pub fn is_published(&self) -> bool {
        matches!(
            self.state(),
            HsState::Running | HsState::DegradedReachable
        )
    }

    /// Check if the hidden service is still bootstrapping.
    pub fn is_bootstrapping(&self) -> bool {
        matches!(self.state(), HsState::Bootstrapping)
    }

    /// Accept an incoming connection.
    pub async fn accept(&mut self) -> Result<TorConnection, ChatError> {
        // Get the next rendezvous request
        let rend_request = self
            .rend_requests
            .next()
            .await
            .ok_or_else(|| ChatError::TorError("Onion service stream ended".to_string()))?;

        // Accept the rendezvous and get stream requests
        let mut stream_requests = rend_request
            .accept()
            .await
            .map_err(|e| ChatError::TorError(format!("Failed to accept rendezvous: {}", e)))?;

        // Get the first stream request
        let stream_request = stream_requests
            .next()
            .await
            .ok_or_else(|| ChatError::TorError("No stream request received".to_string()))?;

        // Accept the stream with an empty Connected message
        let connected = Connected::new_empty();
        let stream = stream_request
            .accept(connected)
            .await
            .map_err(|e| ChatError::TorError(format!("Failed to accept stream: {}", e)))?;

        Ok(TorConnection::new(stream, "tor-client".to_string()))
    }
}

/// Print the security warning about Arti onion services.
pub fn print_tor_warning() {
    eprintln!();
    eprintln!("⚠️  WARNING: Arti onion services are EXPERIMENTAL and not as secure as C-Tor.");
    eprintln!("    Do not use for highly sensitive communications.");
    eprintln!("    See: https://gitlab.torproject.org/tpo/core/arti/-/wikis/Onion-Services");
    eprintln!();
}

/// Print a message about Tor bootstrap progress.
pub fn print_bootstrap_message() {
    eprintln!("Bootstrapping Tor client... (this may take 30-60 seconds on first run)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_encode() {
        // Test vector from RFC 4648
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[tokio::test]
    #[ignore = "requires network and takes time to bootstrap Tor"]
    async fn test_tor_client_creation() {
        print_bootstrap_message();
        let client = AnyhideTorClient::new().await;
        assert!(
            client.is_ok(),
            "Failed to create Tor client: {:?}",
            client.err()
        );
    }
}
