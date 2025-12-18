//! Transport layer for chat connections.
//!
//! This module defines the async transport trait and implementations for
//! different network transports.

mod tcp;
mod tor;

pub use tcp::{TcpConnection, TcpListener, TcpTransport};
pub use tor::{AnyhideTorClient, TorConnection, TorListener, print_tor_warning, print_bootstrap_message};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::chat::error::ChatError;
use crate::chat::protocol::WireMessage;

/// Trait for bidirectional async message transport.
#[async_trait]
pub trait MessageTransport: Send {
    /// Send a wire message.
    async fn send(&mut self, message: &WireMessage) -> Result<(), ChatError>;

    /// Receive a wire message.
    async fn receive(&mut self) -> Result<WireMessage, ChatError>;

    /// Close the connection.
    async fn close(&mut self) -> Result<(), ChatError>;

    /// Get the peer address as a string.
    fn peer_addr(&self) -> Result<String, ChatError>;
}

/// Helper to write a length-prefixed message asynchronously.
pub async fn write_length_prefixed<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> Result<(), ChatError> {
    let len = data.len() as u32;
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Helper to read a length-prefixed message asynchronously.
pub async fn read_length_prefixed<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, ChatError> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;

    // Sanity check: max 10MB
    if len > 10 * 1024 * 1024 {
        return Err(ChatError::TransportError(format!(
            "Message too large: {} bytes",
            len
        )));
    }

    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;
    Ok(data)
}
