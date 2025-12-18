//! TCP transport for chat connections.
//!
//! This provides a TCP-based transport using tokio for async I/O.
//! Used for localhost testing and direct TCP connections.

use async_trait::async_trait;
use tokio::io::{AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream, ToSocketAddrs};

use crate::chat::error::ChatError;
use crate::chat::protocol::WireMessage;
use crate::chat::transport::{read_length_prefixed, write_length_prefixed, MessageTransport};

/// TCP connection wrapper using tokio.
pub struct TcpConnection {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: BufWriter<tokio::io::WriteHalf<TcpStream>>,
    peer_addr: String,
}

impl TcpConnection {
    /// Create a new TCP connection from a stream.
    pub fn new(stream: TcpStream) -> Result<Self, ChatError> {
        let peer_addr = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let (read_half, write_half) = tokio::io::split(stream);

        Ok(Self {
            reader: BufReader::new(read_half),
            writer: BufWriter::new(write_half),
            peer_addr,
        })
    }

    /// Connect to a remote address.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self, ChatError> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| ChatError::TransportError(format!("Failed to connect: {}", e)))?;
        Self::new(stream)
    }

    /// Get the local address.
    pub fn local_addr(&self) -> Result<String, ChatError> {
        // Not directly available after split, return peer addr instead
        Ok(self.peer_addr.clone())
    }
}

#[async_trait]
impl MessageTransport for TcpConnection {
    async fn send(&mut self, message: &WireMessage) -> Result<(), ChatError> {
        let data = message
            .to_bytes()
            .map_err(|e| ChatError::SerializationFailed(e.to_string()))?;
        write_length_prefixed(&mut self.writer, &data).await
    }

    async fn receive(&mut self) -> Result<WireMessage, ChatError> {
        let data = read_length_prefixed(&mut self.reader).await?;
        WireMessage::from_bytes(&data).map_err(|e| ChatError::SerializationFailed(e.to_string()))
    }

    async fn close(&mut self) -> Result<(), ChatError> {
        self.writer.flush().await?;
        self.writer.shutdown().await?;
        Ok(())
    }

    fn peer_addr(&self) -> Result<String, ChatError> {
        Ok(self.peer_addr.clone())
    }
}

/// TCP listener for accepting chat connections using tokio.
pub struct TcpListener {
    listener: TokioTcpListener,
}

impl TcpListener {
    /// Bind to an address and start listening.
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, ChatError> {
        let listener = TokioTcpListener::bind(addr)
            .await
            .map_err(|e| ChatError::TransportError(format!("Failed to bind: {}", e)))?;
        Ok(Self { listener })
    }

    /// Accept a new connection.
    pub async fn accept(&self) -> Result<TcpConnection, ChatError> {
        let (stream, _addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| ChatError::TransportError(format!("Failed to accept: {}", e)))?;
        TcpConnection::new(stream)
    }

    /// Get the local address.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, ChatError> {
        self.listener
            .local_addr()
            .map_err(|e| ChatError::TransportError(format!("Failed to get local addr: {}", e)))
    }
}

/// TCP transport configuration.
pub struct TcpTransport {
    /// Optional bind address for listening.
    pub bind_addr: Option<String>,
}

impl TcpTransport {
    /// Create a new TCP transport.
    pub fn new() -> Self {
        Self { bind_addr: None }
    }

    /// Set the bind address for listening.
    pub fn with_bind_addr(mut self, addr: impl Into<String>) -> Self {
        self.bind_addr = Some(addr.into());
        self
    }

    /// Create a listener bound to the configured address.
    pub async fn listen(&self) -> Result<TcpListener, ChatError> {
        let addr = self.bind_addr.as_deref().unwrap_or("127.0.0.1:0");
        TcpListener::bind(addr).await
    }

    /// Connect to a remote address.
    pub async fn connect(&self, addr: &str) -> Result<TcpConnection, ChatError> {
        TcpConnection::connect(addr).await
    }
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tcp_connection() {
        // Start a listener
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a task to connect
        let client_task = tokio::spawn(async move {
            let mut conn = TcpConnection::connect(addr).await.unwrap();

            // Send a message
            let msg = WireMessage::new(1, [0u8; 12], vec![1, 2, 3], "test".to_string());
            conn.send(&msg).await.unwrap();

            // Receive a response
            let response = conn.receive().await.unwrap();
            assert_eq!(response.version, 1);
            assert_eq!(response.anyhide_code, "response");

            conn.close().await.unwrap();
        });

        // Accept the connection
        let mut server_conn = listener.accept().await.unwrap();

        // Receive the message
        let msg = server_conn.receive().await.unwrap();
        assert_eq!(msg.version, 1);
        assert_eq!(msg.anyhide_code, "test");

        // Send a response
        let response = WireMessage::new(1, [0u8; 12], vec![4, 5, 6], "response".to_string());
        server_conn.send(&response).await.unwrap();
        server_conn.close().await.unwrap();

        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_transport() {
        let transport = TcpTransport::new().with_bind_addr("127.0.0.1:0");

        let listener = transport.listen().await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let transport = TcpTransport::new();
            let _conn = transport.connect(&addr.to_string()).await.unwrap();
        });

        let _server_conn = listener.accept().await.unwrap();
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_multiple_messages() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let mut conn = TcpConnection::connect(addr).await.unwrap();

            for i in 0..10 {
                let msg = WireMessage::new(1, [i as u8; 12], vec![i as u8], format!("msg{}", i));
                conn.send(&msg).await.unwrap();
            }

            conn.close().await.unwrap();
        });

        let mut server_conn = listener.accept().await.unwrap();

        for i in 0..10 {
            let msg = server_conn.receive().await.unwrap();
            assert_eq!(msg.anyhide_code, format!("msg{}", i));
        }

        client_task.await.unwrap();
    }
}
