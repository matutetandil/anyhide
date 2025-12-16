//! Multi-recipient encryption command.

use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Args;

use anyhide::crypto::{encrypt_multi, load_public_key};

use super::CommandExecutor;

/// Encrypt a message for multiple recipients.
#[derive(Args, Debug)]
pub struct MultiEncryptCommand {
    /// Message to encrypt (reads from stdin if not provided)
    #[arg(short, long)]
    pub message: Option<String>,

    /// Passphrase for encryption
    #[arg(short, long)]
    pub passphrase: String,

    /// Paths to recipients' public keys (can specify multiple)
    #[arg(short, long, num_args = 1..)]
    pub keys: Vec<PathBuf>,

    /// Output file for encrypted data (prints base64 to stdout if not specified)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

impl CommandExecutor for MultiEncryptCommand {
    fn execute(&self) -> Result<()> {
        if self.keys.is_empty() {
            anyhow::bail!("At least one recipient public key is required");
        }

        let message = match &self.message {
            Some(m) => m.clone(),
            None => {
                eprintln!("Reading message from stdin (Ctrl+D to finish):");
                let mut buffer = String::new();
                io::stdin()
                    .read_to_string(&mut buffer)
                    .context("Failed to read message from stdin")?;
                buffer.trim().to_string()
            }
        };

        if message.is_empty() {
            anyhow::bail!("Message cannot be empty");
        }

        // Load all public keys
        let mut public_keys = Vec::with_capacity(self.keys.len());
        for path in &self.keys {
            let key = load_public_key(path)
                .with_context(|| format!("Failed to load public key from {}", path.display()))?;
            public_keys.push(key);
        }

        // Encrypt for all recipients
        let encrypted = encrypt_multi(message.as_bytes(), &self.passphrase, &public_keys)
            .context("Failed to encrypt message")?;

        // Serialize
        let bytes = encrypted.to_bytes().context("Failed to serialize encrypted data")?;

        if let Some(output_path) = &self.output {
            std::fs::write(output_path, &bytes)
                .with_context(|| format!("Failed to write to {}", output_path.display()))?;
            println!("Encrypted data written to {}", output_path.display());
        } else {
            println!("{}", BASE64.encode(&bytes));
        }

        println!("  Message size: {} bytes", message.len());
        println!("  Recipients: {}", self.keys.len());
        println!("  Encrypted size: {} bytes", bytes.len());

        Ok(())
    }
}
