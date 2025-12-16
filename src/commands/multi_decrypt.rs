//! Multi-recipient decryption command.

use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Args;

use anyhide::crypto::{decrypt_multi, load_secret_key, MultiRecipientData};

use super::CommandExecutor;

/// Decrypt a multi-recipient message.
#[derive(Args, Debug)]
pub struct MultiDecryptCommand {
    /// Encrypted data (base64 string or file path)
    #[arg(short, long)]
    pub input: String,

    /// Passphrase for decryption
    #[arg(short, long)]
    pub passphrase: String,

    /// Path to your private key
    #[arg(short, long)]
    pub key: PathBuf,
}

impl CommandExecutor for MultiDecryptCommand {
    fn execute(&self) -> Result<()> {
        // Try to read as file first, then as base64
        let bytes = if std::path::Path::new(&self.input).exists() {
            std::fs::read(&self.input)
                .with_context(|| format!("Failed to read file {}", self.input))?
        } else {
            BASE64
                .decode(&self.input)
                .context("Failed to decode base64 input")?
        };

        let secret_key = load_secret_key(&self.key)
            .with_context(|| format!("Failed to load private key from {}", self.key.display()))?;

        // Deserialize
        let encrypted = MultiRecipientData::from_bytes(&bytes)
            .context("Failed to parse encrypted data")?;

        // Decrypt
        let decrypted = decrypt_multi(&encrypted, &self.passphrase, &secret_key)
            .context("Failed to decrypt message")?;

        // Output as string
        let message = String::from_utf8_lossy(&decrypted);
        println!("{}", message);

        Ok(())
    }
}
