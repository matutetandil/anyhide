//! Multi-recipient decryption command.

use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Args;

use anyhide::crypto::{
    decrypt_multi, decrypt_multi_hybrid, detect_key_type, load_hybrid_secret_key, load_secret_key,
    MultiRecipientData, MultiRecipientDataHybrid,
};

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

    /// Path to your private key (classical or hybrid PQ — auto-detected)
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

        // Auto-detect the key flavor from the PEM header
        let key_pem = std::fs::read_to_string(&self.key)
            .with_context(|| format!("Failed to read private key from {}", self.key.display()))?;
        let key_is_hybrid = matches!(detect_key_type(&key_pem), Some(kt) if kt.is_hybrid());

        // The first byte of MultiRecipientDataHybrid serialization is the version
        // discriminator (0x02). v1 classical does not start with this byte.
        let payload_is_hybrid = bytes.first().copied() == Some(0x02);

        if key_is_hybrid != payload_is_hybrid {
            anyhow::bail!(
                "Key / payload flavor mismatch.\n  \
                 Key is {}, payload is {}.\n  \
                 Multi-recipient classical (v1) and hybrid PQ (v2) wire formats are distinct \
                 and do not cross-decrypt.",
                if key_is_hybrid { "hybrid PQ" } else { "classical" },
                if payload_is_hybrid { "hybrid PQ" } else { "classical" },
            );
        }

        let decrypted = if payload_is_hybrid {
            let secret_key = load_hybrid_secret_key(&self.key).with_context(|| {
                format!(
                    "Failed to load hybrid private key from {}",
                    self.key.display()
                )
            })?;
            let encrypted = MultiRecipientDataHybrid::from_bytes(&bytes)
                .context("Failed to parse hybrid encrypted data")?;
            decrypt_multi_hybrid(&encrypted, &self.passphrase, &secret_key)
                .context("Failed to decrypt hybrid message")?
        } else {
            let secret_key = load_secret_key(&self.key)
                .with_context(|| format!("Failed to load private key from {}", self.key.display()))?;
            let encrypted = MultiRecipientData::from_bytes(&bytes)
                .context("Failed to parse encrypted data")?;
            decrypt_multi(&encrypted, &self.passphrase, &secret_key)
                .context("Failed to decrypt message")?
        };

        // Output as string
        let message = String::from_utf8_lossy(&decrypted);
        println!("{}", message);

        Ok(())
    }
}
