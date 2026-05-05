//! Multi-recipient encryption command.

use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Args;

use anyhide::crypto::{
    detect_key_type, encrypt_multi, encrypt_multi_hybrid, load_hybrid_public_key, load_public_key,
    HybridPublicKey,
};

use super::CommandExecutor;

/// Recipient key flavor for the multi-recipient encryption CLI.
///
/// All recipients in a single invocation must share a flavor — `MultiRecipientData`
/// (classical, v1) and `MultiRecipientDataHybrid` (hybrid, v2) are distinct wire
/// formats with no common decoder, so mixing classical and hybrid pubkeys would
/// produce a code that no recipient can read.
enum RecipientKeyVec {
    Classical(Vec<x25519_dalek::PublicKey>),
    Hybrid(Vec<HybridPublicKey>),
}

/// Loads recipient public keys from PEM files, requiring all to share a key flavor.
/// Returns the populated vector and emits a friendly error on a mixed-flavor list.
fn load_recipient_keys(paths: &[PathBuf]) -> Result<RecipientKeyVec> {
    let mut classical: Vec<x25519_dalek::PublicKey> = Vec::new();
    let mut hybrid: Vec<HybridPublicKey> = Vec::new();
    let mut hybrid_seen_first: Option<bool> = None;

    for path in paths {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read public key from {}", path.display()))?;

        let is_hybrid = matches!(detect_key_type(&pem), Some(kt) if kt.is_hybrid());

        match hybrid_seen_first {
            None => hybrid_seen_first = Some(is_hybrid),
            Some(prev) if prev != is_hybrid => {
                anyhow::bail!(
                    "Mixed-flavor recipients are not supported.\n  \
                     All --keys must be the same flavor (all classical or all hybrid PQ).\n  \
                     Mixed list detected at {}.",
                    path.display()
                );
            }
            _ => {}
        }

        if is_hybrid {
            let pk = load_hybrid_public_key(path).with_context(|| {
                format!("Failed to load hybrid public key from {}", path.display())
            })?;
            hybrid.push(pk);
        } else {
            let pk = load_public_key(path)
                .with_context(|| format!("Failed to load public key from {}", path.display()))?;
            classical.push(pk);
        }
    }

    if hybrid.is_empty() {
        Ok(RecipientKeyVec::Classical(classical))
    } else {
        Ok(RecipientKeyVec::Hybrid(hybrid))
    }
}

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

        // Load all public keys, requiring a single key flavor across the list
        let recipients = load_recipient_keys(&self.keys)?;

        let (bytes, flavor) = match recipients {
            RecipientKeyVec::Classical(keys) => {
                let encrypted = encrypt_multi(message.as_bytes(), &self.passphrase, &keys)
                    .context("Failed to encrypt message (classical)")?;
                let bytes = encrypted
                    .to_bytes()
                    .context("Failed to serialize encrypted data")?;
                (bytes, "classical")
            }
            RecipientKeyVec::Hybrid(keys) => {
                let encrypted = encrypt_multi_hybrid(message.as_bytes(), &self.passphrase, &keys)
                    .context("Failed to encrypt message (hybrid PQ)")?;
                let bytes = encrypted
                    .to_bytes()
                    .context("Failed to serialize encrypted data")?;
                (bytes, "hybrid PQ")
            }
        };

        if let Some(output_path) = &self.output {
            std::fs::write(output_path, &bytes)
                .with_context(|| format!("Failed to write to {}", output_path.display()))?;
            println!("Encrypted data written to {}", output_path.display());
        } else {
            println!("{}", BASE64.encode(&bytes));
        }

        println!("  Message size: {} bytes", message.len());
        println!("  Recipients: {} ({})", self.keys.len(), flavor);
        println!("  Encrypted size: {} bytes", bytes.len());

        Ok(())
    }
}
