//! Export mnemonic command - export a key as 24 BIP39 words.

use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;

use anyhide::crypto::{format_mnemonic, key_to_mnemonic};

use super::CommandExecutor;

/// Export a private key as a 24-word mnemonic phrase.
///
/// The mnemonic can be written down on paper for secure backup.
/// Use `import-mnemonic` to restore the key from the phrase.
///
/// Only long-term keys (.key, .sign.key) can be exported.
/// Ephemeral keys are not supported (they rotate per message).
#[derive(Args, Debug)]
pub struct ExportMnemonicCommand {
    /// Path to the private key file (.key or .sign.key)
    #[arg(required = true)]
    pub key_path: PathBuf,
}

impl CommandExecutor for ExportMnemonicCommand {
    fn execute(&self) -> Result<()> {
        // Read the key file
        let content = fs::read_to_string(&self.key_path)
            .with_context(|| format!("Failed to read key file: {}", self.key_path.display()))?;

        // Check if it's an ephemeral key (not supported)
        if content.contains("EPHEMERAL") {
            bail!(
                "Mnemonic backup is only for long-term keys.\n\
                 Ephemeral keys rotate per message and should not be backed up."
            );
        }

        // Detect key type from PEM header
        let key_type = if content.contains("ANYHIDE PRIVATE KEY") {
            "Encryption"
        } else if content.contains("ANYHIDE SIGNING PRIVATE KEY") {
            "Signing"
        } else {
            bail!(
                "Unknown key format. Expected ANYHIDE PRIVATE KEY or ANYHIDE SIGNING PRIVATE KEY.\n\
                 Make sure you're using a private key file (.key or .sign.key)."
            );
        };

        // Extract the base64 content between headers
        let key_bytes = extract_key_bytes(&content)
            .with_context(|| "Failed to parse key file. Is it a valid Anyhide PEM key?")?;

        // Convert to mnemonic
        let words = key_to_mnemonic(&key_bytes);

        println!("{} Key Mnemonic Backup", key_type);
        println!("========================");
        println!();
        println!("Key file: {}", self.key_path.display());
        println!();
        println!("Write down these 24 words in order:");
        println!();
        println!("{}", format_mnemonic(&words));
        println!();
        println!("IMPORTANT:");
        println!("  - Store this phrase in a safe place (paper, not digital)");
        println!("  - Anyone with these words can restore your private key");
        println!("  - The word ORDER matters - keep them numbered");
        println!();
        println!("To restore: anyhide import-mnemonic -o <output>{}",
            if key_type == "Signing" { " --key-type signing" } else { "" });

        Ok(())
    }
}

/// Extract 32-byte key from PEM content.
fn extract_key_bytes(pem_content: &str) -> Result<[u8; 32]> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    // Find the base64 content between header and footer
    let lines: Vec<&str> = pem_content.lines().collect();

    let start = lines
        .iter()
        .position(|l| l.starts_with("-----BEGIN"))
        .context("Missing PEM header")?;

    let end = lines
        .iter()
        .position(|l| l.starts_with("-----END"))
        .context("Missing PEM footer")?;

    // Extract base64 content (skip header line, take until footer)
    let base64_content: String = lines[start + 1..end]
        .iter()
        .map(|l| l.trim())
        .collect();

    // Decode base64
    let bytes = STANDARD
        .decode(&base64_content)
        .context("Invalid base64 in key file")?;

    // Validate length
    if bytes.len() != 32 {
        bail!("Invalid key length: expected 32 bytes, got {}", bytes.len());
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);

    Ok(key_bytes)
}
