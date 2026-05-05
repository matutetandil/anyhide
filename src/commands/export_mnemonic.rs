//! Export mnemonic command - export a key as 24 BIP39 words.

use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;

use anyhide::crypto::{format_mnemonic, hybrid_key_to_mnemonics, key_to_mnemonic};

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

        // Hybrid PQ keys carry a 96-byte secret split across three 24-word
        // phrases. Detect them up front and dispatch to the hybrid printer
        // before falling back to the classical 32-byte path.
        if content.contains("ANYHIDE HYBRID PRIVATE KEY") {
            return self.export_hybrid(&content);
        }

        // Detect key type from PEM header
        let key_type = if content.contains("ANYHIDE PRIVATE KEY") {
            "Encryption"
        } else if content.contains("ANYHIDE SIGNING PRIVATE KEY") {
            "Signing"
        } else {
            bail!(
                "Unknown key format. Expected ANYHIDE PRIVATE KEY, ANYHIDE HYBRID PRIVATE KEY,\n\
                 or ANYHIDE SIGNING PRIVATE KEY. Make sure you're using a private key file."
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

impl ExportMnemonicCommand {
    /// Export a hybrid PQ private key as three 24-word phrases.
    ///
    /// The hybrid secret has the layout
    /// `classical X25519 (32) || ML-KEM seed d (32) || ML-KEM seed z (32)`,
    /// so each component is encoded as an independent BIP39 phrase.
    fn export_hybrid(&self, pem_content: &str) -> Result<()> {
        let bytes = extract_pem_body(pem_content)?;

        if bytes.len() != 96 {
            bail!(
                "Invalid hybrid private key length: expected 96 bytes, got {}.\n\
                 Make sure the file is a valid ANYHIDE HYBRID PRIVATE KEY PEM.",
                bytes.len()
            );
        }

        let mut secret = [0u8; 96];
        secret.copy_from_slice(&bytes);
        let phrases = hybrid_key_to_mnemonics(&secret);

        println!("Hybrid PQ Encryption Key Mnemonic Backup");
        println!("========================================");
        println!();
        println!("Key file: {}", self.key_path.display());
        println!();
        println!("The hybrid encryption secret is 96 bytes and is split into THREE");
        println!("24-word phrases. All three are required to restore the key, in order.");
        println!();

        let labels = [
            "Phrase 1/3 (X25519 component)",
            "Phrase 2/3 (ML-KEM seed d)",
            "Phrase 3/3 (ML-KEM seed z)",
        ];

        for (label, phrase) in labels.iter().zip(phrases.iter()) {
            println!("{}", label);
            println!("------------------------");
            println!("{}", format_mnemonic(phrase));
            println!();
        }

        println!("IMPORTANT:");
        println!("  - Store all three phrases in a safe place (paper, not digital)");
        println!("  - Anyone with these words can restore your private key");
        println!("  - The word ORDER matters within each phrase, AND the phrase order");
        println!("    matters across them — keep them clearly labeled 1/3, 2/3, 3/3");
        println!();
        println!("To restore: anyhide import-mnemonic -o <output> --key-type hybrid");

        Ok(())
    }
}

/// Extracts the raw bytes from a PEM body without enforcing a specific length.
fn extract_pem_body(pem_content: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let lines: Vec<&str> = pem_content.lines().collect();

    let start = lines
        .iter()
        .position(|l| l.starts_with("-----BEGIN"))
        .context("Missing PEM header")?;

    let end = lines
        .iter()
        .position(|l| l.starts_with("-----END"))
        .context("Missing PEM footer")?;

    let base64_content: String = lines[start + 1..end]
        .iter()
        .map(|l| l.trim())
        .collect();

    STANDARD
        .decode(&base64_content)
        .context("Invalid base64 in key file")
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
