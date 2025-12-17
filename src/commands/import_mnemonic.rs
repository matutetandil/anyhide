//! Import mnemonic command - restore a key from 24 BIP39 words.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};

use anyhide::crypto::{mnemonic_to_key, KeyPair, SigningKeyPair};

use super::CommandExecutor;

/// Key type for import.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ImportKeyType {
    /// Encryption key (X25519)
    #[default]
    Encryption,
    /// Signing key (Ed25519)
    Signing,
}

/// Restore a private key from a 24-word mnemonic phrase.
///
/// The mnemonic must have been created with `export-mnemonic` or `keygen --show-mnemonic`.
/// Enter the 24 words when prompted (space-separated or one per line).
#[derive(Args, Debug)]
pub struct ImportMnemonicCommand {
    /// Output path for the restored key (without extension)
    /// Creates .pub + .key (encryption) or .sign.pub + .sign.key (signing)
    #[arg(short, long, default_value = "restored")]
    pub output: PathBuf,

    /// Key type to import: encryption (default) or signing
    #[arg(long, default_value = "encryption")]
    pub key_type: ImportKeyType,
}

impl CommandExecutor for ImportMnemonicCommand {
    fn execute(&self) -> Result<()> {
        let key_type_name = match self.key_type {
            ImportKeyType::Encryption => "Encryption",
            ImportKeyType::Signing => "Signing",
        };

        println!("Import {} Key from Mnemonic", key_type_name);
        println!("================================");
        println!();
        println!("Enter 24 words (space-separated, or press Enter for one-by-one):");
        print!("> ");
        io::stdout().flush()?;

        // Read words interactively
        let words = read_mnemonic_interactive()?;

        // Validate and convert to key
        println!();
        println!("Validating mnemonic...");

        let key_bytes = mnemonic_to_key(&words).context(
            "Invalid mnemonic. Check for typos and ensure words are in the correct order.",
        )?;

        println!("Checksum valid!");
        println!();

        // Generate keypair from recovered bytes and save
        match self.key_type {
            ImportKeyType::Encryption => {
                let keypair = KeyPair::from_secret_bytes(&key_bytes);
                keypair
                    .save_to_files(&self.output)
                    .context("Failed to save encryption keys")?;

                let pub_path = self.output.with_extension("pub");
                let key_path = self.output.with_extension("key");

                println!("Encryption keys restored successfully:");
                println!("  Public key:  {}", pub_path.display());
                println!("  Private key: {}", key_path.display());
            }
            ImportKeyType::Signing => {
                let keypair = SigningKeyPair::from_secret_bytes(&key_bytes)
                    .context("Failed to create signing keypair from mnemonic")?;
                keypair
                    .save_to_files(&self.output)
                    .context("Failed to save signing keys")?;

                // Construct signing key paths
                let sign_pub_path = {
                    let mut p = self.output.as_os_str().to_os_string();
                    p.push(".sign.pub");
                    PathBuf::from(p)
                };
                let sign_key_path = {
                    let mut p = self.output.as_os_str().to_os_string();
                    p.push(".sign.key");
                    PathBuf::from(p)
                };

                println!("Signing keys restored successfully:");
                println!("  Public key:  {}", sign_pub_path.display());
                println!("  Private key: {}", sign_key_path.display());
            }
        }

        println!();
        println!("IMPORTANT: Verify the key fingerprint matches your backup!");
        println!("Run: anyhide fingerprint <key-file>");

        Ok(())
    }
}

/// Read 24 words interactively from stdin.
fn read_mnemonic_interactive() -> Result<Vec<String>> {
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;

    let words: Vec<String> = line
        .split_whitespace()
        .map(|s| s.to_lowercase())
        .collect();

    // If user entered all 24 words at once
    if words.len() == 24 {
        return Ok(words);
    }

    // If user entered some words, start from there
    let mut all_words = words;

    // One-by-one mode
    if all_words.is_empty() {
        println!();
        println!("Enter one word at a time:");
    } else if all_words.len() < 24 {
        println!();
        println!("Got {} words, continuing one at a time:", all_words.len());
    }

    while all_words.len() < 24 {
        print!("Word {}/24: ", all_words.len() + 1);
        io::stdout().flush()?;

        let mut word = String::new();
        stdin.lock().read_line(&mut word)?;
        let word = word.trim().to_lowercase();

        if !word.is_empty() {
            // Handle case where user pastes multiple words
            let new_words: Vec<String> = word
                .split_whitespace()
                .map(|s| s.to_lowercase())
                .collect();

            all_words.extend(new_words);
        }
    }

    // Truncate if user entered too many
    all_words.truncate(24);

    Ok(all_words)
}
