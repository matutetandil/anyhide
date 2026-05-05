//! Import mnemonic command - restore a key from 24 BIP39 words.

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};

use anyhide::crypto::{
    encode_hybrid_public_key_pem, encode_hybrid_secret_key_pem, mnemonic_to_key,
    mnemonics_to_hybrid_key, HybridSecretKey, KeyPair, KeyType, SigningKeyPair,
};

use super::CommandExecutor;

/// Key type for import.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ImportKeyType {
    /// Encryption key (classical X25519, 24 words)
    #[default]
    Encryption,
    /// Signing key (Ed25519, 24 words)
    Signing,
    /// Hybrid post-quantum encryption key (X25519 + ML-KEM-768, three 24-word phrases)
    Hybrid,
}

/// Restore a private key from a 24-word mnemonic phrase.
///
/// The mnemonic must have been created with `export-mnemonic` or `keygen --show-mnemonic`.
/// Enter the 24 words when prompted (space-separated or one per line).
///
/// For `--key-type hybrid`, three 24-word phrases are required (X25519, ML-KEM-d, ML-KEM-z).
#[derive(Args, Debug)]
pub struct ImportMnemonicCommand {
    /// Output path for the restored key (without extension)
    /// Creates .pub + .key (encryption / hybrid) or .sign.pub + .sign.key (signing)
    #[arg(short, long, default_value = "restored")]
    pub output: PathBuf,

    /// Key type to import: encryption (classical), hybrid (post-quantum), or signing
    #[arg(long, default_value = "encryption")]
    pub key_type: ImportKeyType,
}

impl CommandExecutor for ImportMnemonicCommand {
    fn execute(&self) -> Result<()> {
        if matches!(self.key_type, ImportKeyType::Hybrid) {
            return self.execute_hybrid();
        }

        let key_type_name = match self.key_type {
            ImportKeyType::Encryption => "Encryption",
            ImportKeyType::Signing => "Signing",
            ImportKeyType::Hybrid => unreachable!(),
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
            ImportKeyType::Hybrid => unreachable!(),
        }

        println!();
        println!("IMPORTANT: Verify the key fingerprint matches your backup!");
        println!("Run: anyhide fingerprint <key-file>");

        Ok(())
    }
}

impl ImportMnemonicCommand {
    /// Restore a hybrid PQ encryption keypair from three 24-word phrases.
    ///
    /// The phrases are concatenated into the 96-byte hybrid secret per the
    /// `HybridSecretKey::to_bytes` layout, then a fresh `HybridKeyPair`-style
    /// PEM pair is written. We bypass `HybridKeyPair::save_to_files` because
    /// `HybridKeyPair` has no public constructor from raw bytes; the encoder
    /// helpers (`encode_hybrid_*_pem`) work directly off `HybridSecretKey`
    /// and `HybridPublicKey`, both of which we can rebuild deterministically.
    fn execute_hybrid(&self) -> Result<()> {
        println!("Import Hybrid PQ Encryption Key from Mnemonic");
        println!("=============================================");
        println!();
        println!("The hybrid encryption secret is 96 bytes split across THREE 24-word phrases:");
        println!("  Phrase 1/3: X25519 component (32 bytes)");
        println!("  Phrase 2/3: ML-KEM seed d (32 bytes)");
        println!("  Phrase 3/3: ML-KEM seed z (32 bytes)");
        println!();
        println!("All three phrases are required, in the order shown by `export-mnemonic`.");
        println!();

        let labels = ["1/3 (X25519)", "2/3 (ML-KEM seed d)", "3/3 (ML-KEM seed z)"];
        let mut phrases: Vec<Vec<String>> = Vec::with_capacity(3);

        for label in &labels {
            println!("Enter phrase {} — 24 words (space-separated, or press Enter for one-by-one):", label);
            print!("> ");
            io::stdout().flush()?;
            let words = read_mnemonic_interactive()?;
            phrases.push(words);
            println!();
        }

        println!("Validating mnemonics...");
        let phrases_arr: [Vec<String>; 3] = [
            phrases.remove(0),
            phrases.remove(0),
            phrases.remove(0),
        ];
        let secret_bytes = mnemonics_to_hybrid_key(&phrases_arr).context(
            "Invalid mnemonics. Check for typos and ensure each phrase is in the correct order.",
        )?;
        println!("All three checksums valid!");
        println!();

        let secret = HybridSecretKey::from_bytes(&secret_bytes)
            .context("Failed to reconstruct hybrid secret key from mnemonic bytes")?;
        let public = secret.public_key();

        let pub_pem = encode_hybrid_public_key_pem(&public, KeyType::HybridV1)
            .context("Failed to encode hybrid public key as PEM")?;
        let key_pem = encode_hybrid_secret_key_pem(&secret, KeyType::HybridV1)
            .context("Failed to encode hybrid private key as PEM")?;

        let pub_path = self.output.with_extension("pub");
        let key_path = self.output.with_extension("key");

        fs::write(&pub_path, pub_pem)
            .with_context(|| format!("Failed to write hybrid public key to {}", pub_path.display()))?;
        fs::write(&key_path, key_pem)
            .with_context(|| format!("Failed to write hybrid private key to {}", key_path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&key_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&key_path, perms)?;
        }

        println!("Hybrid PQ encryption keys restored successfully:");
        println!("  Public key:  {}", pub_path.display());
        println!("  Private key: {}", key_path.display());
        println!();
        println!("IMPORTANT: Verify the key fingerprint matches your backup!");
        println!("Run: anyhide fingerprint {}", pub_path.display());

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
