//! Key generation command.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;

use anyhide::crypto::{KeyPair, SigningKeyPair};

use super::CommandExecutor;

/// Generate a new key pair (encryption + signing).
#[derive(Args, Debug)]
pub struct KeygenCommand {
    /// Output path for keys (creates .pub, .key, .sign.pub, .sign.key files)
    #[arg(short, long, default_value = "anyhide")]
    pub output: PathBuf,
}

impl CommandExecutor for KeygenCommand {
    fn execute(&self) -> Result<()> {
        // Generate X25519 encryption key pair
        let keypair = KeyPair::generate();
        keypair
            .save_to_files(&self.output)
            .context("Failed to save encryption key pair")?;

        // Generate Ed25519 signing key pair
        let signing_keypair = SigningKeyPair::generate();
        signing_keypair
            .save_to_files(&self.output)
            .context("Failed to save signing key pair")?;

        let pub_path = self.output.with_extension("pub");
        let key_path = self.output.with_extension("key");

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

        println!("Key pairs generated successfully:");
        println!();
        println!("Encryption keys (X25519):");
        println!("  Public key:  {}", pub_path.display());
        println!("  Private key: {}", key_path.display());
        println!();
        println!("Signing keys (Ed25519):");
        println!("  Public key:  {}", sign_pub_path.display());
        println!("  Private key: {}", sign_key_path.display());
        println!();
        println!("Share your public keys (.pub, .sign.pub) with people who want to:");
        println!("  - Send you encrypted messages (use .pub)");
        println!("  - Verify your signatures (use .sign.pub)");
        println!();
        println!("Keep your private keys (.key, .sign.key) secret and secure.");

        Ok(())
    }
}
