//! Key generation command.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;

use anyhide::crypto::{
    save_private_key_for_contact, save_public_key_for_contact, save_unified_keys_for_contact,
    KeyPair, SigningKeyPair,
};

use super::CommandExecutor;

/// Generate a new key pair (encryption + signing).
#[derive(Args, Debug)]
pub struct KeygenCommand {
    /// Output path for keys (creates .pub, .key, .sign.pub, .sign.key files)
    #[arg(short, long, default_value = "anyhide")]
    pub output: PathBuf,

    /// Generate ephemeral keys for forward secrecy (instead of long-term keys)
    #[arg(long)]
    pub ephemeral: bool,

    /// Contact name (required for consolidated ephemeral storage)
    #[arg(long)]
    pub contact: Option<String>,

    /// Path to .eph.key file (consolidated private keys, requires --contact)
    #[arg(long)]
    pub eph_keys: Option<PathBuf>,

    /// Path to .eph.pub file (consolidated public keys, requires --contact)
    #[arg(long)]
    pub eph_pubs: Option<PathBuf>,

    /// Path to .eph file (unified storage, requires --contact)
    #[arg(long)]
    pub eph_file: Option<PathBuf>,
}

impl CommandExecutor for KeygenCommand {
    fn execute(&self) -> Result<()> {
        if self.ephemeral {
            self.generate_ephemeral()
        } else {
            self.generate_long_term()
        }
    }
}

impl KeygenCommand {
    /// Generate long-term keys (original behavior)
    fn generate_long_term(&self) -> Result<()> {
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

    /// Generate ephemeral keys for forward secrecy
    fn generate_ephemeral(&self) -> Result<()> {
        // Determine storage format
        let has_eph_keys = self.eph_keys.is_some();
        let has_eph_pubs = self.eph_pubs.is_some();
        let has_eph_file = self.eph_file.is_some();

        // Validate options
        if has_eph_file && (has_eph_keys || has_eph_pubs) {
            bail!("Cannot use --eph-file with --eph-keys or --eph-pubs");
        }

        if (has_eph_keys || has_eph_pubs || has_eph_file) && self.contact.is_none() {
            bail!("--contact is required when using consolidated storage (--eph-keys, --eph-pubs, or --eph-file)");
        }

        if has_eph_keys != has_eph_pubs {
            bail!("--eph-keys and --eph-pubs must be used together");
        }

        // Generate the ephemeral keypair
        let keypair = KeyPair::generate_ephemeral();

        if let Some(ref eph_file) = self.eph_file {
            // Option 3: Unified storage (.eph)
            self.save_unified_ephemeral(&keypair, eph_file)
        } else if let (Some(ref eph_keys), Some(ref eph_pubs)) = (&self.eph_keys, &self.eph_pubs) {
            // Option 2: Separate storage (.eph.key + .eph.pub)
            self.save_separate_ephemeral(&keypair, eph_keys, eph_pubs)
        } else {
            // Option 1: Individual files (like long-term but with ephemeral headers)
            self.save_individual_ephemeral(&keypair)
        }
    }

    /// Save ephemeral keys as individual files (Option 1)
    fn save_individual_ephemeral(&self, keypair: &KeyPair) -> Result<()> {
        keypair
            .save_to_files(&self.output)
            .context("Failed to save ephemeral key pair")?;

        let pub_path = self.output.with_extension("pub");
        let key_path = self.output.with_extension("key");

        println!("Ephemeral key pair generated successfully:");
        println!();
        println!("  Public key:  {}", pub_path.display());
        println!("  Private key: {}", key_path.display());
        println!();
        println!("These are EPHEMERAL keys for forward secrecy.");
        println!("They will rotate automatically when used with --ratchet.");
        println!();
        println!("Share the public key (.pub) with your contact.");

        Ok(())
    }

    /// Save ephemeral keys to separate consolidated files (Option 2)
    fn save_separate_ephemeral(
        &self,
        keypair: &KeyPair,
        eph_keys: &PathBuf,
        eph_pubs: &PathBuf,
    ) -> Result<()> {
        let contact = self.contact.as_ref().unwrap();

        save_private_key_for_contact(eph_keys, contact, keypair.secret_key())
            .context("Failed to save private key")?;

        save_public_key_for_contact(eph_pubs, contact, keypair.public_key())
            .context("Failed to save public key")?;

        println!(
            "Ephemeral key pair for contact '{}' generated successfully:",
            contact
        );
        println!();
        println!("  Private keys file: {}", eph_keys.display());
        println!("  Public keys file:  {}", eph_pubs.display());
        println!();
        println!("Your public key for '{}' (share this with them):", contact);
        println!();
        self.print_public_key(keypair);
        println!();
        println!("Now waiting for their ephemeral public key.");
        println!("Once received, add it with:");
        println!("  anyhide keygen --ephemeral --eph-pubs {} --contact {} --import <their.pub>",
            eph_pubs.display(), contact);

        Ok(())
    }

    /// Save ephemeral keys to unified file (Option 3)
    fn save_unified_ephemeral(&self, keypair: &KeyPair, eph_file: &PathBuf) -> Result<()> {
        let contact = self.contact.as_ref().unwrap();

        // For now, save with a placeholder public key (zeros)
        // The user will update it when they receive the contact's public key
        let placeholder_public = x25519_dalek::PublicKey::from([0u8; 32]);

        save_unified_keys_for_contact(
            eph_file,
            contact,
            keypair.secret_key(),
            &placeholder_public,
        )
        .context("Failed to save key pair")?;

        println!(
            "Ephemeral key pair for contact '{}' generated successfully:",
            contact
        );
        println!();
        println!("  Storage file: {}", eph_file.display());
        println!();
        println!("Your public key for '{}' (share this with them):", contact);
        println!();
        self.print_public_key(keypair);
        println!();
        println!("IMPORTANT: You need to import their public key.");
        println!("Use: anyhide eph-import --eph-file {} --contact {} <their.pub>",
            eph_file.display(), contact);

        Ok(())
    }

    /// Print the public key in PEM format for sharing
    fn print_public_key(&self, keypair: &KeyPair) {
        use anyhide::crypto::encode_ephemeral_public_key_pem;
        let pem = encode_ephemeral_public_key_pem(keypair.public_key());
        println!("{}", pem);
    }
}
