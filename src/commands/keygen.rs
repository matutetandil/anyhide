//! Key generation command.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;

use anyhide::crypto::{
    format_mnemonic, hybrid_key_to_mnemonics, key_to_mnemonic, save_private_key_for_contact,
    save_private_key_for_contact_hybrid, save_public_key_for_contact,
    save_public_key_for_contact_hybrid, save_unified_keys_for_contact,
    save_unified_keys_for_contact_hybrid, HybridKeyPair, KeyPair, SigningKeyPair,
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

    /// Show mnemonic backup phrases for long-term keys (24 words each)
    /// Write these down for paper backup. Not available for ephemeral keys.
    #[arg(long)]
    pub show_mnemonic: bool,

    /// Generate hybrid post-quantum encryption keys (X25519 + ML-KEM-768).
    ///
    /// Required for chat in protocol v2 — classical X25519 keys are no longer
    /// accepted by the chat handshake. Signing keys remain Ed25519.
    #[arg(long)]
    pub hybrid: bool,
}

impl CommandExecutor for KeygenCommand {
    fn execute(&self) -> Result<()> {
        if self.show_mnemonic && self.ephemeral {
            eprintln!("WARNING: --show-mnemonic is ignored for ephemeral keys.");
            eprintln!("         Ephemeral keys rotate per message and should not be backed up.");
            eprintln!();
        }

        if self.show_mnemonic && self.hybrid && self.ephemeral {
            // Mnemonic backup applies only to long-term hybrid keys. Ephemeral
            // keys rotate per message and should not be backed up.
            eprintln!("WARNING: --show-mnemonic is ignored for ephemeral hybrid keys.");
            eprintln!("         Ephemeral keys rotate per message and should not be backed up.");
            eprintln!();
        }

        if self.hybrid && self.ephemeral {
            self.generate_ephemeral_hybrid()
        } else if self.hybrid {
            self.generate_long_term_hybrid()
        } else if self.ephemeral {
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

        // Show mnemonic backup if requested
        if self.show_mnemonic {
            self.show_mnemonic_backup(&keypair, &signing_keypair)?;
        }

        Ok(())
    }

    /// Generate long-term hybrid PQ encryption keys + Ed25519 signing keys.
    ///
    /// Encryption uses X25519 + ML-KEM-768 (1216-byte pubkey, 96-byte secret seed).
    /// Signing remains Ed25519 — the post-quantum migration covers confidentiality
    /// only; signature-based authentication is a separate concern.
    fn generate_long_term_hybrid(&self) -> Result<()> {
        let keypair = HybridKeyPair::generate();
        keypair
            .save_to_files(&self.output)
            .context("Failed to save hybrid encryption key pair")?;

        let signing_keypair = SigningKeyPair::generate();
        signing_keypair
            .save_to_files(&self.output)
            .context("Failed to save signing key pair")?;

        let pub_path = self.output.with_extension("pub");
        let key_path = self.output.with_extension("key");
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

        println!("Hybrid PQ key pairs generated successfully:");
        println!();
        println!("Encryption keys (X25519 + ML-KEM-768):");
        println!("  Public key:  {}", pub_path.display());
        println!("  Private key: {}", key_path.display());
        println!();
        println!("Signing keys (Ed25519):");
        println!("  Public key:  {}", sign_pub_path.display());
        println!("  Private key: {}", sign_key_path.display());
        println!();
        println!("Use these keys for chat (protocol v2): `anyhide chat init -n <nick> -k {} -s {}`",
            self.output.display(), self.output.display());
        println!();
        println!("Keep your private keys (.key, .sign.key) secret and secure.");

        // Show mnemonic backup if requested. Hybrid keys use a 3-phrase scheme
        // because the 96-byte secret cannot fit a single 24-word BIP39 phrase.
        if self.show_mnemonic {
            self.show_mnemonic_backup_hybrid(&keypair, &signing_keypair)?;
        }

        Ok(())
    }

    /// Generate an ephemeral hybrid PQ keypair (no signing keys; ephemeral by definition).
    fn generate_ephemeral_hybrid(&self) -> Result<()> {
        // Determine storage format — same flag conventions as the classical
        // `generate_ephemeral`, but routed through the v2 (`_hybrid`) store API.
        let has_eph_keys = self.eph_keys.is_some();
        let has_eph_pubs = self.eph_pubs.is_some();
        let has_eph_file = self.eph_file.is_some();

        if has_eph_file && (has_eph_keys || has_eph_pubs) {
            bail!("Cannot use --eph-file with --eph-keys or --eph-pubs");
        }

        if (has_eph_keys || has_eph_pubs || has_eph_file) && self.contact.is_none() {
            bail!("--contact is required when using consolidated storage (--eph-keys, --eph-pubs, or --eph-file)");
        }

        if has_eph_keys != has_eph_pubs {
            bail!("--eph-keys and --eph-pubs must be used together");
        }

        let keypair = HybridKeyPair::generate_ephemeral();

        if let Some(ref eph_file) = self.eph_file {
            self.save_unified_ephemeral_hybrid(&keypair, eph_file)
        } else if let (Some(ref eph_keys), Some(ref eph_pubs)) = (&self.eph_keys, &self.eph_pubs) {
            self.save_separate_ephemeral_hybrid(&keypair, eph_keys, eph_pubs)
        } else {
            self.save_individual_ephemeral_hybrid(&keypair)
        }
    }

    /// Save hybrid ephemeral keys as individual files (Option 1).
    fn save_individual_ephemeral_hybrid(&self, keypair: &HybridKeyPair) -> Result<()> {
        keypair
            .save_to_files(&self.output)
            .context("Failed to save hybrid ephemeral key pair")?;

        let pub_path = self.output.with_extension("pub");
        let key_path = self.output.with_extension("key");

        println!("Hybrid ephemeral key pair generated successfully:");
        println!();
        println!("  Public key:  {}", pub_path.display());
        println!("  Private key: {}", key_path.display());
        println!();
        println!("These are EPHEMERAL hybrid keys for forward secrecy.");
        println!("Share the public key (.pub) with your contact.");

        Ok(())
    }

    /// Save hybrid ephemeral keys to separate consolidated files (Option 2).
    ///
    /// The v2 (`_hybrid`) ephemeral store rejects v1 files at write time via
    /// `EphemeralStoreError::VersionMismatch`. Existing classical stores are
    /// not migrated in place; users keep classical and hybrid stores in
    /// distinct paths.
    fn save_separate_ephemeral_hybrid(
        &self,
        keypair: &HybridKeyPair,
        eph_keys: &PathBuf,
        eph_pubs: &PathBuf,
    ) -> Result<()> {
        let contact = self.contact.as_ref().unwrap();

        save_private_key_for_contact_hybrid(eph_keys, contact, keypair.secret_key())
            .context("Failed to save hybrid private key")?;

        save_public_key_for_contact_hybrid(eph_pubs, contact, keypair.public_key())
            .context("Failed to save hybrid public key")?;

        println!(
            "Hybrid ephemeral key pair for contact '{}' generated successfully:",
            contact
        );
        println!();
        println!("  Private keys file: {}", eph_keys.display());
        println!("  Public keys file:  {}", eph_pubs.display());
        println!();
        println!("Your hybrid public key for '{}' (share this with them):", contact);
        println!();
        self.print_hybrid_public_key(keypair)?;
        println!();
        println!("Now waiting for their hybrid ephemeral public key.");
        println!("Once received, add it with:");
        println!("  anyhide keygen --hybrid --ephemeral --eph-pubs {} --contact {} --import <their.pub>",
            eph_pubs.display(), contact);

        Ok(())
    }

    /// Save hybrid ephemeral keys to a unified file (Option 3).
    ///
    /// The unified store needs *both* my private and the contact's public key.
    /// Until the contact's real key is imported, we write a throwaway hybrid
    /// pubkey as the placeholder; it will be replaced when the user runs
    /// `anyhide eph-import` (or the equivalent flow). Writing zero bytes is
    /// not viable here — `HybridPublicKey::from_bytes` rejects malformed
    /// ML-KEM components, so the placeholder must be a real keypair.
    fn save_unified_ephemeral_hybrid(
        &self,
        keypair: &HybridKeyPair,
        eph_file: &PathBuf,
    ) -> Result<()> {
        let contact = self.contact.as_ref().unwrap();

        let placeholder = HybridKeyPair::generate();

        save_unified_keys_for_contact_hybrid(
            eph_file,
            contact,
            keypair.secret_key(),
            placeholder.public_key(),
        )
        .context("Failed to save hybrid key pair")?;

        println!(
            "Hybrid ephemeral key pair for contact '{}' generated successfully:",
            contact
        );
        println!();
        println!("  Storage file: {}", eph_file.display());
        println!();
        println!("Your hybrid public key for '{}' (share this with them):", contact);
        println!();
        self.print_hybrid_public_key(keypair)?;
        println!();
        println!("IMPORTANT: You need to import their hybrid public key.");
        println!("Use: anyhide eph-import --eph-file {} --contact {} <their.pub>",
            eph_file.display(), contact);

        Ok(())
    }

    /// Print the hybrid public key in PEM format for sharing.
    fn print_hybrid_public_key(&self, keypair: &HybridKeyPair) -> Result<()> {
        use anyhide::crypto::encode_hybrid_public_key_pem;
        // Pass the keypair's KeyType so the encoder produces the
        // EPHEMERAL HYBRID PEM headers (vs the long-term HYBRID headers).
        let pem = encode_hybrid_public_key_pem(keypair.public_key(), keypair.key_type())
            .context("Failed to encode hybrid public key as PEM")?;
        println!("{}", pem);
        Ok(())
    }

    /// Display mnemonic backup phrases for hybrid keys (3 phrases for the
    /// 96-byte hybrid secret + 1 phrase for the Ed25519 signing key).
    fn show_mnemonic_backup_hybrid(
        &self,
        keypair: &HybridKeyPair,
        signing_keypair: &SigningKeyPair,
    ) -> Result<()> {
        println!();
        println!("============================================================");
        println!("              HYBRID PQ MNEMONIC BACKUP PHRASES");
        println!("============================================================");
        println!();
        println!("Write these down on paper and store in a safe place.");
        println!("Anyone with these words can restore your private keys.");
        println!();
        println!("The hybrid encryption secret is 96 bytes (32B X25519 + 64B");
        println!("ML-KEM seed) and is split into THREE 24-word phrases. All");
        println!("three are required to restore the encryption key, in order.");
        println!();

        let hybrid_secret_bytes = keypair.secret_key().to_bytes();
        let phrases = hybrid_key_to_mnemonics(&hybrid_secret_bytes);

        println!(
            "ENCRYPTION KEY ({}) — phrase 1/3 (X25519 component)",
            self.output.with_extension("key").display()
        );
        println!("------------------------");
        println!("{}", format_mnemonic(&phrases[0]));
        println!();

        println!(
            "ENCRYPTION KEY ({}) — phrase 2/3 (ML-KEM seed d)",
            self.output.with_extension("key").display()
        );
        println!("------------------------");
        println!("{}", format_mnemonic(&phrases[1]));
        println!();

        println!(
            "ENCRYPTION KEY ({}) — phrase 3/3 (ML-KEM seed z)",
            self.output.with_extension("key").display()
        );
        println!("------------------------");
        println!("{}", format_mnemonic(&phrases[2]));
        println!();

        let signing_bytes: [u8; 32] = signing_keypair.signing_key().to_bytes();
        let signing_words = key_to_mnemonic(&signing_bytes);

        println!("SIGNING KEY ({}.sign.key)", self.output.display());
        println!("------------------------");
        println!("{}", format_mnemonic(&signing_words));
        println!();
        println!("To restore: anyhide import-mnemonic -o <output> --key-type hybrid");
        println!("            anyhide import-mnemonic -o <output> --key-type signing");
        println!();
        println!("IMPORTANT: All three encryption phrases are required to restore");
        println!("           the hybrid key. Verify fingerprints match after restoration.");

        Ok(())
    }

    /// Display mnemonic backup phrases for the keys.
    fn show_mnemonic_backup(&self, keypair: &KeyPair, signing_keypair: &SigningKeyPair) -> Result<()> {
        println!();
        println!("============================================================");
        println!("                  MNEMONIC BACKUP PHRASES");
        println!("============================================================");
        println!();
        println!("Write these down on paper and store in a safe place.");
        println!("Anyone with these words can restore your private keys.");
        println!();

        // Get encryption key bytes
        let encryption_bytes: [u8; 32] = *keypair.secret_key().as_bytes();
        let encryption_words = key_to_mnemonic(&encryption_bytes);

        println!("ENCRYPTION KEY ({})", self.output.with_extension("key").display());
        println!("------------------------");
        println!("{}", format_mnemonic(&encryption_words));
        println!();

        // Get signing key bytes
        let signing_bytes: [u8; 32] = signing_keypair.signing_key().to_bytes();
        let signing_words = key_to_mnemonic(&signing_bytes);

        println!("SIGNING KEY ({}.sign.key)", self.output.display());
        println!("------------------------");
        println!("{}", format_mnemonic(&signing_words));
        println!();
        println!("To restore: anyhide import-mnemonic -o <output>");
        println!("            anyhide import-mnemonic -o <output> --key-type signing");
        println!();
        println!("IMPORTANT: Verify fingerprints match after restoration!");

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
