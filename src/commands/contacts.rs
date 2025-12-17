//! Contacts command - manage contact aliases.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use sha2::{Digest, Sha256};

use anyhide::contacts::{Contact, ContactsConfig};
use anyhide::crypto::load_public_key;

use super::CommandExecutor;

/// Manage contacts with aliases for easier key management.
///
/// Contacts are stored in ~/.anyhide/contacts.toml and can be used
/// with --to <alias> in the encode command instead of --their-key.
#[derive(Args, Debug)]
pub struct ContactsCommand {
    #[command(subcommand)]
    pub action: ContactsAction,
}

#[derive(Subcommand, Debug)]
pub enum ContactsAction {
    /// List all contacts
    List,

    /// Add a new contact
    Add(ContactsAddArgs),

    /// Remove a contact
    Remove(ContactsRemoveArgs),

    /// Show contact details with fingerprints
    Show(ContactsShowArgs),
}

#[derive(Args, Debug)]
pub struct ContactsAddArgs {
    /// Contact name (alias)
    pub name: String,

    /// Path to contact's public key (.pub)
    pub key_path: PathBuf,

    /// Path to contact's signing public key (.sign.pub)
    #[arg(long)]
    pub signing: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ContactsRemoveArgs {
    /// Contact name to remove
    pub name: String,
}

#[derive(Args, Debug)]
pub struct ContactsShowArgs {
    /// Contact name to show details
    pub name: String,
}

impl CommandExecutor for ContactsCommand {
    fn execute(&self) -> Result<()> {
        match &self.action {
            ContactsAction::List => list_contacts(),
            ContactsAction::Add(args) => add_contact(args),
            ContactsAction::Remove(args) => remove_contact(args),
            ContactsAction::Show(args) => show_contact(args),
        }
    }
}

/// List all contacts.
fn list_contacts() -> Result<()> {
    let config = ContactsConfig::load().context("Failed to load contacts")?;

    if config.is_empty() {
        println!("No contacts configured.");
        println!();
        println!("Add a contact with:");
        println!("  anyhide contacts add <name> <key-path>");
        return Ok(());
    }

    println!("Contacts ({}):", config.len());
    println!();

    for (name, contact) in config.list() {
        println!("  {} ", name);
        println!("    Public key:  {}", contact.public_key.display());
        if let Some(ref signing) = contact.signing_key {
            println!("    Signing key: {}", signing.display());
        }
        println!();
    }

    Ok(())
}

/// Add a new contact.
fn add_contact(args: &ContactsAddArgs) -> Result<()> {
    // Validate that the key file exists and is readable
    load_public_key(&args.key_path)
        .with_context(|| format!("Failed to load public key from {}", args.key_path.display()))?;

    // Validate signing key if provided
    if let Some(ref signing_path) = args.signing {
        load_public_key(signing_path).with_context(|| {
            format!(
                "Failed to load signing key from {}",
                signing_path.display()
            )
        })?;
    }

    // Create contact
    let contact = if let Some(ref signing_path) = args.signing {
        Contact::with_signing(args.key_path.clone(), signing_path.clone())
    } else {
        Contact::new(args.key_path.clone())
    };

    // Load config, add contact, save
    let mut config = ContactsConfig::load().context("Failed to load contacts")?;

    config
        .add(&args.name, contact)
        .with_context(|| format!("Failed to add contact '{}'", args.name))?;

    config.save().context("Failed to save contacts")?;

    println!("Contact '{}' added successfully.", args.name);
    println!();
    println!("You can now use: anyhide encode -m \"message\" ... --to {}", args.name);

    Ok(())
}

/// Remove a contact.
fn remove_contact(args: &ContactsRemoveArgs) -> Result<()> {
    let mut config = ContactsConfig::load().context("Failed to load contacts")?;

    config
        .remove(&args.name)
        .with_context(|| format!("Contact '{}' not found", args.name))?;

    config.save().context("Failed to save contacts")?;

    println!("Contact '{}' removed.", args.name);

    Ok(())
}

/// Show contact details with fingerprints.
fn show_contact(args: &ContactsShowArgs) -> Result<()> {
    let config = ContactsConfig::load().context("Failed to load contacts")?;

    let contact = config
        .get(&args.name)
        .with_context(|| format!("Contact '{}' not found", args.name))?;

    println!("Contact: {}", args.name);
    println!();

    // Show public key with fingerprint
    println!("Public Key:");
    println!("  Path: {}", contact.public_key.display());

    if let Ok(public_key) = load_public_key(&contact.public_key) {
        let fingerprint = compute_emoji_fingerprint(public_key.as_bytes());
        println!("  Fingerprint: {}", fingerprint);
    } else {
        println!("  (unable to load key)");
    }

    // Show signing key with fingerprint if present
    if let Some(ref signing_path) = contact.signing_key {
        println!();
        println!("Signing Key:");
        println!("  Path: {}", signing_path.display());

        if let Ok(signing_key) = load_public_key(signing_path) {
            let fingerprint = compute_emoji_fingerprint(signing_key.as_bytes());
            println!("  Fingerprint: {}", fingerprint);
        } else {
            println!("  (unable to load key)");
        }
    }

    Ok(())
}

/// Compute emoji fingerprint for a key (same logic as fingerprint command).
fn compute_emoji_fingerprint(key_bytes: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key_bytes);
    let hash = hasher.finalize();

    let emojis = [
        "🔐", "🔑", "🛡️", "⚔️", "🏰", "🎯", "💎", "🌟",
        "🔥", "💧", "🌿", "⚡", "🌙", "☀️", "🌈", "❄️",
        "🦁", "🐺", "🦅", "🐉", "🦊", "🐧", "🦋", "🐝",
        "🍎", "🍊", "🍋", "🍇", "🍓", "🥝", "🍒", "🥥",
        "🎸", "🎹", "🎺", "🥁", "🎻", "🎤", "🎧", "🎬",
        "🚀", "✈️", "🚁", "⛵", "🚂", "🏎️", "🛸", "🚲",
        "🏔️", "🌋", "🏝️", "🌊", "🏜️", "🌲", "🌸", "🌺",
        "💜", "💙", "💚", "💛", "🧡", "❤️", "🖤", "🤍",
    ];

    hash[0..8]
        .iter()
        .map(|&b| {
            let idx = (b as usize) % emojis.len();
            emojis[idx]
        })
        .collect::<Vec<_>>()
        .join(" ")
}
