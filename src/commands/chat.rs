//! Chat command for P2P encrypted messaging over Tor.
//!
//! This module provides commands for secure, anonymous chat using
//! Tor hidden services. Both peers are equal - no server/client distinction.
//!
//! ## Commands
//!
//! - `chat <contact>` - Start chat with a contact
//! - `chat init` - Initialize your chat identity (creates .onion address)
//! - `chat add <name> <onion>` - Add a chat contact
//! - `chat list` - List all chat contacts
//! - `chat show <name>` - Show contact details

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use x25519_dalek::{PublicKey, StaticSecret};

/// Prompt for a passphrase (input hidden).
fn prompt_passphrase(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt)
        .context("Failed to read passphrase")
}

/// Generate a retry delay with jitter to avoid synchronized retries.
/// Returns a duration between 3 and 7 seconds.
fn retry_delay_with_jitter() -> Duration {
    use rand::Rng;
    let jitter_secs = rand::thread_rng().gen_range(3..=7);
    Duration::from_secs(jitter_secs)
}

use super::CommandExecutor;

use anyhide::chat::transport::{
    print_bootstrap_message, print_tor_warning, AnyhideTorClient, MessageTransport,
};
use anyhide::chat::tui::{
    init_terminal, restore_terminal, render, App, ConnectionStatus, Event, EventHandler,
    handle_key_event, handle_command, KeyAction,
    // Multi-contact TUI
    render_multi, Contact, ContactStatus, Dialog, MultiApp, MultiKeyAction,
    handle_multi_key_event, handle_multi_command,
};

use anyhide::chat::protocol::{decrypt_carriers, encrypt_carriers, hash_carriers};
use anyhide::chat::{
    generate_carriers, ChatConfig, ChatSession, HandshakeComplete, HandshakeInit,
    HandshakeResponse, WireMessage,
};
use anyhide::crypto::{load_public_key, load_verifying_key, SigningKeyPair};
use anyhide::qr::{generate_qr_to_file, read_qr_from_file, QrConfig, QrFormat};

// Chat contacts configuration
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

/// Chat contact information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatContact {
    /// Contact's .onion address (without port).
    pub onion_address: String,
    /// Path to their encryption public key.
    pub public_key: PathBuf,
    /// Path to their signing public key.
    pub signing_key: PathBuf,
}

/// Ephemeral contact - not persisted, only valid for current session.
/// Contains raw key bytes instead of file paths.
#[derive(Debug, Clone)]
pub struct EphemeralContact {
    /// Contact's .onion address (without port).
    pub onion_address: String,
    /// Their encryption public key (32 bytes).
    pub public_key: [u8; 32],
    /// Their signing public key (32 bytes).
    pub signing_key: [u8; 32],
}

/// Chat identity - your own onion service configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatIdentity {
    /// Nickname for the hidden service.
    pub nickname: String,
    /// Path to your encryption key pair (base path).
    pub key_path: PathBuf,
    /// Path to your signing key pair (base path).
    pub sign_key_path: PathBuf,
}

/// Chat configuration stored in ~/.anyhide/chat.toml
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChatConfig2 {
    /// Your chat identity.
    pub identity: Option<ChatIdentity>,
    /// Your .onion address.
    pub my_onion: Option<String>,
    /// Chat contacts by name.
    #[serde(default)]
    pub contacts: HashMap<String, ChatContact>,
}

impl ChatConfig2 {
    /// Load chat configuration from file.
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if path.exists() {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            toml::from_str(&content)
                .with_context(|| format!("Failed to parse {}", path.display()))
        } else {
            Ok(Self::default())
        }
    }

    /// Save chat configuration to file.
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        fs::write(&path, content)?;
        Ok(())
    }

    /// Get the config file path.
    fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
            .ok_or_else(|| anyhow::anyhow!("Could not find config directory"))?;

        let filename = match get_current_profile() {
            Some(profile) => format!("chat-{}.toml", profile),
            None => "chat.toml".to_string(),
        };

        Ok(config_dir.join("anyhide").join(filename))
    }

    /// Find a contact by their signing public key bytes.
    /// Returns the contact name if found.
    pub fn find_contact_by_signing_key(&self, signing_key_bytes: &[u8; 32]) -> Option<String> {
        for (name, contact) in &self.contacts {
            if let Ok(verifying_key) = load_verifying_key(&contact.signing_key) {
                if verifying_key.as_bytes() == signing_key_bytes {
                    return Some(name.clone());
                }
            }
        }
        None
    }
}

/// Default port for chat connections.
const CHAT_PORT: u16 = 9999;

/// P2P encrypted chat over Tor.
///
/// Usage:
///   anyhide chat <contact>          Start chat with a contact
///   anyhide chat init ...           Initialize your identity
///   anyhide chat add ...            Add a contact
///   anyhide chat list               List contacts
///   anyhide chat show <name>        Show contact details
///   anyhide chat remove <name>      Remove a contact
#[derive(Args, Debug)]
pub struct ChatCommand {
    /// Contact name to chat with (use subcommand for management)
    pub contact: Option<String>,

    /// Number of carriers to generate (default: 10)
    #[arg(long, default_value = "10")]
    pub carriers: usize,

    /// Size of each carrier in bytes (default: 4096)
    #[arg(long, default_value = "4096")]
    pub carrier_size: usize,

    /// Pre-shared carrier file(s). Both parties must use the SAME files in the SAME order.
    /// Order is a secret! Using multiple files provides N! additional security.
    /// If not specified, random carriers are generated and exchanged during handshake.
    #[arg(short = 'c', long = "carrier", num_args = 1..)]
    pub carrier_files: Option<Vec<PathBuf>>,

    /// Profile name for separate identity (useful for local testing)
    #[arg(long, global = true)]
    pub profile: Option<String>,

    // === Ephemeral contact options ===
    /// Ephemeral mode: chat without saving contact. Requires --onion, --pubkey, --sign-key.
    #[arg(short = 'e', long = "ephemeral")]
    pub ephemeral: bool,

    /// Peer's .onion address (for ephemeral mode)
    #[arg(long, requires = "ephemeral")]
    pub onion: Option<String>,

    /// Peer's encryption public key in hex (for ephemeral mode)
    #[arg(long, requires = "ephemeral")]
    pub pubkey: Option<String>,

    /// Peer's signing public key in hex (for ephemeral mode)
    #[arg(long = "sign-key", requires = "ephemeral")]
    pub sign_key: Option<String>,

    /// Import ephemeral contact from QR code image (alternative to --onion/--pubkey/--sign-key)
    #[arg(long = "from-qr", requires = "ephemeral")]
    pub from_qr: Option<PathBuf>,

    #[command(subcommand)]
    pub action: Option<ChatAction>,
}

// Thread-local storage for the current profile.
thread_local! {
    static CURRENT_PROFILE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Set the current profile for config loading.
fn set_current_profile(profile: Option<String>) {
    CURRENT_PROFILE.with(|p| *p.borrow_mut() = profile);
}

/// Get the current profile.
fn get_current_profile() -> Option<String> {
    CURRENT_PROFILE.with(|p| p.borrow().clone())
}

#[derive(Subcommand, Debug)]
pub enum ChatAction {
    /// Initialize your chat identity (creates .onion address)
    Init {
        /// Nickname for your hidden service
        #[arg(short, long, default_value = "anyhide-chat")]
        nickname: String,

        /// Path to your encryption key pair (base path, e.g., "mykeys" for mykeys.pub/mykeys.key)
        #[arg(short, long)]
        key: PathBuf,

        /// Path to your signing key pair (base path)
        #[arg(short = 's', long)]
        sign_key: PathBuf,
    },

    /// Add a chat contact
    Add {
        /// Contact name (alias)
        name: String,

        /// Contact's .onion address
        onion: String,

        /// Path to their encryption public key
        #[arg(long)]
        key: PathBuf,

        /// Path to their signing public key
        #[arg(long)]
        sign_key: PathBuf,
    },

    /// List all chat contacts
    List,

    /// Show contact details
    Show {
        /// Contact name
        name: String,
    },

    /// Remove a chat contact
    Remove {
        /// Contact name
        name: String,
    },

    /// Export your chat identity to a QR code
    ExportQr {
        /// Output file for QR code (default: identity.png)
        #[arg(short, long, default_value = "identity.png")]
        output: PathBuf,

        /// QR format: png (default), svg, or ascii
        #[arg(long, default_value = "png")]
        format: String,
    },

    /// Import a chat contact from a QR code image
    ImportQr {
        /// Path to QR code image
        image: PathBuf,

        /// Contact name (alias)
        #[arg(short, long)]
        name: String,
    },

    /// Show your own identity and .onion address
    Me,
}

impl CommandExecutor for ChatCommand {
    fn execute(&self) -> Result<()> {
        // Set profile for config loading
        set_current_profile(self.profile.clone());

        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

        let profile = self.profile.as_deref();

        rt.block_on(async {
            // Handle ephemeral mode
            if self.ephemeral {
                return self.start_ephemeral_chat(profile).await;
            }

            // If a contact name is provided, start chat
            if let Some(contact) = &self.contact {
                return start_chat(
                    contact,
                    self.carriers,
                    self.carrier_size,
                    self.carrier_files.as_deref(),
                    profile,
                ).await;
            }

            // Otherwise, handle subcommand
            match &self.action {
                Some(ChatAction::Init {
                    nickname,
                    key,
                    sign_key,
                }) => init_identity(nickname, key, sign_key, profile).await,
                Some(ChatAction::Add {
                    name,
                    onion,
                    key,
                    sign_key,
                }) => add_contact(name, onion, key, sign_key),
                Some(ChatAction::List) => list_contacts(),
                Some(ChatAction::Show { name }) => show_contact(name),
                Some(ChatAction::Remove { name }) => remove_contact(name),
                Some(ChatAction::ExportQr { output, format }) => export_qr_identity(output, format),
                Some(ChatAction::ImportQr { image, name }) => import_qr_contact(image, name),
                Some(ChatAction::Me) => show_my_identity(),
                None => {
                    // No contact specified: launch multi-contact TUI
                    start_multi_chat(profile).await
                }
            }
        })
    }
}

impl ChatCommand {
    /// Start an ephemeral chat session (contact not saved).
    async fn start_ephemeral_chat(&self, profile: Option<&str>) -> Result<()> {
        // Parse ephemeral contact from args or QR
        let ephemeral_contact = if let Some(qr_path) = &self.from_qr {
            // Import from QR code
            parse_ephemeral_from_qr(qr_path)?
        } else if let (Some(onion), Some(pubkey_hex), Some(sign_key_hex)) =
            (&self.onion, &self.pubkey, &self.sign_key)
        {
            // Parse from command line args
            parse_ephemeral_from_args(onion, pubkey_hex, sign_key_hex)?
        } else {
            bail!(
                "Ephemeral mode requires either:\n\
                 - --from-qr <image>\n\
                 - --onion <addr> --pubkey <hex> --sign-key <hex>"
            );
        };

        // Show warning about ephemeral session
        println!("========================================");
        println!("  EPHEMERAL SESSION");
        println!("========================================");
        println!("  This contact will NOT be saved.");
        println!("  Session data is lost when you quit.");
        println!("========================================");
        println!();
        println!("Contact: ~ephemeral");
        println!("  Onion: {}", ephemeral_contact.onion_address);
        println!("  Pubkey: {}...", hex::encode(&ephemeral_contact.public_key[..8]));
        println!();

        // Start chat with ephemeral contact
        start_ephemeral_chat_session(
            &ephemeral_contact,
            self.carriers,
            self.carrier_size,
            self.carrier_files.as_deref(),
            profile,
        )
        .await
    }
}

/// Parse ephemeral contact from QR code image.
fn parse_ephemeral_from_qr(qr_path: &PathBuf) -> Result<EphemeralContact> {
    let data = read_qr_from_file(qr_path)
        .with_context(|| format!("Failed to read QR code from {}", qr_path.display()))?;

    let (onion, enc_pubkey, sign_pubkey, _nickname) = decode_chat_identity(&data)
        .context("Failed to decode chat identity from QR")?;

    // Clean onion address (remove .onion suffix for storage)
    let onion_clean = onion.trim_end_matches(".onion").to_string();

    Ok(EphemeralContact {
        onion_address: format!("{}.onion", onion_clean),
        public_key: enc_pubkey,
        signing_key: sign_pubkey,
    })
}

/// Parse ephemeral contact from command line arguments.
fn parse_ephemeral_from_args(onion: &str, pubkey_hex: &str, sign_key_hex: &str) -> Result<EphemeralContact> {
    // Parse encryption public key
    let pubkey_bytes = hex::decode(pubkey_hex)
        .context("Invalid --pubkey: must be valid hex")?;
    if pubkey_bytes.len() != 32 {
        bail!("Invalid --pubkey: must be 32 bytes (64 hex chars), got {}", pubkey_bytes.len());
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&pubkey_bytes);

    // Parse signing public key
    let sign_key_bytes = hex::decode(sign_key_hex)
        .context("Invalid --sign-key: must be valid hex")?;
    if sign_key_bytes.len() != 32 {
        bail!("Invalid --sign-key: must be 32 bytes (64 hex chars), got {}", sign_key_bytes.len());
    }
    let mut signing_key = [0u8; 32];
    signing_key.copy_from_slice(&sign_key_bytes);

    // Clean onion address
    let onion_clean = onion.split(':').next().unwrap_or(onion);
    let onion_addr = if onion_clean.ends_with(".onion") {
        onion_clean.to_string()
    } else {
        format!("{}.onion", onion_clean)
    };

    Ok(EphemeralContact {
        onion_address: onion_addr,
        public_key,
        signing_key,
    })
}

/// Start an ephemeral chat session with inline contact data.
async fn start_ephemeral_chat_session(
    contact: &EphemeralContact,
    carriers_count: usize,
    carrier_size: usize,
    carrier_files: Option<&[PathBuf]>,
    profile: Option<&str>,
) -> Result<()> {
    // Load configuration
    let config = ChatConfig2::load()?;

    // Verify identity is initialized
    let identity = config
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Chat identity not initialized. Run 'anyhide chat init' first."))?;

    // Prompt for passphrase FIRST
    let passphrase = prompt_passphrase("Passphrase: ")?;
    if passphrase.is_empty() {
        bail!("Passphrase cannot be empty");
    }

    // Print security warning
    print_tor_warning();

    // Load our keys
    let my_signing_keypair = SigningKeyPair::load_from_files(&identity.sign_key_path)
        .context("Failed to load signing key pair")?;

    // Create verifying key from raw bytes
    let their_verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&contact.signing_key)
        .context("Invalid signing public key")?;

    // Bootstrap Tor client
    print_bootstrap_message();
    let tor_client = AnyhideTorClient::with_profile(profile)
        .await
        .context("Failed to bootstrap Tor client")?;

    // Create our hidden service
    println!("Creating hidden service '{}'...", identity.nickname);
    let mut my_listener = tor_client
        .listen(&identity.nickname)
        .await
        .context("Failed to create hidden service")?;

    let my_onion = my_listener.onion_addr().to_string();
    println!();
    println!("Your .onion address: {}", my_onion);
    println!();

    // Prepare peer address
    let peer_addr = format!("{}:{}", contact.onion_address, CHAT_PORT);

    // Load pre-shared carriers if specified
    let (preshared_carriers, chat_config) = if let Some(paths) = carrier_files {
        println!("Loading {} pre-shared carrier file(s)...", paths.len());
        let carriers = load_preshared_carriers(paths)?;
        let hash = hash_carriers(&carriers);
        println!("Carrier hash: {}", hex::encode(&hash[..8]));
        (Some(carriers), ChatConfig::with_preshared_carriers(hash))
    } else {
        let mut config = ChatConfig::default();
        config.carriers_per_party = carriers_count;
        config.carrier_size = carrier_size;
        (None, config)
    };

    // Deterministic role selection to avoid crossed-wires when both connect simultaneously
    let i_am_initiator = my_onion > contact.onion_address;
    if i_am_initiator {
        println!("Role: initiator (will try to connect)");
    } else {
        println!("Role: responder (will wait for connection)");
    }

    // Connection + handshake loop with retries (Tor can be flaky)
    let (mut session, mut conn) = loop {
        println!("Looking for ephemeral contact...");

        // Role-based connection strategy to avoid crossed-wires
        let connection_result = if i_am_initiator {
            tokio::select! {
                biased;
                result = tor_client.connect(&peer_addr) => {
                    match result {
                        Ok(conn) => {
                            println!("Connected to ephemeral contact!");
                            Some((conn, true))
                        }
                        Err(e) => {
                            eprintln!("Contact not available: {}", e);
                            None
                        }
                    }
                }
                result = my_listener.accept() => {
                    match result {
                        Ok(conn) => {
                            println!("Ephemeral contact connected!");
                            Some((conn, false))
                        }
                        Err(e) => {
                            eprintln!("Accept error: {}", e);
                            None
                        }
                    }
                }
            }
        } else {
            tokio::select! {
                biased;
                result = my_listener.accept() => {
                    match result {
                        Ok(conn) => {
                            println!("Ephemeral contact connected!");
                            Some((conn, false))
                        }
                        Err(e) => {
                            eprintln!("Accept error: {}", e);
                            None
                        }
                    }
                }
                result = tor_client.connect(&peer_addr) => {
                    match result {
                        Ok(conn) => {
                            println!("Connected to ephemeral contact!");
                            Some((conn, true))
                        }
                        Err(e) => {
                            eprintln!("Contact not available: {}", e);
                            None
                        }
                    }
                }
            }
        };

        let (mut conn, is_initiator) = match connection_result {
            Some(c) => c,
            None => {
                let delay = retry_delay_with_jitter();
                println!("Retrying in {} seconds... (Ctrl+C to cancel)", delay.as_secs());
                tokio::time::sleep(delay).await;
                continue;
            }
        };

        // Generate ephemeral key for this session
        let my_eph_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let my_eph_public = PublicKey::from(&my_eph_secret);

        // Perform handshake based on role
        // Ephemeral contacts are by definition unknown (not in contacts list)
        let i_know_them = false;
        println!("Performing handshake...");
        let handshake_result = if is_initiator {
            perform_initiator_handshake(
                &mut conn,
                my_eph_secret,
                my_eph_public,
                &my_signing_keypair,
                their_verifying_key,
                chat_config.clone(),
                preshared_carriers.as_deref(),
                &passphrase,
                i_know_them,
            )
            .await
        } else {
            perform_responder_handshake(
                &mut conn,
                my_eph_secret,
                my_eph_public,
                &my_signing_keypair,
                their_verifying_key,
                chat_config.clone(),
                preshared_carriers.as_deref(),
                &passphrase,
                i_know_them,
            )
            .await
        };

        match handshake_result {
            Ok(s) => break (s, conn),
            Err(e) => {
                eprintln!("Handshake failed: {}", e);
                let delay = retry_delay_with_jitter();
                println!("Retrying in {} seconds... (Ctrl+C to cancel)", delay.as_secs());
                tokio::time::sleep(delay).await;
                continue;
            }
        }
    };

    // Chat loop with TUI - use "~ephemeral" as contact name
    run_chat_loop(&mut session, &mut conn, "~ephemeral", &my_onion).await
}

/// Get base path (remove extension if present).
fn get_base_path(path: &PathBuf, extension: &str) -> PathBuf {
    let path_str = path.to_string_lossy();
    if path_str.ends_with(extension) {
        PathBuf::from(path_str.trim_end_matches(extension))
    } else {
        path.clone()
    }
}

/// Initialize chat identity.
async fn init_identity(nickname: &str, key_path: &PathBuf, sign_key_path: &PathBuf, profile: Option<&str>) -> Result<()> {
    // Normalize paths - handle both "alice" and "alice.key" as input
    let key_base = get_base_path(key_path, ".key");
    let sign_base = get_base_path(sign_key_path, ".sign.key");
    let sign_base = get_base_path(&sign_base, ".sign"); // Also handle "alice.sign"

    let key_file = key_base.with_extension("key");
    let pub_file = key_base.with_extension("pub");
    let sign_key_file = PathBuf::from(format!("{}.sign.key", sign_base.display()));
    let sign_pub_file = PathBuf::from(format!("{}.sign.pub", sign_base.display()));

    if !key_file.exists() {
        bail!("Encryption key not found: {}", key_file.display());
    }
    if !pub_file.exists() {
        bail!("Encryption public key not found: {}", pub_file.display());
    }
    if !sign_key_file.exists() {
        bail!("Signing key not found: {}", sign_key_file.display());
    }
    if !sign_pub_file.exists() {
        bail!("Signing public key not found: {}", sign_pub_file.display());
    }

    println!("Initializing chat identity...");
    println!();

    // Print security warning
    print_tor_warning();

    // Bootstrap Tor to get our .onion address
    print_bootstrap_message();
    let tor_client = AnyhideTorClient::with_profile(profile)
        .await
        .context("Failed to bootstrap Tor client")?;

    // Create hidden service to get our .onion address
    println!("Creating hidden service '{}'...", nickname);
    let my_listener = tor_client
        .listen(nickname)
        .await
        .context("Failed to create hidden service")?;

    let my_onion = my_listener.onion_addr().to_string();

    // Save identity to config (store base paths and onion address)
    let mut config = ChatConfig2::load()?;
    config.identity = Some(ChatIdentity {
        nickname: nickname.to_string(),
        key_path: key_base.clone(),
        sign_key_path: sign_base.clone(),
    });
    config.my_onion = Some(my_onion.clone());
    config.save()?;

    println!();
    println!("========================================");
    println!("  Chat identity initialized!");
    println!("========================================");
    println!();
    println!("  Nickname: {}", nickname);
    println!("  Your .onion address: {}", my_onion);
    println!();
    println!("  Encryption keys: {}.key / {}.pub", key_base.display(), key_base.display());
    println!("  Signing keys: {}.sign.key / {}.sign.pub", sign_base.display(), sign_base.display());
    println!();
    println!("Share with your contacts:");
    println!("  1. Your .onion address: {}", my_onion);
    println!("  2. Your public key: {}", pub_file.display());
    println!("  3. Your signing key: {}", sign_pub_file.display());
    println!();

    Ok(())
}

/// Add a chat contact.
fn add_contact(name: &str, onion: &str, key_path: &PathBuf, sign_key_path: &PathBuf) -> Result<()> {
    // Verify keys exist
    if !key_path.exists() {
        bail!("Public key not found: {}", key_path.display());
    }
    if !sign_key_path.exists() {
        bail!("Signing public key not found: {}", sign_key_path.display());
    }

    // Clean onion address (remove port if present)
    let onion_clean = onion.split(':').next().unwrap_or(onion).to_string();

    let mut config = ChatConfig2::load()?;
    config.contacts.insert(
        name.to_string(),
        ChatContact {
            onion_address: onion_clean.clone(),
            public_key: key_path.clone(),
            signing_key: sign_key_path.clone(),
        },
    );
    config.save()?;

    println!("Contact '{}' added!", name);
    println!("  Onion: {}", onion_clean);
    println!("  Public key: {}", key_path.display());
    println!("  Signing key: {}", sign_key_path.display());

    Ok(())
}

/// Add a chat contact from dialog input.
/// Note: profile is already set via set_current_profile() at command start.
fn add_contact_from_dialog(
    name: &str,
    onion: &str,
    public_key: &str,
    signing_key: &str,
) -> Result<()> {
    let key_path = PathBuf::from(public_key);
    let sign_key_path = PathBuf::from(signing_key);

    // Verify keys exist
    if !key_path.exists() {
        bail!("Public key not found: {}", key_path.display());
    }
    if !sign_key_path.exists() {
        bail!("Signing public key not found: {}", sign_key_path.display());
    }

    // Clean onion address (remove port if present)
    let onion_clean = onion.split(':').next().unwrap_or(onion).to_string();

    // Load config fresh, modify, and save
    let mut config = ChatConfig2::load()?;
    config.contacts.insert(
        name.to_string(),
        ChatContact {
            onion_address: onion_clean,
            public_key: key_path,
            signing_key: sign_key_path,
        },
    );
    config.save()?;

    Ok(())
}

/// Truncate an onion address for display.
fn truncate_onion(onion: &str) -> String {
    if onion.len() <= 20 {
        onion.to_string()
    } else {
        format!("{}...{}", &onion[..8], &onion[onion.len()-8..])
    }
}

/// List all chat contacts.
fn list_contacts() -> Result<()> {
    let config = ChatConfig2::load()?;

    if config.contacts.is_empty() {
        println!("No chat contacts configured.");
        println!("Use 'anyhide chat add <name> <onion> --key <path> --sign-key <path>' to add one.");
        return Ok(());
    }

    println!("Chat contacts:");
    for (name, contact) in &config.contacts {
        println!("  {} - {}", name, contact.onion_address);
    }

    Ok(())
}

/// Show contact details (or your own identity if name is "me").
fn show_contact(name: &str) -> Result<()> {
    let config = ChatConfig2::load()?;

    // Show own identity if "me"
    if name == "me" {
        let identity = config
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Identity not initialized. Run 'anyhide chat init' first."))?;

        println!("Your identity:");
        println!("  Nickname: {}", identity.nickname);
        if let Some(ref onion) = config.my_onion {
            println!("  Onion address: {}", onion);
        } else {
            println!("  Onion address: (not generated yet - run 'anyhide chat init')");
        }
        println!("  Encryption key: {}.key", identity.key_path.display());
        println!("  Signing key: {}.sign.key", identity.sign_key_path.display());
        println!();
        println!("Share with contacts:");
        println!("  - Onion: {}", config.my_onion.as_deref().unwrap_or("(not generated)"));
        println!("  - Public key: {}.pub", identity.key_path.display());
        println!("  - Signing key: {}.sign.pub", identity.sign_key_path.display());
        return Ok(());
    }

    let contact = config
        .contacts
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found. Use 'anyhide chat show me' to see your own identity.", name))?;

    println!("Contact: {}", name);
    println!("  Onion address: {}", contact.onion_address);
    println!("  Public key: {}", contact.public_key.display());
    println!("  Signing key: {}", contact.signing_key.display());

    Ok(())
}

/// Remove a chat contact.
fn remove_contact(name: &str) -> Result<()> {
    let mut config = ChatConfig2::load()?;

    if config.contacts.remove(name).is_none() {
        bail!("Contact '{}' not found", name);
    }

    config.save()?;
    println!("Contact '{}' removed.", name);

    Ok(())
}

// =============================================================================
// QR Code Identity Export/Import
// =============================================================================

/// Chat identity QR format version.
const CHAT_QR_VERSION: u8 = 0x01;

/// Magic bytes to identify Anyhide chat identity QR codes.
const CHAT_QR_MAGIC: &[u8] = b"AHID"; // Anyhide ID

/// Encode chat identity to binary format for QR.
/// Format: [magic:4][version:1][onion:56][enc_key:32][sign_key:32][nick_len:1][nick:0-63]
fn encode_chat_identity(
    onion: &str,
    enc_pubkey: &[u8; 32],
    sign_pubkey: &[u8; 32],
    nickname: &str,
) -> Result<Vec<u8>> {
    let mut data = Vec::with_capacity(128);

    // Magic bytes
    data.extend_from_slice(CHAT_QR_MAGIC);

    // Version
    data.push(CHAT_QR_VERSION);

    // Onion address (56 bytes without ".onion")
    let onion_clean = onion.trim_end_matches(".onion");
    if onion_clean.len() != 56 {
        bail!("Invalid onion address length: {} (expected 56)", onion_clean.len());
    }
    data.extend_from_slice(onion_clean.as_bytes());

    // Encryption public key (32 bytes)
    data.extend_from_slice(enc_pubkey);

    // Signing public key (32 bytes)
    data.extend_from_slice(sign_pubkey);

    // Nickname (length byte + UTF-8 string, max 63 bytes)
    let nick_bytes = nickname.as_bytes();
    if nick_bytes.len() > 63 {
        bail!("Nickname too long: {} bytes (max 63)", nick_bytes.len());
    }
    data.push(nick_bytes.len() as u8);
    data.extend_from_slice(nick_bytes);

    Ok(data)
}

/// Decode chat identity from binary format.
/// Returns (onion, enc_pubkey, sign_pubkey, nickname).
fn decode_chat_identity(data: &[u8]) -> Result<(String, [u8; 32], [u8; 32], String)> {
    // Minimum size: magic(4) + version(1) + onion(56) + enc_key(32) + sign_key(32) + nick_len(1) = 126
    if data.len() < 126 {
        bail!("Invalid QR data: too short ({} bytes, min 126)", data.len());
    }

    let mut pos = 0;

    // Check magic
    if &data[pos..pos + 4] != CHAT_QR_MAGIC {
        bail!("Invalid QR: not an Anyhide chat identity (wrong magic bytes)");
    }
    pos += 4;

    // Check version
    let version = data[pos];
    if version != CHAT_QR_VERSION {
        bail!("Unsupported QR version: {} (expected {})", version, CHAT_QR_VERSION);
    }
    pos += 1;

    // Onion address (56 bytes)
    let onion_bytes = &data[pos..pos + 56];
    let onion = String::from_utf8(onion_bytes.to_vec())
        .context("Invalid onion address encoding")?;
    let onion_full = format!("{}.onion", onion);
    pos += 56;

    // Encryption public key (32 bytes)
    let mut enc_pubkey = [0u8; 32];
    enc_pubkey.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    // Signing public key (32 bytes)
    let mut sign_pubkey = [0u8; 32];
    sign_pubkey.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    // Nickname
    let nick_len = data[pos] as usize;
    pos += 1;

    if pos + nick_len > data.len() {
        bail!("Invalid QR data: nickname truncated");
    }
    let nickname = String::from_utf8(data[pos..pos + nick_len].to_vec())
        .context("Invalid nickname encoding")?;

    Ok((onion_full, enc_pubkey, sign_pubkey, nickname))
}

/// Export your chat identity to a QR code.
fn export_qr_identity(output: &PathBuf, format: &str) -> Result<()> {
    let config = ChatConfig2::load()?;

    // Check identity exists
    let identity = config
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Chat identity not initialized. Run 'anyhide chat init' first."))?;

    // Get onion address
    let onion = config
        .my_onion
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Onion address not generated. Run 'anyhide chat init' first."))?;

    // Load public keys
    let enc_pub_path = PathBuf::from(format!("{}.pub", identity.key_path.display()));
    let sign_pub_path = PathBuf::from(format!("{}.sign.pub", identity.sign_key_path.display()));

    let enc_pubkey = load_public_key(&enc_pub_path)
        .with_context(|| format!("Failed to load encryption public key from {}", enc_pub_path.display()))?;

    let sign_pubkey = load_verifying_key(&sign_pub_path)
        .with_context(|| format!("Failed to load signing public key from {}", sign_pub_path.display()))?;

    // Encode to binary
    let enc_pubkey_bytes: [u8; 32] = enc_pubkey.to_bytes();
    let sign_pubkey_bytes: [u8; 32] = sign_pubkey.to_bytes();

    let data = encode_chat_identity(onion, &enc_pubkey_bytes, &sign_pubkey_bytes, &identity.nickname)?;

    // Generate QR code
    let qr_format = match format.to_lowercase().as_str() {
        "png" => QrFormat::Png,
        "svg" => QrFormat::Svg,
        "ascii" | "txt" => QrFormat::Ascii,
        _ => bail!("Unknown QR format: {}. Use: png, svg, or ascii", format),
    };

    let qr_config = QrConfig {
        format: qr_format,
        ..Default::default()
    };

    generate_qr_to_file(&data, output, &qr_config)
        .context("Failed to generate QR code")?;

    println!("Chat identity QR exported to: {}", output.display());
    println!();
    println!("Identity info:");
    println!("  Nickname: {}", identity.nickname);
    println!("  Onion: {}", onion);
    println!();
    println!("Share this QR code with your contacts.");
    println!("They can import it with: anyhide chat import-qr <image> -n <name>");

    Ok(())
}

/// Import a chat contact from a QR code.
fn import_qr_contact(image: &PathBuf, name: &str) -> Result<()> {
    // Read QR code
    let data = read_qr_from_file(image)
        .with_context(|| format!("Failed to read QR code from {}", image.display()))?;

    // Decode identity
    let (onion, enc_pubkey, sign_pubkey, nickname) = decode_chat_identity(&data)
        .context("Failed to decode chat identity from QR")?;

    // Create temporary key files
    let config_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
        .join("anyhide")
        .join("contacts");

    fs::create_dir_all(&config_dir)?;

    // Save public keys
    let enc_key_path = config_dir.join(format!("{}.pub", name));
    let sign_key_path = config_dir.join(format!("{}.sign.pub", name));

    // Write encryption public key as PEM
    let enc_pem = format!(
        "-----BEGIN ANYHIDE PUBLIC KEY-----\n{}\n-----END ANYHIDE PUBLIC KEY-----\n",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &enc_pubkey)
    );
    fs::write(&enc_key_path, &enc_pem)
        .with_context(|| format!("Failed to write {}", enc_key_path.display()))?;

    // Write signing public key as PEM
    let sign_pem = format!(
        "-----BEGIN ANYHIDE SIGNING PUBLIC KEY-----\n{}\n-----END ANYHIDE SIGNING PUBLIC KEY-----\n",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &sign_pubkey)
    );
    fs::write(&sign_key_path, &sign_pem)
        .with_context(|| format!("Failed to write {}", sign_key_path.display()))?;

    // Add contact to config
    let mut config = ChatConfig2::load()?;

    if config.contacts.contains_key(name) {
        bail!("Contact '{}' already exists. Remove it first with 'anyhide chat remove {}'", name, name);
    }

    config.contacts.insert(
        name.to_string(),
        ChatContact {
            onion_address: onion.clone(),
            public_key: enc_key_path.clone(),
            signing_key: sign_key_path.clone(),
        },
    );

    config.save()?;

    println!("Contact '{}' imported from QR code.", name);
    println!();
    println!("Contact info:");
    println!("  Original nickname: {}", nickname);
    println!("  Onion address: {}", onion);
    println!("  Encryption key: {}", enc_key_path.display());
    println!("  Signing key: {}", sign_key_path.display());
    println!();
    println!("Start chatting with: anyhide chat {}", name);

    Ok(())
}

/// Show your own chat identity.
fn show_my_identity() -> Result<()> {
    let config = ChatConfig2::load()?;

    let identity = config
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Chat identity not initialized. Run 'anyhide chat init' first."))?;

    println!("Your chat identity:");
    println!();
    println!("  Nickname: {}", identity.nickname);
    if let Some(ref onion) = config.my_onion {
        println!("  Onion address: {}", onion);
    } else {
        println!("  Onion address: (not generated yet)");
    }
    println!();
    println!("  Encryption key: {}.key / {}.pub", identity.key_path.display(), identity.key_path.display());
    println!("  Signing key: {}.sign.key / {}.sign.pub", identity.sign_key_path.display(), identity.sign_key_path.display());
    println!();
    println!("Share with contacts:");
    if let Some(ref onion) = config.my_onion {
        println!("  anyhide chat export-qr -o my-identity.png");
        println!("  Or manually share: {} + public keys", onion);
    } else {
        println!("  Run 'anyhide chat init' first to generate your .onion address");
    }

    Ok(())
}

/// Load carriers from files for pre-shared mode.
fn load_preshared_carriers(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    let mut carriers = Vec::with_capacity(paths.len());
    for path in paths {
        let data = std::fs::read(path)
            .with_context(|| format!("Failed to read carrier file: {}", path.display()))?;
        if data.len() < anyhide::chat::MIN_CARRIER_SIZE {
            bail!(
                "Carrier file too small: {} ({} bytes, minimum {} required)",
                path.display(),
                data.len(),
                anyhide::chat::MIN_CARRIER_SIZE
            );
        }
        carriers.push(data);
    }
    Ok(carriers)
}

/// Start a chat session with a contact.
async fn start_chat(
    contact_name: &str,
    carriers_count: usize,
    carrier_size: usize,
    carrier_files: Option<&[PathBuf]>,
    profile: Option<&str>,
) -> Result<()> {
    // Load configuration
    let config = ChatConfig2::load()?;

    // Verify identity is initialized
    let identity = config
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Chat identity not initialized. Run 'anyhide chat init' first."))?;

    // Get contact
    let contact = config
        .contacts
        .get(contact_name)
        .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found. Use 'anyhide chat add' first.", contact_name))?;

    // Prompt for passphrase FIRST
    let passphrase = prompt_passphrase("Passphrase: ")?;
    if passphrase.is_empty() {
        bail!("Passphrase cannot be empty");
    }

    // Print security warning
    print_tor_warning();

    // Load our keys
    let my_signing_keypair = SigningKeyPair::load_from_files(&identity.sign_key_path)
        .context("Failed to load signing key pair")?;

    // Load their keys
    let their_verifying_key = load_verifying_key(&contact.signing_key)
        .context("Failed to load contact's signing key")?;

    // Bootstrap Tor client
    print_bootstrap_message();
    let tor_client = AnyhideTorClient::with_profile(profile)
        .await
        .context("Failed to bootstrap Tor client")?;

    // Create our hidden service
    println!("Creating hidden service '{}'...", identity.nickname);
    let mut my_listener = tor_client
        .listen(&identity.nickname)
        .await
        .context("Failed to create hidden service")?;

    let my_onion = my_listener.onion_addr().to_string();
    println!();
    println!("Your .onion address: {}", my_onion);
    println!();

    // Prepare peer address
    let peer_addr = format!("{}:{}", contact.onion_address, CHAT_PORT);

    // Load pre-shared carriers if specified
    let (preshared_carriers, chat_config) = if let Some(paths) = carrier_files {
        println!("Loading {} pre-shared carrier file(s)...", paths.len());
        let carriers = load_preshared_carriers(paths)?;
        let hash = hash_carriers(&carriers);
        println!("Carrier hash: {}", hex::encode(&hash[..8]));
        (Some(carriers), ChatConfig::with_preshared_carriers(hash))
    } else {
        let mut config = ChatConfig::default();
        config.carriers_per_party = carriers_count;
        config.carrier_size = carrier_size;
        (None, config)
    };

    // Deterministic role selection to avoid crossed-wires when both connect simultaneously
    // The peer with the "higher" onion address is the initiator (connects first)
    // The peer with the "lower" onion address is the responder (accepts first)
    let i_am_initiator = my_onion > contact.onion_address;
    if i_am_initiator {
        println!("Role: initiator (will try to connect)");
    } else {
        println!("Role: responder (will wait for connection)");
    }

    // Connection + handshake loop with retries (Tor can be flaky)
    let (mut session, mut conn) = loop {
        println!("Looking for {}...", contact_name);

        // Role-based connection strategy to avoid crossed-wires
        let connection_result = if i_am_initiator {
            // I'm initiator: try to connect first, but also accept if they connect to me
            tokio::select! {
                biased;
                // Try to connect to their hidden service (priority)
                result = tor_client.connect(&peer_addr) => {
                    match result {
                        Ok(conn) => {
                            println!("Connected to {}!", contact_name);
                            Some((conn, true))
                        }
                        Err(e) => {
                            eprintln!("{} not available: {}", contact_name, e);
                            None
                        }
                    }
                }
                // Accept incoming connection (fallback)
                result = my_listener.accept() => {
                    match result {
                        Ok(conn) => {
                            println!("{} connected!", contact_name);
                            Some((conn, false))
                        }
                        Err(e) => {
                            eprintln!("Accept error: {}", e);
                            None
                        }
                    }
                }
            }
        } else {
            // I'm responder: wait for incoming connection, with connect as fallback
            tokio::select! {
                biased;
                // Accept incoming connection (priority)
                result = my_listener.accept() => {
                    match result {
                        Ok(conn) => {
                            println!("{} connected!", contact_name);
                            Some((conn, false))
                        }
                        Err(e) => {
                            eprintln!("Accept error: {}", e);
                            None
                        }
                    }
                }
                // Try to connect as fallback (in case they're slow)
                result = tor_client.connect(&peer_addr) => {
                    match result {
                        Ok(conn) => {
                            println!("Connected to {}!", contact_name);
                            Some((conn, true))
                        }
                        Err(e) => {
                            eprintln!("{} not available: {}", contact_name, e);
                            None
                        }
                    }
                }
            }
        };

        let (mut conn, is_initiator) = match connection_result {
            Some(c) => c,
            None => {
                let delay = retry_delay_with_jitter();
                println!("Retrying in {} seconds... (Ctrl+C to cancel)", delay.as_secs());
                tokio::time::sleep(delay).await;
                continue;
            }
        };

        // Generate ephemeral key for this session
        let my_eph_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let my_eph_public = PublicKey::from(&my_eph_secret);

        // Perform handshake based on role
        // This is a known contact (from contacts list)
        let i_know_them = true;
        println!("Performing handshake...");
        let handshake_result = if is_initiator {
            perform_initiator_handshake(
                &mut conn,
                my_eph_secret,
                my_eph_public,
                &my_signing_keypair,
                their_verifying_key.clone(),
                chat_config.clone(),
                preshared_carriers.as_deref(),
                &passphrase,
                i_know_them,
            )
            .await
        } else {
            perform_responder_handshake(
                &mut conn,
                my_eph_secret,
                my_eph_public,
                &my_signing_keypair,
                their_verifying_key.clone(),
                chat_config.clone(),
                preshared_carriers.as_deref(),
                &passphrase,
                i_know_them,
            )
            .await
        };

        match handshake_result {
            Ok(s) => break (s, conn),
            Err(e) => {
                eprintln!("Handshake failed: {}", e);
                let delay = retry_delay_with_jitter();
                println!("Retrying in {} seconds... (Ctrl+C to cancel)", delay.as_secs());
                tokio::time::sleep(delay).await;
                continue;
            }
        }
    };

    // Chat loop with TUI
    run_chat_loop(&mut session, &mut conn, contact_name, &my_onion).await
}

/// Perform handshake as initiator (the one who connected).
async fn perform_initiator_handshake<T: MessageTransport>(
    conn: &mut T,
    my_eph_secret: StaticSecret,
    my_eph_public: PublicKey,
    my_signing_keypair: &SigningKeyPair,
    their_verifying_key: ed25519_dalek::VerifyingKey,
    config: ChatConfig,
    preshared_carriers: Option<&[Vec<u8>]>,
    user_passphrase: &str,
    i_know_them: bool,
) -> Result<ChatSession> {
    // Create and sign init (including i_know_you flag)
    let init_signed_data = {
        let mut data = Vec::new();
        data.push(1u8); // version
        data.extend_from_slice(my_eph_public.as_bytes());
        data.extend_from_slice(&my_signing_keypair.verifying_key().to_bytes());
        data.extend_from_slice(&bincode::serialize(&config).unwrap());
        data.push(if i_know_them { 1 } else { 0 }); // i_know_you flag
        data
    };
    let init_signature = my_signing_keypair.sign(&init_signed_data);

    let init = HandshakeInit::new(
        *my_eph_public.as_bytes(),
        my_signing_keypair.verifying_key().to_bytes(),
        config.clone(),
        i_know_them,
        init_signature.to_vec(),
    );

    // Send init
    let init_bytes = init.to_bytes()?;
    let init_wire = WireMessage::new(
        1,
        [0u8; 12],
        vec![],
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &init_bytes),
    );
    conn.send(&init_wire).await.context("Failed to send handshake")?;

    // Receive response
    let response_wire = conn.receive().await.context("Failed to receive handshake response")?;
    let response_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &response_wire.anyhide_code)
        .context("Failed to decode handshake response")?;
    let response = HandshakeResponse::from_bytes(&response_bytes)
        .context("Failed to parse handshake response")?;

    // Get their ephemeral public key
    let their_eph_public = PublicKey::from(response.ephemeral_public);

    // Negotiate config
    let agreed_config = config.negotiate(&response.config)
        .context("Carrier mode mismatch - both parties must use same mode (random or pre-shared with matching files)")?;

    // Handle carriers based on mode
    let (my_carriers, their_carriers) = if agreed_config.is_preshared() {
        // Pre-shared mode: use the same carriers for both parties
        let carriers = preshared_carriers
            .ok_or_else(|| anyhow::anyhow!("Pre-shared carriers required but not provided"))?
            .to_vec();

        // In pre-shared mode, both parties use the same carriers
        // We still need to send a complete message for protocol consistency
        let carrier_hash = hash_carriers(&carriers);
        let complete_signature = my_signing_keypair.sign(&carrier_hash);
        let complete = HandshakeComplete::new(vec![], complete_signature.to_vec());

        let complete_bytes = complete.to_bytes()?;
        let complete_wire = WireMessage::new(
            1,
            [0u8; 12],
            vec![],
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &complete_bytes),
        );
        conn.send(&complete_wire).await.context("Failed to send handshake complete")?;

        (carriers.clone(), carriers)
    } else {
        // Random mode: exchange carriers
        let mut carrier_enc_key = [0u8; 32];
        use hkdf::Hkdf;
        use sha2::Sha256;
        let temp_shared = my_eph_secret.diffie_hellman(&their_eph_public);
        let hk = Hkdf::<Sha256>::new(None, temp_shared.as_bytes());
        hk.expand(b"ANYHIDE-CHAT-CARRIER-ENC", &mut carrier_enc_key)
            .expect("32 bytes is valid");

        // Decrypt their carriers
        let their_carriers = decrypt_carriers(&response.encrypted_carriers, &carrier_enc_key)
            .context("Failed to decrypt peer carriers")?;

        // Generate and encrypt our carriers
        let my_carriers = generate_carriers(agreed_config.carriers_per_party, agreed_config.carrier_size);
        let encrypted_carriers = encrypt_carriers(&my_carriers, &carrier_enc_key)
            .context("Failed to encrypt carriers")?;

        // Sign complete
        let carrier_hash = hash_carriers(&my_carriers);
        let complete_signature = my_signing_keypair.sign(&carrier_hash);
        let complete = HandshakeComplete::new(encrypted_carriers, complete_signature.to_vec());

        // Send complete
        let complete_bytes = complete.to_bytes()?;
        let complete_wire = WireMessage::new(
            1,
            [0u8; 12],
            vec![],
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &complete_bytes),
        );
        conn.send(&complete_wire).await.context("Failed to send handshake complete")?;

        (my_carriers, their_carriers)
    };

    // Determine mutual recognition for passphrase logic
    // Passphrase is ONLY used if BOTH parties know each other
    let they_know_us = response.i_know_you;
    let mutual_recognition = i_know_them && they_know_us;
    let effective_passphrase = if mutual_recognition { user_passphrase } else { "" };

    // Create session (we are initiator)
    ChatSession::init_as_initiator(
        my_eph_secret,
        my_signing_keypair.signing_key(),
        their_eph_public,
        their_verifying_key,
        my_carriers,
        their_carriers,
        agreed_config,
        effective_passphrase,
    )
    .context("Failed to initialize session")
}

/// Perform handshake as responder (the one who accepted connection).
async fn perform_responder_handshake<T: MessageTransport>(
    conn: &mut T,
    my_eph_secret: StaticSecret,
    my_eph_public: PublicKey,
    my_signing_keypair: &SigningKeyPair,
    their_verifying_key: ed25519_dalek::VerifyingKey,
    proposed_config: ChatConfig,
    preshared_carriers: Option<&[Vec<u8>]>,
    user_passphrase: &str,
    i_know_them: bool,
) -> Result<ChatSession> {
    // Receive HandshakeInit
    let init_wire = conn.receive().await.context("Failed to receive handshake")?;
    let init_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &init_wire.anyhide_code)
        .context("Failed to decode handshake")?;
    let init = HandshakeInit::from_bytes(&init_bytes).context("Failed to parse handshake")?;

    // Verify their signature
    let their_init_verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&init.identity_public)
        .context("Invalid identity public key")?;
    let init_signed_data = init.signed_data();
    let init_signature = ed25519_dalek::Signature::from_slice(&init.signature)
        .context("Invalid signature format")?;
    their_init_verifying_key
        .verify_strict(&init_signed_data, &init_signature)
        .context("Handshake signature verification failed")?;

    // Negotiate config
    let agreed_config = proposed_config.negotiate(&init.config)
        .context("Carrier mode mismatch - both parties must use same mode (random or pre-shared with matching files)")?;

    let their_eph_public = PublicKey::from(init.ephemeral_public);

    // Handle carriers based on mode
    let (my_carriers, their_carriers) = if agreed_config.is_preshared() {
        // Pre-shared mode: use the same carriers for both parties
        let carriers = preshared_carriers
            .ok_or_else(|| anyhow::anyhow!("Pre-shared carriers required but not provided"))?
            .to_vec();

        // Sign response with carrier hash (including i_know_you flag)
        let carrier_hash = hash_carriers(&carriers);
        let response_data = {
            let mut data = Vec::new();
            data.push(1u8); // version
            data.extend_from_slice(my_eph_public.as_bytes());
            data.extend_from_slice(&my_signing_keypair.verifying_key().to_bytes());
            data.extend_from_slice(&bincode::serialize(&agreed_config).unwrap());
            data.push(if i_know_them { 1 } else { 0 }); // i_know_you flag
            data.extend_from_slice(&carrier_hash);
            data
        };
        let response_signature = my_signing_keypair.sign(&response_data);

        // Send response (empty encrypted_carriers in preshared mode)
        let response = HandshakeResponse::new(
            *my_eph_public.as_bytes(),
            my_signing_keypair.verifying_key().to_bytes(),
            agreed_config.clone(),
            i_know_them,
            vec![],
            response_signature.to_vec(),
        );

        let response_bytes = response.to_bytes()?;
        let response_wire = WireMessage::new(
            1,
            [0u8; 12],
            vec![],
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &response_bytes),
        );
        conn.send(&response_wire).await.context("Failed to send handshake response")?;

        // Receive HandshakeComplete (for protocol consistency)
        let _complete_wire = conn.receive().await.context("Failed to receive handshake complete")?;

        (carriers.clone(), carriers)
    } else {
        // Random mode: generate and exchange carriers
        let my_carriers = generate_carriers(agreed_config.carriers_per_party, agreed_config.carrier_size);

        // Derive carrier encryption key
        let temp_shared = my_eph_secret.diffie_hellman(&their_eph_public);
        let mut carrier_enc_key = [0u8; 32];
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(None, temp_shared.as_bytes());
        hk.expand(b"ANYHIDE-CHAT-CARRIER-ENC", &mut carrier_enc_key)
            .expect("32 bytes is valid");

        // Encrypt our carriers
        let encrypted_carriers = encrypt_carriers(&my_carriers, &carrier_enc_key)
            .context("Failed to encrypt carriers")?;

        // Create and sign response (including i_know_you flag)
        let carrier_hash = hash_carriers(&my_carriers);
        let response_data = {
            let mut data = Vec::new();
            data.push(1u8); // version
            data.extend_from_slice(my_eph_public.as_bytes());
            data.extend_from_slice(&my_signing_keypair.verifying_key().to_bytes());
            data.extend_from_slice(&bincode::serialize(&agreed_config).unwrap());
            data.push(if i_know_them { 1 } else { 0 }); // i_know_you flag
            data.extend_from_slice(&carrier_hash);
            data
        };
        let response_signature = my_signing_keypair.sign(&response_data);

        let response = HandshakeResponse::new(
            *my_eph_public.as_bytes(),
            my_signing_keypair.verifying_key().to_bytes(),
            agreed_config.clone(),
            i_know_them,
            encrypted_carriers,
            response_signature.to_vec(),
        );

        // Send response
        let response_bytes = response.to_bytes()?;
        let response_wire = WireMessage::new(
            1,
            [0u8; 12],
            vec![],
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &response_bytes),
        );
        conn.send(&response_wire).await.context("Failed to send handshake response")?;

        // Receive HandshakeComplete
        let complete_wire = conn.receive().await.context("Failed to receive handshake complete")?;
        let complete_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &complete_wire.anyhide_code)
            .context("Failed to decode handshake complete")?;
        let complete = HandshakeComplete::from_bytes(&complete_bytes)
            .context("Failed to parse handshake complete")?;

        // Decrypt their carriers
        let their_carriers = decrypt_carriers(&complete.encrypted_carriers, &carrier_enc_key)
            .context("Failed to decrypt peer carriers")?;

        (my_carriers, their_carriers)
    };

    // Determine mutual recognition for passphrase logic
    // Passphrase is ONLY used if BOTH parties know each other
    let they_know_us = init.i_know_you;
    let mutual_recognition = i_know_them && they_know_us;
    let effective_passphrase = if mutual_recognition { user_passphrase } else { "" };

    // Create session (we are responder)
    ChatSession::init_as_responder(
        my_eph_secret,
        my_signing_keypair.signing_key(),
        their_eph_public,
        their_verifying_key,
        my_carriers,
        their_carriers,
        agreed_config,
        effective_passphrase,
    )
    .context("Failed to initialize session")
}

/// Run the interactive chat loop with TUI.
async fn run_chat_loop<T: MessageTransport>(
    session: &mut ChatSession,
    conn: &mut T,
    contact_name: &str,
    my_onion: &str,
) -> Result<()> {
    // Initialize terminal
    let mut terminal = init_terminal()
        .map_err(|e| anyhow::anyhow!("Failed to initialize terminal: {}", e))?;

    // Create app state with session's max message length
    let mut app = App::with_max_len(contact_name, session.config().max_message_len);
    app.set_status(ConnectionStatus::Connected);
    app.set_my_onion(my_onion);
    app.add_system_message(format!("Connected to {}", contact_name));
    app.add_system_message("Type /help for commands. Ctrl+C to quit.");

    // Setup event handler
    let mut events = EventHandler::new();
    let event_tx = events.sender();
    EventHandler::spawn_reader(event_tx, Duration::from_millis(100));

    // Main loop
    let result = run_tui_loop(&mut terminal, &mut app, &mut events, session, conn).await;

    // Restore terminal
    restore_terminal(&mut terminal)
        .map_err(|e| anyhow::anyhow!("Failed to restore terminal: {}", e))?;

    result
}

/// Inner TUI loop.
async fn run_tui_loop<T: MessageTransport>(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>,
    app: &mut App,
    events: &mut EventHandler,
    session: &mut ChatSession,
    conn: &mut T,
) -> Result<()> {
    loop {
        // Draw UI
        terminal.draw(|frame| render(frame, app))?;

        // Handle events
        tokio::select! {
            // Terminal event (keyboard, resize, etc)
            event = events.next() => {
                match event {
                    Some(Event::Key(key)) => {
                        let action = handle_key_event(app, key);
                        match action {
                            KeyAction::Quit => {
                                app.add_system_message("Disconnecting...");
                                let _ = conn.close().await;
                                return Ok(());
                            }
                            KeyAction::SendMessage => {
                                let input = app.take_input();

                                // Check for commands
                                if input.starts_with('/') {
                                    let cmd_action = handle_command(app, &input);
                                    if cmd_action == KeyAction::Quit {
                                        app.add_system_message("Disconnecting...");
                                        let _ = conn.close().await;
                                        return Ok(());
                                    }
                                } else {
                                    // Send as chat message
                                    match session.send_message(&input) {
                                        Ok(wire) => {
                                            if let Err(e) = conn.send(&wire).await {
                                                app.add_system_message(format!("Send failed: {}", e));
                                            } else {
                                                app.add_my_message(&input);
                                            }
                                        }
                                        Err(e) => {
                                            app.add_system_message(format!("Encode failed: {}", e));
                                        }
                                    }
                                }
                            }
                            KeyAction::None => {}
                        }
                    }
                    Some(Event::Resize(_, _)) => {
                        // Terminal will redraw on next iteration
                    }
                    Some(Event::Tick) => {
                        // Periodic tick - no action needed
                    }
                    Some(Event::Mouse(_)) => {
                        // Ignore mouse events for now
                    }
                    None => {
                        // Event channel closed
                        return Ok(());
                    }
                }

                if app.should_quit {
                    let _ = conn.close().await;
                    return Ok(());
                }
            }

            // Incoming message from peer
            result = conn.receive() => {
                match result {
                    Ok(wire) => {
                        match session.receive_message(&wire) {
                            Ok(msg) => {
                                app.add_peer_message(&msg);
                            }
                            Err(e) => {
                                app.add_system_message(format!("Decode error: {}", e));
                            }
                        }
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("end of file")
                            || err_str.contains("connection")
                            || err_str.contains("Connection reset")
                        {
                            app.add_system_message(format!("{} disconnected.", app.peer_name));
                            app.set_status(ConnectionStatus::Disconnected);
                            // Wait for user to acknowledge
                            while !app.should_quit {
                                terminal.draw(|frame| render(frame, app))?;
                                if let Some(Event::Key(key)) = events.next().await {
                                    let action = handle_key_event(app, key);
                                    if action == KeyAction::Quit {
                                        break;
                                    }
                                }
                            }
                            return Ok(());
                        }
                        app.add_system_message(format!("Receive error: {}", e));
                    }
                }
            }
        }
    }
}

/// Start multi-contact chat TUI (dashboard mode).
/// This is the main entry point when no specific contact is provided.
async fn start_multi_chat(profile: Option<&str>) -> Result<()> {
    // Load configuration
    let config = ChatConfig2::load()?;

    // Verify identity is initialized
    let identity = config
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Chat identity not initialized. Run 'anyhide chat init' first."))?;

    // Note: Passphrase is now per-contact, prompted via dialog when connecting

    // Print security warning
    print_tor_warning();

    // Bootstrap Tor client
    print_bootstrap_message();
    let tor_client = AnyhideTorClient::with_profile(profile)
        .await
        .context("Failed to bootstrap Tor client")?;

    // Create our hidden service
    println!("Creating hidden service '{}'...", identity.nickname);
    let mut my_listener = tor_client
        .listen(&identity.nickname)
        .await
        .context("Failed to create hidden service")?;

    let my_onion = my_listener.onion_addr().to_string();
    println!();
    println!("Your .onion address: {}", my_onion);
    println!();

    // Initialize terminal
    let mut terminal = init_terminal()
        .map_err(|e| anyhow::anyhow!("Failed to initialize terminal: {}", e))?;

    // Create multi-app state
    let mut app = MultiApp::new();
    app.tor_status = ConnectionStatus::Connected;
    app.chat_status = anyhide::chat::tui::ChatServiceStatus::Starting; // Will become Ready when HS is published
    app.my_onion = Some(my_onion.clone());

    // Load contacts from config
    for (name, contact) in &config.contacts {
        let mut ui_contact = Contact::with_onion(name, &contact.onion_address);
        ui_contact.status = ContactStatus::Offline;
        app.add_contact(ui_contact);
    }

    // Setup event handler
    let mut events = EventHandler::new();
    let event_tx = events.sender();
    EventHandler::spawn_reader(event_tx, Duration::from_millis(100));

    // Add welcome message as notification
    app.add_notification(
        anyhide::chat::tui::NotificationKind::Info,
        format!(
            "Listening on {}. Select a contact to connect.",
            &my_onion[..20.min(my_onion.len())]
        ),
    );

    // Add important warning about Arti
    app.add_notification(
        anyhide::chat::tui::NotificationKind::Info,
        "Note: Hidden service may take 1-2 minutes to be reachable on the network.",
    );

    // Get a handle for status checking before moving listener to task
    let hs_handle = my_listener.handle();

    // Create channel for incoming connections from listener task
    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel::<
        Result<anyhide::chat::transport::TorConnection, anyhide::chat::ChatError>,
    >(16);

    // Spawn dedicated listener task that won't be cancelled by select!
    let _listener_task = tokio::spawn(async move {
        loop {
            let result = my_listener.accept().await;
            // Send result to main loop - if channel is closed, exit
            if incoming_tx.send(result).await.is_err() {
                break;
            }
        }
    });

    // Main loop
    let result = run_multi_tui_loop(
        &mut terminal,
        &mut app,
        &mut events,
        incoming_rx,
        &hs_handle,
        &tor_client,
        &config,
    ).await;

    // Restore terminal
    restore_terminal(&mut terminal)
        .map_err(|e| anyhow::anyhow!("Failed to restore terminal: {}", e))?;

    result
}

/// Pending connection waiting for handshake.
struct PendingConnection {
    /// Onion address of the peer (may be "tor-client" if not identified).
    onion_address: String,
    /// Resolved contact name (if found by signing key).
    resolved_name: Option<String>,
    /// The Tor connection.
    connection: anyhide::chat::transport::TorConnection,
    /// Pre-received HandshakeInit (read early to identify sender).
    handshake_init: HandshakeInit,
}

/// Active chat session with a peer.
#[allow(dead_code)]
struct ActiveSession {
    /// Contact name.
    contact_name: String,
    /// The chat session.
    session: ChatSession,
    /// The Tor connection.
    connection: anyhide::chat::transport::TorConnection,
}

/// Result of a background connection task.
#[allow(dead_code)]
enum ConnectionTaskResult {
    /// Outgoing connection (we initiated).
    Outgoing {
        contact_name: String,
        result: Result<(ChatSession, anyhide::chat::transport::TorConnection)>,
    },
    /// Incoming connection (we accepted).
    Incoming {
        /// Display name used in UI (may be updated after handshake).
        contact_name: String,
        /// Peer's onion address.
        onion_address: String,
        /// Result includes session, connection, and resolved contact name (if found by signing key).
        result: Result<(ChatSession, anyhide::chat::transport::TorConnection, Option<String>)>,
    },
}

/// Multi-contact TUI loop (dashboard mode).
/// Handles multiple concurrent chat sessions.
async fn run_multi_tui_loop(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>,
    app: &mut MultiApp,
    events: &mut EventHandler,
    mut incoming_rx: tokio::sync::mpsc::Receiver<
        Result<anyhide::chat::transport::TorConnection, anyhide::chat::ChatError>,
    >,
    hs_handle: &anyhide::chat::transport::OnionServiceHandle,
    tor_client: &AnyhideTorClient,
    config: &ChatConfig2,
) -> Result<()> {
    use tokio::sync::mpsc;
    use std::time::Instant;

    // Pending incoming connections (waiting for accept)
    let mut pending_connections: Vec<PendingConnection> = Vec::new();

    // Active sessions (established)
    let mut active_sessions: HashMap<String, ActiveSession> = HashMap::new();

    // Channel for receiving connection task results
    let (conn_tx, mut conn_rx) = mpsc::channel::<ConnectionTaskResult>(16);

    // Track when we started listening (for uptime display)
    let start_time = Instant::now();
    let mut last_heartbeat = Instant::now();

    loop {
        // Draw UI
        terminal.draw(|frame| render_multi(frame, app))?;

        // Clear old notifications
        app.clear_old_notifications();

        // Handle events with timeout to allow checking multiple sources
        tokio::select! {
            biased;

            // Connection task completed
            Some(result) = conn_rx.recv() => {
                handle_connection_result(app, &mut active_sessions, result).await;
            }

            // Terminal event (keyboard, resize, etc)
            event = events.next() => {
                if let Some(event) = event {
                    let quit = handle_terminal_event(
                        app,
                        event,
                        &mut active_sessions,
                        &mut pending_connections,
                        tor_client,
                        config,
                        conn_tx.clone(),
                    ).await?;
                    if quit {
                        // Close all active sessions
                        for (_, mut session) in active_sessions.drain() {
                            let _ = session.connection.close().await;
                        }
                        return Ok(());
                    }
                }
            }

            // Incoming connection from listener (via channel from spawned task)
            Some(result) = incoming_rx.recv() => {
                match result {
                    Ok(mut conn) => {
                        // Read HandshakeInit immediately to identify who is connecting
                        match read_handshake_init(&mut conn).await {
                            Ok(init) => {
                                // Try to find the contact by their signing key
                                let resolved_name = config.find_contact_by_signing_key(&init.identity_public);

                                // Use resolved name for display, or generate from onion
                                let display_name = resolved_name.clone().unwrap_or_else(|| {
                                    // Unknown contact - show truncated key fingerprint
                                    format!("~unknown_{}", hex::encode(&init.identity_public[..4]))
                                });

                                // Add to pending and create notification with real name
                                app.add_chat_request_with_name(&display_name, resolved_name.is_some());
                                pending_connections.push(PendingConnection {
                                    onion_address: display_name.clone(),
                                    resolved_name,
                                    connection: conn,
                                    handshake_init: init,
                                });
                            }
                            Err(e) => {
                                app.set_status_message(format!("Failed to read handshake: {}", e));
                                let _ = conn.close().await;
                            }
                        }
                    }
                    Err(e) => {
                        app.set_status_message(format!("Accept error: {}", e));
                    }
                }
            }

            // Check for incoming messages from active sessions
            _ = check_active_sessions(&mut active_sessions, app) => {
                // Messages are added to conversations in check_active_sessions
            }
        }

        // Heartbeat: update status every 30 seconds (outside select to always run)
        if last_heartbeat.elapsed() >= Duration::from_secs(30) {
            let uptime = start_time.elapsed().as_secs();
            let mins = uptime / 60;
            let secs = uptime % 60;
            app.set_status_message(format!(
                "Listening... (uptime: {}m {}s, pending: {})",
                mins, secs, pending_connections.len()
            ));
            last_heartbeat = Instant::now();
        }

        // Update hidden service status based on actual Arti state
        use anyhide::chat::transport::OnionServiceState;
        let hs_state = hs_handle.state();
        let new_chat_status = match hs_state {
            OnionServiceState::Running | OnionServiceState::DegradedReachable => {
                anyhide::chat::tui::ChatServiceStatus::Ready
            }
            OnionServiceState::Bootstrapping => {
                anyhide::chat::tui::ChatServiceStatus::Starting
            }
            OnionServiceState::Shutdown
            | OnionServiceState::DegradedUnreachable
            | OnionServiceState::Recovering
            | OnionServiceState::Broken => anyhide::chat::tui::ChatServiceStatus::Error,
            // Non-exhaustive enum - treat unknown states as Starting
            _ => anyhide::chat::tui::ChatServiceStatus::Starting,
        };

        // Notify user when status changes from Starting to Ready
        if app.chat_status == anyhide::chat::tui::ChatServiceStatus::Starting
            && new_chat_status == anyhide::chat::tui::ChatServiceStatus::Ready
        {
            app.add_notification(
                anyhide::chat::tui::NotificationKind::Info,
                "Hidden service is now published and reachable!",
            );
        }
        app.chat_status = new_chat_status;

        if app.should_quit {
            // Close all active sessions
            for (_, mut session) in active_sessions.drain() {
                let _ = session.connection.close().await;
            }
            return Ok(());
        }
    }
}

/// Perform handshake when accepting an incoming connection.
/// The HandshakeInit has already been read to identify the sender.
/// Returns a ChatSession and the resolved contact name (if found in contacts).
async fn perform_accept_handshake(
    conn: &mut anyhide::chat::transport::TorConnection,
    config: &ChatConfig2,
    passphrase: &str,
    is_known_contact: bool,
    contact_name: Option<&str>,
    init: HandshakeInit, // Pre-received HandshakeInit
) -> Result<(ChatSession, Option<String>)> {
    // Load our identity
    let identity = config
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Chat identity not initialized"))?;

    // Load our signing keypair
    let my_signing_keypair = SigningKeyPair::load_from_files(&identity.sign_key_path)
        .context("Failed to load signing key pair")?;

    // Load their verifying key if this is a known contact
    let their_verifying_key = if is_known_contact {
        if let Some(name) = contact_name {
            if let Some(contact) = config.contacts.get(name) {
                Some(load_verifying_key(&contact.signing_key)
                    .context("Failed to load contact's signing key")?)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None // Unknown contact - will extract from handshake
    };

    // Generate ephemeral keys for this session
    let my_eph_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let my_eph_public = PublicKey::from(&my_eph_secret);

    // Default chat config (random carriers)
    let proposed_config = ChatConfig::default();

    // HandshakeInit already received - get their verifying key from it if not known
    let their_verifying_key = match their_verifying_key {
        Some(key) => {
            // Verify it matches the one in the handshake
            let handshake_key = ed25519_dalek::VerifyingKey::from_bytes(&init.identity_public)
                .context("Invalid identity public key in handshake")?;
            if key != handshake_key {
                bail!("Contact key mismatch! Expected key doesn't match handshake.");
            }
            key
        }
        None => {
            // Accept the key from handshake (unknown contact)
            ed25519_dalek::VerifyingKey::from_bytes(&init.identity_public)
                .context("Invalid identity public key")?
        }
    };

    // Verify their signature
    let init_signed_data = init.signed_data();
    let init_signature = ed25519_dalek::Signature::from_slice(&init.signature)
        .context("Invalid signature format")?;
    their_verifying_key
        .verify_strict(&init_signed_data, &init_signature)
        .context("Handshake signature verification failed")?;

    // Try to find the contact by their signing key if not already known
    let resolved_contact_name = if let Some(name) = contact_name {
        Some(name.to_string())
    } else {
        config.find_contact_by_signing_key(&init.identity_public)
    };

    // Negotiate config (always random carriers for multi-TUI for now)
    let agreed_config = proposed_config.negotiate(&init.config)
        .context("Carrier mode mismatch")?;

    let their_eph_public = PublicKey::from(init.ephemeral_public);

    // Generate and exchange carriers (random mode)
    let my_carriers = generate_carriers(agreed_config.carriers_per_party, agreed_config.carrier_size);

    // Derive carrier encryption key
    let temp_shared = my_eph_secret.diffie_hellman(&their_eph_public);
    let mut carrier_enc_key = [0u8; 32];
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, temp_shared.as_bytes());
    hk.expand(b"ANYHIDE-CHAT-CARRIER-ENC", &mut carrier_enc_key)
        .expect("32 bytes is valid");

    // Encrypt our carriers
    let encrypted_carriers = encrypt_carriers(&my_carriers, &carrier_enc_key)
        .context("Failed to encrypt carriers")?;

    // Determine if we know the initiator (for mutual recognition)
    let i_know_them = is_known_contact;

    // Create and sign response (including i_know_you flag)
    let carrier_hash = hash_carriers(&my_carriers);
    let response_data = {
        let mut data = Vec::new();
        data.push(1u8); // version
        data.extend_from_slice(my_eph_public.as_bytes());
        data.extend_from_slice(&my_signing_keypair.verifying_key().to_bytes());
        data.extend_from_slice(&bincode::serialize(&agreed_config).unwrap());
        data.push(if i_know_them { 1 } else { 0 }); // i_know_you flag
        data.extend_from_slice(&carrier_hash);
        data
    };
    let response_signature = my_signing_keypair.sign(&response_data);

    let response = HandshakeResponse::new(
        *my_eph_public.as_bytes(),
        my_signing_keypair.verifying_key().to_bytes(),
        agreed_config.clone(),
        i_know_them,
        encrypted_carriers,
        response_signature.to_vec(),
    );

    // Send response
    let response_bytes = response.to_bytes()?;
    let response_wire = WireMessage::new(
        1,
        [0u8; 12],
        vec![],
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &response_bytes),
    );
    conn.send(&response_wire).await.context("Failed to send handshake response")?;

    // Receive HandshakeComplete
    let complete_wire = conn.receive().await.context("Failed to receive handshake complete")?;
    let complete_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &complete_wire.anyhide_code)
        .context("Failed to decode handshake complete")?;
    let complete = HandshakeComplete::from_bytes(&complete_bytes)
        .context("Failed to parse handshake complete")?;

    // Decrypt their carriers
    let their_carriers = decrypt_carriers(&complete.encrypted_carriers, &carrier_enc_key)
        .context("Failed to decrypt peer carriers")?;

    // Determine mutual recognition for passphrase logic
    // Passphrase is ONLY used if BOTH parties know each other
    let they_know_us = init.i_know_you;
    let mutual_recognition = i_know_them && they_know_us;
    let effective_passphrase = if mutual_recognition { passphrase } else { "" };

    // Create session (we are responder)
    let session = ChatSession::init_as_responder(
        my_eph_secret,
        my_signing_keypair.signing_key(),
        their_eph_public,
        their_verifying_key,
        my_carriers,
        their_carriers,
        agreed_config,
        effective_passphrase,
    )
    .context("Failed to initialize session")?;

    Ok((session, resolved_contact_name))
}

/// Perform handshake when connecting to a contact (we are initiator).
/// Returns a ChatSession if successful.
async fn perform_connect_handshake(
    conn: &mut anyhide::chat::transport::TorConnection,
    config: &ChatConfig2,
    passphrase: &str,
    contact_name: &str,
) -> Result<ChatSession> {
    // Load our identity
    let identity = config
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Chat identity not initialized"))?;

    // Load our signing keypair
    let my_signing_keypair = SigningKeyPair::load_from_files(&identity.sign_key_path)
        .context("Failed to load signing key pair")?;

    // Load their verifying key
    let contact = config.contacts.get(contact_name)
        .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found", contact_name))?;
    let their_verifying_key = load_verifying_key(&contact.signing_key)
        .context("Failed to load contact's signing key")?;

    // Generate ephemeral keys for this session
    let my_eph_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let my_eph_public = PublicKey::from(&my_eph_secret);

    // Default chat config (random carriers)
    let chat_config = ChatConfig::default();

    // We know them since they're in our contacts
    let i_know_them = true;

    // Create and sign init (including i_know_you flag)
    let init_signed_data = {
        let mut data = Vec::new();
        data.push(1u8); // version
        data.extend_from_slice(my_eph_public.as_bytes());
        data.extend_from_slice(&my_signing_keypair.verifying_key().to_bytes());
        data.extend_from_slice(&bincode::serialize(&chat_config).unwrap());
        data.push(if i_know_them { 1 } else { 0 }); // i_know_you flag
        data
    };
    let init_signature = my_signing_keypair.sign(&init_signed_data);

    let init = HandshakeInit::new(
        *my_eph_public.as_bytes(),
        my_signing_keypair.verifying_key().to_bytes(),
        chat_config.clone(),
        i_know_them,
        init_signature.to_vec(),
    );

    // Send init
    let init_bytes = init.to_bytes()?;
    let init_wire = WireMessage::new(
        1,
        [0u8; 12],
        vec![],
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &init_bytes),
    );
    conn.send(&init_wire).await.context("Failed to send handshake")?;

    // Receive response
    let response_wire = conn.receive().await.context("Failed to receive handshake response")?;
    let response_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &response_wire.anyhide_code)
        .context("Failed to decode handshake response")?;
    let response = HandshakeResponse::from_bytes(&response_bytes)
        .context("Failed to parse handshake response")?;

    // Get their ephemeral public key
    let their_eph_public = PublicKey::from(response.ephemeral_public);

    // Negotiate config
    let agreed_config = chat_config.negotiate(&response.config)
        .context("Carrier mode mismatch")?;

    // Derive carrier encryption key
    let temp_shared = my_eph_secret.diffie_hellman(&their_eph_public);
    let mut carrier_enc_key = [0u8; 32];
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, temp_shared.as_bytes());
    hk.expand(b"ANYHIDE-CHAT-CARRIER-ENC", &mut carrier_enc_key)
        .expect("32 bytes is valid");

    // Decrypt their carriers
    let their_carriers = decrypt_carriers(&response.encrypted_carriers, &carrier_enc_key)
        .context("Failed to decrypt peer carriers")?;

    // Generate and encrypt our carriers
    let my_carriers = generate_carriers(agreed_config.carriers_per_party, agreed_config.carrier_size);
    let encrypted_carriers = encrypt_carriers(&my_carriers, &carrier_enc_key)
        .context("Failed to encrypt carriers")?;

    // Sign complete
    let carrier_hash = hash_carriers(&my_carriers);
    let complete_signature = my_signing_keypair.sign(&carrier_hash);
    let complete = HandshakeComplete::new(encrypted_carriers, complete_signature.to_vec());

    // Send complete
    let complete_bytes = complete.to_bytes()?;
    let complete_wire = WireMessage::new(
        1,
        [0u8; 12],
        vec![],
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &complete_bytes),
    );
    conn.send(&complete_wire).await.context("Failed to send handshake complete")?;

    // Determine mutual recognition for passphrase logic
    // Passphrase is ONLY used if BOTH parties know each other
    let they_know_us = response.i_know_you;
    let mutual_recognition = i_know_them && they_know_us;
    let effective_passphrase = if mutual_recognition { passphrase } else { "" };

    // Create session (we are initiator)
    ChatSession::init_as_initiator(
        my_eph_secret,
        my_signing_keypair.signing_key(),
        their_eph_public,
        their_verifying_key,
        my_carriers,
        their_carriers,
        agreed_config,
        effective_passphrase,
    )
    .context("Failed to initialize session")
}

/// Handle a terminal event (keyboard, resize, etc).
async fn handle_terminal_event(
    app: &mut MultiApp,
    event: Event,
    active_sessions: &mut HashMap<String, ActiveSession>,
    pending_connections: &mut Vec<PendingConnection>,
    tor_client: &AnyhideTorClient,
    config: &ChatConfig2,
    conn_tx: tokio::sync::mpsc::Sender<ConnectionTaskResult>,
) -> Result<bool> {
    match event {
        Event::Key(key) => {
            let action = handle_multi_key_event(app, key);
            match action {
                MultiKeyAction::Quit => {
                    return Ok(true);
                }
                MultiKeyAction::SendMessage => {
                    let input = app.take_input();

                    // Check for commands
                    if input.starts_with('/') {
                        let cmd_action = handle_multi_command(app, &input);
                        if cmd_action == MultiKeyAction::Quit {
                            return Ok(true);
                        }
                    } else {
                        // Try to send to active session
                        if let Some(tab_name) = app.tabs.get(app.active_tab).cloned() {
                            if let Some(session) = active_sessions.get_mut(&tab_name) {
                                match session.session.send_message(&input) {
                                    Ok(wire) => {
                                        if let Err(e) = session.connection.send(&wire).await {
                                            if let Some(conv) = app.active_conversation_mut() {
                                                conv.add_system_message(format!("Send failed: {}", e));
                                            }
                                        } else {
                                            if let Some(conv) = app.active_conversation_mut() {
                                                conv.add_my_message(&input);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        if let Some(conv) = app.active_conversation_mut() {
                                            conv.add_system_message(format!("Encode failed: {}", e));
                                        }
                                    }
                                }
                            } else {
                                if let Some(conv) = app.active_conversation_mut() {
                                    conv.add_system_message("Not connected. Press Enter on contact to connect.");
                                }
                            }
                        }
                    }
                }
                MultiKeyAction::OpenConversation => {
                    // Get selected contact
                    if let Some(contact) = app.selected_contact().cloned() {
                        if active_sessions.contains_key(&contact.name) {
                            // Already connected - just open the conversation
                            app.open_conversation(&contact.name);
                            if let Some(conv) = app.active_conversation_mut() {
                                conv.add_system_message("Already connected.");
                            }
                        } else if config.contacts.contains_key(&contact.name) {
                            // Known contact - show passphrase dialog
                            let onion = contact.onion_address.clone()
                                .or_else(|| config.contacts.get(&contact.name).map(|c| c.onion_address.clone()));
                            if let Some(onion) = onion {
                                app.show_initiate_dialog(&contact.name, &onion);
                            } else {
                                app.show_error_dialog("Error", "Contact has no onion address.");
                            }
                        } else if let Some(onion) = &contact.onion_address {
                            // Ephemeral contact - skip passphrase, connect directly
                            app.set_contact_status(&contact.name, ContactStatus::Connecting);
                            app.open_conversation(&contact.name);
                            if let Some(conv) = app.active_conversation_mut() {
                                conv.add_system_message("⚠ EPHEMERAL CHAT - No passphrase protection");
                                conv.add_system_message("This chat uses automatic encryption only.");
                                conv.add_system_message(format!(
                                    "Connecting to {}... (retrying up to 5 times)",
                                    &onion[..16.min(onion.len())]
                                ));
                            }

                            // Spawn connection with empty passphrase
                            let tx = conn_tx.clone();
                            let tor = tor_client.clone();
                            let cfg = config.clone();
                            let name = contact.name.clone();
                            let onion_addr = onion.clone();
                            tokio::spawn(async move {
                                let result = connect_and_handshake(&tor, &cfg, &name, &onion_addr, "").await;
                                let _ = tx.send(ConnectionTaskResult::Outgoing {
                                    contact_name: name,
                                    result,
                                }).await;
                            });
                        } else {
                            // Unknown contact with no onion - show error
                            app.show_error_dialog("Error", "Contact has no onion address.");
                        }
                    }
                }
                MultiKeyAction::AddContact => {
                    app.show_dialog(Dialog::add_contact());
                }
                MultiKeyAction::QuickEphemeral => {
                    app.show_dialog(Dialog::quick_ephemeral());
                }
                MultiKeyAction::DialogAddContact { name, onion_address, public_key, signing_key } => {
                    // Add the contact to config
                    match add_contact_from_dialog(&name, &onion_address, &public_key, &signing_key) {
                        Ok(()) => {
                            // Add contact to app
                            let mut contact = Contact::with_onion(&name, &onion_address);
                            contact.status = ContactStatus::Offline;
                            app.add_contact(contact);
                            app.set_status_message(format!("Contact '{}' added!", name));
                        }
                        Err(e) => {
                            app.show_error_dialog("Error", &format!("Failed to add contact: {}", e));
                        }
                    }
                }
                MultiKeyAction::DialogQuickEphemeral { onion_address } => {
                    // Create ephemeral contact and start chat
                    let eph_name = format!("~{}", &onion_address[..8.min(onion_address.len())]);

                    // Add ephemeral contact to app (not saved to config)
                    let mut contact = Contact::ephemeral_with_onion(&eph_name, &onion_address);
                    contact.status = ContactStatus::Connecting;
                    app.add_contact(contact);

                    // Open conversation
                    app.open_conversation(&eph_name);
                    if let Some(conv) = app.active_conversation_mut() {
                        conv.add_system_message("⚠ EPHEMERAL CHAT - No passphrase protection");
                        conv.add_system_message("This chat uses automatic encryption only.");
                        conv.add_system_message(&format!("Connecting to {}...", truncate_onion(&onion_address)));
                    }

                    // Spawn connection task with empty passphrase
                    let tor = tor_client.clone();
                    let cfg = config.clone();
                    let name = eph_name.clone();
                    let onion = onion_address.clone();
                    let tx = conn_tx.clone();

                    tokio::spawn(async move {
                        let result = connect_and_handshake(&tor, &cfg, &name, &onion, "").await;
                        let _ = tx.send(ConnectionTaskResult::Outgoing {
                            contact_name: name,
                            result,
                        }).await;
                    });
                }
                MultiKeyAction::AcceptRequest(id) => {
                    // Show incoming request dialog instead of immediately accepting
                    if let Some(request) = app.get_request(id).cloned() {
                        app.show_incoming_request_dialog(&request);
                    }
                }
                MultiKeyAction::RejectRequest(id) => {
                    if let Some(request) = app.reject_request(id) {
                        // Close and remove the pending connection
                        if let Some(pos) = pending_connections.iter().position(|p| p.onion_address == request.onion_address) {
                            let mut pending = pending_connections.remove(pos);
                            let _ = pending.connection.close().await;
                        }
                    }
                    app.set_status_message("Request rejected.");
                }
                MultiKeyAction::ViewRequests | MultiKeyAction::MarkNotificationsSeen => {
                    // Already handled elsewhere
                }
                MultiKeyAction::CloseTab => {
                    // Close session if active
                    if let Some(tab_name) = app.tabs.get(app.active_tab).cloned() {
                        if let Some(mut session) = active_sessions.remove(&tab_name) {
                            let _ = session.connection.close().await;
                            app.set_contact_status(&tab_name, ContactStatus::Offline);
                        }
                    }
                }
                MultiKeyAction::DialogInitiateChat { contact_name, onion_address, passphrase } => {
                    // User confirmed: initiate connection with passphrase
                    // Update UI immediately
                    app.set_contact_status(&contact_name, ContactStatus::Connecting);
                    app.open_conversation(&contact_name);
                    if let Some(conv) = app.active_conversation_mut() {
                        conv.add_system_message(format!(
                            "Connecting to {}... (retrying up to 5 times, may take ~30s)",
                            &onion_address[..16.min(onion_address.len())]
                        ));
                    }

                    // Spawn background task for connection
                    let tx = conn_tx.clone();
                    let tor = tor_client.clone();
                    let cfg = config.clone();
                    let name = contact_name.clone();
                    let onion = onion_address.clone();
                    let pass = passphrase.clone();
                    tokio::spawn(async move {
                        let result = connect_and_handshake(&tor, &cfg, &name, &onion, &pass).await;
                        let _ = tx.send(ConnectionTaskResult::Outgoing {
                            contact_name: name,
                            result,
                        }).await;
                    });
                }
                MultiKeyAction::DialogAcceptRequest { request_id, source_name, onion_address } => {
                    // Check if this is an ephemeral chat (unknown contact)
                    let is_ephemeral = pending_connections
                        .iter()
                        .find(|p| p.onion_address == onion_address)
                        .map(|p| p.resolved_name.is_none())
                        .unwrap_or(true);

                    if is_ephemeral {
                        // Ephemeral chat - skip passphrase dialog, use automatic passphrase
                        // Find the pending connection
                        if let Some(request) = app.accept_request(request_id) {
                            if let Some(pos) = pending_connections.iter().position(|p| p.onion_address == onion_address) {
                                let pending = pending_connections.remove(pos);
                                let conn = pending.connection;
                                let init = pending.handshake_init;

                                let contact_name = source_name.clone();

                                // Update UI with ephemeral warning
                                app.set_contact_status(&contact_name, ContactStatus::Connecting);
                                app.open_conversation(&contact_name);
                                if let Some(conv) = app.active_conversation_mut() {
                                    conv.add_system_message("⚠ EPHEMERAL CHAT - No passphrase protection");
                                    conv.add_system_message("This chat uses automatic encryption only.");
                                    conv.add_system_message(format!("Connecting to {}...", &onion_address[..16.min(onion_address.len())]));
                                }

                                // Spawn handshake with empty passphrase
                                let tx = conn_tx.clone();
                                let cfg = config.clone();
                                let name = contact_name.clone();
                                let onion = onion_address.clone();
                                let is_known = request.is_known;
                                let known_name = request.contact_name.clone();
                                tokio::spawn(async move {
                                    // Empty passphrase for ephemeral chats
                                    let result = accept_handshake(conn, &cfg, "", is_known, known_name.as_deref(), init).await;
                                    let _ = tx.send(ConnectionTaskResult::Incoming {
                                        contact_name: name,
                                        onion_address: onion,
                                        result,
                                    }).await;
                                });
                            }
                        }
                    } else {
                        // Known contact - show passphrase dialog
                        app.show_accept_dialog(request_id, &source_name, &onion_address);
                    }
                }
                MultiKeyAction::DialogAcceptChat { request_id, onion_address, passphrase } => {
                    // User entered passphrase to accept incoming chat
                    // Find the pending connection first
                    if let Some(request) = app.accept_request(request_id) {
                        if let Some(pos) = pending_connections.iter().position(|p| p.onion_address == onion_address) {
                            let pending = pending_connections.remove(pos);
                            let conn = pending.connection;
                            let init = pending.handshake_init;

                            // Use the resolved name from early identification, or generate one
                            let contact_name = pending.resolved_name.clone().unwrap_or_else(|| {
                                request.contact_name.clone().unwrap_or_else(|| {
                                    format!("~{}", &onion_address[..8.min(onion_address.len())])
                                })
                            });

                            // Update UI immediately
                            app.set_contact_status(&contact_name, ContactStatus::Connecting);
                            app.open_conversation(&contact_name);
                            if let Some(conv) = app.active_conversation_mut() {
                                conv.add_system_message(format!("Accepting connection from {}...", onion_address));
                            }

                            // Spawn background task for handshake
                            let tx = conn_tx.clone();
                            let cfg = config.clone();
                            let name = contact_name.clone();
                            let onion = onion_address.clone();
                            let pass = passphrase.clone();
                            let is_known = request.is_known;
                            let known_name = request.contact_name.clone();
                            tokio::spawn(async move {
                                let result = accept_handshake(conn, &cfg, &pass, is_known, known_name.as_deref(), init).await;
                                let _ = tx.send(ConnectionTaskResult::Incoming {
                                    contact_name: name,
                                    onion_address: onion,
                                    result,
                                }).await;
                            });
                        } else {
                            app.show_error_dialog("Error", "Connection expired. Please try again.");
                        }
                    }
                }
                MultiKeyAction::DialogRejectRequest { request_id, onion_address } => {
                    // User rejected incoming request
                    app.reject_request(request_id);
                    // Close the pending connection
                    if let Some(pos) = pending_connections.iter().position(|p| p.onion_address == onion_address) {
                        let mut pending = pending_connections.remove(pos);
                        let _ = pending.connection.close().await;
                    }
                    // Show generic error to the initiator (for security)
                    app.set_status_message("Request declined.");
                }
                MultiKeyAction::DialogCancelled => {
                    // User cancelled dialog - nothing to do
                }
                MultiKeyAction::NotificationDismissed { .. } => {
                    // Notification was viewed and dismissed - nothing more to do
                }
                MultiKeyAction::None => {}
            }
        }
        Event::Resize(_, _) => {
            // Terminal will redraw on next iteration
        }
        Event::Tick => {
            // Periodic tick
        }
        Event::Mouse(_) => {
            // Ignore mouse events
        }
    }

    Ok(false)
}

/// Check all active sessions for incoming messages.
async fn check_active_sessions(
    active_sessions: &mut HashMap<String, ActiveSession>,
    app: &mut MultiApp,
) {
    // Check each session for incoming data
    // Note: This is a simple polling approach. A more sophisticated
    // implementation would use futures::select_all or similar.

    let mut disconnected: Vec<String> = Vec::new();

    for (name, session) in active_sessions.iter_mut() {
        // Try to receive with a very short timeout
        match tokio::time::timeout(
            Duration::from_millis(10),
            session.connection.receive()
        ).await {
            Ok(Ok(wire)) => {
                // Got a message
                match session.session.receive_message(&wire) {
                    Ok(msg) => {
                        app.receive_message(name, &msg);
                    }
                    Err(e) => {
                        if let Some(conv) = app.conversations.get_mut(name) {
                            conv.add_system_message(format!("Decode error: {}", e));
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                // Connection error
                let err_str = e.to_string();
                if err_str.contains("end of file")
                    || err_str.contains("connection")
                    || err_str.contains("reset")
                {
                    if let Some(conv) = app.conversations.get_mut(name) {
                        conv.add_system_message(format!("{} disconnected.", name));
                    }
                    disconnected.push(name.clone());
                }
            }
            Err(_) => {
                // Timeout - no data available, which is fine
            }
        }
    }

    // Remove disconnected sessions
    for name in disconnected {
        active_sessions.remove(&name);
        app.set_contact_status(&name, ContactStatus::Offline);
    }
}

/// Background task: Connect to peer and perform handshake.
/// Returns the session and connection on success.
/// Retries connection up to MAX_CONNECT_RETRIES times.
async fn connect_and_handshake(
    tor_client: &AnyhideTorClient,
    config: &ChatConfig2,
    contact_name: &str,
    onion_address: &str,
    passphrase: &str,
) -> Result<(ChatSession, anyhide::chat::transport::TorConnection)> {
    use rand::Rng;

    const MAX_CONNECT_RETRIES: u32 = 5;
    let peer_addr = format!("{}:{}", onion_address, CHAT_PORT);

    let mut last_error = None;

    for attempt in 1..=MAX_CONNECT_RETRIES {
        // Try to connect
        match tor_client.connect(&peer_addr).await {
            Ok(mut conn) => {
                // Connected! Now try handshake
                match perform_connect_handshake(&mut conn, config, passphrase, contact_name).await {
                    Ok(session) => {
                        return Ok((session, conn));
                    }
                    Err(e) => {
                        // Handshake failed - don't retry, it's likely a passphrase or protocol issue
                        let _ = conn.close().await;
                        return Err(e).context("Handshake failed");
                    }
                }
            }
            Err(e) => {
                last_error = Some(e);
                if attempt < MAX_CONNECT_RETRIES {
                    // Wait with jitter before retrying (3-7 seconds)
                    let delay_secs = rand::thread_rng().gen_range(3..=7);
                    tokio::time::sleep(Duration::from_secs(delay_secs)).await;
                }
            }
        }
    }

    Err(last_error.unwrap()).context(format!(
        "Failed to connect after {} attempts",
        MAX_CONNECT_RETRIES
    ))
}

/// Read the initial HandshakeInit from a connection to identify the sender.
/// This is called early (before user accepts) to know who is connecting.
async fn read_handshake_init(
    conn: &mut anyhide::chat::transport::TorConnection,
) -> Result<HandshakeInit> {
    use anyhide::chat::transport::MessageTransport;

    let init_wire = conn.receive().await.context("Failed to receive handshake init")?;
    let init_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &init_wire.anyhide_code)
        .context("Failed to decode handshake init")?;
    let init = HandshakeInit::from_bytes(&init_bytes).context("Failed to parse handshake init")?;
    Ok(init)
}

/// Background task: Accept incoming connection and perform handshake.
/// Returns the session, connection, and resolved contact name (if found).
async fn accept_handshake(
    mut conn: anyhide::chat::transport::TorConnection,
    config: &ChatConfig2,
    passphrase: &str,
    is_known: bool,
    contact_name: Option<&str>,
    init: HandshakeInit, // Pre-received HandshakeInit
) -> Result<(ChatSession, anyhide::chat::transport::TorConnection, Option<String>)> {
    // Perform handshake - returns session and resolved contact name
    let (session, resolved_name) = perform_accept_handshake(&mut conn, config, passphrase, is_known, contact_name, init).await
        .context("Handshake failed")?;

    Ok((session, conn, resolved_name))
}

/// Handle the result of a background connection task.
async fn handle_connection_result(
    app: &mut MultiApp,
    active_sessions: &mut HashMap<String, ActiveSession>,
    result: ConnectionTaskResult,
) {
    match result {
        ConnectionTaskResult::Outgoing { contact_name, result } => {
            match result {
                Ok((session, conn)) => {
                    active_sessions.insert(contact_name.clone(), ActiveSession {
                        contact_name: contact_name.clone(),
                        session,
                        connection: conn,
                    });
                    app.set_contact_status(&contact_name, ContactStatus::Online);
                    if let Some(conv) = app.conversations.get_mut(&contact_name) {
                        conv.add_system_message("Connected! Ready to chat.");
                    }
                }
                Err(e) => {
                    app.set_contact_status(&contact_name, ContactStatus::Offline);
                    if let Some(conv) = app.conversations.get_mut(&contact_name) {
                        conv.add_system_message(format!("Connection failed: {}", e));
                    }
                }
            }
        }
        ConnectionTaskResult::Incoming { contact_name, onion_address, result } => {
            match result {
                Ok((session, conn, resolved_name)) => {
                    // Use resolved name if found, otherwise generate from onion or use original
                    let final_name = resolved_name.unwrap_or_else(|| {
                        // Generate a display name from the onion address if not a known contact
                        if contact_name.starts_with("~") {
                            // Already a generated name, use onion-based name
                            if onion_address.len() > 12 {
                                format!("~{}...", &onion_address[..12])
                            } else {
                                format!("~{}", onion_address)
                            }
                        } else {
                            contact_name.clone()
                        }
                    });

                    // If the name changed, update the UI
                    if final_name != contact_name {
                        // Move conversation to new name
                        if let Some(conv) = app.conversations.remove(&contact_name) {
                            app.conversations.insert(final_name.clone(), conv);
                        }
                        // Update tabs
                        if let Some(pos) = app.tabs.iter().position(|t| t == &contact_name) {
                            app.tabs[pos] = final_name.clone();
                        }
                        // Update contacts list (add as known contact in UI)
                        app.set_contact_status(&contact_name, ContactStatus::Offline);
                    }

                    active_sessions.insert(final_name.clone(), ActiveSession {
                        contact_name: final_name.clone(),
                        session,
                        connection: conn,
                    });
                    app.set_contact_status(&final_name, ContactStatus::Online);
                    if let Some(conv) = app.conversations.get_mut(&final_name) {
                        conv.add_system_message("Connected! Ready to chat.");
                    }
                }
                Err(e) => {
                    app.set_contact_status(&contact_name, ContactStatus::Offline);
                    if let Some(conv) = app.conversations.get_mut(&contact_name) {
                        conv.add_system_message(format!("Connection failed: {}", e));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Onion v3 addresses are exactly 56 characters (without .onion suffix)
    // Format: base32(ed25519_pubkey || checksum || version) = 56 chars
    const TEST_ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    #[test]
    fn test_encode_decode_chat_identity_roundtrip() {
        let enc_pubkey = [1u8; 32];
        let sign_pubkey = [2u8; 32];
        let nickname = "alice";

        let data = encode_chat_identity(TEST_ONION, &enc_pubkey, &sign_pubkey, nickname).unwrap();

        let (decoded_onion, decoded_enc, decoded_sign, decoded_nick) =
            decode_chat_identity(&data).unwrap();

        assert_eq!(decoded_onion, TEST_ONION);
        assert_eq!(decoded_enc, enc_pubkey);
        assert_eq!(decoded_sign, sign_pubkey);
        assert_eq!(decoded_nick, nickname);
    }

    #[test]
    fn test_encode_decode_empty_nickname() {
        let enc_pubkey = [0xAA; 32];
        let sign_pubkey = [0xBB; 32];
        let nickname = "";

        let data = encode_chat_identity(TEST_ONION, &enc_pubkey, &sign_pubkey, nickname).unwrap();

        let (decoded_onion, decoded_enc, decoded_sign, decoded_nick) =
            decode_chat_identity(&data).unwrap();

        assert_eq!(decoded_onion, TEST_ONION);
        assert_eq!(decoded_enc, enc_pubkey);
        assert_eq!(decoded_sign, sign_pubkey);
        assert_eq!(decoded_nick, "");
    }

    #[test]
    fn test_encode_decode_long_nickname() {
        let enc_pubkey = [0xCC; 32];
        let sign_pubkey = [0xDD; 32];
        let nickname = "a".repeat(63); // Max length

        let data = encode_chat_identity(TEST_ONION, &enc_pubkey, &sign_pubkey, &nickname).unwrap();

        let (_, _, _, decoded_nick) = decode_chat_identity(&data).unwrap();

        assert_eq!(decoded_nick, nickname);
    }

    #[test]
    fn test_encode_nickname_too_long() {
        let enc_pubkey = [0; 32];
        let sign_pubkey = [0; 32];
        let nickname = "a".repeat(64); // Too long

        let result = encode_chat_identity(TEST_ONION, &enc_pubkey, &sign_pubkey, &nickname);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_invalid_magic() {
        let data = b"XXXX\x01abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\x05alice";
        let result = decode_chat_identity(data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("wrong magic"));
    }

    #[test]
    fn test_decode_invalid_version() {
        let mut data = vec![];
        data.extend_from_slice(CHAT_QR_MAGIC);
        data.push(0xFF); // Invalid version
        data.extend_from_slice(&[0u8; 56]); // onion
        data.extend_from_slice(&[0u8; 32]); // enc key
        data.extend_from_slice(&[0u8; 32]); // sign key
        data.push(0); // nick len

        let result = decode_chat_identity(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported QR version"));
    }

    #[test]
    fn test_decode_too_short() {
        let data = b"AHID\x01short";
        let result = decode_chat_identity(data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_chat_qr_format_size() {
        // Verify the format fits in QR code capacity
        let enc_pubkey = [0xDE; 32];
        let sign_pubkey = [0xAD; 32];
        let nickname = "maximum-length-nickname-that-is-quite-long";

        let data = encode_chat_identity(TEST_ONION, &enc_pubkey, &sign_pubkey, nickname).unwrap();

        // Format: magic(4) + version(1) + onion(56) + enc(32) + sign(32) + nick_len(1) + nick
        let expected_size = 4 + 1 + 56 + 32 + 32 + 1 + nickname.len();
        assert_eq!(data.len(), expected_size);

        // Should fit easily in QR Version 10 (capacity ~914 bytes in binary mode L)
        assert!(data.len() < 900);
    }

    // ==========================================================================
    // Ephemeral Contact Tests
    // ==========================================================================

    #[test]
    fn test_parse_ephemeral_from_args_valid() {
        let onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
        let pubkey_hex = "0101010101010101010101010101010101010101010101010101010101010101";
        let sign_key_hex = "0202020202020202020202020202020202020202020202020202020202020202";

        let contact = parse_ephemeral_from_args(onion, pubkey_hex, sign_key_hex).unwrap();

        assert_eq!(contact.onion_address, onion);
        assert_eq!(contact.public_key, [1u8; 32]);
        assert_eq!(contact.signing_key, [2u8; 32]);
    }

    #[test]
    fn test_parse_ephemeral_from_args_without_onion_suffix() {
        let onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx";
        let pubkey_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let sign_key_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let contact = parse_ephemeral_from_args(onion, pubkey_hex, sign_key_hex).unwrap();

        // Should add .onion suffix
        assert_eq!(contact.onion_address, format!("{}.onion", onion));
        assert_eq!(contact.public_key, [0xAA; 32]);
        assert_eq!(contact.signing_key, [0xBB; 32]);
    }

    #[test]
    fn test_parse_ephemeral_from_args_with_port() {
        let onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9999";
        let pubkey_hex = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let sign_key_hex = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

        let contact = parse_ephemeral_from_args(onion, pubkey_hex, sign_key_hex).unwrap();

        // Should strip port
        assert_eq!(contact.onion_address, "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion");
    }

    #[test]
    fn test_parse_ephemeral_from_args_invalid_pubkey_hex() {
        let onion = "test.onion";
        let pubkey_hex = "not_valid_hex";
        let sign_key_hex = "0202020202020202020202020202020202020202020202020202020202020202";

        let result = parse_ephemeral_from_args(onion, pubkey_hex, sign_key_hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid --pubkey"));
    }

    #[test]
    fn test_parse_ephemeral_from_args_wrong_pubkey_length() {
        let onion = "test.onion";
        let pubkey_hex = "0101010101"; // Too short (5 bytes)
        let sign_key_hex = "0202020202020202020202020202020202020202020202020202020202020202";

        let result = parse_ephemeral_from_args(onion, pubkey_hex, sign_key_hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be 32 bytes"));
    }

    #[test]
    fn test_parse_ephemeral_from_args_invalid_sign_key_hex() {
        let onion = "test.onion";
        let pubkey_hex = "0101010101010101010101010101010101010101010101010101010101010101";
        let sign_key_hex = "not_valid_hex";

        let result = parse_ephemeral_from_args(onion, pubkey_hex, sign_key_hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid --sign-key"));
    }

    #[test]
    fn test_ephemeral_contact_struct() {
        let contact = EphemeralContact {
            onion_address: "test.onion".to_string(),
            public_key: [0xAA; 32],
            signing_key: [0xBB; 32],
        };

        assert_eq!(contact.onion_address, "test.onion");
        assert_eq!(contact.public_key.len(), 32);
        assert_eq!(contact.signing_key.len(), 32);
    }
}
