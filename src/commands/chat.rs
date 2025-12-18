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

use super::CommandExecutor;

use anyhide::chat::transport::{
    print_bootstrap_message, print_tor_warning, AnyhideTorClient, MessageTransport,
};
use anyhide::chat::tui::{
    init_terminal, restore_terminal, render, App, ConnectionStatus, Event, EventHandler,
    handle_key_event, handle_command, KeyAction,
};

use anyhide::chat::protocol::{decrypt_carriers, encrypt_carriers, hash_carriers};
use anyhide::chat::{
    generate_carriers, ChatConfig, ChatSession, HandshakeComplete, HandshakeInit,
    HandshakeResponse, WireMessage,
};
use anyhide::crypto::{load_verifying_key, SigningKeyPair};

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

    /// Profile name for separate identity (useful for local testing)
    #[arg(long, global = true)]
    pub profile: Option<String>,

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
}

impl CommandExecutor for ChatCommand {
    fn execute(&self) -> Result<()> {
        // Set profile for config loading
        set_current_profile(self.profile.clone());

        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

        let profile = self.profile.as_deref();

        rt.block_on(async {
            // If a contact name is provided, start chat
            if let Some(contact) = &self.contact {
                return start_chat(contact, self.carriers, self.carrier_size, profile).await;
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
                None => {
                    println!("Usage:");
                    println!("  anyhide chat <contact>              Start chat with a contact");
                    println!("  anyhide chat init -k <keys> -s <sign>   Initialize your identity");
                    println!("  anyhide chat add <name> <onion> ...     Add a contact");
                    println!("  anyhide chat list                       List contacts");
                    println!("  anyhide chat show <name>                Show contact details");
                    println!("  anyhide chat remove <name>              Remove a contact");
                    Ok(())
                }
            }
        })
    }
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

/// Start a chat session with a contact.
async fn start_chat(contact_name: &str, _carriers_count: usize, _carrier_size: usize, profile: Option<&str>) -> Result<()> {
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

    // Connection + handshake loop with retries (Tor can be flaky)
    let (mut session, mut conn) = loop {
        println!("Looking for {}...", contact_name);

        // Race: try to connect to them OR accept connection from them
        let connection_result = tokio::select! {
            // Try to connect to their hidden service
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
            // Accept incoming connection
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
        };

        let (mut conn, is_initiator) = match connection_result {
            Some(c) => c,
            None => {
                println!("Retrying in 5 seconds... (Ctrl+C to cancel)");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        // Generate ephemeral key for this session
        let my_eph_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let my_eph_public = PublicKey::from(&my_eph_secret);

        // Create config (256 char limit for steganographic efficiency)
        let chat_config = ChatConfig::default();

        // Perform handshake based on role
        println!("Performing handshake...");
        let handshake_result = if is_initiator {
            perform_initiator_handshake(
                &mut conn,
                my_eph_secret,
                my_eph_public,
                &my_signing_keypair,
                their_verifying_key.clone(),
                chat_config,
                &passphrase,
            )
            .await
        } else {
            perform_responder_handshake(
                &mut conn,
                my_eph_secret,
                my_eph_public,
                &my_signing_keypair,
                their_verifying_key.clone(),
                chat_config,
                &passphrase,
            )
            .await
        };

        match handshake_result {
            Ok(s) => break (s, conn),
            Err(e) => {
                eprintln!("Handshake failed: {}", e);
                println!("Retrying in 5 seconds... (Ctrl+C to cancel)");
                tokio::time::sleep(Duration::from_secs(5)).await;
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
    user_passphrase: &str,
) -> Result<ChatSession> {
    // Create and sign init
    let init_signed_data = {
        let mut data = Vec::new();
        data.push(1u8); // version
        data.extend_from_slice(my_eph_public.as_bytes());
        data.extend_from_slice(&my_signing_keypair.verifying_key().to_bytes());
        data.extend_from_slice(&bincode::serialize(&config).unwrap());
        data
    };
    let init_signature = my_signing_keypair.sign(&init_signed_data);

    let init = HandshakeInit::new(
        *my_eph_public.as_bytes(),
        my_signing_keypair.verifying_key().to_bytes(),
        config.clone(),
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
    let agreed_config = config.negotiate(&response.config);
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

    // Create session (we are initiator)
    ChatSession::init_as_initiator(
        my_eph_secret,
        my_signing_keypair.signing_key(),
        their_eph_public,
        their_verifying_key,
        my_carriers,
        their_carriers,
        agreed_config,
        user_passphrase,
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
    user_passphrase: &str,
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
    let agreed_config = proposed_config.negotiate(&init.config);

    // Generate carriers
    let my_carriers = generate_carriers(agreed_config.carriers_per_party, agreed_config.carrier_size);

    // Derive carrier encryption key
    let their_eph_public = PublicKey::from(init.ephemeral_public);
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

    // Create and sign response
    let carrier_hash = hash_carriers(&my_carriers);
    let response_data = {
        let mut data = Vec::new();
        data.push(1u8); // version
        data.extend_from_slice(my_eph_public.as_bytes());
        data.extend_from_slice(&my_signing_keypair.verifying_key().to_bytes());
        data.extend_from_slice(&bincode::serialize(&agreed_config).unwrap());
        data.extend_from_slice(&carrier_hash);
        data
    };
    let response_signature = my_signing_keypair.sign(&response_data);

    let response = HandshakeResponse::new(
        *my_eph_public.as_bytes(),
        my_signing_keypair.verifying_key().to_bytes(),
        agreed_config.clone(),
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

    // Create session (we are responder)
    ChatSession::init_as_responder(
        my_eph_secret,
        my_signing_keypair.signing_key(),
        their_eph_public,
        their_verifying_key,
        my_carriers,
        their_carriers,
        agreed_config,
        user_passphrase,
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
