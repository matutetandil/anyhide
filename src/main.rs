//! Anyhide - Hide anything in anything
//!
//! A CLI tool for advanced steganography with hybrid encryption.
//! Uses pre-shared carriers (any file) - only encrypted codes are transmitted.

mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};

use commands::{
    ChatCommand, CommandExecutor, ContactsCommand, DecodeCommand, EncodeCommand,
    ExportMnemonicCommand, FingerprintCommand, ImportMnemonicCommand, KeygenCommand,
    MultiDecryptCommand, MultiEncryptCommand, QrGenerateCommand, QrInfoCommand, QrReadCommand,
    UpdateCommand,
};

/// Anyhide - Hide anything in anything
///
/// Advanced steganography tool with:
/// - Hybrid encryption (X25519 + ChaCha20-Poly1305)
/// - Forward secrecy with ephemeral keys
/// - Message signing (Ed25519)
/// - Message expiration with plausible deniability
/// - Code splitting for multi-channel delivery
/// - QR code support (Base45 encoding)
/// - Universal carrier support (text, images, audio, video, any file)
///
/// Use ANY file as a pre-shared carrier - only encrypted codes are transmitted.
#[derive(Parser)]
#[command(name = "anyhide")]
#[command(version = "0.11.0")]
#[command(about = "Hide anything in anything - advanced steganography with encryption")]
#[command(long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new key pair (encryption + signing)
    Keygen(KeygenCommand),

    /// Encode a message or file into an encrypted code
    Encode(EncodeCommand),

    /// Decode an encrypted code back to message or file
    Decode(DecodeCommand),

    /// Display a key's fingerprint for verification
    Fingerprint(FingerprintCommand),

    /// Manage contacts with aliases
    Contacts(ContactsCommand),

    /// P2P encrypted chat (TCP for now, Tor coming soon)
    Chat(ChatCommand),

    /// Export a key as a 24-word mnemonic phrase
    #[command(name = "export-mnemonic")]
    ExportMnemonic(ExportMnemonicCommand),

    /// Import a key from a 24-word mnemonic phrase
    #[command(name = "import-mnemonic")]
    ImportMnemonic(ImportMnemonicCommand),

    /// Encrypt a message for multiple recipients
    #[command(name = "multi-encrypt")]
    MultiEncrypt(MultiEncryptCommand),

    /// Decrypt a multi-recipient message
    #[command(name = "multi-decrypt")]
    MultiDecrypt(MultiDecryptCommand),

    /// Generate a QR code from an Anyhide code
    #[command(name = "qr-generate")]
    QrGenerate(QrGenerateCommand),

    /// Read a QR code and extract the Anyhide code
    #[command(name = "qr-read")]
    QrRead(QrReadCommand),

    /// Show QR code capacity info
    #[command(name = "qr-info")]
    QrInfo(QrInfoCommand),

    /// Update anyhide to the latest version
    Update(UpdateCommand),
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen(cmd) => cmd.execute(),
        Commands::Encode(cmd) => cmd.execute(),
        Commands::Decode(cmd) => cmd.execute(),
        Commands::Fingerprint(cmd) => cmd.execute(),
        Commands::Contacts(cmd) => cmd.execute(),
        Commands::Chat(cmd) => cmd.execute(),
        Commands::ExportMnemonic(cmd) => cmd.execute(),
        Commands::ImportMnemonic(cmd) => cmd.execute(),
        Commands::MultiEncrypt(cmd) => cmd.execute(),
        Commands::MultiDecrypt(cmd) => cmd.execute(),
        Commands::QrGenerate(cmd) => cmd.execute(),
        Commands::QrRead(cmd) => cmd.execute(),
        Commands::QrInfo(cmd) => cmd.execute(),
        Commands::Update(cmd) => cmd.execute(),
    }
}
