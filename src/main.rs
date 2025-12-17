//! Anyhide - Hide anything in anything
//!
//! A CLI tool for advanced steganography with hybrid encryption.
//! Uses pre-shared carriers (any file) - only encrypted codes are transmitted.

mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};

use commands::{
    CommandExecutor, DecodeCommand, EncodeCommand, KeygenCommand, MultiDecryptCommand,
    MultiEncryptCommand, QrGenerateCommand, QrInfoCommand, QrReadCommand, UpdateCommand,
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
#[command(version = "0.8.1")]
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
        Commands::MultiEncrypt(cmd) => cmd.execute(),
        Commands::MultiDecrypt(cmd) => cmd.execute(),
        Commands::QrGenerate(cmd) => cmd.execute(),
        Commands::QrRead(cmd) => cmd.execute(),
        Commands::QrInfo(cmd) => cmd.execute(),
        Commands::Update(cmd) => cmd.execute(),
    }
}
