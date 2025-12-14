//! KAMO - Key Asymmetric Message Obfuscation
//!
//! A CLI tool for pre-shared carrier steganography with hybrid encryption.
//! Version 0.4.1 features substring fragments, distributed selection, and block padding.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::{self, Read};
use std::path::PathBuf;

use kamo::crypto::{load_public_key, load_secret_key, KeyPair};
use kamo::{decode_with_config, encode_with_config, DecoderConfig, EncoderConfig};

/// KAMO - Key Asymmetric Message Obfuscation
///
/// Four-factor steganography with substring fragments and block padding.
/// Decoder NEVER fails - returns garbage if inputs are wrong.
#[derive(Parser)]
#[command(name = "kamo")]
#[command(version = "0.4.1")]
#[command(about = "Four-factor steganography with substring fragments and block padding")]
#[command(long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new key pair
    Keygen {
        /// Output path for keys (creates .pub and .key files)
        #[arg(short, long, default_value = "kamo")]
        output: PathBuf,
    },

    /// Encode a message using a pre-shared carrier
    Encode {
        /// Path to the carrier file (pre-shared text)
        #[arg(short, long)]
        carrier: PathBuf,

        /// Message to encode (reads from stdin if not provided)
        #[arg(short, long)]
        message: Option<String>,

        /// Passphrase for encryption (also determines fragmentation and positions)
        #[arg(short, long)]
        passphrase: String,

        /// Path to recipient's public key
        #[arg(short, long)]
        key: PathBuf,

        /// Verbose output (shows permutation and positions)
        #[arg(short, long)]
        verbose: bool,
    },

    /// Decode a message using a pre-shared carrier
    /// NOTE: This command NEVER fails - it returns garbage if inputs are wrong
    Decode {
        /// The encrypted code to decode
        #[arg(long)]
        code: String,

        /// Path to the carrier file (must match encoding carrier)
        #[arg(short, long)]
        carrier: PathBuf,

        /// Passphrase for decryption (must match encoding passphrase)
        #[arg(short, long)]
        passphrase: String,

        /// Path to your private key
        #[arg(short, long)]
        key: PathBuf,

        /// Verbose output (shows extracted words)
        #[arg(short, long)]
        verbose: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output } => {
            keygen(&output)?;
        }
        Commands::Encode {
            carrier,
            message,
            passphrase,
            key,
            verbose,
        } => {
            encode_cmd(&carrier, message, &passphrase, &key, verbose)?;
        }
        Commands::Decode {
            code,
            carrier,
            passphrase,
            key,
            verbose,
        } => {
            decode_cmd(&code, &carrier, &passphrase, &key, verbose);
        }
    }

    Ok(())
}

/// Generates a new key pair and saves to files.
fn keygen(output: &PathBuf) -> Result<()> {
    let keypair = KeyPair::generate();

    keypair
        .save_to_files(output)
        .context("Failed to save key pair")?;

    let pub_path = output.with_extension("pub");
    let key_path = output.with_extension("key");

    println!("Key pair generated successfully:");
    println!("  Public key:  {}", pub_path.display());
    println!("  Private key: {}", key_path.display());
    println!();
    println!("Share your public key (.pub) with people who want to send you messages.");
    println!("Keep your private key (.key) secret and secure.");

    Ok(())
}

/// Encodes a message into an encrypted code.
fn encode_cmd(
    carrier_path: &PathBuf,
    message: Option<String>,
    passphrase: &str,
    key_path: &PathBuf,
    verbose: bool,
) -> Result<()> {
    // Read carrier from file
    let carrier = std::fs::read_to_string(carrier_path)
        .with_context(|| format!("Failed to read carrier from {}", carrier_path.display()))?;

    // Read message from argument or stdin
    let message = match message {
        Some(m) => m,
        None => {
            eprintln!("Reading message from stdin (Ctrl+D to finish):");
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .context("Failed to read message from stdin")?;
            buffer.trim().to_string()
        }
    };

    if message.is_empty() {
        anyhow::bail!("Message cannot be empty");
    }

    // Load recipient's public key
    let public_key = load_public_key(key_path)
        .with_context(|| format!("Failed to load public key from {}", key_path.display()))?;

    // Create encoder config
    let config = EncoderConfig { verbose };

    // Encode the message
    let encoded = encode_with_config(&carrier, &message, passphrase, &public_key, &config)
        .context("Failed to encode message")?;

    // Output the encrypted code
    println!("{}", encoded.code);

    if verbose {
        eprintln!();
        eprintln!("Encoded {} real fragments ({} total with padding)",
                  encoded.real_fragment_count, encoded.total_fragments);
    }

    Ok(())
}

/// Decodes an encrypted code back to a message.
/// NOTE: This function NEVER fails - it always produces output.
fn decode_cmd(
    code: &str,
    carrier_path: &PathBuf,
    passphrase: &str,
    key_path: &PathBuf,
    verbose: bool,
) {
    // Read carrier from file
    let carrier = match std::fs::read_to_string(carrier_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: Could not read carrier file: {}", e);
            String::new() // Empty carrier will produce garbage
        }
    };

    // Load private key
    let secret_key = match load_secret_key(key_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Warning: Could not load private key: {}", e);
            // Generate a dummy key for the fallback
            KeyPair::generate().into_secret_key()
        }
    };

    // Create decoder config
    let config = DecoderConfig { verbose };

    // Decode the message - NEVER fails
    let decoded = decode_with_config(code, &carrier, passphrase, &secret_key, &config);

    // Output the message (may be garbage if inputs were wrong)
    println!("{}", decoded.message);

    if verbose {
        eprintln!();
        eprintln!("Fragments: {:?}", decoded.fragments);
    }
}
