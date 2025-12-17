//! Decode command - extract hidden messages or files from a carrier.

use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Args;

use anyhide::crypto::{load_secret_key, load_verifying_key, KeyPair};
use anyhide::qr::read_qr_from_file;
use anyhide::{decode_with_carrier_config, decode_bytes_with_carrier_config, Carrier, DecoderConfig};

use super::CommandExecutor;

/// Decode a message using a pre-shared carrier (ANY file).
///
/// NOTE: This command NEVER fails - it returns garbage if inputs are wrong.
/// This provides plausible deniability.
///
/// Use -o/--output to write raw bytes to a file (required for binary data).
/// Without -o, output is printed as text (lossy UTF-8 conversion).
///
/// Code can be provided as:
/// - Direct text: --code "abc..."
/// - QR image: --code-qr image.png
/// - Text file: --code-file code.txt
/// - Split parts: --parts part1.txt part2.txt (files or QR images, in order)
#[derive(Args, Debug)]
pub struct DecodeCommand {
    /// The encrypted code (direct text)
    #[arg(long, conflicts_with_all = ["code_qr", "code_file", "parts"])]
    pub code: Option<String>,

    /// Read code from a QR image file (.png, .jpg)
    #[arg(long, conflicts_with_all = ["code", "code_file", "parts"])]
    pub code_qr: Option<PathBuf>,

    /// Read code from a text file
    #[arg(long, conflicts_with_all = ["code", "code_qr", "parts"])]
    pub code_file: Option<PathBuf>,

    /// Split code parts (text files or QR images, in order)
    /// Order matters - wrong order = garbage (plausible deniability)
    #[arg(long, num_args = 2..=10, conflicts_with_all = ["code", "code_qr", "code_file"])]
    pub parts: Option<Vec<PathBuf>>,

    /// Path to carrier file (must be the EXACT same file used for encoding)
    #[arg(short, long)]
    pub carrier: PathBuf,

    /// Passphrase for decryption (must match encoding passphrase)
    #[arg(short, long)]
    pub passphrase: String,

    /// Path to your private key
    #[arg(short, long)]
    pub key: PathBuf,

    /// Output file for decoded data (required for binary data)
    /// If not specified, prints decoded text to stdout
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Verbose output (shows extracted fragments)
    #[arg(short, long)]
    pub verbose: bool,

    /// Verify the sender's signature with their signing public key
    /// If provided and message is signed, verifies the signature
    #[arg(long)]
    pub verify: Option<PathBuf>,
}

impl CommandExecutor for DecodeCommand {
    /// Decode never returns an error - it returns garbage on invalid inputs
    /// to preserve plausible deniability.
    fn execute(&self) -> Result<()> {
        self.execute_decode();
        Ok(())
    }
}

impl DecodeCommand {
    /// Internal decode logic that never fails.
    fn execute_decode(&self) {
        // Resolve code from the various input sources
        let code: String = if let Some(c) = &self.code {
            join_code_parts(c)
        } else if let Some(qr_path) = &self.code_qr {
            match read_code_from_file(qr_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Warning: Could not read QR code: {}", e);
                    String::new()
                }
            }
        } else if let Some(file_path) = &self.code_file {
            match read_code_from_file(file_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Warning: Could not read code file: {}", e);
                    String::new()
                }
            }
        } else if let Some(part_paths) = &self.parts {
            match read_code_parts(part_paths) {
                Ok(c) => {
                    if self.verbose {
                        eprintln!("Combined {} parts", part_paths.len());
                    }
                    c
                }
                Err(e) => {
                    eprintln!("Warning: Could not read parts: {}", e);
                    String::new()
                }
            }
        } else {
            eprintln!("Error: No code provided. Use --code, --code-qr, --code-file, or --parts");
            return;
        };

        // Load carrier with auto-detection based on file extension
        let carrier = match Carrier::from_file(&self.carrier) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Warning: Could not read carrier file: {}", e);
                Carrier::from_text("")
            }
        };

        let carrier_type = if carrier.is_binary() { "binary" } else { "text" };
        if self.verbose {
            eprintln!("Loaded {} carrier ({} units)", carrier_type, carrier.len());
        }

        let secret_key = match load_secret_key(&self.key) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Warning: Could not load private key: {}", e);
                KeyPair::generate().into_secret_key()
            }
        };

        // Load verifying key if provided
        let verifying_key = self.verify.as_ref().and_then(|path| {
            match load_verifying_key(path) {
                Ok(k) => {
                    if self.verbose {
                        eprintln!("Will verify signature with sender's public key");
                    }
                    Some(k)
                }
                Err(e) => {
                    eprintln!("Warning: Could not load verifying key: {}", e);
                    None
                }
            }
        });

        let config = DecoderConfig {
            verbose: self.verbose,
            verifying_key: verifying_key.as_ref(),
        };

        // If output file is specified, decode as binary
        if let Some(output_path) = &self.output {
            let decoded = decode_bytes_with_carrier_config(&code, &carrier, &self.passphrase, &secret_key, &config);

            match std::fs::write(output_path, &decoded.data) {
                Ok(_) => {
                    eprintln!("Decoded {} bytes to {}", decoded.data.len(), output_path.display());
                }
                Err(e) => {
                    eprintln!("Failed to write output file: {}", e);
                }
            }

            show_signature_status(decoded.signature_valid, self.verbose);
            show_next_public_key(&decoded.next_public_key, self.verbose);

            if self.verbose {
                eprintln!();
                eprintln!("Byte fragments: {} fragments", decoded.fragments.len());
            }
        } else {
            // Decode as text
            let decoded = decode_with_carrier_config(&code, &carrier, &self.passphrase, &secret_key, &config);

            println!("{}", decoded.message);

            show_signature_status(decoded.signature_valid, self.verbose);
            show_next_public_key(&decoded.next_public_key, self.verbose);

            if self.verbose {
                eprintln!();
                eprintln!("Fragments: {:?}", decoded.fragments);
            }
        }
    }
}

/// Shows the signature verification status to the user.
fn show_signature_status(signature_valid: Option<bool>, verbose: bool) {
    match signature_valid {
        Some(true) => {
            eprintln!("Signature: VALID (message authenticated)");
        }
        Some(false) => {
            eprintln!("WARNING: Signature verification FAILED!");
            eprintln!("         The message may have been tampered with or signed by a different key.");
        }
        None => {
            if verbose {
                eprintln!("Signature: None (message was not signed or no verifying key provided)");
            }
        }
    }
}

/// Shows the next public key for forward secrecy ratchet.
fn show_next_public_key(next_public_key: &Option<Vec<u8>>, verbose: bool) {
    if let Some(key_bytes) = next_public_key {
        eprintln!();
        eprintln!("Forward Secrecy Ratchet:");
        eprintln!("  Sender included their NEXT public key for your reply.");

        // Convert bytes to X25519 PublicKey and encode as PEM
        if key_bytes.len() == 32 {
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(key_bytes);
            let public_key = x25519_dalek::PublicKey::from(key_array);

            use anyhide::crypto::encode_ephemeral_public_key_pem;
            let pem = encode_ephemeral_public_key_pem(&public_key);
            eprintln!("  Use this key when replying to maintain forward secrecy:");
            eprintln!("{}", pem);
            eprintln!("  Save this key and use it with --key when encoding your reply.");
        } else {
            eprintln!("  (Invalid key length: {} bytes)", key_bytes.len());
        }
    } else if verbose {
        eprintln!("Forward Secrecy: None (sender did not include next public key)");
    }
}

/// Joins split code parts back together.
fn join_code_parts(code: &str) -> String {
    if code.contains(',') {
        code.split(',')
            .map(|s| s.trim())
            .collect::<Vec<_>>()
            .join("")
    } else {
        code.to_string()
    }
}

/// Reads code from a file - either a text file or a QR image.
fn read_code_from_file(path: &PathBuf) -> Result<String> {
    let ext = path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "bmp" => {
            let data = read_qr_from_file(path)
                .with_context(|| format!("Failed to read QR code from {}", path.display()))?;
            Ok(BASE64.encode(&data))
        }
        _ => {
            std::fs::read_to_string(path)
                .map(|s| s.trim().to_string())
                .with_context(|| format!("Failed to read code from {}", path.display()))
        }
    }
}

/// Reads and concatenates code from multiple part files.
fn read_code_parts(parts: &[PathBuf]) -> Result<String> {
    // Check if all parts are QR images
    let all_qr = parts.iter().all(|p| {
        let ext = p.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "gif" | "bmp")
    });

    if all_qr {
        // QR mode: concatenate binary data, then encode to base64
        let mut combined_bytes = Vec::new();
        for (i, part_path) in parts.iter().enumerate() {
            let part_data = read_qr_from_file(part_path)
                .with_context(|| format!("Failed to read QR part {} from {}", i + 1, part_path.display()))?;
            combined_bytes.extend_from_slice(&part_data);
        }
        Ok(BASE64.encode(&combined_bytes))
    } else {
        // Text mode: concatenate text directly
        let mut combined = String::new();
        for (i, part_path) in parts.iter().enumerate() {
            let part_code = std::fs::read_to_string(part_path)
                .map(|s| s.trim().to_string())
                .with_context(|| format!("Failed to read part {} from {}", i + 1, part_path.display()))?;
            combined.push_str(&part_code);
        }
        Ok(combined)
    }
}
