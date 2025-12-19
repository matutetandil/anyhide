//! Decode command - extract hidden messages or files from a carrier.

use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Args;

use anyhide::crypto::{
    load_secret_key, load_verifying_key, KeyPair,
    load_unified_keys_for_contact, update_unified_public_key,
    load_private_key_for_contact, save_public_key_for_contact,
    save_ephemeral_public_key_pem,
};
use anyhide::qr::read_qr_from_file;
use anyhide::{decode_with_carrier_config, decode_bytes_with_carrier_config, Carrier, DecoderConfig};

use super::CommandExecutor;

/// Decode a message using a pre-shared carrier (ANY file).
///
/// NOTE: This command NEVER fails - it returns garbage if inputs are wrong.
/// This provides plausible deniability.
///
/// Multiple carriers can be provided with -c file1 -c file2 -c file3.
/// They MUST be the EXACT same files in the EXACT same order as encoding.
/// Wrong order = garbage (plausible deniability, N! combinations).
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

    /// Path to carrier file(s). Must be EXACT same files in EXACT same order as encoding!
    /// Multiple -c flags concatenate carriers. Wrong order = garbage (N! combinations).
    #[arg(short, long, required = true, num_args = 1..)]
    pub carriers: Vec<PathBuf>,

    /// Passphrase for decryption (must match encoding passphrase)
    #[arg(short, long)]
    pub passphrase: String,

    /// [DEPRECATED: use --my-key] Path to your private key
    #[arg(short, long)]
    pub key: Option<PathBuf>,

    /// Path to your private key file (your .key or ephemeral .key file)
    #[arg(long)]
    pub my_key: Option<PathBuf>,

    /// Path to sender's public key file (for auto-saving their next_public_key)
    /// Required with --ratchet for automatic key rotation
    #[arg(long)]
    pub their_key: Option<PathBuf>,

    /// Ephemeral key store file (.eph unified format)
    /// Use with --contact for automatic key management
    #[arg(long, conflicts_with_all = ["eph_keys", "eph_pubs"])]
    pub eph_file: Option<PathBuf>,

    /// Ephemeral private keys file (.eph.key, separated format)
    /// Use with --eph-pubs and --contact
    #[arg(long, requires = "eph_pubs")]
    pub eph_keys: Option<PathBuf>,

    /// Ephemeral public keys file (.eph.pub, separated format)
    /// Use with --eph-keys and --contact
    #[arg(long, requires = "eph_keys")]
    pub eph_pubs: Option<PathBuf>,

    /// Contact name in the ephemeral key store (required with --eph-file or --eph-keys/--eph-pubs)
    #[arg(long)]
    pub contact: Option<String>,

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

        // Load carrier(s) - multiple carriers are concatenated in order
        let carrier = match Carrier::from_files(&self.carriers) {
            Ok(c) => c,
            Err(e) => {
                let paths: Vec<_> = self.carriers.iter().map(|p| p.display().to_string()).collect();
                eprintln!("Warning: Could not read carrier file(s) {}: {}", paths.join(", "), e);
                Carrier::from_bytes(vec![]) // Empty carrier for plausible deniability
            }
        };

        let carrier_type = if carrier.is_binary() { "binary" } else { "text" };
        if self.verbose {
            if self.carriers.len() > 1 {
                eprintln!(
                    "Loaded {} carriers concatenated as {} ({} units total)",
                    self.carriers.len(),
                    carrier_type,
                    carrier.len()
                );
            } else {
                eprintln!("Loaded {} carrier ({} units)", carrier_type, carrier.len());
            }
        }

        // Resolve private key from various sources
        let (secret_key, eph_store_info) = self.resolve_my_private_key();

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

            // Auto-save next_public_key if present
            if let Some(ref next_key) = decoded.next_public_key {
                self.save_their_next_public_key(next_key, &eph_store_info);
            }

            if self.verbose {
                show_next_public_key(&decoded.next_public_key);
                eprintln!();
                eprintln!("Byte fragments: {} fragments", decoded.fragments.len());
            }
        } else {
            // Decode as text
            let decoded = decode_with_carrier_config(&code, &carrier, &self.passphrase, &secret_key, &config);

            println!("{}", decoded.message);

            show_signature_status(decoded.signature_valid, self.verbose);

            // Auto-save next_public_key if present
            if let Some(ref next_key) = decoded.next_public_key {
                self.save_their_next_public_key(next_key, &eph_store_info);
            }

            if self.verbose {
                show_next_public_key(&decoded.next_public_key);
                eprintln!();
                eprintln!("Fragments: {:?}", decoded.fragments);
            }
        }
    }

    /// Resolves my private key from various sources.
    /// Returns (secret_key, optional_eph_store_info)
    fn resolve_my_private_key(&self) -> (x25519_dalek::StaticSecret, Option<EphStoreInfo>) {
        // Priority 1: Unified ephemeral store (.eph)
        if let Some(eph_path) = &self.eph_file {
            let contact = match &self.contact {
                Some(c) => c,
                None => {
                    eprintln!("Warning: --contact is required when using --eph-file");
                    return (KeyPair::generate().into_secret_key(), None);
                }
            };

            match load_unified_keys_for_contact(eph_path, contact) {
                Ok(keys) => {
                    if self.verbose {
                        eprintln!("Loaded private key for contact '{}' from {}", contact, eph_path.display());
                    }
                    let store_info = EphStoreInfo {
                        pub_store: eph_path.clone(),
                        key_store: None,
                        contact: contact.clone(),
                        is_unified: true,
                    };
                    return (keys.my_private, Some(store_info));
                }
                Err(e) => {
                    eprintln!("Warning: Could not load keys for contact '{}': {}", contact, e);
                    return (KeyPair::generate().into_secret_key(), None);
                }
            }
        }

        // Priority 2: Separated ephemeral stores (.eph.key + .eph.pub)
        if let (Some(eph_keys), Some(eph_pubs)) = (&self.eph_keys, &self.eph_pubs) {
            let contact = match &self.contact {
                Some(c) => c,
                None => {
                    eprintln!("Warning: --contact is required when using --eph-keys/--eph-pubs");
                    return (KeyPair::generate().into_secret_key(), None);
                }
            };

            match load_private_key_for_contact(eph_keys, contact) {
                Ok(key) => {
                    if self.verbose {
                        eprintln!("Loaded private key for contact '{}' from {}", contact, eph_keys.display());
                    }
                    let store_info = EphStoreInfo {
                        pub_store: eph_pubs.clone(),
                        key_store: Some(eph_keys.clone()),
                        contact: contact.clone(),
                        is_unified: false,
                    };
                    return (key, Some(store_info));
                }
                Err(e) => {
                    eprintln!("Warning: Could not load private key for contact '{}': {}", contact, e);
                    return (KeyPair::generate().into_secret_key(), None);
                }
            }
        }

        // Priority 3: --my-key (new parameter)
        if let Some(my_key_path) = &self.my_key {
            match load_secret_key(my_key_path) {
                Ok(key) => {
                    if self.verbose {
                        eprintln!("Loaded private key from {}", my_key_path.display());
                    }
                    return (key, None);
                }
                Err(e) => {
                    eprintln!("Warning: Could not load private key from {}: {}", my_key_path.display(), e);
                    return (KeyPair::generate().into_secret_key(), None);
                }
            }
        }

        // Priority 4: --key (deprecated)
        if let Some(key_path) = &self.key {
            eprintln!("WARNING: --key is deprecated. Use --my-key instead.");

            match load_secret_key(key_path) {
                Ok(key) => {
                    return (key, None);
                }
                Err(e) => {
                    eprintln!("Warning: Could not load private key from {}: {}", key_path.display(), e);
                    return (KeyPair::generate().into_secret_key(), None);
                }
            }
        }

        // No key provided - for plausible deniability, generate a random key
        eprintln!("Warning: No private key specified. Use --my-key, --eph-file, or --eph-keys/--eph-pubs");
        (KeyPair::generate().into_secret_key(), None)
    }

    /// Saves the sender's next public key for forward secrecy ratchet.
    fn save_their_next_public_key(
        &self,
        next_key_bytes: &[u8],
        store_info: &Option<EphStoreInfo>,
    ) {
        // Convert bytes to PublicKey
        if next_key_bytes.len() != 32 {
            if self.verbose {
                eprintln!("Warning: Invalid next_public_key length: {} bytes", next_key_bytes.len());
            }
            return;
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(next_key_bytes);
        let public_key = x25519_dalek::PublicKey::from(key_array);

        // Option 1: Ephemeral store (unified or separated)
        if let Some(info) = store_info {
            let result = if info.is_unified {
                // Unified format: update public key in .eph file
                update_unified_public_key(&info.pub_store, &info.contact, &public_key)
            } else {
                // Separated format: save to .eph.pub file
                save_public_key_for_contact(&info.pub_store, &info.contact, &public_key)
            };

            match result {
                Ok(_) => {
                    if self.verbose {
                        eprintln!("Saved sender's next public key for contact '{}' to {}", info.contact, info.pub_store.display());
                    }
                }
                Err(e) => {
                    if self.verbose {
                        eprintln!("Warning: Could not save next public key: {}", e);
                    }
                }
            }
            return;
        }

        // Option 2: Loose ephemeral file (--their-key)
        if let Some(their_key_path) = &self.their_key {
            match save_ephemeral_public_key_pem(&public_key, their_key_path) {
                Ok(_) => {
                    if self.verbose {
                        eprintln!("Saved sender's next public key to {}", their_key_path.display());
                    }
                }
                Err(e) => {
                    if self.verbose {
                        eprintln!("Warning: Could not save next public key: {}", e);
                    }
                }
            }
            return;
        }

        // No destination for saving - just log if verbose
        if self.verbose {
            eprintln!("Note: Sender included next_public_key but no --their-key or --eph-file specified");
        }
    }
}

/// Ephemeral store info for tracking which files to use
struct EphStoreInfo {
    /// For unified format: the .eph file. For separated: the .eph.pub file
    pub_store: PathBuf,
    /// For separated format only: the .eph.key file
    #[allow(dead_code)]
    key_store: Option<PathBuf>,
    /// Contact name
    contact: String,
    /// Is this unified format?
    is_unified: bool,
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

/// Shows the next public key for forward secrecy ratchet (verbose mode only).
fn show_next_public_key(next_public_key: &Option<Vec<u8>>) {
    if let Some(key_bytes) = next_public_key {
        eprintln!();
        eprintln!("Forward Secrecy Ratchet: Sender included their next public key");

        // Convert bytes to X25519 PublicKey and encode as PEM
        if key_bytes.len() == 32 {
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(key_bytes);
            let public_key = x25519_dalek::PublicKey::from(key_array);

            use anyhide::crypto::encode_ephemeral_public_key_pem;
            let pem = encode_ephemeral_public_key_pem(&public_key);
            eprintln!("{}", pem);
        } else {
            eprintln!("  (Invalid key length: {} bytes)", key_bytes.len());
        }
    } else {
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
