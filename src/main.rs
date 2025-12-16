//! Anyhide - Hide anything in anything
//!
//! A CLI tool for advanced steganography with hybrid encryption.
//! Uses pre-shared carriers (any file) - only encrypted codes are transmitted.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::{self, Read};
use std::path::PathBuf;

use anyhide::crypto::{
    decrypt_multi, encrypt_multi, load_public_key, load_secret_key, load_signing_key,
    load_verifying_key, KeyPair, MultiRecipientData, SigningKeyPair,
};
use anyhide::qr::{generate_qr_to_file, qr_capacity_info, read_qr_from_file, QrConfig, QrFormat};
use anyhide::{
    decode_with_carrier_config, encode_with_carrier_config, Carrier, DecoderConfig, EncoderConfig,
};

/// Anyhide - Hide anything in anything
///
/// Advanced steganography with compression, forward secrecy, and universal carrier support.
/// Use ANY file as a pre-shared carrier - only encrypted codes are transmitted.
#[derive(Parser)]
#[command(name = "anyhide")]
#[command(version = "0.7.0")]
#[command(about = "Advanced steganography with compression, forward secrecy, and multi-carrier support")]
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
        #[arg(short, long, default_value = "anyhide")]
        output: PathBuf,
    },

    /// Encode a message using a pre-shared carrier (ANY file)
    ///
    /// The carrier can be ANY file:
    /// - Text files (.txt, .md, .csv, .json, .xml, .html) - substring matching
    /// - Any other file (images, audio, video, PDFs, executables, etc.) - byte-sequence matching
    ///
    /// Output is always an encrypted code (base64) - the carrier is NEVER modified.
    /// The code does NOT reveal whether the hidden data is text or binary.
    Encode {
        /// Path to carrier file (any file - text uses substring matching, others use byte matching)
        #[arg(short, long)]
        carrier: PathBuf,

        /// Text message to encode (mutually exclusive with --file)
        #[arg(short, long, conflicts_with = "file")]
        message: Option<String>,

        /// Binary file to encode (mutually exclusive with --message)
        /// Use this to hide any file (zip, image, executable, etc.) inside the carrier
        #[arg(short, long, conflicts_with = "message")]
        file: Option<PathBuf>,

        /// Passphrase for encryption (also determines fragmentation and positions)
        #[arg(short, long)]
        passphrase: String,

        /// Path to recipient's public key
        #[arg(short, long)]
        key: PathBuf,

        /// Verbose output (shows fragmentation and positions)
        #[arg(short, long)]
        verbose: bool,

        /// Generate QR code and save to this path (in addition to printing the code)
        #[arg(long)]
        qr: Option<PathBuf>,

        /// QR code format: png (default), svg, or ascii
        #[arg(long, default_value = "png")]
        qr_format: String,

        /// Sign the message with your signing key (Ed25519)
        /// The recipient can verify the signature with your .sign.pub key
        #[arg(long)]
        sign: Option<PathBuf>,

        /// Minimum carrier coverage required (0-100, default: 100)
        /// At 100%, all message characters must exist exactly in the carrier.
        /// Lower values allow encoding but may leak information about the message.
        /// WARNING: Values below 100 reduce security - only use with trusted carriers.
        #[arg(long, default_value = "100", value_parser = clap::value_parser!(u8).range(0..=100))]
        min_coverage: u8,

        /// Message expiration time
        /// Relative: "+30m" (30 minutes), "+24h" (24 hours), "+7d" (7 days)
        /// Absolute: "2025-12-31" or "2025-12-31T23:59:59"
        /// After expiration, decode returns garbage (plausible deniability)
        #[arg(long)]
        expires: Option<String>,

        /// Split the code into N parts (2-10)
        /// Each part is independent base64 without indices
        /// The correct ORDER is part of the secret - wrong order = garbage
        /// Parts can be sent via different channels for extra security
        #[arg(long, value_parser = clap::value_parser!(u8).range(2..=10))]
        split: Option<u8>,
    },

    /// Decode a message using a pre-shared carrier (ANY file)
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
    Decode {
        /// The encrypted code (direct text)
        #[arg(long, conflicts_with_all = ["code_qr", "code_file", "parts"])]
        code: Option<String>,

        /// Read code from a QR image file (.png, .jpg)
        #[arg(long, conflicts_with_all = ["code", "code_file", "parts"])]
        code_qr: Option<PathBuf>,

        /// Read code from a text file
        #[arg(long, conflicts_with_all = ["code", "code_qr", "parts"])]
        code_file: Option<PathBuf>,

        /// Split code parts (text files or QR images, in order)
        /// Order matters - wrong order = garbage (plausible deniability)
        #[arg(long, num_args = 2..=10, conflicts_with_all = ["code", "code_qr", "code_file"])]
        parts: Option<Vec<PathBuf>>,

        /// Path to carrier file (must be the EXACT same file used for encoding)
        #[arg(short, long)]
        carrier: PathBuf,

        /// Passphrase for decryption (must match encoding passphrase)
        #[arg(short, long)]
        passphrase: String,

        /// Path to your private key
        #[arg(short, long)]
        key: PathBuf,

        /// Output file for decoded data (required for binary data)
        /// If not specified, prints decoded text to stdout
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Verbose output (shows extracted fragments)
        #[arg(short, long)]
        verbose: bool,

        /// Verify the sender's signature with their signing public key
        /// If provided and message is signed, verifies the signature
        #[arg(long)]
        verify: Option<PathBuf>,
    },

    /// Encrypt a message for multiple recipients
    #[command(name = "multi-encrypt")]
    MultiEncrypt {
        /// Message to encrypt (reads from stdin if not provided)
        #[arg(short, long)]
        message: Option<String>,

        /// Passphrase for encryption
        #[arg(short, long)]
        passphrase: String,

        /// Paths to recipients' public keys (can specify multiple)
        #[arg(short, long, num_args = 1..)]
        keys: Vec<PathBuf>,

        /// Output file for encrypted data (prints base64 to stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Decrypt a multi-recipient message
    #[command(name = "multi-decrypt")]
    MultiDecrypt {
        /// Encrypted data (base64 string or file path)
        #[arg(short, long)]
        input: String,

        /// Passphrase for decryption
        #[arg(short, long)]
        passphrase: String,

        /// Path to your private key
        #[arg(short, long)]
        key: PathBuf,
    },

    /// Generate a QR code from an Anyhide code (uses Base45 for optimal capacity)
    #[command(name = "qr-generate")]
    QrGenerate {
        /// Anyhide code (base64 string) - reads from stdin if not provided
        #[arg(short, long)]
        code: Option<String>,

        /// Output file path (PNG, SVG, or TXT for ASCII)
        #[arg(short, long)]
        output: PathBuf,

        /// Output format: png (default), svg, or ascii
        #[arg(short, long, default_value = "png")]
        format: String,
    },

    /// Read a QR code and extract the Anyhide code
    #[command(name = "qr-read")]
    QrRead {
        /// Path to image containing QR code
        #[arg(short, long)]
        input: PathBuf,

        /// Output as base64 (default) or raw bytes to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show QR code capacity info for a given data size
    #[command(name = "qr-info")]
    QrInfo {
        /// Data size in bytes (or provide --code to calculate from actual data)
        #[arg(short, long)]
        size: Option<usize>,

        /// Anyhide code to analyze
        #[arg(short, long)]
        code: Option<String>,
    },

    /// Update anyhide to the latest version
    ///
    /// Downloads the latest release from GitHub and replaces the current binary.
    /// Use --check to only check for updates without installing.
    Update {
        /// Only check for updates, don't install
        #[arg(long)]
        check: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output } => keygen(&output)?,

        Commands::Encode {
            carrier,
            message,
            file,
            passphrase,
            key,
            verbose,
            qr,
            qr_format,
            sign,
            min_coverage,
            expires,
            split,
        } => encode_cmd(&carrier, message, file.as_ref(), &passphrase, &key, verbose, qr.as_ref(), &qr_format, sign.as_ref(), min_coverage, expires.as_deref(), split)?,

        Commands::Decode {
            code,
            code_qr,
            code_file,
            parts,
            carrier,
            passphrase,
            key,
            output,
            verbose,
            verify,
        } => decode_cmd(code.as_deref(), code_qr.as_ref(), code_file.as_ref(), parts.as_ref(), &carrier, &passphrase, &key, output.as_ref(), verbose, verify.as_ref()),

        Commands::MultiEncrypt {
            message,
            passphrase,
            keys,
            output,
        } => multi_encrypt(message, &passphrase, &keys, output.as_ref())?,

        Commands::MultiDecrypt {
            input,
            passphrase,
            key,
        } => multi_decrypt(&input, &passphrase, &key)?,

        Commands::QrGenerate {
            code,
            output,
            format,
        } => qr_generate(code, &output, &format)?,

        Commands::QrRead { input, output } => qr_read(&input, output.as_ref())?,

        Commands::QrInfo { size, code } => qr_info(size, code.as_ref())?,

        Commands::Update { check } => update_cmd(check)?,
    }

    Ok(())
}

/// Parses an expiration string into a Unix timestamp.
///
/// Supported formats:
/// - Relative: "+30m" (30 minutes), "+24h" (24 hours), "+7d" (7 days), "+1w" (1 week)
/// - Absolute: "2025-12-31" or "2025-12-31T23:59:59"
///
/// Returns None if parsing fails.
fn parse_expiration(expires: &str) -> Option<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();

    let expires = expires.trim();

    // Relative time format: +Nm, +Nh, +Nd, +Nw
    if expires.starts_with('+') {
        let suffix = expires.chars().last()?;
        let value: u64 = expires[1..expires.len() - 1].parse().ok()?;

        let seconds = match suffix {
            'm' => value * 60,
            'h' => value * 60 * 60,
            'd' => value * 60 * 60 * 24,
            'w' => value * 60 * 60 * 24 * 7,
            _ => return None,
        };

        return Some(now + seconds);
    }

    // Absolute date format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS
    // Simple parsing without external crates
    let parts: Vec<&str> = expires.split('T').collect();

    let date_parts: Vec<u32> = parts[0]
        .split('-')
        .filter_map(|s| s.parse().ok())
        .collect();

    if date_parts.len() != 3 {
        return None;
    }

    let (year, month, day) = (date_parts[0], date_parts[1], date_parts[2]);

    let (hour, minute, second) = if parts.len() > 1 {
        let time_parts: Vec<u32> = parts[1]
            .split(':')
            .filter_map(|s| s.parse().ok())
            .collect();
        if time_parts.len() >= 2 {
            (
                time_parts[0],
                time_parts[1],
                time_parts.get(2).copied().unwrap_or(0),
            )
        } else {
            (23, 59, 59) // End of day if no time specified
        }
    } else {
        (23, 59, 59) // End of day if no time specified
    };

    // Convert to timestamp (simplified calculation - doesn't handle all edge cases)
    // Days since 1970-01-01
    let mut days: i64 = 0;

    // Add years
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    // Add months
    let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += month_days[(m - 1) as usize] as i64;
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }

    // Add days
    days += (day - 1) as i64;

    let timestamp = days * 86400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64;

    if timestamp < 0 {
        return None;
    }

    Some(timestamp as u64)
}

/// Helper function to check if a year is a leap year.
fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Splits a code into N approximately equal parts.
/// Parts are split at character boundaries (not byte boundaries).
fn split_code(code: &str, n: usize) -> Vec<String> {
    if n <= 1 {
        return vec![code.to_string()];
    }

    let chars: Vec<char> = code.chars().collect();
    let total = chars.len();
    let base_size = total / n;
    let remainder = total % n;

    let mut parts = Vec::with_capacity(n);
    let mut start = 0;

    for i in 0..n {
        // Distribute remainder across first parts
        let size = base_size + if i < remainder { 1 } else { 0 };
        let end = start + size;
        parts.push(chars[start..end].iter().collect());
        start = end;
    }

    parts
}

/// Joins split code parts back together.
/// Parts can be separated by commas or provided in order.
fn join_code_parts(code: &str) -> String {
    // Check if it looks like split parts (contains commas)
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
/// Determines type by file extension.
fn read_code_from_file(path: &PathBuf) -> Result<String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    let ext = path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "bmp" => {
            // Read from QR image - returns binary data, need to encode to base64
            let data = read_qr_from_file(path)
                .with_context(|| format!("Failed to read QR code from {}", path.display()))?;
            Ok(BASE64.encode(&data))
        }
        _ => {
            // Read as text file
            std::fs::read_to_string(path)
                .map(|s| s.trim().to_string())
                .with_context(|| format!("Failed to read code from {}", path.display()))
        }
    }
}

/// Reads and concatenates code from multiple part files.
/// Parts can be text files or QR images.
/// For QR images: concatenate binary data, then encode to base64.
/// For text files: concatenate the text directly.
fn read_code_parts(parts: &[PathBuf]) -> Result<String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

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

/// Generates new key pairs (encryption + signing) and saves to files.
fn keygen(output: &PathBuf) -> Result<()> {
    // Generate X25519 encryption key pair
    let keypair = KeyPair::generate();
    keypair
        .save_to_files(output)
        .context("Failed to save encryption key pair")?;

    // Generate Ed25519 signing key pair
    let signing_keypair = SigningKeyPair::generate();
    signing_keypair
        .save_to_files(output)
        .context("Failed to save signing key pair")?;

    let pub_path = output.with_extension("pub");
    let key_path = output.with_extension("key");

    // Construct signing key paths
    let sign_pub_path = {
        let mut p = output.as_os_str().to_os_string();
        p.push(".sign.pub");
        std::path::PathBuf::from(p)
    };
    let sign_key_path = {
        let mut p = output.as_os_str().to_os_string();
        p.push(".sign.key");
        std::path::PathBuf::from(p)
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

/// Encodes a message or file into an encrypted code.
/// Supports text messages (--message) or binary files (--file).
/// Carrier type is auto-detected by extension.
/// Optionally generates a QR code if --qr is specified.
fn encode_cmd(
    carrier_path: &PathBuf,
    message: Option<String>,
    file: Option<&PathBuf>,
    passphrase: &str,
    key_path: &PathBuf,
    verbose: bool,
    qr_output: Option<&PathBuf>,
    qr_format: &str,
    sign_key_path: Option<&PathBuf>,
    min_coverage: u8,
    expires: Option<&str>,
    split: Option<u8>,
) -> Result<()> {
    // Load carrier with auto-detection based on file extension
    let carrier = Carrier::from_file(carrier_path)
        .with_context(|| format!("Failed to read carrier from {}", carrier_path.display()))?;

    let carrier_type = if carrier.is_binary() { "binary" } else { "text" };
    if verbose {
        eprintln!("Loaded {} carrier ({} units)", carrier_type, carrier.len());
    }

    let public_key = load_public_key(key_path)
        .with_context(|| format!("Failed to load public key from {}", key_path.display()))?;

    // Load signing key if provided
    let signing_key = if let Some(sign_path) = sign_key_path {
        let key = load_signing_key(sign_path)
            .with_context(|| format!("Failed to load signing key from {}", sign_path.display()))?;
        if verbose {
            eprintln!("Message will be signed with Ed25519");
        }
        Some(key)
    } else {
        None
    };

    // Parse expiration time if provided
    let expires_at = if let Some(exp_str) = expires {
        let ts = parse_expiration(exp_str)
            .with_context(|| format!("Invalid expiration format: '{}'. Use '+30m', '+24h', '+7d', or '2025-12-31'", exp_str))?;
        if verbose {
            // Format timestamp for display
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let remaining = ts.saturating_sub(now);
            let hours = remaining / 3600;
            let mins = (remaining % 3600) / 60;
            eprintln!("Message expires in {}h {}m (timestamp: {})", hours, mins, ts);
        }
        Some(ts)
    } else {
        None
    };

    let config = EncoderConfig {
        verbose,
        signing_key: signing_key.as_ref(),
        min_coverage: min_coverage as f64 / 100.0,
        expires_at,
    };

    // Determine if we're encoding text or binary
    let encoded = if let Some(file_path) = file {
        // Binary file encoding
        let data = std::fs::read(file_path)
            .with_context(|| format!("Failed to read file {}", file_path.display()))?;

        if data.is_empty() {
            anyhow::bail!("File is empty");
        }

        if verbose {
            eprintln!("Encoding binary file: {} ({} bytes)", file_path.display(), data.len());
        }

        anyhide::encode_bytes_with_carrier_config(&carrier, &data, passphrase, &public_key, &config)
            .context("Failed to encode file")?
    } else {
        // Text message encoding
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

        if verbose {
            eprintln!("Encoding text message ({} chars)", message.len());
        }

        encode_with_carrier_config(&carrier, &message, passphrase, &public_key, &config)
            .context("Failed to encode message")?
    };

    // Output code (split if requested)
    if let Some(n) = split {
        let parts = split_code(&encoded.code, n as usize);
        for (i, part) in parts.iter().enumerate() {
            println!("part-{}: {}", i + 1, part);
        }
        if verbose {
            eprintln!();
            eprintln!("Split into {} parts ({} chars each approx)", n, encoded.code.len() / n as usize);
            eprintln!("IMPORTANT: Parts must be combined in EXACT order to decode");
        }
    } else {
        println!("{}", encoded.code);
    }

    if verbose {
        eprintln!();
        eprintln!(
            "Encoded {} real fragments ({} total with padding)",
            encoded.real_fragment_count, encoded.total_fragments
        );
    }

    // Generate QR code if requested
    if let Some(qr_path) = qr_output {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let format = match qr_format.to_lowercase().as_str() {
            "png" => QrFormat::Png,
            "svg" => QrFormat::Svg,
            "ascii" | "txt" => QrFormat::Ascii,
            _ => anyhow::bail!("Unknown QR format: {}. Use: png, svg, or ascii", qr_format),
        };

        let qr_config = QrConfig {
            format,
            ..Default::default()
        };

        // If split is enabled, generate multiple QR codes
        if let Some(n) = split {
            // Decode the full code to binary, then split the binary data
            let full_data = BASE64.decode(&encoded.code)
                .context("Failed to decode code for QR splitting")?;

            let stem = qr_path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("code");
            let ext = qr_path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("png");
            let parent = qr_path.parent().unwrap_or(std::path::Path::new("."));

            // Split binary data into n parts
            let chunk_size = (full_data.len() + n as usize - 1) / n as usize;
            let binary_parts: Vec<&[u8]> = full_data.chunks(chunk_size).collect();

            eprintln!();
            for (i, part_data) in binary_parts.iter().enumerate() {
                let part_path = parent.join(format!("{}-{}.{}", stem, i + 1, ext));

                generate_qr_to_file(part_data, &part_path, &qr_config)
                    .with_context(|| format!("Failed to generate QR code part {}", i + 1))?;

                let info = qr_capacity_info(part_data.len());
                eprintln!("QR part {}/{} saved: {} (QR version: {}, {} bytes)", i + 1, n, part_path.display(), info.qr_version, part_data.len());
            }
            eprintln!("IMPORTANT: Decode with --parts in EXACT order");
        } else {
            let data = BASE64
                .decode(&encoded.code)
                .context("Failed to decode generated code for QR")?;

            generate_qr_to_file(&data, qr_path, &qr_config)
                .context("Failed to generate QR code")?;

            let info = qr_capacity_info(data.len());
            eprintln!();
            eprintln!("QR code saved: {}", qr_path.display());
            eprintln!("  QR version: {} | Format: {}", info.qr_version, qr_format);
        }
    }

    Ok(())
}

/// Decodes an encrypted code back to a message or file.
/// Use -o/--output to write raw bytes to a file (required for binary data).
/// Without -o, output is printed as text.
/// NEVER fails - returns garbage if inputs are wrong (plausible deniability).
fn decode_cmd(
    code: Option<&str>,
    code_qr: Option<&PathBuf>,
    code_file: Option<&PathBuf>,
    parts: Option<&Vec<PathBuf>>,
    carrier_path: &PathBuf,
    passphrase: &str,
    key_path: &PathBuf,
    output: Option<&PathBuf>,
    verbose: bool,
    verify_key_path: Option<&PathBuf>,
) {
    // Resolve code from the various input sources
    let code: String = if let Some(c) = code {
        // Direct text, possibly comma-separated parts
        join_code_parts(c)
    } else if let Some(qr_path) = code_qr {
        // Read from QR image
        match read_code_from_file(qr_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Warning: Could not read QR code: {}", e);
                String::new()
            }
        }
    } else if let Some(file_path) = code_file {
        // Read from text file
        match read_code_from_file(file_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Warning: Could not read code file: {}", e);
                String::new()
            }
        }
    } else if let Some(part_paths) = parts {
        // Read and concatenate parts
        match read_code_parts(part_paths) {
            Ok(c) => {
                if verbose {
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
    let carrier = match Carrier::from_file(carrier_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: Could not read carrier file: {}", e);
            // Create an empty text carrier for fallback
            Carrier::from_text("")
        }
    };

    let carrier_type = if carrier.is_binary() { "binary" } else { "text" };
    if verbose {
        eprintln!("Loaded {} carrier ({} units)", carrier_type, carrier.len());
    }

    let secret_key = match load_secret_key(key_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Warning: Could not load private key: {}", e);
            KeyPair::generate().into_secret_key()
        }
    };

    // Load verifying key if provided
    let verifying_key = verify_key_path.and_then(|path| {
        match load_verifying_key(path) {
            Ok(k) => {
                if verbose {
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
        verbose,
        verifying_key: verifying_key.as_ref(),
    };

    // If output file is specified, decode as binary
    if let Some(output_path) = output {
        let decoded = anyhide::decode_bytes_with_carrier_config(&code, &carrier, passphrase, &secret_key, &config);

        match std::fs::write(output_path, &decoded.data) {
            Ok(_) => {
                eprintln!("Decoded {} bytes to {}", decoded.data.len(), output_path.display());
            }
            Err(e) => {
                eprintln!("Failed to write output file: {}", e);
            }
        }

        // Show signature verification result
        show_signature_status(decoded.signature_valid, verbose);

        if verbose {
            eprintln!();
            eprintln!("Byte fragments: {} fragments", decoded.fragments.len());
        }
    } else {
        // Decode as text
        let decoded = decode_with_carrier_config(&code, &carrier, passphrase, &secret_key, &config);

        println!("{}", decoded.message);

        // Show signature verification result
        show_signature_status(decoded.signature_valid, verbose);

        if verbose {
            eprintln!();
            eprintln!("Fragments: {:?}", decoded.fragments);
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

/// Encrypts a message for multiple recipients.
fn multi_encrypt(
    message: Option<String>,
    passphrase: &str,
    key_paths: &[PathBuf],
    output: Option<&PathBuf>,
) -> Result<()> {
    if key_paths.is_empty() {
        anyhow::bail!("At least one recipient public key is required");
    }

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

    // Load all public keys
    let mut public_keys = Vec::with_capacity(key_paths.len());
    for path in key_paths {
        let key = load_public_key(path)
            .with_context(|| format!("Failed to load public key from {}", path.display()))?;
        public_keys.push(key);
    }

    // Encrypt for all recipients
    let encrypted = encrypt_multi(message.as_bytes(), passphrase, &public_keys)
        .context("Failed to encrypt message")?;

    // Serialize
    let bytes = encrypted.to_bytes().context("Failed to serialize encrypted data")?;

    if let Some(output_path) = output {
        std::fs::write(output_path, &bytes)
            .with_context(|| format!("Failed to write to {}", output_path.display()))?;
        println!("Encrypted data written to {}", output_path.display());
    } else {
        // Output as base64
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        println!("{}", BASE64.encode(&bytes));
    }

    println!("  Message size: {} bytes", message.len());
    println!("  Recipients: {}", key_paths.len());
    println!("  Encrypted size: {} bytes", bytes.len());

    Ok(())
}

/// Decrypts a multi-recipient message.
fn multi_decrypt(input: &str, passphrase: &str, key_path: &PathBuf) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    // Try to read as file first, then as base64
    let bytes = if std::path::Path::new(input).exists() {
        std::fs::read(input).with_context(|| format!("Failed to read file {}", input))?
    } else {
        BASE64
            .decode(input)
            .context("Failed to decode base64 input")?
    };

    let secret_key = load_secret_key(key_path)
        .with_context(|| format!("Failed to load private key from {}", key_path.display()))?;

    // Deserialize
    let encrypted =
        MultiRecipientData::from_bytes(&bytes).context("Failed to parse encrypted data")?;

    // Decrypt
    let decrypted = decrypt_multi(&encrypted, passphrase, &secret_key)
        .context("Failed to decrypt message")?;

    // Output as string
    let message = String::from_utf8_lossy(&decrypted);
    println!("{}", message);

    Ok(())
}

/// Generates a QR code from an Anyhide code.
fn qr_generate(code: Option<String>, output: &PathBuf, format: &str) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    // Get the code from argument or stdin
    let code_str = match code {
        Some(c) => c,
        None => {
            eprintln!("Reading Anyhide code from stdin (Ctrl+D to finish):");
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .context("Failed to read code from stdin")?;
            buffer.trim().to_string()
        }
    };

    if code_str.is_empty() {
        anyhow::bail!("Code cannot be empty");
    }

    // Decode base64 to get raw bytes
    let data = BASE64
        .decode(&code_str)
        .context("Failed to decode base64 Anyhide code")?;

    // Determine output format
    let qr_format = match format.to_lowercase().as_str() {
        "png" => QrFormat::Png,
        "svg" => QrFormat::Svg,
        "ascii" | "txt" => QrFormat::Ascii,
        _ => anyhow::bail!("Unknown format: {}. Use: png, svg, or ascii", format),
    };

    // Generate QR code
    let config = QrConfig {
        format: qr_format,
        ..Default::default()
    };

    generate_qr_to_file(&data, output, &config)
        .context("Failed to generate QR code")?;

    // Show capacity info
    let info = qr_capacity_info(data.len());

    println!("QR code generated: {}", output.display());
    println!("  Original size: {} bytes", data.len());
    println!("  Base45 encoded: ~{} chars", info.base45_chars);
    println!("  QR version: {}", info.qr_version);
    println!("  Format: {}", format);

    Ok(())
}

/// Reads a QR code and extracts the Anyhide code.
fn qr_read(input: &PathBuf, output: Option<&PathBuf>) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    // Read QR code
    let data = read_qr_from_file(input)
        .with_context(|| format!("Failed to read QR code from {}", input.display()))?;

    if let Some(output_path) = output {
        // Write raw bytes to file
        std::fs::write(output_path, &data)
            .with_context(|| format!("Failed to write to {}", output_path.display()))?;
        println!("Anyhide code written to: {}", output_path.display());
        println!("  Size: {} bytes", data.len());
    } else {
        // Output as base64 (standard Anyhide code format)
        let base64_code = BASE64.encode(&data);
        println!("{}", base64_code);
    }

    Ok(())
}

/// Shows QR code capacity information.
fn qr_info(size: Option<usize>, code: Option<&String>) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    let data_size = if let Some(s) = size {
        s
    } else if let Some(c) = code {
        BASE64
            .decode(c)
            .context("Failed to decode base64 code")?
            .len()
    } else {
        anyhow::bail!("Provide either --size or --code");
    };

    let info = qr_capacity_info(data_size);

    println!("QR Code Capacity Analysis");
    println!("========================");
    println!("  Data size: {} bytes", info.data_bytes);
    println!("  Base45 encoded: ~{} characters", info.base45_chars);

    if info.fits_in_qr {
        println!("  QR version needed: {} (of 40)", info.qr_version);
        println!("  Status: FITS in standard QR code");

        // Provide some context
        if info.qr_version <= 10 {
            println!("  Note: Small QR code, easy to scan");
        } else if info.qr_version <= 25 {
            println!("  Note: Medium QR code, should scan well");
        } else {
            println!("  Note: Large QR code, may need good camera");
        }
    } else {
        println!("  Status: TOO LARGE for standard QR code");
        println!("  Maximum data: ~2000 bytes");
        println!("  Consider: Split message or use shorter carrier");
    }

    // Show Base45 vs Base64 comparison
    let base64_size = (data_size * 4 + 2) / 3;
    println!();
    println!("Encoding comparison for QR:");
    println!("  Base45 (alphanumeric mode): ~{} chars", info.base45_chars);
    println!("  Base64 (byte mode): ~{} chars", base64_size);
    println!(
        "  Base45 advantage: ~{:.0}% more capacity",
        (1.0 - info.base45_chars as f64 / base64_size as f64 / 1.5) * 100.0
    );

    Ok(())
}

/// Updates anyhide to the latest version from GitHub releases.
fn update_cmd(check_only: bool) -> Result<()> {
    use self_update::backends::github::Update;
    use self_update::cargo_crate_version;

    println!("Checking for updates...");

    let current_version = cargo_crate_version!();

    // Determine target based on OS and architecture
    let target = get_update_target();

    let update = Update::configure()
        .repo_owner("matutetandil")
        .repo_name("anyhide")
        .bin_name("anyhide")
        .target(&target)
        .current_version(current_version)
        .no_confirm(true)
        .build()
        .context("Failed to configure updater")?;

    let latest = update
        .get_latest_release()
        .context("Failed to fetch latest release")?;

    println!("  Current version: v{}", current_version);
    println!("  Latest version:  {}", latest.version);

    if latest.version == current_version {
        println!("\nYou're already on the latest version!");
        return Ok(());
    }

    if check_only {
        println!("\nUpdate available! Run 'anyhide update' to install.");
        return Ok(());
    }

    println!("\nDownloading update...");

    let status = update
        .update()
        .context("Failed to update")?;

    if status.updated() {
        println!("Updated successfully to {}!", status.version());
    } else {
        println!("Already up to date.");
    }

    Ok(())
}

/// Returns the target string for the current platform.
fn get_update_target() -> String {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    };

    format!("anyhide-{}-{}", os, arch)
}
