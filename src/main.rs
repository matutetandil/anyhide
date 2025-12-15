//! Anyhide - Hide anything in anything
//!
//! A CLI tool for advanced steganography with hybrid encryption.
//! Uses pre-shared carriers (any file) - only encrypted codes are transmitted.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::{self, Read};
use std::path::PathBuf;

use anyhide::crypto::{
    decrypt_multi, encrypt_multi, load_public_key, load_secret_key, KeyPair, MultiRecipientData,
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
#[command(version = "0.5.2")]
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
    },

    /// Decode a message using a pre-shared carrier (ANY file)
    ///
    /// NOTE: This command NEVER fails - it returns garbage if inputs are wrong.
    /// This provides plausible deniability.
    ///
    /// Use -o/--output to write raw bytes to a file (required for binary data).
    /// Without -o, output is printed as text (lossy UTF-8 conversion).
    Decode {
        /// The encrypted code to decode
        #[arg(long)]
        code: String,

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
        } => encode_cmd(&carrier, message, file.as_ref(), &passphrase, &key, verbose, qr.as_ref(), &qr_format)?,

        Commands::Decode {
            code,
            carrier,
            passphrase,
            key,
            output,
            verbose,
        } => decode_cmd(&code, &carrier, &passphrase, &key, output.as_ref(), verbose),

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

    let config = EncoderConfig { verbose };

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

    println!("{}", encoded.code);

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

        let data = BASE64
            .decode(&encoded.code)
            .context("Failed to decode generated code for QR")?;

        let format = match qr_format.to_lowercase().as_str() {
            "png" => QrFormat::Png,
            "svg" => QrFormat::Svg,
            "ascii" | "txt" => QrFormat::Ascii,
            _ => anyhow::bail!("Unknown QR format: {}. Use: png, svg, or ascii", qr_format),
        };

        let config = QrConfig {
            format,
            ..Default::default()
        };

        generate_qr_to_file(&data, qr_path, &config)
            .context("Failed to generate QR code")?;

        let info = qr_capacity_info(data.len());
        eprintln!();
        eprintln!("QR code saved: {}", qr_path.display());
        eprintln!("  QR version: {} | Format: {}", info.qr_version, qr_format);
    }

    Ok(())
}

/// Decodes an encrypted code back to a message or file.
/// Use -o/--output to write raw bytes to a file (required for binary data).
/// Without -o, output is printed as text.
/// NEVER fails - returns garbage if inputs are wrong (plausible deniability).
fn decode_cmd(
    code: &str,
    carrier_path: &PathBuf,
    passphrase: &str,
    key_path: &PathBuf,
    output: Option<&PathBuf>,
    verbose: bool,
) {
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

    let config = DecoderConfig { verbose };

    // If output file is specified, decode as binary
    if let Some(output_path) = output {
        let decoded = anyhide::decode_bytes_with_carrier_config(code, &carrier, passphrase, &secret_key, &config);

        match std::fs::write(output_path, &decoded.data) {
            Ok(_) => {
                eprintln!("Decoded {} bytes to {}", decoded.data.len(), output_path.display());
            }
            Err(e) => {
                eprintln!("Failed to write output file: {}", e);
            }
        }

        if verbose {
            eprintln!();
            eprintln!("Byte fragments: {} fragments", decoded.fragments.len());
        }
    } else {
        // Decode as text
        let decoded = decode_with_carrier_config(code, &carrier, passphrase, &secret_key, &config);

        println!("{}", decoded.message);

        if verbose {
            eprintln!();
            eprintln!("Fragments: {:?}", decoded.fragments);
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
