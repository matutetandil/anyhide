//! KAMO - Key Asymmetric Message Obfuscation
//!
//! A CLI tool for advanced steganography with hybrid encryption.
//! Version 0.5.0 features compression, forward secrecy, and multi-carrier support.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use image::GenericImageView;
use std::io::{self, Read};
use std::path::PathBuf;

use kamo::crypto::{
    decrypt_multi, encrypt_multi, load_public_key, load_secret_key, KeyPair, MultiRecipientData,
};
use kamo::qr::{generate_qr_to_file, qr_capacity_info, read_qr_from_file, QrConfig, QrFormat};
use kamo::stego::{AudioStego, ImageStego};
use kamo::{decode_with_config, encode_with_config, DecoderConfig, EncoderConfig};

/// KAMO - Key Asymmetric Message Obfuscation
///
/// Advanced steganography with compression, forward secrecy, and multi-carrier support.
/// Supports text, image (PNG/BMP), and audio (WAV) carriers.
#[derive(Parser)]
#[command(name = "kamo")]
#[command(version = "0.5.0")]
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
        #[arg(short, long, default_value = "kamo")]
        output: PathBuf,
    },

    /// Encode a message using a pre-shared text carrier
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

    /// Decode a message using a pre-shared text carrier
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

    /// Hide data in an image (LSB steganography)
    #[command(name = "image-hide")]
    ImageHide {
        /// Input image (PNG or BMP)
        #[arg(short, long)]
        input: PathBuf,

        /// Output image path
        #[arg(short, long)]
        output: PathBuf,

        /// Data to hide (reads from stdin if not provided)
        #[arg(short, long)]
        data: Option<String>,

        /// Passphrase for encryption
        #[arg(short, long)]
        passphrase: String,

        /// Path to recipient's public key
        #[arg(short, long)]
        key: PathBuf,
    },

    /// Extract hidden data from an image
    #[command(name = "image-extract")]
    ImageExtract {
        /// Input image with hidden data
        #[arg(short, long)]
        input: PathBuf,

        /// Passphrase for decryption
        #[arg(short, long)]
        passphrase: String,

        /// Path to your private key
        #[arg(short, long)]
        key: PathBuf,
    },

    /// Hide data in an audio file (LSB steganography)
    #[command(name = "audio-hide")]
    AudioHide {
        /// Input audio file (WAV, 16-bit PCM)
        #[arg(short, long)]
        input: PathBuf,

        /// Output audio path
        #[arg(short, long)]
        output: PathBuf,

        /// Data to hide (reads from stdin if not provided)
        #[arg(short, long)]
        data: Option<String>,

        /// Passphrase for encryption
        #[arg(short, long)]
        passphrase: String,

        /// Path to recipient's public key
        #[arg(short, long)]
        key: PathBuf,
    },

    /// Extract hidden data from an audio file
    #[command(name = "audio-extract")]
    AudioExtract {
        /// Input audio with hidden data
        #[arg(short, long)]
        input: PathBuf,

        /// Passphrase for decryption
        #[arg(short, long)]
        passphrase: String,

        /// Path to your private key
        #[arg(short, long)]
        key: PathBuf,
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

    /// Show capacity of an image or audio file for hiding data
    Capacity {
        /// Path to image or audio file
        #[arg(short, long)]
        file: PathBuf,
    },

    /// Generate a QR code from a KAMO code (uses Base45 for optimal capacity)
    #[command(name = "qr-generate")]
    QrGenerate {
        /// KAMO code (base64 string) - reads from stdin if not provided
        #[arg(short, long)]
        code: Option<String>,

        /// Output file path (PNG, SVG, or TXT for ASCII)
        #[arg(short, long)]
        output: PathBuf,

        /// Output format: png (default), svg, or ascii
        #[arg(short, long, default_value = "png")]
        format: String,
    },

    /// Read a QR code and extract the KAMO code
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

        /// KAMO code to analyze
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
            passphrase,
            key,
            verbose,
        } => encode_cmd(&carrier, message, &passphrase, &key, verbose)?,

        Commands::Decode {
            code,
            carrier,
            passphrase,
            key,
            verbose,
        } => decode_cmd(&code, &carrier, &passphrase, &key, verbose),

        Commands::ImageHide {
            input,
            output,
            data,
            passphrase,
            key,
        } => image_hide(&input, &output, data, &passphrase, &key)?,

        Commands::ImageExtract {
            input,
            passphrase,
            key,
        } => image_extract(&input, &passphrase, &key)?,

        Commands::AudioHide {
            input,
            output,
            data,
            passphrase,
            key,
        } => audio_hide(&input, &output, data, &passphrase, &key)?,

        Commands::AudioExtract {
            input,
            passphrase,
            key,
        } => audio_extract(&input, &passphrase, &key)?,

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

        Commands::Capacity { file } => show_capacity(&file)?,

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

/// Encodes a message into an encrypted code.
fn encode_cmd(
    carrier_path: &PathBuf,
    message: Option<String>,
    passphrase: &str,
    key_path: &PathBuf,
    verbose: bool,
) -> Result<()> {
    let carrier = std::fs::read_to_string(carrier_path)
        .with_context(|| format!("Failed to read carrier from {}", carrier_path.display()))?;

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

    let public_key = load_public_key(key_path)
        .with_context(|| format!("Failed to load public key from {}", key_path.display()))?;

    let config = EncoderConfig { verbose };

    let encoded = encode_with_config(&carrier, &message, passphrase, &public_key, &config)
        .context("Failed to encode message")?;

    println!("{}", encoded.code);

    if verbose {
        eprintln!();
        eprintln!(
            "Encoded {} real fragments ({} total with padding)",
            encoded.real_fragment_count, encoded.total_fragments
        );
    }

    Ok(())
}

/// Decodes an encrypted code back to a message.
fn decode_cmd(code: &str, carrier_path: &PathBuf, passphrase: &str, key_path: &PathBuf, verbose: bool) {
    let carrier = match std::fs::read_to_string(carrier_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: Could not read carrier file: {}", e);
            String::new()
        }
    };

    let secret_key = match load_secret_key(key_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Warning: Could not load private key: {}", e);
            KeyPair::generate().into_secret_key()
        }
    };

    let config = DecoderConfig { verbose };
    let decoded = decode_with_config(code, &carrier, passphrase, &secret_key, &config);

    println!("{}", decoded.message);

    if verbose {
        eprintln!();
        eprintln!("Fragments: {:?}", decoded.fragments);
    }
}

/// Hides data in an image using LSB steganography.
fn image_hide(
    input: &PathBuf,
    output: &PathBuf,
    data: Option<String>,
    passphrase: &str,
    key_path: &PathBuf,
) -> Result<()> {
    let stego = ImageStego::from_file(input)
        .with_context(|| format!("Failed to load image from {}", input.display()))?;

    let data = match data {
        Some(d) => d,
        None => {
            eprintln!("Reading data from stdin (Ctrl+D to finish):");
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .context("Failed to read data from stdin")?;
            buffer.trim().to_string()
        }
    };

    if data.is_empty() {
        anyhow::bail!("Data cannot be empty");
    }

    let public_key = load_public_key(key_path)
        .with_context(|| format!("Failed to load public key from {}", key_path.display()))?;

    // Encrypt the data
    let encrypted = kamo::crypto::encrypt_with_passphrase(data.as_bytes(), passphrase, &public_key)
        .context("Failed to encrypt data")?;

    // Check capacity
    if encrypted.len() > stego.capacity() {
        anyhow::bail!(
            "Data too large: {} bytes encrypted, image can hold {} bytes",
            encrypted.len(),
            stego.capacity()
        );
    }

    // Hide in image
    let result = stego.hide(&encrypted).context("Failed to hide data in image")?;

    // Save
    let stego_result = ImageStego::from_image(result);
    stego_result
        .save(output)
        .with_context(|| format!("Failed to save image to {}", output.display()))?;

    println!("Data hidden successfully in {}", output.display());
    println!("  Original message: {} bytes", data.len());
    println!("  Encrypted size: {} bytes", encrypted.len());
    println!("  Image capacity: {} bytes", stego.capacity());

    Ok(())
}

/// Extracts hidden data from an image.
fn image_extract(input: &PathBuf, passphrase: &str, key_path: &PathBuf) -> Result<()> {
    let stego = ImageStego::from_file(input)
        .with_context(|| format!("Failed to load image from {}", input.display()))?;

    let secret_key = load_secret_key(key_path)
        .with_context(|| format!("Failed to load private key from {}", key_path.display()))?;

    // Extract encrypted data
    let encrypted = stego.extract().context("Failed to extract data from image")?;

    // Decrypt
    let decrypted = kamo::crypto::decrypt_with_passphrase(&encrypted, passphrase, &secret_key)
        .context("Failed to decrypt data")?;

    // Output as string
    let message = String::from_utf8_lossy(&decrypted);
    println!("{}", message);

    Ok(())
}

/// Hides data in an audio file using LSB steganography.
fn audio_hide(
    input: &PathBuf,
    output: &PathBuf,
    data: Option<String>,
    passphrase: &str,
    key_path: &PathBuf,
) -> Result<()> {
    let stego = AudioStego::from_file(input)
        .with_context(|| format!("Failed to load audio from {}", input.display()))?;

    let data = match data {
        Some(d) => d,
        None => {
            eprintln!("Reading data from stdin (Ctrl+D to finish):");
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .context("Failed to read data from stdin")?;
            buffer.trim().to_string()
        }
    };

    if data.is_empty() {
        anyhow::bail!("Data cannot be empty");
    }

    let public_key = load_public_key(key_path)
        .with_context(|| format!("Failed to load public key from {}", key_path.display()))?;

    // Encrypt the data
    let encrypted = kamo::crypto::encrypt_with_passphrase(data.as_bytes(), passphrase, &public_key)
        .context("Failed to encrypt data")?;

    // Check capacity
    if encrypted.len() > stego.capacity() {
        anyhow::bail!(
            "Data too large: {} bytes encrypted, audio can hold {} bytes",
            encrypted.len(),
            stego.capacity()
        );
    }

    // Hide in audio
    let result = stego.hide(&encrypted).context("Failed to hide data in audio")?;

    // Save
    result
        .save(output)
        .with_context(|| format!("Failed to save audio to {}", output.display()))?;

    println!("Data hidden successfully in {}", output.display());
    println!("  Original message: {} bytes", data.len());
    println!("  Encrypted size: {} bytes", encrypted.len());
    println!("  Audio capacity: {} bytes", stego.capacity());
    println!("  Audio duration: {:.2} seconds", stego.duration_secs());

    Ok(())
}

/// Extracts hidden data from an audio file.
fn audio_extract(input: &PathBuf, passphrase: &str, key_path: &PathBuf) -> Result<()> {
    let stego = AudioStego::from_file(input)
        .with_context(|| format!("Failed to load audio from {}", input.display()))?;

    let secret_key = load_secret_key(key_path)
        .with_context(|| format!("Failed to load private key from {}", key_path.display()))?;

    // Extract encrypted data
    let encrypted = stego.extract().context("Failed to extract data from audio")?;

    // Decrypt
    let decrypted = kamo::crypto::decrypt_with_passphrase(&encrypted, passphrase, &secret_key)
        .context("Failed to decrypt data")?;

    // Output as string
    let message = String::from_utf8_lossy(&decrypted);
    println!("{}", message);

    Ok(())
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

/// Shows the capacity of an image or audio file.
fn show_capacity(file: &PathBuf) -> Result<()> {
    let extension = file
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match extension.as_str() {
        "png" | "bmp" | "jpg" | "jpeg" | "gif" => {
            let stego = ImageStego::from_file(file)
                .with_context(|| format!("Failed to load image from {}", file.display()))?;

            let (width, height) = stego.image().dimensions();
            println!("Image: {}", file.display());
            println!("  Dimensions: {}x{}", width, height);
            println!("  Capacity: {} bytes", stego.capacity());
            println!(
                "  Can hide approximately {} characters of text",
                stego.capacity()
            );
        }
        "wav" => {
            let stego = AudioStego::from_file(file)
                .with_context(|| format!("Failed to load audio from {}", file.display()))?;

            println!("Audio: {}", file.display());
            println!("  Duration: {:.2} seconds", stego.duration_secs());
            println!("  Samples: {}", stego.sample_count());
            println!("  Capacity: {} bytes", stego.capacity());
            println!(
                "  Can hide approximately {} characters of text",
                stego.capacity()
            );
        }
        _ => {
            anyhow::bail!(
                "Unsupported file type: {}. Supported: PNG, BMP, WAV",
                extension
            );
        }
    }

    Ok(())
}

/// Generates a QR code from a KAMO code.
fn qr_generate(code: Option<String>, output: &PathBuf, format: &str) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    // Get the code from argument or stdin
    let code_str = match code {
        Some(c) => c,
        None => {
            eprintln!("Reading KAMO code from stdin (Ctrl+D to finish):");
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
        .context("Failed to decode base64 KAMO code")?;

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

/// Reads a QR code and extracts the KAMO code.
fn qr_read(input: &PathBuf, output: Option<&PathBuf>) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    // Read QR code
    let data = read_qr_from_file(input)
        .with_context(|| format!("Failed to read QR code from {}", input.display()))?;

    if let Some(output_path) = output {
        // Write raw bytes to file
        std::fs::write(output_path, &data)
            .with_context(|| format!("Failed to write to {}", output_path.display()))?;
        println!("KAMO code written to: {}", output_path.display());
        println!("  Size: {} bytes", data.len());
    } else {
        // Output as base64 (standard KAMO code format)
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
