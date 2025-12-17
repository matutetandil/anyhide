//! Encode command - hide messages or files in a carrier.

use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Args;

use anyhide::contacts::ContactsConfig;
use anyhide::crypto::{
    load_public_key, load_signing_key, save_ephemeral_private_key_pem,
    load_unified_keys_for_contact, update_unified_private_key,
    load_public_key_for_contact, save_private_key_for_contact,
};
use anyhide::qr::{generate_qr_to_file, qr_capacity_info, QrConfig, QrFormat};
use anyhide::{encode_with_carrier_config, encode_bytes_with_carrier_config, Carrier, EncoderConfig, DecoyConfig};

use super::CommandExecutor;

/// Encode a message using a pre-shared carrier (ANY file).
///
/// The carrier can be ANY file:
/// - Text files (.txt, .md, .csv, .json, .xml, .html) - substring matching
/// - Any other file (images, audio, video, PDFs, executables, etc.) - byte-sequence matching
///
/// Output is always an encrypted code (base64) - the carrier is NEVER modified.
/// The code does NOT reveal whether the hidden data is text or binary.
#[derive(Args, Debug)]
pub struct EncodeCommand {
    /// Path to carrier file (any file - text uses substring matching, others use byte matching)
    #[arg(short, long)]
    pub carrier: PathBuf,

    /// Text message to encode (mutually exclusive with --file)
    #[arg(short, long, conflicts_with = "file")]
    pub message: Option<String>,

    /// Binary file to encode (mutually exclusive with --message)
    /// Use this to hide any file (zip, image, executable, etc.) inside the carrier
    #[arg(short, long, conflicts_with = "message")]
    pub file: Option<PathBuf>,

    /// Passphrase for encryption (also determines fragmentation and positions)
    #[arg(short, long)]
    pub passphrase: String,

    /// [DEPRECATED: use --their-key] Path to recipient's public key
    #[arg(short, long)]
    pub key: Option<PathBuf>,

    /// Contact alias from ~/.anyhide/contacts.toml
    /// Use instead of --their-key for configured contacts
    #[arg(long, conflicts_with_all = ["their_key", "key"])]
    pub to: Option<String>,

    /// Path to recipient's public key (their .pub or ephemeral .pub file)
    #[arg(long)]
    pub their_key: Option<PathBuf>,

    /// Path to your private key file (required with --ratchet for auto-update)
    /// After encoding, the new ephemeral private key is saved here automatically
    #[arg(long)]
    pub my_key: Option<PathBuf>,

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

    /// Verbose output (shows fragmentation and positions)
    #[arg(short, long)]
    pub verbose: bool,

    /// Generate QR code and save to this path (in addition to printing the code)
    #[arg(long)]
    pub qr: Option<PathBuf>,

    /// QR code format: png (default), svg, or ascii
    #[arg(long, default_value = "png")]
    pub qr_format: String,

    /// Sign the message with your signing key (Ed25519)
    /// The recipient can verify the signature with your .sign.pub key
    #[arg(long)]
    pub sign: Option<PathBuf>,

    /// Minimum carrier coverage required (0-100, default: 100)
    /// At 100%, all message characters must exist exactly in the carrier.
    /// Lower values allow encoding but may leak information about the message.
    /// WARNING: Values below 100 reduce security - only use with trusted carriers.
    #[arg(long, default_value = "100", value_parser = clap::value_parser!(u8).range(0..=100))]
    pub min_coverage: u8,

    /// Message expiration time
    /// Relative: "+30m" (30 minutes), "+24h" (24 hours), "+7d" (7 days)
    /// Absolute: "2025-12-31" or "2025-12-31T23:59:59"
    /// After expiration, decode returns garbage (plausible deniability)
    #[arg(long)]
    pub expires: Option<String>,

    /// Split the code into N parts (2-10)
    /// Each part is independent base64 without indices
    /// The correct ORDER is part of the secret - wrong order = garbage
    /// Parts can be sent via different channels for extra security
    #[arg(long, value_parser = clap::value_parser!(u8).range(2..=10))]
    pub split: Option<u8>,

    /// Enable forward secrecy ratchet (requires ephemeral keys)
    /// A new ephemeral keypair is generated for each message.
    /// The recipient receives next_public_key to use in their reply.
    /// You should update your ephemeral key storage after encoding.
    #[arg(long)]
    pub ratchet: bool,

    /// Decoy message for duress password (plausible deniability)
    /// If someone forces you to reveal the passphrase, give them --decoy-pass
    /// and they'll see this innocent message instead of the real one.
    #[arg(long, requires = "decoy_pass")]
    pub decoy: Option<String>,

    /// Passphrase for the decoy message
    /// Use this to decode the decoy message instead of the real one.
    #[arg(long, requires = "decoy")]
    pub decoy_pass: Option<String>,
}

impl CommandExecutor for EncodeCommand {
    fn execute(&self) -> Result<()> {
        // Load carrier with auto-detection based on file extension
        let carrier = Carrier::from_file(&self.carrier)
            .with_context(|| format!("Failed to read carrier from {}", self.carrier.display()))?;

        let carrier_type = if carrier.is_binary() { "binary" } else { "text" };
        if self.verbose {
            eprintln!("Loaded {} carrier ({} units)", carrier_type, carrier.len());
        }

        // Resolve recipient's public key from various sources
        let (public_key, eph_store_info) = self.resolve_their_public_key()?;

        // Validate ratchet requirements
        if self.ratchet {
            let has_my_key = self.my_key.is_some();
            let has_eph_store = eph_store_info.is_some();

            if !has_my_key && !has_eph_store {
                anyhow::bail!(
                    "--ratchet requires either:\n  \
                     - --my-key <path> for loose ephemeral files, or\n  \
                     - --eph-file <path> --contact <name> for unified store, or\n  \
                     - --eph-keys <path> --eph-pubs <path> --contact <name> for separated stores"
                );
            }
        }

        // Load signing key if provided
        let signing_key = if let Some(sign_path) = &self.sign {
            let key = load_signing_key(sign_path)
                .with_context(|| format!("Failed to load signing key from {}", sign_path.display()))?;
            if self.verbose {
                eprintln!("Message will be signed with Ed25519");
            }
            Some(key)
        } else {
            None
        };

        // Parse expiration time if provided
        let expires_at = if let Some(exp_str) = &self.expires {
            let ts = parse_expiration(exp_str)
                .with_context(|| format!("Invalid expiration format: '{}'. Use '+30m', '+24h', '+7d', or '2025-12-31'", exp_str))?;
            if self.verbose {
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

        // Build decoy config if provided
        let decoy_config = match (&self.decoy, &self.decoy_pass) {
            (Some(decoy_msg), Some(decoy_passphrase)) => {
                if self.verbose {
                    eprintln!("Duress password enabled with decoy message");
                }
                Some(DecoyConfig {
                    message: decoy_msg,
                    passphrase: decoy_passphrase,
                })
            }
            _ => None,
        };

        let config = EncoderConfig {
            verbose: self.verbose,
            signing_key: signing_key.as_ref(),
            min_coverage: self.min_coverage as f64 / 100.0,
            expires_at,
            ratchet: self.ratchet,
            decoy: decoy_config,
        };

        // Determine if we're encoding text or binary
        let encoded = if let Some(file_path) = &self.file {
            // Binary file encoding
            let data = std::fs::read(file_path)
                .with_context(|| format!("Failed to read file {}", file_path.display()))?;

            if data.is_empty() {
                anyhow::bail!("File is empty");
            }

            if self.verbose {
                eprintln!("Encoding binary file: {} ({} bytes)", file_path.display(), data.len());
            }

            encode_bytes_with_carrier_config(&carrier, &data, &self.passphrase, &public_key, &config)
                .context("Failed to encode file")?
        } else {
            // Text message encoding
            let message = match &self.message {
                Some(m) => m.clone(),
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

            if self.verbose {
                eprintln!("Encoding text message ({} chars)", message.len());
            }

            encode_with_carrier_config(&carrier, &message, &self.passphrase, &public_key, &config)
                .context("Failed to encode message")?
        };

        // Output code (split if requested)
        if let Some(n) = self.split {
            let parts = split_code(&encoded.code, n as usize);
            for (i, part) in parts.iter().enumerate() {
                println!("part-{}: {}", i + 1, part);
            }
            if self.verbose {
                eprintln!();
                eprintln!("Split into {} parts ({} chars each approx)", n, encoded.code.len() / n as usize);
                eprintln!("IMPORTANT: Parts must be combined in EXACT order to decode");
            }
        } else {
            println!("{}", encoded.code);
        }

        if self.verbose {
            eprintln!();
            eprintln!(
                "Encoded {} real fragments ({} total with padding)",
                encoded.real_fragment_count, encoded.total_fragments
            );
        }

        // Handle forward secrecy ratchet - auto-save next keypair
        if let Some(ref next_keypair) = encoded.next_keypair {
            self.save_next_keypair(next_keypair, &eph_store_info)?;

            if self.verbose {
                eprintln!();
                eprintln!("Forward Secrecy Ratchet: next keypair saved automatically");
            }
        }

        // Generate QR code if requested
        if let Some(qr_path) = &self.qr {
            let format = match self.qr_format.to_lowercase().as_str() {
                "png" => QrFormat::Png,
                "svg" => QrFormat::Svg,
                "ascii" | "txt" => QrFormat::Ascii,
                _ => anyhow::bail!("Unknown QR format: {}. Use: png, svg, or ascii", self.qr_format),
            };

            let qr_config = QrConfig {
                format,
                ..Default::default()
            };

            // If split is enabled, generate multiple QR codes
            if let Some(n) = self.split {
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
                eprintln!("  QR version: {} | Format: {}", info.qr_version, self.qr_format);
            }
        }

        Ok(())
    }
}

/// Ephemeral store info for tracking which files to use
struct EphStoreInfo {
    /// For unified format: the .eph file. For separated: the .eph.pub file
    pub_store: PathBuf,
    /// For separated format only: the .eph.key file
    key_store: Option<PathBuf>,
    /// Contact name
    contact: String,
    /// Is this unified format?
    is_unified: bool,
}

impl EncodeCommand {
    /// Resolves the recipient's public key from various sources.
    /// Returns (public_key, optional_eph_store_info)
    fn resolve_their_public_key(&self) -> Result<(x25519_dalek::PublicKey, Option<EphStoreInfo>)> {
        // Priority 0: Contact alias from ~/.anyhide/contacts.toml
        if let Some(alias) = &self.to {
            let contacts = ContactsConfig::load()
                .context("Failed to load contacts config")?;

            let contact = contacts.get(alias).ok_or_else(|| {
                let available: Vec<_> = contacts.list().iter().map(|(n, _)| *n).collect();
                let available_str = if available.is_empty() {
                    "none configured".to_string()
                } else {
                    available.join(", ")
                };
                anyhow::anyhow!(
                    "Contact '{}' not found.\n  \
                     Available contacts: {}\n  \
                     Add with: anyhide contacts add {} <key-path>",
                    alias, available_str, alias
                )
            })?;

            let public_key = load_public_key(&contact.public_key)
                .with_context(|| format!(
                    "Failed to load public key for contact '{}' from {}",
                    alias, contact.public_key.display()
                ))?;

            if self.verbose {
                eprintln!("Using contact '{}' ({})", alias, contact.public_key.display());
            }

            return Ok((public_key, None));
        }

        // Priority 1: Unified ephemeral store (.eph)
        if let Some(eph_path) = &self.eph_file {
            let contact = self.contact.as_ref().ok_or_else(|| {
                anyhow::anyhow!("--contact is required when using --eph-file")
            })?;

            let keys = load_unified_keys_for_contact(eph_path, contact)
                .with_context(|| format!("Failed to load keys for contact '{}' from {}", contact, eph_path.display()))?;

            if self.verbose {
                eprintln!("Loaded recipient's public key for contact '{}' from {}", contact, eph_path.display());
            }

            let store_info = EphStoreInfo {
                pub_store: eph_path.clone(),
                key_store: None,
                contact: contact.clone(),
                is_unified: true,
            };

            return Ok((keys.their_public, Some(store_info)));
        }

        // Priority 2: Separated ephemeral stores (.eph.key + .eph.pub)
        if let (Some(eph_keys), Some(eph_pubs)) = (&self.eph_keys, &self.eph_pubs) {
            let contact = self.contact.as_ref().ok_or_else(|| {
                anyhow::anyhow!("--contact is required when using --eph-keys/--eph-pubs")
            })?;

            let public_key = load_public_key_for_contact(eph_pubs, contact)
                .with_context(|| format!("Failed to load public key for contact '{}' from {}", contact, eph_pubs.display()))?;

            if self.verbose {
                eprintln!("Loaded recipient's public key for contact '{}' from {}", contact, eph_pubs.display());
            }

            let store_info = EphStoreInfo {
                pub_store: eph_pubs.clone(),
                key_store: Some(eph_keys.clone()),
                contact: contact.clone(),
                is_unified: false,
            };

            return Ok((public_key, Some(store_info)));
        }

        // Priority 3: --their-key (new parameter)
        if let Some(their_key_path) = &self.their_key {
            let public_key = load_public_key(their_key_path)
                .with_context(|| format!("Failed to load public key from {}", their_key_path.display()))?;

            if self.verbose {
                eprintln!("Loaded recipient's public key from {}", their_key_path.display());
            }

            return Ok((public_key, None));
        }

        // Priority 4: --key (deprecated)
        if let Some(key_path) = &self.key {
            eprintln!("WARNING: --key is deprecated. Use --their-key instead.");

            let public_key = load_public_key(key_path)
                .with_context(|| format!("Failed to load public key from {}", key_path.display()))?;

            return Ok((public_key, None));
        }

        anyhow::bail!(
            "No recipient public key specified. Use one of:\n  \
             - --to <alias>                              (contact from ~/.anyhide/contacts.toml)\n  \
             - --their-key <path>                        (recipient's .pub file)\n  \
             - --eph-file <path> --contact <name>        (unified .eph store)\n  \
             - --eph-keys <path> --eph-pubs <path> --contact <name>  (separated stores)"
        )
    }

    /// Saves the next keypair for forward secrecy ratchet.
    fn save_next_keypair(
        &self,
        next_keypair: &anyhide::crypto::KeyPair,
        store_info: &Option<EphStoreInfo>,
    ) -> Result<()> {
        // Option 1: Ephemeral store (unified or separated)
        if let Some(info) = store_info {
            if info.is_unified {
                // Unified format: update private key in .eph file
                update_unified_private_key(&info.pub_store, &info.contact, next_keypair.secret_key())
                    .with_context(|| format!("Failed to update private key for contact '{}' in {}", info.contact, info.pub_store.display()))?;

                if self.verbose {
                    eprintln!("Saved next private key for contact '{}' to {}", info.contact, info.pub_store.display());
                }
            } else {
                // Separated format: save to .eph.key file
                let key_store = info.key_store.as_ref().unwrap();
                save_private_key_for_contact(key_store, &info.contact, next_keypair.secret_key())
                    .with_context(|| format!("Failed to save private key for contact '{}' in {}", info.contact, key_store.display()))?;

                if self.verbose {
                    eprintln!("Saved next private key for contact '{}' to {}", info.contact, key_store.display());
                }
            }

            return Ok(());
        }

        // Option 2: Loose ephemeral file (--my-key)
        if let Some(my_key_path) = &self.my_key {
            save_ephemeral_private_key_pem(next_keypair.secret_key(), my_key_path)
                .with_context(|| format!("Failed to save private key to {}", my_key_path.display()))?;

            if self.verbose {
                eprintln!("Saved next private key to {}", my_key_path.display());
            }

            return Ok(());
        }

        // Should not reach here due to validation in execute()
        anyhow::bail!("No destination for saving next keypair")
    }
}

/// Splits a code into N approximately equal parts.
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
        let size = base_size + if i < remainder { 1 } else { 0 };
        let end = start + size;
        parts.push(chars[start..end].iter().collect());
        start = end;
    }

    parts
}

/// Parses an expiration string into a Unix timestamp.
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
            (23, 59, 59)
        }
    } else {
        (23, 59, 59)
    };

    // Convert to timestamp
    let mut days: i64 = 0;

    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += month_days[(m - 1) as usize] as i64;
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }

    days += (day - 1) as i64;

    let timestamp = days * 86400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64;

    if timestamp < 0 {
        return None;
    }

    Some(timestamp as u64)
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}
