//! Demo command — public encode/decode using baked-in keys, carrier, and
//! passphrase. Educational/onboarding feature only; provides no privacy.
//!
//! Implementation calls the encoder/decoder library functions directly rather
//! than going through `EncodeCommand`/`DecodeCommand`. Demo mode has its own
//! conceptual surface (no key choice, no carrier choice, no advanced flags),
//! so a thin dedicated layer is cleaner than coercing the full command structs.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use console::style;

use anyhide::{
    decode_with_carrier_config, encode_with_carrier_config, Carrier, DecoderConfig, EncoderConfig,
};

use super::CommandExecutor;
use crate::demo;

/// Width of the visual separator drawn above/below demo output. Picked to be
/// wider than typical terminal labels but narrow enough to render on 80-col.
const SEPARATOR_WIDTH: usize = 50;

/// Public demo mode — encode or decode messages using a baked-in keypair,
/// carrier, and passphrase. Useful for trying Anyhide without generating an
/// identity. NOT private: anyone can decode demo codes.
#[derive(Args, Debug)]
pub struct DemoCommand {
    #[command(subcommand)]
    pub action: DemoAction,
}

#[derive(Subcommand, Debug)]
pub enum DemoAction {
    /// Encode a message with the public demo bundle. Output is decodable by anyone.
    Encode {
        /// The text message to hide.
        message: String,
    },

    /// Decode a code produced by `anyhide demo encode`.
    Decode {
        /// The Anyhide code to decode.
        code: String,
    },

    /// Show the demo bundle contents (passphrase, key seed, carrier preview).
    Info,
}

impl CommandExecutor for DemoCommand {
    fn execute(&self) -> Result<()> {
        eprintln!("{}", demo::WARNING);
        eprintln!();
        match &self.action {
            DemoAction::Encode { message } => demo_encode(message),
            DemoAction::Decode { code } => demo_decode(code),
            DemoAction::Info => demo_info(),
        }
    }
}

fn demo_encode(message: &str) -> Result<()> {
    let carrier = Carrier::from_text(demo::CARRIER);
    let pubkey = demo::recipient_public_key();
    // min_coverage = 1.0: forces exact substring matching, which is what the
    // decoder also expects. Looser values would cause the encoder to emit
    // fragments that the decoder reassembles with whitespace artifacts.
    // Coverage failures here mean the demo carrier doesn't contain every char
    // of the message — the carrier is wide enough to handle printable ASCII.
    let config = EncoderConfig {
        verbose: false,
        signing_key: None,
        min_coverage: 1.0,
        expires_at: None,
        ratchet: false,
        decoy: None,
    };
    let encoded =
        encode_with_carrier_config(&carrier, message, demo::PASSPHRASE, &pubkey, &config)
            .context("Demo encoding failed — the demo carrier may not contain every character of your message. Try plain ASCII text.")?;
    print_delimited("Anyhide code (base64)", &encoded.code);
    Ok(())
}

fn demo_decode(code: &str) -> Result<()> {
    let carrier = Carrier::from_text(demo::CARRIER);
    let secret = demo::recipient_secret_key();
    let config = DecoderConfig {
        verbose: false,
        verifying_key: None,
    };
    let decoded =
        decode_with_carrier_config(code, &carrier, demo::PASSPHRASE, &secret, &config);
    print_delimited("Decoded message", &decoded.message);
    Ok(())
}

/// Print `content` (the actual demo output that callers may want to pipe)
/// to stdout, surrounded by labelled separator lines on stderr. Splitting the
/// streams keeps `anyhide demo encode "..." | anyhide demo decode` working
/// even though we add visual framing for interactive use.
fn print_delimited(label: &str, content: &str) {
    eprintln!();
    eprintln!(
        "{}",
        style(format!("── {} {}", label, "─".repeat(SEPARATOR_WIDTH.saturating_sub(label.len() + 4))))
            .cyan()
            .bold()
    );
    println!("{}", content);
    eprintln!("{}", style("─".repeat(SEPARATOR_WIDTH)).dim());
}

fn demo_info() -> Result<()> {
    println!("Anyhide demo bundle (public, no privacy):");
    println!();
    println!("  Passphrase:  {}", demo::PASSPHRASE);
    println!(
        "  Key seed:    {} (SHA-256'd to produce the X25519 secret)",
        std::str::from_utf8(demo::KEY_SEED).unwrap_or("<non-utf8>")
    );
    println!();
    println!("  Public key:  {}", hex::encode(demo::recipient_public_key().as_bytes()));
    println!();
    println!("  Carrier ({} bytes):", demo::CARRIER.len());
    println!("    {}", preview(demo::CARRIER, 80));
    println!();
    println!("Reproduce the demo key with:");
    println!("    echo -n '{}' | sha256sum", std::str::from_utf8(demo::KEY_SEED).unwrap_or(""));
    Ok(())
}

/// Truncate a long string for display, showing the first `n` chars + ellipsis.
fn preview(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let head: String = s.chars().take(n).collect();
        format!("{}...", head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Roundtrip: byte-equal recovery of the original message. Demo mode
    /// uses the text carrier path (`Carrier::from_text`), where the encoder
    /// fragments along word boundaries and the decoder reinserts the
    /// inter-word spaces exactly once. This matches the contract verified
    /// by `tests/integration_tests::test_exact_case_matching`.
    #[test]
    fn demo_roundtrip_returns_original_message() {
        let original = "Hello world 123";
        let carrier = Carrier::from_text(demo::CARRIER);
        let pubkey = demo::recipient_public_key();
        let secret = demo::recipient_secret_key();

        let enc_config = EncoderConfig {
            verbose: false,
            signing_key: None,
            min_coverage: 1.0,
            expires_at: None,
            ratchet: false,
            decoy: None,
        };
        let dec_config = DecoderConfig {
            verbose: false,
            verifying_key: None,
        };

        let encoded =
            encode_with_carrier_config(&carrier, original, demo::PASSPHRASE, &pubkey, &enc_config)
                .expect("demo encode should succeed for plain ASCII messages");

        let decoded = decode_with_carrier_config(
            &encoded.code,
            &carrier,
            demo::PASSPHRASE,
            &secret,
            &dec_config,
        );

        assert_eq!(decoded.message, original);
    }

    #[test]
    fn preview_returns_full_string_when_short() {
        assert_eq!(preview("hello", 10), "hello");
    }

    #[test]
    fn preview_truncates_with_ellipsis_when_long() {
        let truncated = preview("abcdefghij", 5);
        assert_eq!(truncated, "abcde...");
    }
}
