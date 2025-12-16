//! QR code capacity info command.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Args;

use anyhide::qr::qr_capacity_info;

use super::CommandExecutor;

/// Show QR code capacity info for a given data size.
#[derive(Args, Debug)]
pub struct QrInfoCommand {
    /// Data size in bytes (or provide --code to calculate from actual data)
    #[arg(short, long)]
    pub size: Option<usize>,

    /// Anyhide code to analyze
    #[arg(short, long)]
    pub code: Option<String>,
}

impl CommandExecutor for QrInfoCommand {
    fn execute(&self) -> Result<()> {
        let data_size = if let Some(s) = self.size {
            s
        } else if let Some(c) = &self.code {
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
}
