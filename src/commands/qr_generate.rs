//! QR code generation command.

use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Args;

use anyhide::qr::{generate_qr_to_file, qr_capacity_info, QrConfig, QrFormat};

use super::CommandExecutor;

/// Generate a QR code from an Anyhide code (uses Base45 for optimal capacity).
#[derive(Args, Debug)]
pub struct QrGenerateCommand {
    /// Anyhide code (base64 string) - reads from stdin if not provided
    #[arg(short, long)]
    pub code: Option<String>,

    /// Output file path (PNG, SVG, or TXT for ASCII)
    #[arg(short, long)]
    pub output: PathBuf,

    /// Output format: png (default), svg, or ascii
    #[arg(short, long, default_value = "png")]
    pub format: String,
}

impl CommandExecutor for QrGenerateCommand {
    fn execute(&self) -> Result<()> {
        // Get the code from argument or stdin
        let code_str = match &self.code {
            Some(c) => c.clone(),
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
        let qr_format = match self.format.to_lowercase().as_str() {
            "png" => QrFormat::Png,
            "svg" => QrFormat::Svg,
            "ascii" | "txt" => QrFormat::Ascii,
            _ => anyhow::bail!("Unknown format: {}. Use: png, svg, or ascii", self.format),
        };

        // Generate QR code
        let config = QrConfig {
            format: qr_format,
            ..Default::default()
        };

        generate_qr_to_file(&data, &self.output, &config)
            .context("Failed to generate QR code")?;

        // Show capacity info
        let info = qr_capacity_info(data.len());

        println!("QR code generated: {}", self.output.display());
        println!("  Original size: {} bytes", data.len());
        println!("  Base45 encoded: ~{} chars", info.base45_chars);
        println!("  QR version: {}", info.qr_version);
        println!("  Format: {}", self.format);

        Ok(())
    }
}
