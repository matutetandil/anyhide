//! QR code reading command.

use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Args;

use anyhide::qr::read_qr_from_file;

use super::CommandExecutor;

/// Read a QR code and extract the Anyhide code.
#[derive(Args, Debug)]
pub struct QrReadCommand {
    /// Path to image containing QR code
    #[arg(short, long)]
    pub input: PathBuf,

    /// Output as base64 (default) or raw bytes to file
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

impl CommandExecutor for QrReadCommand {
    fn execute(&self) -> Result<()> {
        // Read QR code
        let data = read_qr_from_file(&self.input)
            .with_context(|| format!("Failed to read QR code from {}", self.input.display()))?;

        if let Some(output_path) = &self.output {
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
}
