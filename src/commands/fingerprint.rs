//! Fingerprint command - display key fingerprints for verification.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use sha2::{Sha256, Digest};

use anyhide::crypto::{load_public_key, load_secret_key};

use super::CommandExecutor;

/// Display a key's fingerprint for out-of-band verification.
///
/// Use this to verify keys with your contact over a secure channel
/// (phone call, in person, etc.) to prevent MITM attacks.
///
/// Supports both public (.pub) and private (.key) key files.
#[derive(Args, Debug)]
pub struct FingerprintCommand {
    /// Path to the key file (.pub or .key)
    #[arg(required = true)]
    pub key_path: PathBuf,

    /// Output format: hex, emoji, art, or all (default: all)
    #[arg(short, long, default_value = "all")]
    pub format: String,
}

impl CommandExecutor for FingerprintCommand {
    fn execute(&self) -> Result<()> {
        // Load the key (try public first, then private)
        let key_bytes = self.load_key_bytes()?;

        // Calculate SHA-256 fingerprint
        let mut hasher = Sha256::new();
        hasher.update(&key_bytes);
        let hash = hasher.finalize();
        let hash_bytes: [u8; 32] = hash.into();

        println!("Key: {}", self.key_path.display());
        println!();

        match self.format.to_lowercase().as_str() {
            "hex" => self.print_hex(&hash_bytes),
            "emoji" => self.print_emoji(&hash_bytes),
            "art" => self.print_art(&hash_bytes),
            "all" | _ => {
                self.print_hex(&hash_bytes);
                println!();
                self.print_emoji(&hash_bytes);
                println!();
                self.print_art(&hash_bytes);
            }
        }

        Ok(())
    }
}

impl FingerprintCommand {
    /// Load key bytes from file (public or private).
    fn load_key_bytes(&self) -> Result<[u8; 32]> {
        let ext = self.key_path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        if ext == "pub" {
            let public_key = load_public_key(&self.key_path)?;
            Ok(*public_key.as_bytes())
        } else {
            // Try loading as private key, extract public key bytes for fingerprint
            let secret_key = load_secret_key(&self.key_path)?;
            let public_key = x25519_dalek::PublicKey::from(&secret_key);
            Ok(*public_key.as_bytes())
        }
    }

    /// Print fingerprint in hex format (grouped for readability).
    fn print_hex(&self, hash: &[u8; 32]) {
        let hex: Vec<String> = hash.iter()
            .map(|b| format!("{:02X}", b))
            .collect();

        // Group in 4-byte chunks
        let grouped: Vec<String> = hex.chunks(4)
            .map(|chunk| chunk.join(""))
            .collect();

        println!("Hex Fingerprint:");
        println!("  {}", grouped[0..4].join(" "));
        println!("  {}", grouped[4..8].join(" "));
    }

    /// Print fingerprint as emoji sequence.
    fn print_emoji(&self, hash: &[u8; 32]) {
        // Use first 16 bytes mapped to emojis for a memorable fingerprint
        let emojis = [
            "🔐", "🔑", "🛡️", "⚔️", "🏰", "🎯", "💎", "🌟",
            "🔥", "💧", "🌿", "⚡", "🌙", "☀️", "🌈", "❄️",
            "🦁", "🐺", "🦅", "🐉", "🦊", "🐧", "🦋", "🐝",
            "🍎", "🍊", "🍋", "🍇", "🍓", "🥝", "🍒", "🥥",
            "🎸", "🎹", "🎺", "🥁", "🎻", "🎤", "🎧", "🎬",
            "🚀", "✈️", "🚁", "⛵", "🚂", "🏎️", "🛸", "🚲",
            "🏔️", "🌋", "🏝️", "🌊", "🏜️", "🌲", "🌸", "🌺",
            "💜", "💙", "💚", "💛", "🧡", "❤️", "🖤", "🤍",
        ];

        let emoji_fp: String = hash[0..8].iter()
            .map(|&b| {
                let idx = (b as usize) % emojis.len();
                emojis[idx]
            })
            .collect::<Vec<_>>()
            .join(" ");

        println!("Emoji Fingerprint:");
        println!("  {}", emoji_fp);
    }

    /// Print fingerprint as visual ASCII art (similar to SSH randomart).
    fn print_art(&self, hash: &[u8; 32]) {
        // Create a 9x17 grid (like SSH)
        const HEIGHT: usize = 9;
        const WIDTH: usize = 17;
        let mut grid = [[0u8; WIDTH]; HEIGHT];

        // Start in the middle
        let mut x = WIDTH / 2;
        let mut y = HEIGHT / 2;

        // Walk the grid based on hash bits
        for byte in hash.iter() {
            for i in 0..4 {
                let bits = (byte >> (i * 2)) & 0b11;

                // Move based on 2-bit value
                match bits {
                    0 => { // up-left
                        if y > 0 { y -= 1; }
                        if x > 0 { x -= 1; }
                    }
                    1 => { // up-right
                        if y > 0 { y -= 1; }
                        if x < WIDTH - 1 { x += 1; }
                    }
                    2 => { // down-left
                        if y < HEIGHT - 1 { y += 1; }
                        if x > 0 { x -= 1; }
                    }
                    3 => { // down-right
                        if y < HEIGHT - 1 { y += 1; }
                        if x < WIDTH - 1 { x += 1; }
                    }
                    _ => {}
                }

                // Increment cell visit count (max 14)
                if grid[y][x] < 14 {
                    grid[y][x] += 1;
                }
            }
        }

        // Mark start and end positions
        let start_y = HEIGHT / 2;
        let start_x = WIDTH / 2;

        // Characters for different visit counts
        let chars = [' ', '.', 'o', '+', '=', '*', 'B', 'O', 'X', '@', '%', '&', '#', '/', '^'];

        println!("Visual Fingerprint:");
        println!("  +{:-<width$}+", "", width = WIDTH);

        for (row_idx, row) in grid.iter().enumerate() {
            print!("  |");
            for (col_idx, &cell) in row.iter().enumerate() {
                if row_idx == start_y && col_idx == start_x {
                    print!("S"); // Start position
                } else if row_idx == y && col_idx == x {
                    print!("E"); // End position
                } else {
                    let ch = chars[cell as usize];
                    print!("{}", ch);
                }
            }
            println!("|");
        }

        println!("  +{:-<width$}+", "", width = WIDTH);
    }
}
