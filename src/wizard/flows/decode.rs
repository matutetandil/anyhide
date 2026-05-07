//! Wizard flow: decode an Anyhide code back to a message or file.
//!
//! `DecodeCommand::execute` is intentionally infallible — wrong inputs return
//! garbage rather than errors, to preserve plausible deniability. This wizard
//! preserves that contract: we collect inputs, build the command, call
//! `execute()`. Anything the user wants to know about the decode (signature
//! status, byte counts) is printed by the underlying decoder.

use std::path::PathBuf;

use anyhow::Result;
use cliclack::{confirm, input, log, outro, select};

use crate::commands::{CommandExecutor, DecodeCommand};
use crate::wizard::helpers::{
    collect_carriers, prompt_existing_path, prompt_new_path, prompt_passphrase, select_my_key,
    MyKeySelection, BACK, BACK_LABEL,
};

pub fn run() -> Result<()> {
    log::info("Decode an Anyhide code back to a message or file")?;

    // Step 1: code source.
    let code_source: &str = select("Code source")
        .item("text", "Paste code as text", "")
        .item("file", "Read code from text file", "")
        .item("qr", "Read code from QR image", "")
        .item("parts", "Combine split parts", "files or QR images, in order")
        .item(BACK, BACK_LABEL, "")
        .interact()?;
    if code_source == BACK {
        return Ok(());
    }

    let (code, code_file, code_qr, parts) = match code_source {
        "text" => {
            let c: String = input("Paste the code")
                .placeholder("BASE64...")
                .validate(|s: &String| {
                    if s.trim().is_empty() {
                        Err("Code cannot be empty.")
                    } else {
                        Ok(())
                    }
                })
                .interact()?;
            (Some(c.trim().to_string()), None, None, None)
        }
        "file" => {
            let p = prompt_existing_path("Path to text file with code", "./code.txt")?;
            (None, Some(p), None, None)
        }
        "qr" => {
            let p = prompt_existing_path("Path to QR image (.png/.jpg/...)", "./code.png")?;
            (None, None, Some(p), None)
        }
        "parts" => {
            let parts = collect_parts()?;
            (None, None, None, Some(parts))
        }
        _ => unreachable!(),
    };

    // Step 2: carriers.
    let carriers = collect_carriers()?;

    // Step 3: passphrase.
    let passphrase = prompt_passphrase("Passphrase")?;

    // Step 4: private key (None = Back to home).
    let my_key = match select_my_key()? {
        Some(k) => k,
        None => return Ok(()),
    };

    // Step 5: optional advanced.
    let advanced = if confirm("Configure advanced options?")
        .initial_value(false)
        .interact()?
    {
        prompt_advanced()?
    } else {
        AdvancedDecodeOptions::default()
    };

    let mut cmd = DecodeCommand {
        code,
        code_qr,
        code_file,
        parts,
        carriers,
        passphrase,
        key: None,
        my_key: None,
        their_key: advanced.their_key,
        eph_file: None,
        eph_keys: None,
        eph_pubs: None,
        contact: None,
        output: advanced.output,
        verbose: advanced.verbose,
        verify: advanced.verify,
    };
    apply_my_key(&mut cmd, my_key);

    log::step("Decoding...")?;
    cmd.execute()?;

    outro("Decoded.")?;
    Ok(())
}

/// Collect 2..=10 part files, in order (each can be a text file or a QR image).
fn collect_parts() -> Result<Vec<PathBuf>> {
    let mut parts = Vec::new();
    log::info("Add part files in the order they were emitted (2-10 parts).")?;
    loop {
        let label = format!("Path to part #{}", parts.len() + 1);
        let p = prompt_existing_path(&label, "./code-1.txt")?;
        parts.push(p);

        if parts.len() >= 10 {
            break;
        }
        if parts.len() >= 2 {
            let more = confirm("Add another part?").initial_value(false).interact()?;
            if !more {
                break;
            }
        }
    }
    Ok(parts)
}

struct AdvancedDecodeOptions {
    output: Option<PathBuf>,
    verify: Option<PathBuf>,
    their_key: Option<PathBuf>,
    verbose: bool,
}

impl Default for AdvancedDecodeOptions {
    fn default() -> Self {
        Self {
            output: None,
            verify: None,
            their_key: None,
            verbose: false,
        }
    }
}

fn prompt_advanced() -> Result<AdvancedDecodeOptions> {
    let mut opts = AdvancedDecodeOptions::default();

    if confirm("Decoded data is binary? (write to file instead of printing)")
        .initial_value(false)
        .interact()?
    {
        opts.output = Some(prompt_new_path("Output file path", "./decoded.bin")?);
    }

    if confirm("Verify sender's signature? (requires their .sign.pub)")
        .initial_value(false)
        .interact()?
    {
        opts.verify = Some(prompt_existing_path(
            "Path to sender's signing public key",
            "./alice.sign.pub",
        )?);
    }

    if confirm("Auto-save sender's next public key? (forward-secrecy ratchet)")
        .initial_value(false)
        .interact()?
    {
        opts.their_key = Some(prompt_new_path(
            "Path where the next public key should be written",
            "./alice.pub",
        )?);
    }

    opts.verbose = confirm("Verbose output?").initial_value(false).interact()?;

    Ok(opts)
}

fn apply_my_key(cmd: &mut DecodeCommand, sel: MyKeySelection) {
    match sel {
        MyKeySelection::MyKey(path) => cmd.my_key = Some(path),
        MyKeySelection::EphFile { eph_file, contact } => {
            cmd.eph_file = Some(eph_file);
            cmd.contact = Some(contact);
        }
        MyKeySelection::EphSeparated {
            eph_keys,
            eph_pubs,
            contact,
        } => {
            cmd.eph_keys = Some(eph_keys);
            cmd.eph_pubs = Some(eph_pubs);
            cmd.contact = Some(contact);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_my_key_my_key_sets_my_key_only() {
        let mut cmd = empty_decode_cmd();
        apply_my_key(&mut cmd, MyKeySelection::MyKey(PathBuf::from("/me.key")));
        assert_eq!(cmd.my_key, Some(PathBuf::from("/me.key")));
        assert!(cmd.eph_file.is_none());
        assert!(cmd.eph_keys.is_none());
    }

    #[test]
    fn apply_my_key_eph_file_sets_eph_file_and_contact() {
        let mut cmd = empty_decode_cmd();
        apply_my_key(
            &mut cmd,
            MyKeySelection::EphFile {
                eph_file: PathBuf::from("/c.eph"),
                contact: "alice".to_string(),
            },
        );
        assert_eq!(cmd.eph_file, Some(PathBuf::from("/c.eph")));
        assert_eq!(cmd.contact.as_deref(), Some("alice"));
        assert!(cmd.my_key.is_none());
    }

    fn empty_decode_cmd() -> DecodeCommand {
        DecodeCommand {
            code: None,
            code_qr: None,
            code_file: None,
            parts: None,
            carriers: vec![],
            passphrase: String::new(),
            key: None,
            my_key: None,
            their_key: None,
            eph_file: None,
            eph_keys: None,
            eph_pubs: None,
            contact: None,
            output: None,
            verbose: false,
            verify: None,
        }
    }
}
