//! Wizard flow: encode a message or file.
//!
//! Walks the user through `EncodeCommand` options, exposing all advanced
//! security features (signing, expiration, ratchet, decoy, QR output, split,
//! min-coverage). Builds the `EncodeCommand` struct and delegates execution.

use std::path::PathBuf;

use anyhow::Result;
use cliclack::{confirm, input, log, outro, select};

use crate::commands::{CommandExecutor, EncodeCommand};
use crate::wizard::helpers::{
    collect_carriers, prompt_existing_path, prompt_new_path, prompt_passphrase, select_recipient,
    RecipientSelection, BACK, BACK_LABEL,
};

pub fn run() -> Result<()> {
    log::info("Encode a message or file as an Anyhide code")?;

    // Step 1: source — text vs binary file.
    let source: &str = select("Source")
        .item("text", "Text message", "type or paste content")
        .item("file", "File", "any binary file")
        .item(BACK, BACK_LABEL, "")
        .interact()?;
    if source == BACK {
        return Ok(());
    }

    let (message, file): (Option<String>, Option<PathBuf>) = match source {
        "text" => {
            let m: String = input("Message").placeholder("Hello world").interact()?;
            (Some(m), None)
        }
        "file" => {
            let path = prompt_existing_path("Path to file", "./secret.pdf")?;
            (None, Some(path))
        }
        _ => unreachable!(),
    };

    // Step 2: recipient (None = Back to home).
    let recipient = match select_recipient()? {
        Some(r) => r,
        None => return Ok(()),
    };

    // Step 3: carriers (1+, in order).
    let carriers = collect_carriers()?;

    // Step 4: passphrase. Required.
    let passphrase = prompt_passphrase("Passphrase")?;

    // Step 5: optional advanced toggles.
    let advanced = if confirm("Configure advanced options?")
        .initial_value(false)
        .interact()?
    {
        prompt_advanced()?
    } else {
        AdvancedEncodeOptions::default()
    };

    // Build the command. The `to`/`their_key`/`eph_*` fields are populated
    // mutually exclusively to match clap's `conflicts_with_all` rules in
    // `EncodeCommand`.
    let mut cmd = EncodeCommand {
        carriers,
        message,
        file,
        passphrase,
        key: None,
        to: None,
        their_key: None,
        my_key: advanced.my_key,
        eph_file: None,
        eph_keys: None,
        eph_pubs: None,
        contact: None,
        verbose: advanced.verbose,
        qr: advanced.qr,
        qr_format: advanced.qr_format,
        sign: advanced.sign,
        min_coverage: advanced.min_coverage,
        expires: advanced.expires,
        split: advanced.split,
        ratchet: advanced.ratchet,
        decoy: advanced.decoy,
        decoy_pass: advanced.decoy_pass,
    };
    apply_recipient(&mut cmd, recipient);

    log::step("Encoding...")?;
    cmd.execute()?;

    outro("Encoded successfully.")?;
    Ok(())
}

/// Optional encode flags collected behind the "Configure advanced options?"
/// gate. Defaults match the CLI defaults.
struct AdvancedEncodeOptions {
    sign: Option<PathBuf>,
    expires: Option<String>,
    ratchet: bool,
    my_key: Option<PathBuf>,
    decoy: Option<String>,
    decoy_pass: Option<String>,
    qr: Option<PathBuf>,
    qr_format: String,
    split: Option<u8>,
    min_coverage: u8,
    verbose: bool,
}

impl Default for AdvancedEncodeOptions {
    fn default() -> Self {
        Self {
            sign: None,
            expires: None,
            ratchet: false,
            my_key: None,
            decoy: None,
            decoy_pass: None,
            qr: None,
            qr_format: "png".to_string(),
            split: None,
            min_coverage: 100,
            verbose: false,
        }
    }
}

fn prompt_advanced() -> Result<AdvancedEncodeOptions> {
    let mut opts = AdvancedEncodeOptions::default();

    if confirm("Sign the message? (Ed25519, recipient can verify)")
        .initial_value(false)
        .interact()?
    {
        let path = prompt_existing_path("Path to your signing key (.sign.key)", "./me.sign.key")?;
        opts.sign = Some(path);
    }

    if confirm("Set expiration? (after which decode returns garbage)")
        .initial_value(false)
        .interact()?
    {
        let exp: String = input("Expiration (relative '+30m', '+24h', '+7d' or absolute '2025-12-31')")
            .placeholder("+24h")
            .interact()?;
        opts.expires = Some(exp.trim().to_string());
    }

    if confirm("Enable forward-secrecy ratchet? (requires ephemeral keys, classical only)")
        .initial_value(false)
        .interact()?
    {
        opts.ratchet = true;
        let path = prompt_existing_path(
            "Path to your private key for ratchet (will be auto-rotated)",
            "./me.key",
        )?;
        opts.my_key = Some(path);
    }

    if confirm("Add a decoy message? (duress password, plausible deniability)")
        .initial_value(false)
        .interact()?
    {
        log::warning(
            "The decoy message is shown when someone decodes with the decoy passphrase.\n\
             Pick something innocent and believable.",
        )?;
        let decoy: String = input("Decoy message")
            .placeholder("nothing important here")
            .interact()?;
        opts.decoy = Some(decoy);
        let decoy_pass = prompt_passphrase("Decoy passphrase")?;
        opts.decoy_pass = Some(decoy_pass);
    }

    if confirm("Generate a QR code in addition to the text code?")
        .initial_value(false)
        .interact()?
    {
        opts.qr = Some(prompt_new_path("QR output path", "./code.png")?);
        let format: &str = select("QR format")
            .item("png", "PNG (image)", "")
            .item("svg", "SVG (vector)", "")
            .item("ascii", "ASCII (terminal)", "")
            .interact()?;
        opts.qr_format = format.to_string();
    }

    if confirm("Split the code into N parts? (multi-channel delivery)")
        .initial_value(false)
        .interact()?
    {
        let n: u8 = input("Number of parts (2-10)")
            .default_input("3")
            .validate(|s: &String| match s.trim().parse::<u8>() {
                Ok(n) if (2..=10).contains(&n) => Ok(()),
                _ => Err("Enter a number between 2 and 10.".to_string()),
            })
            .interact()?;
        opts.split = Some(n);
    }

    if confirm("Lower minimum carrier coverage? (default 100% — secure)")
        .initial_value(false)
        .interact()?
    {
        log::warning(
            "Reducing coverage may leak information about the message.\n\
             Only use with carriers you trust completely.",
        )?;
        let pct: u8 = input("Min carrier coverage (0-100)")
            .default_input("100")
            .validate(|s: &String| match s.trim().parse::<u8>() {
                Ok(n) if n <= 100 => Ok(()),
                _ => Err("Enter a number between 0 and 100.".to_string()),
            })
            .interact()?;
        opts.min_coverage = pct;
    }

    opts.verbose = confirm("Verbose output?").initial_value(false).interact()?;

    Ok(opts)
}

fn apply_recipient(cmd: &mut EncodeCommand, sel: RecipientSelection) {
    match sel {
        RecipientSelection::Contact(alias) => cmd.to = Some(alias),
        RecipientSelection::TheirKey(path) => cmd.their_key = Some(path),
        RecipientSelection::EphFile { eph_file, contact } => {
            cmd.eph_file = Some(eph_file);
            cmd.contact = Some(contact);
        }
        RecipientSelection::EphSeparated {
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
    fn apply_recipient_contact_sets_to_field_only() {
        let mut cmd = empty_encode_cmd();
        apply_recipient(
            &mut cmd,
            RecipientSelection::Contact("alice".to_string()),
        );
        assert_eq!(cmd.to.as_deref(), Some("alice"));
        assert!(cmd.their_key.is_none());
        assert!(cmd.eph_file.is_none());
        assert!(cmd.contact.is_none());
    }

    #[test]
    fn apply_recipient_eph_separated_sets_three_fields() {
        let mut cmd = empty_encode_cmd();
        apply_recipient(
            &mut cmd,
            RecipientSelection::EphSeparated {
                eph_keys: PathBuf::from("/k.eph.key"),
                eph_pubs: PathBuf::from("/p.eph.pub"),
                contact: "alice".to_string(),
            },
        );
        assert_eq!(cmd.eph_keys, Some(PathBuf::from("/k.eph.key")));
        assert_eq!(cmd.eph_pubs, Some(PathBuf::from("/p.eph.pub")));
        assert_eq!(cmd.contact.as_deref(), Some("alice"));
        assert!(cmd.to.is_none());
    }

    fn empty_encode_cmd() -> EncodeCommand {
        EncodeCommand {
            carriers: vec![],
            message: None,
            file: None,
            passphrase: String::new(),
            key: None,
            to: None,
            their_key: None,
            my_key: None,
            eph_file: None,
            eph_keys: None,
            eph_pubs: None,
            contact: None,
            verbose: false,
            qr: None,
            qr_format: "png".to_string(),
            sign: None,
            min_coverage: 100,
            expires: None,
            split: None,
            ratchet: false,
            decoy: None,
            decoy_pass: None,
        }
    }
}
