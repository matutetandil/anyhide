//! Wizard flow: generate keys.
//!
//! Walks the user through `KeygenCommand` options and delegates execution to
//! the existing CLI command. The flow is intentionally a thin presentation
//! layer; all crypto/persistence logic lives in `commands::keygen`.

use anyhow::Result;
use cliclack::{confirm, input, log, outro, select};

use crate::commands::{CommandExecutor, KeygenCommand};
use crate::wizard::helpers::{prompt_path_with_default, BACK, BACK_LABEL};

/// Runs the keygen wizard. Errors propagated from the underlying command are
/// surfaced to the home loop, which logs them and returns to the menu.
pub fn run() -> Result<()> {
    log::info("Generate a new Anyhide identity (encryption + signing keys)")?;

    let lifecycle: &str = select("Key lifecycle")
        .item(
            "long_term",
            "Long-term keys",
            "persistent identity, share once",
        )
        .item(
            "ephemeral",
            "Ephemeral keys",
            "rotate per message — forward secrecy",
        )
        .item(BACK, BACK_LABEL, "")
        .interact()?;
    if lifecycle == BACK {
        return Ok(());
    }
    let ephemeral = lifecycle == "ephemeral";

    let crypto: &str = select("Encryption algorithm")
        .item(
            "hybrid",
            "Hybrid post-quantum (X25519 + ML-KEM-768)",
            "recommended — required for chat v2",
        )
        .item(
            "classical",
            "Classical X25519",
            "smaller keys, no PQ protection",
        )
        .item(BACK, BACK_LABEL, "")
        .interact()?;
    if crypto == BACK {
        return Ok(());
    }
    let hybrid = crypto == "hybrid";

    let output = prompt_path_with_default("Output path (without extension)", "anyhide")?;

    // Long-term keys can optionally show a paper-backup mnemonic. Ephemeral
    // keys rotate per message, so a paper backup makes no sense — KeygenCommand
    // emits a warning if both flags are set, but we suppress the option here
    // for a cleaner UX.
    let show_mnemonic = if !ephemeral {
        confirm("Show mnemonic backup phrases? (write down on paper)")
            .initial_value(false)
            .interact()?
    } else {
        false
    };

    // Ephemeral storage format. Only relevant for ephemeral keys.
    let (contact, eph_file, eph_keys, eph_pubs) = if ephemeral {
        match prompt_ephemeral_storage()? {
            Some(fields) => fields,
            None => return Ok(()),
        }
    } else {
        (None, None, None, None)
    };

    // Build the command struct as if it had been parsed from the CLI.
    let cmd = KeygenCommand {
        output,
        ephemeral,
        contact,
        eph_keys,
        eph_pubs,
        eph_file,
        show_mnemonic,
        hybrid,
    };

    log::step("Generating keys...")?;
    cmd.execute()?;

    outro("Keys generated successfully.")?;
    Ok(())
}

/// Prompt the ephemeral-store storage format (individual / unified / separated)
/// and return the matching `KeygenCommand` field values.
type EphFields = (
    Option<String>,
    Option<std::path::PathBuf>,
    Option<std::path::PathBuf>,
    Option<std::path::PathBuf>,
);

/// Returns `None` if the user picked Back.
fn prompt_ephemeral_storage() -> Result<Option<EphFields>> {
    let format: &str = select("Ephemeral storage format")
        .item(
            "individual",
            "Individual files (.pub + .key)",
            "simplest — like long-term keys",
        )
        .item(
            "unified",
            "Unified store (.eph)",
            "one file, both keys per contact",
        )
        .item(
            "separated",
            "Separated store (.eph.key + .eph.pub)",
            "private and public in different files",
        )
        .item(BACK, BACK_LABEL, "")
        .interact()?;

    match format {
        BACK => Ok(None),
        "individual" => Ok(Some((None, None, None, None))),
        "unified" => {
            let contact = prompt_contact_name()?;
            let eph_file = prompt_path_with_default(
                "Path to .eph file",
                &format!("{}.eph", contact),
            )?;
            Ok(Some((Some(contact), None, None, Some(eph_file))))
        }
        "separated" => {
            let contact = prompt_contact_name()?;
            let eph_keys = prompt_path_with_default(
                "Path to .eph.key file",
                &format!("{}.eph.key", contact),
            )?;
            let eph_pubs = prompt_path_with_default(
                "Path to .eph.pub file",
                &format!("{}.eph.pub", contact),
            )?;
            Ok(Some((Some(contact), Some(eph_keys), Some(eph_pubs), None)))
        }
        _ => unreachable!("select returned an unknown variant"),
    }
}

fn prompt_contact_name() -> Result<String> {
    let name: String = input("Contact name (used as the store key)")
        .placeholder("alice")
        .validate(|s: &String| {
            if s.trim().is_empty() {
                Err("Contact name cannot be empty.")
            } else {
                Ok(())
            }
        })
        .interact()?;
    Ok(name.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Sanity-check that the KeygenCommand struct can be constructed
    /// programmatically with the same shape clap would produce.
    #[test]
    fn keygen_command_constructs_with_default_long_term_classical() {
        let cmd = KeygenCommand {
            output: PathBuf::from("anyhide"),
            ephemeral: false,
            contact: None,
            eph_keys: None,
            eph_pubs: None,
            eph_file: None,
            show_mnemonic: false,
            hybrid: false,
        };
        assert!(!cmd.hybrid);
        assert!(!cmd.ephemeral);
        assert_eq!(cmd.output, PathBuf::from("anyhide"));
    }

    #[test]
    fn keygen_command_constructs_for_ephemeral_unified() {
        let cmd = KeygenCommand {
            output: PathBuf::from("anyhide"),
            ephemeral: true,
            contact: Some("alice".to_string()),
            eph_keys: None,
            eph_pubs: None,
            eph_file: Some(PathBuf::from("alice.eph")),
            show_mnemonic: false,
            hybrid: true,
        };
        assert!(cmd.hybrid);
        assert!(cmd.ephemeral);
        assert_eq!(cmd.contact.as_deref(), Some("alice"));
        assert!(cmd.eph_file.is_some());
        assert!(cmd.eph_keys.is_none());
    }
}
