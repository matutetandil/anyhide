//! Wizard flow: BIP39 mnemonic backup/restore.
//!
//! Export takes a long-term key file and prints its 24-word phrase (or three
//! phrases for hybrid PQ keys) so the user can write them down on paper.
//! Import does the reverse — reading the phrase(s) from stdin and rebuilding
//! the .pub/.key files. Ephemeral keys are not supported (they rotate per
//! message and shouldn't be backed up).

use anyhow::Result;
use cliclack::{log, outro, select};

use crate::commands::{
    CommandExecutor, ExportMnemonicCommand, ImportKeyType, ImportMnemonicCommand,
};
use crate::wizard::helpers::{prompt_existing_path, prompt_path_with_default, BACK, BACK_LABEL};

pub fn run() -> Result<()> {
    log::info("Mnemonic backup (BIP39)")?;

    let action: &str = select("Mnemonic action")
        .item("export", "Export key as a 24-word phrase", "long-term keys only")
        .item("import", "Import key from phrase(s)", "restore from paper backup")
        .item(BACK, BACK_LABEL, "")
        .interact()?;

    match action {
        BACK => Ok(()),
        "export" => run_export(),
        "import" => run_import(),
        _ => unreachable!("select returned an unknown variant"),
    }
}

fn run_export() -> Result<()> {
    let key_path = prompt_existing_path(
        "Path to long-term key file (.key, .sign.key, or hybrid .key)",
        "./me.key",
    )?;

    let cmd = ExportMnemonicCommand { key_path };

    log::step("Exporting mnemonic...")?;
    cmd.execute()?;

    outro("Mnemonic exported. Write it down on paper.")?;
    Ok(())
}

fn run_import() -> Result<()> {
    let key_type: &str = select("Key type to restore")
        .item(
            "encryption",
            "Classical X25519 encryption key",
            "1 phrase × 24 words",
        )
        .item(
            "hybrid",
            "Hybrid PQ encryption key (X25519 + ML-KEM-768)",
            "3 phrases × 24 words",
        )
        .item("signing", "Ed25519 signing key", "1 phrase × 24 words")
        .interact()?;

    let import_key_type = match key_type {
        "encryption" => ImportKeyType::Encryption,
        "hybrid" => ImportKeyType::Hybrid,
        "signing" => ImportKeyType::Signing,
        _ => unreachable!(),
    };

    let output = prompt_path_with_default("Output base path (without extension)", "restored")?;

    log::warning(
        "You'll be prompted on stdin for the mnemonic phrase(s).\n\
         Type or paste 24 space-separated words per phrase.",
    )?;

    let cmd = ImportMnemonicCommand {
        output,
        key_type: import_key_type,
    };

    log::step("Restoring key...")?;
    cmd.execute()?;

    outro("Key restored.")?;
    Ok(())
}
