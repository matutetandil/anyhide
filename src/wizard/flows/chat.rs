//! Wizard flow: P2P encrypted chat over Tor.
//!
//! Wraps `ChatCommand`, which has both a positional "open chat with contact"
//! mode and a set of subcommands (init, me, list, add, show, remove, export-qr,
//! import-qr). When the user picks "Open chat", `ChatCommand::execute()`
//! starts the chat ratatui — the wizard's home loop will clear the screen
//! after the chat exits, so the two TUIs hand off cleanly.

use std::path::PathBuf;

use anyhow::Result;
use cliclack::{input, log, outro, select};

use crate::commands::{ChatAction, ChatCommand, CommandExecutor};
use crate::wizard::helpers::{prompt_existing_path, prompt_path_with_default, BACK, BACK_LABEL};

pub fn run() -> Result<()> {
    log::info("P2P encrypted chat over Tor (hybrid PQ handshake)")?;

    let action: &str = select("Chat action")
        .item("init", "Initialize my chat identity", "creates an .onion address")
        .item("me", "Show my identity", "address + key fingerprints")
        .item("open", "Open chat with a contact", "starts the chat TUI")
        .item("list", "List chat contacts", "")
        .item("add", "Add a chat contact", "")
        .item("show", "Show contact details", "")
        .item("remove", "Remove a chat contact", "")
        .item("export_qr", "Export my identity to QR", "share with peers")
        .item("import_qr", "Import contact from QR", "")
        .item(BACK, BACK_LABEL, "")
        .interact()?;

    if action == BACK {
        return Ok(());
    }

    let cmd = match action {
        "init" => build_init()?,
        "me" => default_with_action(ChatAction::Me),
        "open" => build_open()?,
        "list" => default_with_action(ChatAction::List),
        "add" => build_add()?,
        "show" => build_show()?,
        "remove" => build_remove()?,
        "export_qr" => build_export_qr()?,
        "import_qr" => build_import_qr()?,
        _ => unreachable!("select returned an unknown variant"),
    };

    log::step("Running chat command...")?;
    cmd.execute()?;

    outro("Done.")?;
    Ok(())
}

/// Default `ChatCommand` skeleton. Each flow overrides the field(s) it cares
/// about, mirroring how clap fills in defaults from `#[arg(default_value)]`.
fn default_chat_command() -> ChatCommand {
    ChatCommand {
        contact: None,
        carriers: 10,
        carrier_size: 4096,
        carrier_files: None,
        profile: None,
        ephemeral: false,
        onion: None,
        pubkey: None,
        sign_key: None,
        from_qr: None,
        action: None,
    }
}

fn default_with_action(action: ChatAction) -> ChatCommand {
    ChatCommand {
        action: Some(action),
        ..default_chat_command()
    }
}

fn build_init() -> Result<ChatCommand> {
    let nickname: String = input("Nickname for your hidden service")
        .default_input("anyhide-chat")
        .interact()?;
    let key = prompt_existing_path(
        "Encryption key pair base path (e.g. './me' for me.pub/me.key)",
        "./me",
    )?;
    let sign_key = prompt_existing_path("Signing key pair base path", "./me")?;
    Ok(ChatCommand {
        action: Some(ChatAction::Init {
            nickname: nickname.trim().to_string(),
            key,
            sign_key,
        }),
        ..default_chat_command()
    })
}

fn build_open() -> Result<ChatCommand> {
    let contact: String = input("Contact name")
        .placeholder("alice")
        .validate(non_empty)
        .interact()?;
    Ok(ChatCommand {
        contact: Some(contact.trim().to_string()),
        ..default_chat_command()
    })
}

fn build_add() -> Result<ChatCommand> {
    let name: String = input("Contact name (alias)")
        .placeholder("alice")
        .validate(non_empty)
        .interact()?;
    let onion: String = input("Their .onion address")
        .placeholder("xxxxxxxxxxxxxxxx.onion")
        .validate(non_empty)
        .interact()?;
    let key = prompt_existing_path("Path to their encryption public key (.pub)", "./alice.pub")?;
    let sign_key = prompt_existing_path(
        "Path to their signing public key (.sign.pub)",
        "./alice.sign.pub",
    )?;
    Ok(ChatCommand {
        action: Some(ChatAction::Add {
            name: name.trim().to_string(),
            onion: onion.trim().to_string(),
            key,
            sign_key,
        }),
        ..default_chat_command()
    })
}

fn build_show() -> Result<ChatCommand> {
    let name: String = input("Contact name to show")
        .placeholder("alice")
        .validate(non_empty)
        .interact()?;
    Ok(default_with_action(ChatAction::Show {
        name: name.trim().to_string(),
    }))
}

fn build_remove() -> Result<ChatCommand> {
    let name: String = input("Contact name to remove")
        .placeholder("alice")
        .validate(non_empty)
        .interact()?;
    Ok(default_with_action(ChatAction::Remove {
        name: name.trim().to_string(),
    }))
}

fn build_export_qr() -> Result<ChatCommand> {
    let output: PathBuf = prompt_path_with_default("Output file for QR", "identity.png")?;
    let format: &str = select("QR format")
        .item("png", "PNG (image)", "")
        .item("svg", "SVG (vector)", "")
        .item("ascii", "ASCII (terminal)", "")
        .interact()?;
    Ok(default_with_action(ChatAction::ExportQr {
        output,
        format: format.to_string(),
    }))
}

fn build_import_qr() -> Result<ChatCommand> {
    let image = prompt_existing_path("Path to QR image", "./identity.png")?;
    let name: String = input("Contact name (alias)")
        .placeholder("alice")
        .validate(non_empty)
        .interact()?;
    Ok(default_with_action(ChatAction::ImportQr {
        image,
        name: name.trim().to_string(),
    }))
}

fn non_empty(s: &String) -> Result<(), &'static str> {
    if s.trim().is_empty() {
        Err("Cannot be empty.")
    } else {
        Ok(())
    }
}
