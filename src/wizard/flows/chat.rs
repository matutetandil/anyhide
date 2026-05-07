//! Wizard flow: P2P encrypted chat over Tor.
//!
//! Wraps `ChatCommand`, which has both a positional "open chat with contact"
//! mode and a set of subcommands (init, me, list, add, show, remove, export-qr,
//! import-qr). When the user picks "Open chat", `ChatCommand::execute()`
//! starts the chat ratatui — the wizard's home loop will clear the screen
//! after the chat exits, so the two TUIs hand off cleanly.

use std::path::PathBuf;

use anyhow::{Context, Result};
use cliclack::{input, log, outro, select};

use crate::commands::{ChatAction, ChatCommand, CommandExecutor, KeygenCommand};
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

/// Build the `ChatCommand` for `Init`, generating identity keys under
/// `~/.anyhide/<nickname>.{pub,key,sign.pub,sign.key}` if they don't exist.
///
/// First-run UX: the user only types a nickname; everything else is derived.
/// On re-run, existing keys are reused (no overwrite). This matches the
/// post-v0.15.0 filesystem layout where Anyhide owns `~/.anyhide/` and
/// stores its own state there instead of asking the user for arbitrary paths.
fn build_init() -> Result<ChatCommand> {
    let nickname: String = input("Nickname for your chat identity")
        .default_input("anyhide-chat")
        .validate(|s: &String| {
            let t = s.trim();
            if t.is_empty() {
                Err("Nickname cannot be empty.")
            } else if t.contains('/') || t.contains('\\') {
                Err("Nickname cannot contain path separators.")
            } else {
                Ok(())
            }
        })
        .interact()?;
    let nickname = nickname.trim().to_string();

    // Resolve `~/.anyhide/<nickname>` as the base path. The encryption files
    // become `<base>.pub`/`<base>.key`, the signing files become
    // `<base>.sign.pub`/`<base>.sign.key` — same convention `KeygenCommand`
    // already uses for `--output`.
    let home = anyhide::paths::home().context("Failed to resolve ~/.anyhide directory")?;
    std::fs::create_dir_all(&home)
        .with_context(|| format!("Failed to create {}", home.display()))?;
    let key_base = home.join(&nickname);

    ensure_identity_keys(&key_base)?;

    Ok(ChatCommand {
        action: Some(ChatAction::Init {
            nickname,
            key: key_base.clone(),
            sign_key: key_base,
        }),
        ..default_chat_command()
    })
}

/// Generate hybrid PQ identity keys at `<key_base>` if they don't already
/// exist. Reuses any complete set on disk; bails on a partial/corrupt state
/// rather than silently regenerating (would orphan the contact's view of us).
fn ensure_identity_keys(key_base: &PathBuf) -> Result<()> {
    let pub_path = key_base.with_extension("pub");
    let key_path = key_base.with_extension("key");
    let sign_pub_path = with_extra_ext(key_base, "sign.pub");
    let sign_key_path = with_extra_ext(key_base, "sign.key");

    let parts = [&pub_path, &key_path, &sign_pub_path, &sign_key_path];
    let exists: Vec<bool> = parts.iter().map(|p| p.exists()).collect();

    if exists.iter().all(|e| *e) {
        log::info(format!(
            "Reusing existing identity keys at {}.{{pub,key,sign.pub,sign.key}}",
            key_base.display()
        ))?;
        return Ok(());
    }

    if exists.iter().any(|e| *e) {
        anyhow::bail!(
            "Inconsistent identity at {}: some of .pub/.key/.sign.pub/.sign.key exist but not all. \
             Remove or rename them and try again.",
            key_base.display()
        );
    }

    log::info(format!(
        "Generating hybrid PQ identity at {}.{{pub,key,sign.pub,sign.key}}",
        key_base.display()
    ))?;

    let keygen = KeygenCommand {
        output: key_base.clone(),
        ephemeral: false,
        contact: None,
        eph_keys: None,
        eph_pubs: None,
        eph_file: None,
        show_mnemonic: false,
        hybrid: true,
    };
    keygen.execute().context("Failed to generate identity keys")?;

    log::remark(format!(
        "Tip: back up your keys with `anyhide export-mnemonic {}` (and {})",
        key_path.display(),
        sign_key_path.display()
    ))?;

    Ok(())
}

/// Append a multi-segment extension like `sign.pub` to a base path. Rust's
/// `with_extension` only handles single segments, so we splice manually to
/// match `KeygenCommand`'s naming (`<base>.sign.pub`).
fn with_extra_ext(base: &PathBuf, ext: &str) -> PathBuf {
    let mut s = base.as_os_str().to_os_string();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
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
