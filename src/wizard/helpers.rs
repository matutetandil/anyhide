//! Shared prompt helpers reused across wizard flows.
//!
//! These functions wrap cliclack primitives with project-specific defaults
//! (path validation, carrier collection loop, recipient/key resolution).

use std::path::PathBuf;

use anyhow::Result;
use cliclack::{confirm, input, password, select};

/// Magic value for the "← Back" item added to flow-level select prompts.
/// Selecting this signals that the caller should unwind to the previous level
/// (or the home menu, depending on where Back was invoked).
pub const BACK: &str = "_back";

/// Visible label for the Back item. Shared so all selects look identical.
pub const BACK_LABEL: &str = "← Back";

/// Prompt for a filesystem path that must exist. Loops on the same prompt
/// until the user enters a valid existing path or cancels.
pub fn prompt_existing_path(label: &str, placeholder: &str) -> Result<PathBuf> {
    let raw: String = input(label)
        .placeholder(placeholder)
        .validate(|s: &String| {
            let p = PathBuf::from(s.trim());
            if s.trim().is_empty() {
                Err("Path cannot be empty.".to_string())
            } else if !p.exists() {
                Err(format!("Path does not exist: {}", p.display()))
            } else {
                Ok(())
            }
        })
        .interact()?;
    Ok(PathBuf::from(raw.trim()))
}

/// Prompt for a path that may or may not exist (e.g., output destinations).
pub fn prompt_new_path(label: &str, placeholder: &str) -> Result<PathBuf> {
    let raw: String = input(label)
        .placeholder(placeholder)
        .validate(|s: &String| {
            if s.trim().is_empty() {
                Err("Path cannot be empty.".to_string())
            } else {
                Ok(())
            }
        })
        .interact()?;
    Ok(PathBuf::from(raw.trim()))
}

/// Prompt for a path with a default value. Empty input returns the default.
pub fn prompt_path_with_default(label: &str, default: &str) -> Result<PathBuf> {
    let raw: String = input(label).default_input(default).interact()?;
    let trimmed = raw.trim();
    let final_path = if trimmed.is_empty() { default } else { trimmed };
    Ok(PathBuf::from(final_path))
}

/// Prompt for a hidden passphrase (masked input).
pub fn prompt_passphrase(label: &str) -> Result<String> {
    let p: String = password(label)
        .mask('*')
        .validate(|s: &String| {
            if s.is_empty() {
                Err("Passphrase cannot be empty.")
            } else {
                Ok(())
            }
        })
        .interact()?;
    Ok(p)
}

/// Collect one or more carrier paths in order. Order matters — see
/// `EncodeCommand` doc-comment.
pub fn collect_carriers() -> Result<Vec<PathBuf>> {
    let mut carriers = Vec::new();
    loop {
        let label = if carriers.is_empty() {
            "Carrier file path (any file: text, image, audio, etc.)".to_string()
        } else {
            format!(
                "Next carrier path (carrier #{}, order matters)",
                carriers.len() + 1
            )
        };
        let path = prompt_existing_path(&label, "./carrier.txt")?;
        carriers.push(path);

        let add_more = confirm("Add another carrier?")
            .initial_value(false)
            .interact()?;
        if !add_more {
            break;
        }
    }
    Ok(carriers)
}

/// User's recipient selection — encode flow.
#[derive(Debug, Clone)]
pub enum RecipientSelection {
    /// Contact alias from `~/.anyhide/contacts.toml`.
    Contact(String),
    /// Direct path to a `.pub` file (classical or hybrid PEM, auto-detected).
    TheirKey(PathBuf),
    /// Unified ephemeral store `.eph` + contact name.
    EphFile { eph_file: PathBuf, contact: String },
    /// Separated ephemeral store `.eph.key` + `.eph.pub` + contact name.
    EphSeparated {
        eph_keys: PathBuf,
        eph_pubs: PathBuf,
        contact: String,
    },
}

/// Walk the user through picking a recipient. The four variants map 1:1 to
/// `EncodeCommand::resolve_their_public_key` priority order.
///
/// Returns `None` if the user picked "← Back" — the caller should unwind to
/// the previous level (typically the home menu).
pub fn select_recipient() -> Result<Option<RecipientSelection>> {
    let kind: &str = select("Recipient")
        .item("contact", "Contact alias", "from ~/.anyhide/contacts.toml")
        .item("file", "Public key file (.pub)", "PEM file path")
        .item(
            "eph_file",
            "Unified ephemeral store",
            ".eph file + contact name",
        )
        .item(
            "eph_sep",
            "Separated ephemeral store",
            ".eph.key + .eph.pub + contact",
        )
        .item(BACK, BACK_LABEL, "")
        .interact()?;

    match kind {
        BACK => Ok(None),
        "contact" => {
            let alias: String = input("Contact alias")
                .placeholder("alice")
                .validate(|s: &String| {
                    if s.trim().is_empty() {
                        Err("Alias cannot be empty.")
                    } else {
                        Ok(())
                    }
                })
                .interact()?;
            Ok(Some(RecipientSelection::Contact(alias.trim().to_string())))
        }
        "file" => {
            let path = prompt_existing_path("Path to recipient's .pub file", "./alice.pub")?;
            Ok(Some(RecipientSelection::TheirKey(path)))
        }
        "eph_file" => {
            let eph_file = prompt_existing_path("Path to .eph file", "./contacts.eph")?;
            let contact: String = input("Contact name")
                .placeholder("alice")
                .interact()?;
            Ok(Some(RecipientSelection::EphFile {
                eph_file,
                contact: contact.trim().to_string(),
            }))
        }
        "eph_sep" => {
            let eph_keys = prompt_existing_path("Path to .eph.key file", "./contacts.eph.key")?;
            let eph_pubs = prompt_existing_path("Path to .eph.pub file", "./contacts.eph.pub")?;
            let contact: String = input("Contact name")
                .placeholder("alice")
                .interact()?;
            Ok(Some(RecipientSelection::EphSeparated {
                eph_keys,
                eph_pubs,
                contact: contact.trim().to_string(),
            }))
        }
        _ => unreachable!("select returned an unknown variant"),
    }
}

/// User's private-key selection — decode flow. Mirrors `RecipientSelection`
/// but the variants reflect `DecodeCommand::resolve_my_private_key` semantics.
#[derive(Debug, Clone)]
pub enum MyKeySelection {
    /// Direct path to your `.key` file (classical or hybrid PEM, auto-detected).
    MyKey(PathBuf),
    /// Unified ephemeral store `.eph` + contact name.
    EphFile { eph_file: PathBuf, contact: String },
    /// Separated ephemeral store `.eph.key` + `.eph.pub` + contact name.
    EphSeparated {
        eph_keys: PathBuf,
        eph_pubs: PathBuf,
        contact: String,
    },
}

/// Returns `None` if the user picked "← Back".
pub fn select_my_key() -> Result<Option<MyKeySelection>> {
    let kind: &str = select("Your private key")
        .item("file", "Private key file (.key)", "PEM file path")
        .item(
            "eph_file",
            "Unified ephemeral store",
            ".eph file + contact name",
        )
        .item(
            "eph_sep",
            "Separated ephemeral store",
            ".eph.key + .eph.pub + contact",
        )
        .item(BACK, BACK_LABEL, "")
        .interact()?;

    match kind {
        BACK => Ok(None),
        "file" => {
            let path = prompt_existing_path("Path to your .key file", "./me.key")?;
            Ok(Some(MyKeySelection::MyKey(path)))
        }
        "eph_file" => {
            let eph_file = prompt_existing_path("Path to .eph file", "./contacts.eph")?;
            let contact: String = input("Contact name")
                .placeholder("alice")
                .interact()?;
            Ok(Some(MyKeySelection::EphFile {
                eph_file,
                contact: contact.trim().to_string(),
            }))
        }
        "eph_sep" => {
            let eph_keys = prompt_existing_path("Path to .eph.key file", "./contacts.eph.key")?;
            let eph_pubs = prompt_existing_path("Path to .eph.pub file", "./contacts.eph.pub")?;
            let contact: String = input("Contact name")
                .placeholder("alice")
                .interact()?;
            Ok(Some(MyKeySelection::EphSeparated {
                eph_keys,
                eph_pubs,
                contact: contact.trim().to_string(),
            }))
        }
        _ => unreachable!("select returned an unknown variant"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_selection_contact_variant_holds_alias() {
        let sel = RecipientSelection::Contact("alice".to_string());
        match sel {
            RecipientSelection::Contact(name) => assert_eq!(name, "alice"),
            _ => panic!("expected Contact variant"),
        }
    }

    #[test]
    fn my_key_eph_separated_variant_holds_paths_and_contact() {
        let sel = MyKeySelection::EphSeparated {
            eph_keys: PathBuf::from("/a.eph.key"),
            eph_pubs: PathBuf::from("/a.eph.pub"),
            contact: "alice".to_string(),
        };
        match sel {
            MyKeySelection::EphSeparated {
                eph_keys,
                eph_pubs,
                contact,
            } => {
                assert_eq!(eph_keys, PathBuf::from("/a.eph.key"));
                assert_eq!(eph_pubs, PathBuf::from("/a.eph.pub"));
                assert_eq!(contact, "alice");
            }
            _ => panic!("expected EphSeparated variant"),
        }
    }
}
