//! Wizard flow: manage contact aliases.
//!
//! Wraps `ContactsCommand` (`add`/`list`/`show`/`remove`). Contacts are
//! stored in `~/.anyhide/contacts.toml` and used by encode via `--to <alias>`.

use anyhow::Result;
use cliclack::{confirm, input, log, outro, select};

use crate::commands::{
    CommandExecutor, ContactsAction, ContactsAddArgs, ContactsCommand, ContactsRemoveArgs,
    ContactsShowArgs,
};
use crate::wizard::helpers::{prompt_existing_path, BACK, BACK_LABEL};

pub fn run() -> Result<()> {
    log::info("Manage contact aliases (~/.anyhide/contacts.toml)")?;

    let action: &str = select("Contacts action")
        .item("list", "List all contacts", "")
        .item("add", "Add a new contact", "")
        .item("show", "Show contact details + fingerprint", "")
        .item("remove", "Remove a contact", "")
        .item(BACK, BACK_LABEL, "")
        .interact()?;

    if action == BACK {
        return Ok(());
    }

    let cmd = match action {
        "list" => ContactsCommand {
            action: ContactsAction::List,
        },
        "add" => {
            let name: String = input("Contact name (alias)")
                .placeholder("alice")
                .validate(non_empty)
                .interact()?;
            let key_path =
                prompt_existing_path("Path to contact's public key (.pub)", "./alice.pub")?;
            let signing = if confirm("Also add their signing public key?")
                .initial_value(false)
                .interact()?
            {
                Some(prompt_existing_path(
                    "Path to signing public key (.sign.pub)",
                    "./alice.sign.pub",
                )?)
            } else {
                None
            };
            ContactsCommand {
                action: ContactsAction::Add(ContactsAddArgs {
                    name: name.trim().to_string(),
                    key_path,
                    signing,
                }),
            }
        }
        "show" => {
            let name: String = input("Contact name to show")
                .placeholder("alice")
                .validate(non_empty)
                .interact()?;
            ContactsCommand {
                action: ContactsAction::Show(ContactsShowArgs {
                    name: name.trim().to_string(),
                }),
            }
        }
        "remove" => {
            let name: String = input("Contact name to remove")
                .placeholder("alice")
                .validate(non_empty)
                .interact()?;
            ContactsCommand {
                action: ContactsAction::Remove(ContactsRemoveArgs {
                    name: name.trim().to_string(),
                }),
            }
        }
        _ => unreachable!("select returned an unknown variant"),
    };

    log::step("Running...")?;
    cmd.execute()?;

    outro("Done.")?;
    Ok(())
}

fn non_empty(s: &String) -> Result<(), &'static str> {
    if s.trim().is_empty() {
        Err("Cannot be empty.")
    } else {
        Ok(())
    }
}
