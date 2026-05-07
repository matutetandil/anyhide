//! Wizard flow: public demo / test mode.
//!
//! Lets newcomers play with Anyhide's encoder without generating identities
//! or picking carriers. Wraps `commands::demo::DemoCommand` with a guided
//! menu. All security warnings from the demo bundle apply.

use anyhow::Result;
use cliclack::{input, log, outro, select};

use crate::commands::{CommandExecutor, DemoAction, DemoCommand};
use crate::demo;
use crate::wizard::helpers::{BACK, BACK_LABEL};

pub fn run() -> Result<()> {
    log::warning(demo::WARNING)?;

    let action: &str = select("Demo mode action")
        .item("encode", "Encode a message", "produce a public code")
        .item("decode", "Decode a code", "decode something you produced")
        .item("info", "Show demo bundle info", "passphrase, key, carrier")
        .item(BACK, BACK_LABEL, "")
        .interact()?;

    let cmd = match action {
        BACK => return Ok(()),
        "encode" => {
            let message: String = input("Message to encode")
                .placeholder("Hello world!")
                .validate(|s: &String| {
                    if s.trim().is_empty() {
                        Err("Message cannot be empty.")
                    } else {
                        Ok(())
                    }
                })
                .interact()?;
            DemoCommand {
                action: DemoAction::Encode { message },
            }
        }
        "decode" => {
            let code: String = input("Anyhide code to decode")
                .placeholder("base64 string from `anyhide demo encode`")
                .validate(|s: &String| {
                    if s.trim().is_empty() {
                        Err("Code cannot be empty.")
                    } else {
                        Ok(())
                    }
                })
                .interact()?;
            DemoCommand {
                action: DemoAction::Decode {
                    code: code.trim().to_string(),
                },
            }
        }
        "info" => DemoCommand {
            action: DemoAction::Info,
        },
        _ => unreachable!("select returned an unknown variant"),
    };

    log::step("Running demo...")?;
    cmd.execute()?;

    outro("Demo complete.")?;
    Ok(())
}
