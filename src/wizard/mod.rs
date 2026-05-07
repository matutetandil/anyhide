//! Interactive wizard mode entry point.
//!
//! Triggered by running `anyhide` without a subcommand. Presents a top-level
//! menu and dispatches into per-command flows. Each flow collects user input
//! via cliclack prompts, builds the corresponding `*Command` struct (the same
//! one clap parses), and calls `CommandExecutor::execute()`. The wizard is
//! purely a front-end — all business logic remains in `src/commands/`.

mod flows;
mod helpers;

use anyhow::Result;
use cliclack::{intro, log, outro, select};
use console::style;

/// Block-style ANYHIDE banner. Width 43, height 5, fits any terminal >= 60 cols.
/// Cyan styling matches the project brand color (#22D3EE in the dev.to covers).
const ANYHIDE_BANNER_LINES: [&str; 5] = [
    " █████  ███   ██ ██   ██ ██ ██████  ███████",
    "██   ██ ████  ██  ██ ██  ██ ██   ██ ██     ",
    "███████ ██ ██ ██   ███   ██ ██   ██ █████  ",
    "██   ██ ██  ████    ██   ██ ██   ██ ██     ",
    "██   ██ ██   ███    ██   ██ ██████  ███████",
];

/// Print the ASCII art banner with cyan styling and a tagline below.
fn print_banner() {
    println!();
    for line in ANYHIDE_BANNER_LINES.iter() {
        println!("  {}", style(line).cyan().bold());
    }
    println!(
        "\n  {} {} {}",
        style(format!("v{}", env!("CARGO_PKG_VERSION"))).cyan(),
        style("·").dim(),
        style("hide anything in anything").dim(),
    );
    println!();
}

/// Run the interactive wizard. Loops over the home menu until the user picks
/// "Exit" (or presses Esc/Ctrl+C, which is caught and treated as Exit).
pub fn run_wizard() -> Result<()> {
    print_banner();
    intro(style(" anyhide ").on_cyan().black())?;

    loop {
        // Esc/Ctrl+C at the home menu cancels the prompt. cliclack returns
        // io::Error in that case — we treat it as "exit" rather than crashing.
        let action_result = select("What would you like to do?")
            .item("encode", "Encode a message or file", "")
            .item("decode", "Decode a code", "")
            .item("keygen", "Generate keys", "")
            .item("demo", "Test mode (public demo)", "no keys needed")
            .item("chat", "Open chat", "coming soon")
            .item("contacts", "Manage contacts", "coming soon")
            .item("qr", "QR codes", "coming soon")
            .item("mnemonic", "Mnemonic backup", "coming soon")
            .item("exit", "Exit", "")
            .interact();

        let action = match action_result {
            Ok(a) => a,
            Err(_) => {
                outro("Bye!")?;
                return Ok(());
            }
        };

        let result = match action {
            "encode" => flows::encode::run(),
            "decode" => flows::decode::run(),
            "keygen" => flows::keygen::run(),
            "demo" => flows::demo::run(),
            "chat" | "contacts" | "qr" | "mnemonic" => {
                log::info(format!(
                    "'{}' wizard flow is coming in the next session — for now, run `anyhide {} --help`",
                    action, command_hint(action)
                ))?;
                Ok(())
            }
            "exit" => {
                outro("Bye!")?;
                return Ok(());
            }
            _ => Ok(()),
        };

        if let Err(e) = result {
            log::error(format!("{:#}", e))?;
        }
    }
}

/// Maps an action key to the CLI subcommand name shown in the "coming soon" hint.
fn command_hint(action: &str) -> &'static str {
    match action {
        "chat" => "chat",
        "contacts" => "contacts",
        "qr" => "qr-generate",
        "mnemonic" => "export-mnemonic",
        _ => "",
    }
}
