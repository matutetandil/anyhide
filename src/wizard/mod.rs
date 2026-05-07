//! Interactive wizard mode entry point.
//!
//! Triggered by running `anyhide` without a subcommand. Presents a top-level
//! menu and dispatches into per-command flows. Each flow collects user input
//! via cliclack prompts, builds the corresponding `*Command` struct (the same
//! one clap parses), and calls `CommandExecutor::execute()`. The wizard is
//! purely a front-end — all business logic remains in `src/commands/`.

mod flows;
mod helpers;

use std::io::{self, BufRead};

use anyhow::Result;
use cliclack::{clear_screen, intro, log, outro, select};
use console::style;

/// ANSI Shadow ANYHIDE banner with the 6-dot braille logo on the left.
///
/// Logo (cols 0-4) reproduces the same 6-dot pattern as the chat TUI's `⠿`
/// app icon: three rows of `██ ██` separated by blank rows so each dot is
/// visually distinct (without the gaps the columns merge into solid bars).
/// Banner reads "ANYHIDE" in ANSI Shadow font (6 rows × 54 cols, the
/// box-drawing chars `╔╗╚╝═║` give the 3D-shadow effect). Total width 63,
/// fits any terminal ≥ 80 cols. Cyan styling matches the project brand
/// color (#22D3EE in the dev.to covers).
const ANYHIDE_BANNER_LINES: [&str; 6] = [
    "██ ██     █████╗ ███╗   ██╗██╗   ██╗██╗  ██╗██╗██████╗ ███████╗",
    "         ██╔══██╗████╗  ██║╚██╗ ██╔╝██║  ██║██║██╔══██╗██╔════╝",
    "██ ██    ███████║██╔██╗ ██║ ╚████╔╝ ███████║██║██║  ██║█████╗  ",
    "         ██╔══██║██║╚██╗██║  ╚██╔╝  ██╔══██║██║██║  ██║██╔══╝  ",
    "██ ██    ██║  ██║██║ ╚████║   ██║   ██║  ██║██║██████╔╝███████╗",
    "         ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝",
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

/// Run the interactive wizard.
///
/// Each loop iteration is treated as an isolated "screen": the terminal is
/// cleared and the banner + intro are repainted before the home select. After
/// a flow finishes, the wizard pauses on a "Press Enter to return to menu"
/// line so the user has time to read or copy the printed result before the
/// next clear. This keeps the prompt-style UX (we don't manage a persistent
/// dashboard like ratatui) while avoiding the indefinite scrollback that
/// happens when each iteration just appends to stdout.
///
/// Esc/Ctrl+C on the home select is treated as Exit rather than a crash.
pub fn run_wizard() -> Result<()> {
    loop {
        clear_screen()?;
        print_banner();
        intro(style(" anyhide ").on_cyan().black())?;

        let action_result = select("What would you like to do?")
            .item("encode", "Encode a message or file", "")
            .item("decode", "Decode a code", "")
            .item("keygen", "Generate keys", "")
            .item("demo", "Test mode (public demo)", "no keys needed")
            .item("chat", "P2P chat over Tor", "")
            .item("contacts", "Manage contacts", "")
            .item("qr", "QR codes", "")
            .item("mnemonic", "Mnemonic backup", "")
            .item("exit", "Exit", "")
            .interact();

        let action = match action_result {
            Ok(a) => a,
            Err(_) => {
                outro("Bye!")?;
                return Ok(());
            }
        };

        if action == "exit" {
            outro("Bye!")?;
            return Ok(());
        }

        let result = match action {
            "encode" => flows::encode::run(),
            "decode" => flows::decode::run(),
            "keygen" => flows::keygen::run(),
            "demo" => flows::demo::run(),
            "chat" => flows::chat::run(),
            "contacts" => flows::contacts::run(),
            "qr" => flows::qr::run(),
            "mnemonic" => flows::mnemonic::run(),
            _ => Ok(()),
        };

        if let Err(e) = result {
            log::error(format!("{:#}", e))?;
        }

        pause_for_ack();
    }
}

/// Block until the user presses Enter, so they can read or copy the previous
/// flow's output before the next clear_screen wipes it. Errors (e.g. Ctrl+C
/// on the read) fall through silently — the home loop will clear and ask
/// again, and the user can pick Exit.
fn pause_for_ack() {
    println!();
    println!("  {}", style("Press Enter to return to menu...").dim());
    let stdin = io::stdin();
    let mut buf = String::new();
    let _ = stdin.lock().read_line(&mut buf);
}

