//! Wizard flow: QR code utilities (generate / read / capacity info).
//!
//! Wraps the three top-level QR commands. The wizard surfaces them under a
//! single "QR codes" entry point so the user picks the action interactively
//! instead of remembering three separate subcommand names.

use anyhow::Result;
use cliclack::{confirm, input, log, outro, select};

use crate::commands::{CommandExecutor, QrGenerateCommand, QrInfoCommand, QrReadCommand};
use crate::wizard::helpers::{prompt_existing_path, prompt_new_path, BACK, BACK_LABEL};

pub fn run() -> Result<()> {
    log::info("QR code utilities")?;

    let action: &str = select("QR action")
        .item("generate", "Generate QR from an Anyhide code", "")
        .item("read", "Read an Anyhide code from a QR image", "")
        .item("info", "Show QR capacity info for a given size/code", "")
        .item(BACK, BACK_LABEL, "")
        .interact()?;

    match action {
        BACK => Ok(()),
        "generate" => run_generate(),
        "read" => run_read(),
        "info" => run_info(),
        _ => unreachable!("select returned an unknown variant"),
    }
}

fn run_generate() -> Result<()> {
    let code: String = input("Anyhide code (base64)")
        .placeholder("paste the code here")
        .validate(non_empty)
        .interact()?;
    let output = prompt_new_path("Output file path", "./code.png")?;
    let format: &str = select("Output format")
        .item("png", "PNG (image)", "")
        .item("svg", "SVG (vector)", "")
        .item("ascii", "ASCII (terminal)", "")
        .interact()?;

    let cmd = QrGenerateCommand {
        code: Some(code.trim().to_string()),
        output,
        format: format.to_string(),
    };

    log::step("Generating QR...")?;
    cmd.execute()?;

    outro("QR generated.")?;
    Ok(())
}

fn run_read() -> Result<()> {
    let input_path = prompt_existing_path("Path to QR image", "./code.png")?;
    let output = if confirm("Save raw bytes to a file? (otherwise prints base64 to stdout)")
        .initial_value(false)
        .interact()?
    {
        Some(prompt_new_path("Output file", "./code.bin")?)
    } else {
        None
    };

    let cmd = QrReadCommand {
        input: input_path,
        output,
    };

    log::step("Reading QR...")?;
    cmd.execute()?;

    outro("QR read.")?;
    Ok(())
}

fn run_info() -> Result<()> {
    let mode: &str = select("Provide info from")
        .item("size", "Data size in bytes", "")
        .item("code", "An Anyhide code (base64)", "")
        .interact()?;

    let (size, code) = match mode {
        "size" => {
            let s: usize = input("Data size in bytes")
                .placeholder("1024")
                .validate(|s: &String| {
                    s.trim()
                        .parse::<usize>()
                        .map(|_| ())
                        .map_err(|_| "Enter a positive integer.")
                })
                .interact()?;
            (Some(s), None)
        }
        "code" => {
            let c: String = input("Anyhide code")
                .placeholder("base64 string")
                .validate(non_empty)
                .interact()?;
            (None, Some(c.trim().to_string()))
        }
        _ => unreachable!(),
    };

    let cmd = QrInfoCommand { size, code };

    log::step("Analyzing...")?;
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
