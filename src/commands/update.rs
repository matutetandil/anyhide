//! Self-update command.

use anyhow::{Context, Result};
use clap::Args;

use super::CommandExecutor;

/// Update anyhide to the latest version.
///
/// Downloads the latest release from GitHub and replaces the current binary.
/// Use --check to only check for updates without installing.
#[derive(Args, Debug)]
pub struct UpdateCommand {
    /// Only check for updates, don't install
    #[arg(long)]
    pub check: bool,
}

impl CommandExecutor for UpdateCommand {
    fn execute(&self) -> Result<()> {
        use self_update::backends::github::Update;
        use self_update::cargo_crate_version;

        println!("Checking for updates...");

        let current_version = cargo_crate_version!();
        let target = get_update_target();

        let update = Update::configure()
            .repo_owner("matutetandil")
            .repo_name("anyhide")
            .bin_name("anyhide")
            .target(&target)
            .current_version(current_version)
            .no_confirm(true)
            .build()
            .context("Failed to configure updater")?;

        let latest = update
            .get_latest_release()
            .context("Failed to fetch latest release")?;

        println!("  Current version: v{}", current_version);
        println!("  Latest version:  {}", latest.version);

        if latest.version == current_version {
            println!("\nYou're already on the latest version!");
            return Ok(());
        }

        if self.check {
            println!("\nUpdate available! Run 'anyhide update' to install.");
            return Ok(());
        }

        println!("\nDownloading update...");

        let status = update
            .update()
            .context("Failed to update")?;

        if status.updated() {
            println!("Updated successfully to {}!", status.version());
        } else {
            println!("Already up to date.");
        }

        Ok(())
    }
}

/// Returns the target string for the current platform.
fn get_update_target() -> String {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    };

    format!("anyhide-{}-{}", os, arch)
}
