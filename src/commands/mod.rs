//! Command module - Strategy pattern for CLI commands.
//!
//! Each command is a separate module implementing the `CommandExecutor` trait.
//! This provides clean separation of concerns and makes adding new commands easy.

mod contacts;
mod decode;
mod encode;
mod export_mnemonic;
mod fingerprint;
mod import_mnemonic;
mod keygen;
mod multi_decrypt;
mod multi_encrypt;
mod qr_generate;
mod qr_info;
mod qr_read;
mod update;

pub use contacts::ContactsCommand;
pub use decode::DecodeCommand;
pub use encode::EncodeCommand;
pub use export_mnemonic::ExportMnemonicCommand;
pub use fingerprint::FingerprintCommand;
pub use import_mnemonic::ImportMnemonicCommand;
pub use keygen::KeygenCommand;
pub use multi_decrypt::MultiDecryptCommand;
pub use multi_encrypt::MultiEncryptCommand;
pub use qr_generate::QrGenerateCommand;
pub use qr_info::QrInfoCommand;
pub use qr_read::QrReadCommand;
pub use update::UpdateCommand;

use anyhow::Result;

/// Trait for command execution - Strategy pattern.
///
/// Each command struct holds its parsed arguments and implements
/// this trait to define its execution logic.
pub trait CommandExecutor {
    /// Executes the command with its parsed arguments.
    fn execute(&self) -> Result<()>;
}
