//! Per-command wizard flows. Each flow is a self-contained function that
//! collects user input and delegates execution to the matching `*Command`
//! in `crate::commands`.

pub mod chat;
pub mod contacts;
pub mod decode;
pub mod demo;
pub mod encode;
pub mod keygen;
pub mod mnemonic;
pub mod qr;
