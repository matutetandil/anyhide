//! Text processing for KAMO steganography.
//!
//! This module provides:
//! - Variable message fragmentation (passphrase-based sizes)
//! - Substring search with distributed selection
//! - Block padding with carrier fragments
//! - Text normalization

pub mod fragment;
pub mod padding;
pub mod permute;
pub mod tokenize;

pub use fragment::{fragment_message, fragment_message_adaptive, Fragment, FragmentedMessage, FoundFragment};
pub use padding::{calculate_padded_length, pad_message};
pub use permute::{find_distributed, normalize, permute_carrier};
pub use tokenize::{find_substring, normalize_text, select_distributed_position, CarrierSearch};
