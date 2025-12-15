//! Text processing for KAMO steganography.
//!
//! This module provides:
//! - Variable message fragmentation (passphrase-based sizes)
//! - Substring search with distributed selection
//! - Block padding with carrier fragments
//! - Text normalization
//! - Suffix array for O(m * log n) substring search
//! - Generic carrier abstraction (text and binary)

pub mod carrier;
pub mod fragment;
pub mod padding;
pub mod permute;
pub mod suffix_array;
pub mod tokenize;

pub use carrier::{fragment_bytes_for_carrier, fragment_message_for_binary, BinaryCarrierSearch, BinaryFragment, Carrier};
pub use fragment::{fragment_message, fragment_message_adaptive, Fragment, FragmentedMessage, FoundFragment};
pub use padding::{calculate_padded_length, pad_message};
pub use permute::{find_distributed, normalize, permute_carrier};
pub use suffix_array::{IndexedCarrier, SuffixArray};
pub use tokenize::{find_substring, normalize_text, select_distributed_position, CarrierSearch};
