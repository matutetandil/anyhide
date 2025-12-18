//! KDF chains and DH ratchet for forward secrecy.
//!
//! This module implements the cryptographic ratcheting mechanism that provides
//! forward secrecy. Each message uses a unique key derived from a chain, and
//! the chain advances after each use, making it impossible to recover past keys.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain separation labels for HKDF derivations.
const LABEL_HEADER_KEY: &[u8] = b"ANYHIDE-CHAT-HEADER";
const LABEL_SEND_CHAIN: &[u8] = b"ANYHIDE-CHAT-SEND";
const LABEL_RECV_CHAIN: &[u8] = b"ANYHIDE-CHAT-RECV";
const LABEL_CARRIER_CHAIN: &[u8] = b"ANYHIDE-CHAT-CARRIER";
const LABEL_PASSPHRASE: &[u8] = b"ANYHIDE-CHAT-PASS";
const LABEL_CHAIN_ADVANCE: &[u8] = b"ANYHIDE-CHAT-CHAIN";
const LABEL_MESSAGE_KEY: &[u8] = b"ANYHIDE-CHAT-MESSAGE";

/// Session keys derived from the initial DH exchange.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// Key for encrypting/decrypting message headers.
    pub header_key: [u8; 32],
    /// Initial sending chain key.
    pub send_chain: [u8; 32],
    /// Initial receiving chain key.
    pub recv_chain: [u8; 32],
    /// Chain for deterministic carrier selection.
    pub carrier_chain: [u8; 32],
    /// Derived passphrase for anyhide encoding (not user-provided).
    pub passphrase: [u8; 32],
}

/// Output from a DH ratchet step.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RatchetOutput {
    /// New DH private key.
    pub new_secret: [u8; 32],
    /// New DH public key.
    pub new_public: [u8; 32],
    /// New sending chain key.
    pub send_chain: [u8; 32],
    /// New receiving chain key.
    pub recv_chain: [u8; 32],
}

/// Derive initial session keys from the DH shared secret.
///
/// This is called once after the handshake completes. The initiator and responder
/// public keys are included to ensure both parties derive the same keys regardless
/// of who initiated.
///
/// # Arguments
///
/// * `shared_secret` - The X25519 DH shared secret.
/// * `initiator_public` - The initiator's ephemeral public key.
/// * `responder_public` - The responder's ephemeral public key.
///
/// # Returns
///
/// Session keys for header encryption, message chains, and carrier selection.
pub fn derive_session_keys(
    shared_secret: &[u8; 32],
    initiator_public: &[u8; 32],
    responder_public: &[u8; 32],
) -> SessionKeys {
    // Combine public keys in deterministic order (initiator first)
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(initiator_public);
    info.extend_from_slice(responder_public);

    let hk = Hkdf::<Sha256>::new(Some(&info), shared_secret);

    let mut header_key = [0u8; 32];
    let mut send_chain = [0u8; 32];
    let mut recv_chain = [0u8; 32];
    let mut carrier_chain = [0u8; 32];
    let mut passphrase = [0u8; 32];

    hk.expand(LABEL_HEADER_KEY, &mut header_key)
        .expect("32 bytes is valid output length");
    hk.expand(LABEL_SEND_CHAIN, &mut send_chain)
        .expect("32 bytes is valid output length");
    hk.expand(LABEL_RECV_CHAIN, &mut recv_chain)
        .expect("32 bytes is valid output length");
    hk.expand(LABEL_CARRIER_CHAIN, &mut carrier_chain)
        .expect("32 bytes is valid output length");
    hk.expand(LABEL_PASSPHRASE, &mut passphrase)
        .expect("32 bytes is valid output length");

    SessionKeys {
        header_key,
        send_chain,
        recv_chain,
        carrier_chain,
        passphrase,
    }
}

/// Advance a KDF chain and derive a message key.
///
/// This is the symmetric ratchet step. The chain key is updated and a message
/// key is derived for encrypting/decrypting a single message.
///
/// # Arguments
///
/// * `chain_key` - Current chain key (will be updated in place).
///
/// # Returns
///
/// A tuple of (new_chain_key, message_key).
pub fn kdf_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, chain_key);

    let mut new_chain = [0u8; 32];
    let mut message_key = [0u8; 32];

    hk.expand(LABEL_CHAIN_ADVANCE, &mut new_chain)
        .expect("32 bytes is valid output length");
    hk.expand(LABEL_MESSAGE_KEY, &mut message_key)
        .expect("32 bytes is valid output length");

    (new_chain, message_key)
}

/// Perform a DH ratchet step when the conversation direction changes.
///
/// This generates a new ephemeral keypair, performs DH with the peer's public key,
/// and derives new chain keys.
///
/// # Arguments
///
/// * `their_public` - The peer's current DH public key.
/// * `current_chain` - The current root chain key (for mixing).
///
/// # Returns
///
/// New ephemeral keys and chain keys.
pub fn dh_ratchet(their_public: &PublicKey, current_chain: &[u8; 32]) -> RatchetOutput {
    // Generate new ephemeral keypair
    let new_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let new_public = PublicKey::from(&new_secret);

    // DH with their public key
    let dh_output = new_secret.diffie_hellman(their_public);

    // Derive new chains using current chain as salt
    let hk = Hkdf::<Sha256>::new(Some(current_chain), dh_output.as_bytes());

    let mut send_chain = [0u8; 32];
    let mut recv_chain = [0u8; 32];

    hk.expand(LABEL_SEND_CHAIN, &mut send_chain)
        .expect("32 bytes is valid output length");
    hk.expand(LABEL_RECV_CHAIN, &mut recv_chain)
        .expect("32 bytes is valid output length");

    RatchetOutput {
        new_secret: new_secret.to_bytes(),
        new_public: new_public.to_bytes(),
        send_chain,
        recv_chain,
    }
}

/// Advance the carrier chain and select a carrier.
///
/// Returns the new chain key and carrier selection indices.
///
/// # Arguments
///
/// * `carrier_chain` - Current carrier chain key.
/// * `carriers_per_party` - Number of carriers each party contributed.
///
/// # Returns
///
/// A tuple of (new_chain_key, carrier_owner, carrier_index).
pub fn advance_carrier_chain(
    carrier_chain: &[u8; 32],
    carriers_per_party: usize,
) -> ([u8; 32], u8, u16) {
    let hk = Hkdf::<Sha256>::new(None, carrier_chain);

    let mut new_chain = [0u8; 32];
    let mut selection = [0u8; 32];

    hk.expand(LABEL_CHAIN_ADVANCE, &mut new_chain)
        .expect("32 bytes is valid output length");
    hk.expand(b"ANYHIDE-CHAT-CARRIER-SELECT", &mut selection)
        .expect("32 bytes is valid output length");

    // Use selection bytes to determine carrier
    let owner = selection[0] % 2;
    let index = u16::from_le_bytes([selection[1], selection[2]]) % carriers_per_party as u16;

    (new_chain, owner, index)
}

/// Derive a message-specific passphrase for anyhide encoding.
///
/// # Arguments
///
/// * `base_passphrase` - The session base passphrase.
/// * `message_key` - The per-message key.
///
/// # Returns
///
/// A hex-encoded passphrase string for anyhide.
pub fn derive_message_passphrase(base_passphrase: &[u8; 32], message_key: &[u8; 32]) -> String {
    let hk = Hkdf::<Sha256>::new(Some(base_passphrase), message_key);

    let mut derived = [0u8; 32];
    hk.expand(b"ANYHIDE-CHAT-MSG-PASS", &mut derived)
        .expect("32 bytes is valid output length");

    // Convert to hex string for use as passphrase
    hex::encode(derived)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_session_keys() {
        let shared_secret = [1u8; 32];
        let initiator_pub = [2u8; 32];
        let responder_pub = [3u8; 32];

        let keys = derive_session_keys(&shared_secret, &initiator_pub, &responder_pub);

        // Keys should be non-zero
        assert_ne!(keys.header_key, [0u8; 32]);
        assert_ne!(keys.send_chain, [0u8; 32]);
        assert_ne!(keys.recv_chain, [0u8; 32]);
        assert_ne!(keys.carrier_chain, [0u8; 32]);
        assert_ne!(keys.passphrase, [0u8; 32]);

        // All keys should be different
        assert_ne!(keys.header_key, keys.send_chain);
        assert_ne!(keys.send_chain, keys.recv_chain);
        assert_ne!(keys.recv_chain, keys.carrier_chain);
    }

    #[test]
    fn test_derive_session_keys_deterministic() {
        let shared_secret = [42u8; 32];
        let initiator_pub = [10u8; 32];
        let responder_pub = [20u8; 32];

        let keys1 = derive_session_keys(&shared_secret, &initiator_pub, &responder_pub);
        let keys2 = derive_session_keys(&shared_secret, &initiator_pub, &responder_pub);

        assert_eq!(keys1.header_key, keys2.header_key);
        assert_eq!(keys1.send_chain, keys2.send_chain);
        assert_eq!(keys1.recv_chain, keys2.recv_chain);
        assert_eq!(keys1.carrier_chain, keys2.carrier_chain);
        assert_eq!(keys1.passphrase, keys2.passphrase);
    }

    #[test]
    fn test_kdf_chain_advances() {
        let initial_chain = [5u8; 32];

        let (chain1, msg_key1) = kdf_chain(&initial_chain);
        let (chain2, msg_key2) = kdf_chain(&chain1);

        // Chain should advance
        assert_ne!(initial_chain, chain1);
        assert_ne!(chain1, chain2);

        // Message keys should be different
        assert_ne!(msg_key1, msg_key2);

        // Message key should differ from chain key
        assert_ne!(chain1, msg_key1);
    }

    #[test]
    fn test_kdf_chain_deterministic() {
        let chain = [99u8; 32];

        let (new_chain1, msg_key1) = kdf_chain(&chain);
        let (new_chain2, msg_key2) = kdf_chain(&chain);

        assert_eq!(new_chain1, new_chain2);
        assert_eq!(msg_key1, msg_key2);
    }

    #[test]
    fn test_dh_ratchet() {
        // Generate a peer public key
        let peer_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let peer_public = PublicKey::from(&peer_secret);
        let current_chain = [7u8; 32];

        let output = dh_ratchet(&peer_public, &current_chain);

        // Should have new keys
        assert_ne!(output.new_secret, [0u8; 32]);
        assert_ne!(output.new_public, [0u8; 32]);
        assert_ne!(output.send_chain, [0u8; 32]);
        assert_ne!(output.recv_chain, [0u8; 32]);

        // Send and recv chains should be different
        assert_ne!(output.send_chain, output.recv_chain);
    }

    #[test]
    fn test_advance_carrier_chain() {
        let chain = [11u8; 32];

        let (new_chain, owner, index) = advance_carrier_chain(&chain, 10);

        // Chain should advance
        assert_ne!(chain, new_chain);

        // Owner should be 0 or 1
        assert!(owner < 2);

        // Index should be < carriers_per_party
        assert!(index < 10);
    }

    #[test]
    fn test_carrier_selection_deterministic() {
        let chain = [22u8; 32];

        let (_, owner1, index1) = advance_carrier_chain(&chain, 10);
        let (_, owner2, index2) = advance_carrier_chain(&chain, 10);

        assert_eq!(owner1, owner2);
        assert_eq!(index1, index2);
    }

    #[test]
    fn test_derive_message_passphrase() {
        let base = [33u8; 32];
        let msg_key = [44u8; 32];

        let pass = derive_message_passphrase(&base, &msg_key);

        // Should be 64 hex characters
        assert_eq!(pass.len(), 64);

        // Should be valid hex
        assert!(pass.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_derive_message_passphrase_different_keys() {
        let base = [55u8; 32];
        let msg_key1 = [66u8; 32];
        let msg_key2 = [77u8; 32];

        let pass1 = derive_message_passphrase(&base, &msg_key1);
        let pass2 = derive_message_passphrase(&base, &msg_key2);

        assert_ne!(pass1, pass2);
    }
}
