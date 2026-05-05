//! KDF chains and KEM ratchet for forward secrecy (hybrid post-quantum).
//!
//! This module implements the cryptographic ratcheting mechanism that provides
//! forward secrecy. Each message uses a unique key derived from a chain, and
//! the chain advances after each use, making it impossible to recover past keys.
//!
//! In v2 the DH ratchet from v1 is replaced by a KEM ratchet (X25519 + ML-KEM-768
//! via [`hybrid_kem`]). Whoever ratchets generates a fresh hybrid keypair and
//! encapsulates against the peer's current pubkey; the resulting shared secret
//! is mixed with the running chain via HKDF. The receiver decapsulates the
//! ciphertext attached to the message header to recover the same shared secret.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::hybrid_kem::{
    self, HybridCiphertext, HybridKemError, HybridPublicKey, HybridSecretKey,
};

/// Domain separation labels for HKDF derivations.
const LABEL_HEADER_KEY: &[u8] = b"ANYHIDE-CHAT-HEADER";
const LABEL_SEND_CHAIN: &[u8] = b"ANYHIDE-CHAT-SEND";
const LABEL_RECV_CHAIN: &[u8] = b"ANYHIDE-CHAT-RECV";
const LABEL_CARRIER_CHAIN: &[u8] = b"ANYHIDE-CHAT-CARRIER";
const LABEL_PASSPHRASE: &[u8] = b"ANYHIDE-CHAT-PASS";
const LABEL_CHAIN_ADVANCE: &[u8] = b"ANYHIDE-CHAT-CHAIN";
const LABEL_MESSAGE_KEY: &[u8] = b"ANYHIDE-CHAT-MESSAGE";

/// HKDF info string mixing the two handshake KEM secrets into a master session secret.
const LABEL_SESSION_MASTER: &[u8] = b"ANYHIDE-CHAT-V2-MASTER";

/// HKDF info string for the responder's handshake-time carrier encryption key.
const LABEL_RESP_CARRIERS: &[u8] = b"ANYHIDE-CHAT-V2-RESP-CARRIERS";

/// HKDF info string for the initiator's handshake-time carrier encryption key.
const LABEL_INIT_CARRIERS: &[u8] = b"ANYHIDE-CHAT-V2-INIT-CARRIERS";

/// Session keys derived from the handshake's two KEM shared secrets.
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

/// Output of a sender-side KEM ratchet step.
///
/// The sender generates a fresh ratchet keypair and encapsulates against the
/// peer's current public key. The resulting `kem_ciphertext` and `new_public`
/// must be attached to the next outgoing message header so the peer can
/// decapsulate and derive the matching chain key.
pub struct KemRatchetOutput {
    /// New hybrid secret to retain (used to decapsulate the peer's reply).
    pub new_secret: HybridSecretKey,
    /// New hybrid public to publish in the next message header.
    pub new_public: HybridPublicKey,
    /// KEM ciphertext encapsulated against the peer's current public key.
    pub kem_ciphertext: HybridCiphertext,
    /// New sending chain key.
    pub send_chain: [u8; 32],
}

/// Derives the master session secret from the two handshake KEM shared secrets.
///
/// The master is bound to the order `(ss_resp_to_init, ss_init_to_resp)` so both
/// parties recompute the same value regardless of role. The actual session keys
/// are derived from this master via [`derive_session_keys`].
pub fn derive_master_secret(
    ss_resp_to_init: &[u8; 32],
    ss_init_to_resp: &[u8; 32],
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(ss_resp_to_init);
    ikm.extend_from_slice(ss_init_to_resp);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; 32];
    hk.expand(LABEL_SESSION_MASTER, &mut out)
        .expect("32 bytes is valid output length");
    out
}

/// Derives a 32-byte handshake-time carrier encryption key from one shared secret.
///
/// The responder encrypts its carrier blob with `derive_handshake_carrier_key(&ss_resp_to_init, true)`
/// after computing `ss_resp_to_init` from its first encapsulation. The initiator
/// later encrypts its own carriers with `derive_handshake_carrier_key(&ss_init_to_resp, false)`.
/// Domain-separated labels prevent key reuse across directions.
pub fn derive_handshake_carrier_key(shared_secret: &[u8; 32], responder: bool) -> [u8; 32] {
    let label = if responder {
        LABEL_RESP_CARRIERS
    } else {
        LABEL_INIT_CARRIERS
    };
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut out = [0u8; 32];
    hk.expand(label, &mut out)
        .expect("32 bytes is valid output length");
    out
}

/// Derives the initial session keys from the master secret and both ephemeral pubkeys.
///
/// The pubkeys are bound into the HKDF info field (initiator first, responder second)
/// so transcript binding is preserved: an attacker who substitutes a different pubkey
/// cannot drive both parties to the same session keys.
pub fn derive_session_keys(
    master_secret: &[u8; 32],
    initiator_public_hybrid: &[u8],
    responder_public_hybrid: &[u8],
) -> SessionKeys {
    let mut info = Vec::with_capacity(initiator_public_hybrid.len() + responder_public_hybrid.len());
    info.extend_from_slice(initiator_public_hybrid);
    info.extend_from_slice(responder_public_hybrid);

    let hk = Hkdf::<Sha256>::new(Some(&info), master_secret);

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

/// Advances a KDF chain and derives a per-message key (symmetric ratchet step).
///
/// This is unchanged from v1 — the symmetric chain is purely HKDF-driven and
/// does not involve any KEM operation.
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

/// Performs a sender-side KEM ratchet step.
///
/// Called when the sender's direction reverses (last action was receiving;
/// now we want to send). Generates a fresh hybrid keypair and encapsulates
/// against the peer's current public key. The resulting shared secret is
/// mixed with the existing chain to derive a new send chain.
///
/// The caller must:
/// - Retain `new_secret` (needed to decapsulate the peer's reply when they
///   later ratchet back).
/// - Attach `new_public` and `kem_ciphertext` to the next outgoing message
///   header so the peer can perform the matching receive-side step.
pub fn kem_ratchet_send(
    their_public: &HybridPublicKey,
    current_chain: &[u8; 32],
) -> Result<KemRatchetOutput, HybridKemError> {
    let (new_secret, new_public) = hybrid_kem::generate_keypair();
    let (kem_ciphertext, shared) = hybrid_kem::encapsulate(their_public)?;

    let hk = Hkdf::<Sha256>::new(Some(current_chain), shared.as_bytes());
    let mut send_chain = [0u8; 32];
    hk.expand(LABEL_SEND_CHAIN, &mut send_chain)
        .expect("32 bytes is valid output length");

    Ok(KemRatchetOutput {
        new_secret,
        new_public,
        kem_ciphertext,
        send_chain,
    })
}

/// Performs a receiver-side KEM ratchet step.
///
/// Called when the receiver sees a new ratchet pubkey + KEM ciphertext in an
/// incoming message header. Decapsulates the ciphertext with the receiver's
/// current secret to recover the same shared secret the sender derived, then
/// mixes it with the receiver's chain to produce a new recv chain.
///
/// Uses [`LABEL_SEND_CHAIN`] (the sender's send-side label) so the receiver's
/// recv chain matches the sender's send chain — they are the same key.
pub fn kem_ratchet_receive(
    my_secret: &HybridSecretKey,
    kem_ciphertext: &HybridCiphertext,
    current_chain: &[u8; 32],
) -> Result<[u8; 32], HybridKemError> {
    let shared = hybrid_kem::decapsulate(my_secret, kem_ciphertext)?;

    let hk = Hkdf::<Sha256>::new(Some(current_chain), shared.as_bytes());
    let mut recv_chain = [0u8; 32];
    hk.expand(LABEL_SEND_CHAIN, &mut recv_chain)
        .expect("32 bytes is valid output length");

    Ok(recv_chain)
}

/// Advances the carrier chain and selects a carrier (unchanged from v1).
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

    let owner = selection[0] % 2;
    let index = u16::from_le_bytes([selection[1], selection[2]]) % carriers_per_party as u16;

    (new_chain, owner, index)
}

/// Derives a message-specific passphrase for anyhide encoding (unchanged from v1).
pub fn derive_message_passphrase(base_passphrase: &[u8; 32], message_key: &[u8; 32]) -> String {
    let hk = Hkdf::<Sha256>::new(Some(base_passphrase), message_key);

    let mut derived = [0u8; 32];
    hk.expand(b"ANYHIDE-CHAT-MSG-PASS", &mut derived)
        .expect("32 bytes is valid output length");

    hex::encode(derived)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pubkey_bytes() -> Vec<u8> {
        vec![1u8; crate::crypto::hybrid_kem::HYBRID_PUBKEY_SIZE]
    }

    #[test]
    fn test_derive_master_secret_deterministic() {
        let ss1 = [1u8; 32];
        let ss2 = [2u8; 32];

        let m1 = derive_master_secret(&ss1, &ss2);
        let m2 = derive_master_secret(&ss1, &ss2);

        assert_eq!(m1, m2);
        assert_ne!(m1, [0u8; 32]);
    }

    #[test]
    fn test_derive_master_secret_order_matters() {
        let ss1 = [1u8; 32];
        let ss2 = [2u8; 32];

        let forward = derive_master_secret(&ss1, &ss2);
        let reversed = derive_master_secret(&ss2, &ss1);

        assert_ne!(forward, reversed);
    }

    #[test]
    fn test_derive_handshake_carrier_keys_are_distinct() {
        let ss = [42u8; 32];

        let resp_key = derive_handshake_carrier_key(&ss, true);
        let init_key = derive_handshake_carrier_key(&ss, false);

        assert_ne!(resp_key, init_key);
    }

    #[test]
    fn test_derive_session_keys() {
        let master = [1u8; 32];
        let init_pub = dummy_pubkey_bytes();
        let resp_pub = vec![5u8; crate::crypto::hybrid_kem::HYBRID_PUBKEY_SIZE];

        let keys = derive_session_keys(&master, &init_pub, &resp_pub);

        assert_ne!(keys.header_key, [0u8; 32]);
        assert_ne!(keys.send_chain, [0u8; 32]);
        assert_ne!(keys.recv_chain, [0u8; 32]);
        assert_ne!(keys.carrier_chain, [0u8; 32]);
        assert_ne!(keys.passphrase, [0u8; 32]);

        assert_ne!(keys.header_key, keys.send_chain);
        assert_ne!(keys.send_chain, keys.recv_chain);
        assert_ne!(keys.recv_chain, keys.carrier_chain);
    }

    #[test]
    fn test_derive_session_keys_deterministic() {
        let master = [42u8; 32];
        let init_pub = dummy_pubkey_bytes();
        let resp_pub = vec![5u8; crate::crypto::hybrid_kem::HYBRID_PUBKEY_SIZE];

        let k1 = derive_session_keys(&master, &init_pub, &resp_pub);
        let k2 = derive_session_keys(&master, &init_pub, &resp_pub);

        assert_eq!(k1.header_key, k2.header_key);
        assert_eq!(k1.send_chain, k2.send_chain);
        assert_eq!(k1.recv_chain, k2.recv_chain);
        assert_eq!(k1.carrier_chain, k2.carrier_chain);
    }

    #[test]
    fn test_kdf_chain_advances() {
        let initial_chain = [5u8; 32];

        let (chain1, msg_key1) = kdf_chain(&initial_chain);
        let (chain2, msg_key2) = kdf_chain(&chain1);

        assert_ne!(initial_chain, chain1);
        assert_ne!(chain1, chain2);
        assert_ne!(msg_key1, msg_key2);
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
    fn test_kem_ratchet_send_receive_roundtrip() {
        // Receiver holds a hybrid keypair. Sender will encapsulate against it.
        let (recv_secret, recv_public) = hybrid_kem::generate_keypair();
        let chain = [7u8; 32];

        let send_output = kem_ratchet_send(&recv_public, &chain).unwrap();

        // Receiver runs receive-side ratchet using the ciphertext from the header.
        let recv_chain = kem_ratchet_receive(&recv_secret, &send_output.kem_ciphertext, &chain).unwrap();

        // Sender's send_chain and receiver's recv_chain must match.
        assert_eq!(send_output.send_chain, recv_chain);
    }

    #[test]
    fn test_kem_ratchet_wrong_secret_diverges() {
        let (_correct_secret, correct_public) = hybrid_kem::generate_keypair();
        let (wrong_secret, _wrong_public) = hybrid_kem::generate_keypair();
        let chain = [7u8; 32];

        let send_output = kem_ratchet_send(&correct_public, &chain).unwrap();

        // ML-KEM uses implicit rejection: decapsulating with the wrong secret
        // returns a pseudorandom value rather than an error. The derived chain
        // therefore differs from the sender's, breaking forward decryption.
        let wrong_chain =
            kem_ratchet_receive(&wrong_secret, &send_output.kem_ciphertext, &chain).unwrap();

        assert_ne!(send_output.send_chain, wrong_chain);
    }

    #[test]
    fn test_kem_ratchet_chain_mixing_changes_output() {
        // Same encapsulation but different starting chain → different send_chain.
        let (_, recv_public) = hybrid_kem::generate_keypair();
        let chain1 = [7u8; 32];
        let chain2 = [8u8; 32];

        let out1 = kem_ratchet_send(&recv_public, &chain1).unwrap();
        let out2 = kem_ratchet_send(&recv_public, &chain2).unwrap();

        assert_ne!(out1.send_chain, out2.send_chain);
    }

    #[test]
    fn test_kem_ratchet_distinct_steps_produce_distinct_chains() {
        let (_, recv_public) = hybrid_kem::generate_keypair();
        let chain = [7u8; 32];

        let out1 = kem_ratchet_send(&recv_public, &chain).unwrap();
        let out2 = kem_ratchet_send(&recv_public, &chain).unwrap();

        // Each step generates a fresh keypair and a fresh KEM encapsulation,
        // so the resulting shared secrets — and therefore the chains — differ.
        assert_ne!(out1.send_chain, out2.send_chain);
        assert_ne!(out1.kem_ciphertext.to_bytes(), out2.kem_ciphertext.to_bytes());
        assert_ne!(out1.new_public.to_bytes(), out2.new_public.to_bytes());
    }

    #[test]
    fn test_advance_carrier_chain() {
        let chain = [11u8; 32];

        let (new_chain, owner, index) = advance_carrier_chain(&chain, 10);

        assert_ne!(chain, new_chain);
        assert!(owner < 2);
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

        assert_eq!(pass.len(), 64);
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
