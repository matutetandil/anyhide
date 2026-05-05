//! Chat session management with zeroize (hybrid post-quantum, v2).
//!
//! The `ChatSession` struct holds all cryptographic state for an active chat.
//! All sensitive data is automatically zeroized when the session is dropped.
//!
//! In v2 the long-term and ephemeral encryption keys are hybrid (X25519 + ML-KEM-768
//! via [`HybridKeyPair`]) and the DH ratchet is replaced by a KEM ratchet
//! (see [`crate::chat::protocol::kem_ratchet_send`] and
//! [`crate::chat::protocol::kem_ratchet_receive`]). Identity signing remains
//! Ed25519 — the harvest-now-decrypt-later threat does not apply to authentication
//! the same way it does to confidentiality.

use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::Zeroize;

use crate::chat::config::{ChatConfig, CHAT_PROTOCOL_VERSION};
use crate::chat::error::ChatError;
use crate::chat::protocol::{
    advance_carrier_chain, decrypt_header, derive_session_keys, encrypt_header, kdf_chain,
    kem_ratchet_receive, kem_ratchet_send, MessageHeader, SignedMessage, WireMessage,
};
use crate::crypto::hybrid_kem::{
    HybridCiphertext, HybridPublicKey, HybridSecretKey, HYBRID_PUBKEY_SIZE,
};
use crate::text::carrier::Carrier;
use crate::{decode_bytes_with_carrier, encode_bytes_with_carrier};

/// Message direction for ratchet state tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// We are sending messages.
    Sending,
    /// We are receiving messages.
    Receiving,
}

/// Role in the chat session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Initiated the connection.
    Initiator,
    /// Accepted the connection.
    Responder,
}

/// RAM-only chat session state.
///
/// All sensitive cryptographic material is zeroized on drop. The hybrid keys
/// (`HybridSecretKey`) zeroize themselves via the underlying `x25519-dalek` and
/// `ml-kem` crates' Drop impls; this struct's Drop only handles the raw byte
/// arrays for chains, passphrases, signing key, carriers, and skipped keys.
pub struct ChatSession {
    // === Chain keys ===
    /// Header encryption key (derived from initial handshake).
    header_key: [u8; 32],
    /// Current sending chain key.
    send_chain: [u8; 32],
    /// Current receiving chain key.
    recv_chain: [u8; 32],
    /// Carrier chain key for selecting carriers.
    carrier_chain: [u8; 32],

    // === Hybrid ratchet state ===
    /// My current hybrid ratchet secret key (zeroizes via x25519-dalek + ml-kem).
    my_hybrid_secret: HybridSecretKey,
    /// My current hybrid ratchet public key (1216 bytes when serialized).
    my_hybrid_public: HybridPublicKey,
    /// Their current hybrid ratchet public key.
    their_hybrid_public: HybridPublicKey,
    /// KEM ciphertext to attach to the next outgoing message — populated by
    /// `perform_kem_ratchet` and consumed on the first `send_message` after.
    pending_kem_ct: Option<HybridCiphertext>,

    // === Session passphrases ===
    /// User-provided passphrase (hashed to 32 bytes).
    user_passphrase: [u8; 32],
    /// Derived passphrase from the handshake master secret.
    derived_passphrase: [u8; 32],
    /// My Ed25519 signing key bytes (independent of the hybrid encryption identity).
    my_signing_key: [u8; 32],

    // === Sequence numbers ===
    send_seq: u32,
    recv_seq: u32,
    prev_chain_len: u32,
    last_direction: Option<Direction>,

    // === Skipped message keys ===
    /// Cache of skipped message keys keyed by the X25519 component of the
    /// hybrid pubkey (32 bytes — small and unique per ratchet step) plus seq.
    skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>,

    // === Carriers ===
    my_carriers: Vec<Vec<u8>>,
    their_carriers: Vec<Vec<u8>>,

    // === Identity ===
    their_verifying_key: VerifyingKey,

    // === Config ===
    config: ChatConfig,
    role: Role,
}

impl Drop for ChatSession {
    fn drop(&mut self) {
        // The hybrid keys' zeroize is handled by their own Drop impls; here
        // we wipe everything else that holds raw key material.
        self.header_key.zeroize();
        self.send_chain.zeroize();
        self.recv_chain.zeroize();
        self.carrier_chain.zeroize();
        self.user_passphrase.zeroize();
        self.derived_passphrase.zeroize();
        self.my_signing_key.zeroize();

        for (_, key) in self.skipped_keys.drain() {
            let mut key_copy = key;
            key_copy.zeroize();
        }

        for carrier in &mut self.my_carriers {
            carrier.zeroize();
        }
        for carrier in &mut self.their_carriers {
            carrier.zeroize();
        }
    }
}

impl ChatSession {
    /// Creates a new session as the initiator after a successful hybrid handshake.
    ///
    /// `master_secret` is the 32-byte output of [`derive_master_secret`] over the
    /// two KEM shared secrets exchanged during the handshake.
    ///
    /// [`derive_master_secret`]: crate::chat::protocol::derive_master_secret
    pub fn init_as_initiator(
        my_ephemeral_secret: HybridSecretKey,
        my_signing_key: &SigningKey,
        their_ephemeral_public: HybridPublicKey,
        their_verifying_key: VerifyingKey,
        master_secret: &[u8; 32],
        my_carriers: Vec<Vec<u8>>,
        their_carriers: Vec<Vec<u8>>,
        config: ChatConfig,
        user_passphrase: &str,
    ) -> Result<Self, ChatError> {
        let my_public = my_ephemeral_secret.public_key();

        let session_keys = derive_session_keys(
            master_secret,
            &my_public.to_bytes(),
            &their_ephemeral_public.to_bytes(),
        );

        let mut user_pass_hash = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(user_passphrase.as_bytes());
        user_pass_hash.copy_from_slice(&hasher.finalize());

        Ok(Self {
            header_key: session_keys.header_key,
            send_chain: session_keys.send_chain,
            recv_chain: session_keys.recv_chain,
            carrier_chain: session_keys.carrier_chain,
            my_hybrid_secret: my_ephemeral_secret,
            my_hybrid_public: my_public,
            their_hybrid_public: their_ephemeral_public,
            pending_kem_ct: None,
            user_passphrase: user_pass_hash,
            derived_passphrase: session_keys.passphrase,
            my_signing_key: my_signing_key.to_bytes(),
            send_seq: 0,
            recv_seq: 0,
            prev_chain_len: 0,
            last_direction: None,
            skipped_keys: HashMap::new(),
            my_carriers,
            their_carriers,
            their_verifying_key,
            config,
            role: Role::Initiator,
        })
    }

    /// Creates a new session as the responder after a successful hybrid handshake.
    ///
    /// The responder swaps `send_chain` and `recv_chain` so both parties end up
    /// with matching chain keys for their respective directions.
    pub fn init_as_responder(
        my_ephemeral_secret: HybridSecretKey,
        my_signing_key: &SigningKey,
        their_ephemeral_public: HybridPublicKey,
        their_verifying_key: VerifyingKey,
        master_secret: &[u8; 32],
        my_carriers: Vec<Vec<u8>>,
        their_carriers: Vec<Vec<u8>>,
        config: ChatConfig,
        user_passphrase: &str,
    ) -> Result<Self, ChatError> {
        let my_public = my_ephemeral_secret.public_key();

        // Initiator's pubkey first — same as the initiator's derivation, so both
        // parties compute identical chain keys.
        let session_keys = derive_session_keys(
            master_secret,
            &their_ephemeral_public.to_bytes(),
            &my_public.to_bytes(),
        );

        let mut user_pass_hash = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(user_passphrase.as_bytes());
        user_pass_hash.copy_from_slice(&hasher.finalize());

        Ok(Self {
            header_key: session_keys.header_key,
            send_chain: session_keys.recv_chain, // swapped
            recv_chain: session_keys.send_chain, // swapped
            carrier_chain: session_keys.carrier_chain,
            my_hybrid_secret: my_ephemeral_secret,
            my_hybrid_public: my_public,
            their_hybrid_public: their_ephemeral_public,
            pending_kem_ct: None,
            user_passphrase: user_pass_hash,
            derived_passphrase: session_keys.passphrase,
            my_signing_key: my_signing_key.to_bytes(),
            send_seq: 0,
            recv_seq: 0,
            prev_chain_len: 0,
            last_direction: None,
            skipped_keys: HashMap::new(),
            my_carriers,
            their_carriers,
            their_verifying_key,
            config,
            role: Role::Responder,
        })
    }

    pub fn config(&self) -> &ChatConfig {
        &self.config
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn messages_sent(&self) -> u32 {
        self.send_seq
    }

    pub fn messages_received(&self) -> u32 {
        self.recv_seq
    }

    /// Sends a message.
    ///
    /// Generates a `WireMessage` ready for the transport. If the previous action
    /// was receiving, performs a sender-side KEM ratchet (new hybrid keypair +
    /// encapsulation against peer's pubkey) and attaches the resulting ciphertext
    /// to the outgoing header.
    pub fn send_message(&mut self, plaintext: &str) -> Result<WireMessage, ChatError> {
        if plaintext.len() > self.config.max_message_len {
            return Err(ChatError::EncodingFailed(format!(
                "Message too long: {} > {}",
                plaintext.len(),
                self.config.max_message_len
            )));
        }

        if self.last_direction == Some(Direction::Receiving) {
            self.perform_kem_ratchet()?;
        }

        let (new_chain, message_key) = kdf_chain(&self.send_chain);
        self.send_chain = new_chain;

        let (new_carrier_chain, carrier_owner, carrier_index) =
            advance_carrier_chain(&self.carrier_chain, self.config.carriers_per_party);
        self.carrier_chain = new_carrier_chain;

        let carrier = self.get_carrier(carrier_owner, carrier_index)?;

        let signing_key = SigningKey::from_bytes(&self.my_signing_key);
        let mut hasher = Sha256::new();
        hasher.update(plaintext.as_bytes());
        hasher.update(&self.send_seq.to_le_bytes());
        let msg_hash = hasher.finalize();
        let signature = signing_key.sign(&msg_hash);

        let signed_message =
            SignedMessage::new(plaintext.to_string(), signature.to_bytes().to_vec());
        let signed_bytes = signed_message
            .to_bytes()
            .map_err(|e| ChatError::SerializationFailed(e.to_string()))?;

        let msg_passphrase = self.combine_passphrases(&message_key);

        // Per-message ephemeral encryption keypair (X25519 only — the per-message
        // anyhide encoding does not need to be hybrid because confidentiality
        // already comes from the chain key + passphrase; this keypair only
        // identifies the encoding).
        let msg_secret = X25519Secret::from(message_key);
        let msg_public = X25519PublicKey::from(&msg_secret);

        let binary_carrier = Carrier::from_bytes(carrier.clone());
        let encoded =
            encode_bytes_with_carrier(&binary_carrier, &signed_bytes, &msg_passphrase, &msg_public)
                .map_err(|e| ChatError::EncodingFailed(e.to_string()))?;

        // Consume any pending KEM ciphertext from the most recent ratchet step.
        let kem_ct_bytes = self
            .pending_kem_ct
            .take()
            .map(|ct| ct.to_bytes().to_vec());

        let header = MessageHeader {
            seq: self.send_seq,
            dh_public_hybrid: self.my_hybrid_public.to_bytes().to_vec(),
            kem_ciphertext: kem_ct_bytes,
            carrier_owner,
            carrier_index,
            prev_chain_len: self.prev_chain_len,
        };

        let (encrypted_header, header_nonce) = encrypt_header(&header, &self.header_key)?;

        self.send_seq += 1;
        self.last_direction = Some(Direction::Sending);

        Ok(WireMessage::new(
            CHAT_PROTOCOL_VERSION,
            header_nonce,
            encrypted_header,
            encoded.code,
        ))
    }

    /// Receives and decrypts a message.
    pub fn receive_message(&mut self, wire: &WireMessage) -> Result<String, ChatError> {
        if wire.version != CHAT_PROTOCOL_VERSION {
            return Err(ChatError::VersionMismatch {
                expected: CHAT_PROTOCOL_VERSION,
                got: wire.version,
            });
        }

        let header = decrypt_header(&wire.encrypted_header, &wire.header_nonce, &self.header_key)?;

        let header_pubkey_bytes: [u8; HYBRID_PUBKEY_SIZE] = header
            .dh_public_hybrid
            .as_slice()
            .try_into()
            .map_err(|_| {
                ChatError::SerializationFailed("Header pubkey size mismatch".to_string())
            })?;

        let their_current_bytes = self.their_hybrid_public.to_bytes();
        let their_x25519_id = current_x25519_identifier(&self.their_hybrid_public);

        // Detect ratchet step: peer published a new pubkey we haven't seen yet.
        if header_pubkey_bytes != their_current_bytes {
            let kem_ct_bytes = header
                .kem_ciphertext
                .as_ref()
                .ok_or_else(|| {
                    ChatError::SerializationFailed(
                        "Ratchet step header missing kem_ciphertext".to_string(),
                    )
                })?;

            self.handle_their_ratchet(&header_pubkey_bytes, kem_ct_bytes, header.prev_chain_len)?;
        }

        // Once `handle_their_ratchet` has run, `their_hybrid_public` matches the header
        // value. Re-derive its X25519 identifier for skipped-key bookkeeping.
        let their_x25519_now = current_x25519_identifier(&self.their_hybrid_public);

        let message_key = if header.seq == self.recv_seq {
            let (new_chain, message_key) = kdf_chain(&self.recv_chain);
            self.recv_chain = new_chain;
            self.recv_seq += 1;
            message_key
        } else if header.seq > self.recv_seq {
            self.skip_message_keys(header.seq, &their_x25519_now)?
        } else {
            // Past message — try the cache. For pre-ratchet messages stored under
            // the previous identifier, fall back to that one too.
            self.skipped_keys
                .remove(&(their_x25519_now, header.seq))
                .or_else(|| self.skipped_keys.remove(&(their_x25519_id, header.seq)))
                .ok_or(ChatError::SkippedKeyNotFound(header.seq))?
        };

        let carrier = self.get_carrier(header.carrier_owner, header.carrier_index)?;

        let msg_passphrase = self.combine_passphrases(&message_key);

        let msg_secret = X25519Secret::from(message_key);

        let binary_carrier = Carrier::from_bytes(carrier.clone());
        let decoded = decode_bytes_with_carrier(
            &wire.anyhide_code,
            &binary_carrier,
            &msg_passphrase,
            &msg_secret,
        );

        let signed_message = SignedMessage::from_bytes(&decoded.data)
            .map_err(|e| ChatError::DecodingFailed(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(signed_message.content.as_bytes());
        hasher.update(&header.seq.to_le_bytes());
        let msg_hash = hasher.finalize();

        let signature = Signature::from_slice(&signed_message.signature)
            .map_err(|_| ChatError::InvalidSignature)?;

        self.their_verifying_key
            .verify(&msg_hash, &signature)
            .map_err(|_| ChatError::SignatureVerificationFailed)?;

        self.last_direction = Some(Direction::Receiving);

        Ok(signed_message.content)
    }

    /// Performs a sender-side KEM ratchet when we switch from receiving to sending.
    ///
    /// Generates a fresh hybrid keypair and encapsulates against the peer's
    /// current pubkey. The new send chain is mixed with the resulting shared
    /// secret. The KEM ciphertext is stashed in `pending_kem_ct` and attached
    /// to the next outgoing message header.
    fn perform_kem_ratchet(&mut self) -> Result<(), ChatError> {
        let output = kem_ratchet_send(&self.their_hybrid_public, &self.send_chain)
            .map_err(|e| ChatError::HeaderCryptoFailed(format!("KEM ratchet failed: {}", e)))?;

        self.prev_chain_len = self.send_seq;
        self.send_seq = 0;

        // Replace my secret/public with the freshly generated pair. The previous
        // secret is dropped here, which zeroizes via HybridSecretKey's Drop impls.
        self.my_hybrid_secret = output.new_secret;
        self.my_hybrid_public = output.new_public;
        self.send_chain = output.send_chain;
        self.pending_kem_ct = Some(output.kem_ciphertext);

        Ok(())
    }

    /// Handles their KEM ratchet when we receive a message with a new pubkey + ct.
    fn handle_their_ratchet(
        &mut self,
        new_their_public_bytes: &[u8; HYBRID_PUBKEY_SIZE],
        kem_ct_bytes: &[u8],
        prev_chain_len: u32,
    ) -> Result<(), ChatError> {
        // Skip any remaining message keys from the old chain (under the previous
        // their_x25519 identifier).
        self.skip_remaining_keys(prev_chain_len)?;

        let new_their_public = HybridPublicKey::from_bytes(new_their_public_bytes)
            .map_err(|e| ChatError::SerializationFailed(format!("Invalid hybrid pubkey: {}", e)))?;

        let kem_ct = HybridCiphertext::from_bytes(kem_ct_bytes)
            .map_err(|e| ChatError::SerializationFailed(format!("Invalid kem_ct: {}", e)))?;

        let new_recv_chain = kem_ratchet_receive(&self.my_hybrid_secret, &kem_ct, &self.recv_chain)
            .map_err(|e| {
                ChatError::HeaderCryptoFailed(format!("KEM ratchet decapsulation failed: {}", e))
            })?;

        self.their_hybrid_public = new_their_public;
        self.recv_chain = new_recv_chain;
        self.recv_seq = 0;

        Ok(())
    }

    fn skip_remaining_keys(&mut self, target: u32) -> Result<(), ChatError> {
        let identifier = current_x25519_identifier(&self.their_hybrid_public);

        while self.recv_seq < target {
            if self.skipped_keys.len() >= self.config.max_skip {
                return Err(ChatError::TooManySkipped {
                    max: self.config.max_skip,
                    requested: self.skipped_keys.len() + 1,
                });
            }

            let (new_chain, message_key) = kdf_chain(&self.recv_chain);
            self.recv_chain = new_chain;

            self.skipped_keys
                .insert((identifier, self.recv_seq), message_key);
            self.recv_seq += 1;
        }
        Ok(())
    }

    fn skip_message_keys(
        &mut self,
        target_seq: u32,
        identifier: &[u8; 32],
    ) -> Result<[u8; 32], ChatError> {
        let skip_count = (target_seq - self.recv_seq) as usize;
        if skip_count > self.config.max_skip {
            return Err(ChatError::TooManySkipped {
                max: self.config.max_skip,
                requested: skip_count,
            });
        }

        while self.recv_seq < target_seq {
            let (new_chain, message_key) = kdf_chain(&self.recv_chain);
            self.recv_chain = new_chain;

            self.skipped_keys
                .insert((*identifier, self.recv_seq), message_key);
            self.recv_seq += 1;
        }

        let (new_chain, message_key) = kdf_chain(&self.recv_chain);
        self.recv_chain = new_chain;
        self.recv_seq += 1;

        Ok(message_key)
    }

    fn combine_passphrases(&self, message_key: &[u8; 32]) -> String {
        use hkdf::Hkdf;

        let mut combined_input = Vec::with_capacity(96);
        combined_input.extend_from_slice(&self.user_passphrase);
        combined_input.extend_from_slice(&self.derived_passphrase);
        combined_input.extend_from_slice(message_key);

        let hk = Hkdf::<Sha256>::new(None, &combined_input);
        let mut output = [0u8; 32];
        hk.expand(b"ANYHIDE-CHAT-MSG-PASS", &mut output)
            .expect("32 bytes is valid");

        hex::encode(output)
    }

    fn get_carrier(&self, owner: u8, index: u16) -> Result<&Vec<u8>, ChatError> {
        let carriers = match (self.role, owner) {
            (Role::Initiator, 0) | (Role::Responder, 1) => &self.my_carriers,
            (Role::Initiator, 1) | (Role::Responder, 0) => &self.their_carriers,
            _ => {
                return Err(ChatError::InvalidCarrier { owner, index });
            }
        };

        carriers
            .get(index as usize)
            .ok_or(ChatError::InvalidCarrier { owner, index })
    }
}

/// Returns the 32-byte X25519 component of a hybrid public key for use as a
/// compact identifier (HashMap keys, skipped-key bookkeeping). The full hybrid
/// pubkey is 1216 bytes; using just the X25519 piece keeps map keys small while
/// preserving uniqueness — each ratchet step generates a fresh X25519 component.
fn current_x25519_identifier(public: &HybridPublicKey) -> [u8; 32] {
    *public.classical().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::generate_carriers;
    use crate::chat::protocol::derive_master_secret;
    use crate::crypto::hybrid_kem;

    /// Generates a hybrid keypair and an Ed25519 signing keypair for tests.
    fn create_test_keypairs() -> (HybridSecretKey, HybridPublicKey, SigningKey, VerifyingKey) {
        let (secret, public) = hybrid_kem::generate_keypair();
        let signing = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying = signing.verifying_key();
        (secret, public, signing, verifying)
    }

    /// Builds a matched pair of `ChatSession`s with a shared master secret as
    /// would be produced by a real handshake. Both sides use the same passphrase
    /// for testing.
    fn create_test_sessions() -> (ChatSession, ChatSession) {
        let (alice_secret, alice_public, alice_sign, alice_verify) = create_test_keypairs();
        let (bob_secret, bob_public, bob_sign, bob_verify) = create_test_keypairs();

        let config = ChatConfig::default();
        let alice_carriers = generate_carriers(config.carriers_per_party, config.carrier_size);
        let bob_carriers = generate_carriers(config.carriers_per_party, config.carrier_size);

        let test_passphrase = "test_passphrase_123";

        // Stand in for the two handshake KEM shared secrets — any agreed-on
        // 32-byte values produce the same master both sides.
        let ss_resp_to_init = [0xA1u8; 32];
        let ss_init_to_resp = [0xB2u8; 32];
        let master = derive_master_secret(&ss_resp_to_init, &ss_init_to_resp);

        let alice_session = ChatSession::init_as_initiator(
            alice_secret,
            &alice_sign,
            bob_public.clone(),
            bob_verify,
            &master,
            alice_carriers.clone(),
            bob_carriers.clone(),
            config.clone(),
            test_passphrase,
        )
        .unwrap();

        let bob_session = ChatSession::init_as_responder(
            bob_secret,
            &bob_sign,
            alice_public,
            alice_verify,
            &master,
            bob_carriers,
            alice_carriers,
            config,
            test_passphrase,
        )
        .unwrap();

        (alice_session, bob_session)
    }

    #[test]
    fn test_session_initialization() {
        let (alice, bob) = create_test_sessions();

        assert_eq!(alice.role(), Role::Initiator);
        assert_eq!(bob.role(), Role::Responder);
        assert_eq!(alice.messages_sent(), 0);
        assert_eq!(alice.messages_received(), 0);
    }

    #[test]
    fn test_single_message_exchange() {
        let (mut alice, mut bob) = create_test_sessions();

        let wire = alice.send_message("Hello, Bob!").unwrap();
        let received = bob.receive_message(&wire).unwrap();

        assert_eq!(received, "Hello, Bob!");
        assert_eq!(alice.messages_sent(), 1);
        assert_eq!(bob.messages_received(), 1);
    }

    #[test]
    fn test_bidirectional_messages_drive_kem_ratchet() {
        let (mut alice, mut bob) = create_test_sessions();

        let wire1 = alice.send_message("Hi Bob").unwrap();
        // First message has no kem_ciphertext (no ratchet step yet).
        // Inspect after decrypting on Bob's side via header_key by going through receive.
        let msg1 = bob.receive_message(&wire1).unwrap();
        assert_eq!(msg1, "Hi Bob");

        // Bob's reply triggers a KEM ratchet.
        let wire2 = bob.send_message("Hi Alice").unwrap();
        let msg2 = alice.receive_message(&wire2).unwrap();
        assert_eq!(msg2, "Hi Alice");

        // Alice replies — another KEM ratchet step.
        let wire3 = alice.send_message("How are you?").unwrap();
        let msg3 = bob.receive_message(&wire3).unwrap();
        assert_eq!(msg3, "How are you?");

        // Bob replies again.
        let wire4 = bob.send_message("Doing well").unwrap();
        let msg4 = alice.receive_message(&wire4).unwrap();
        assert_eq!(msg4, "Doing well");
    }

    #[test]
    fn test_multiple_consecutive_messages_no_ratchet() {
        let (mut alice, mut bob) = create_test_sessions();

        for i in 0..5 {
            let wire = alice.send_message(&format!("Message {}", i)).unwrap();
            let received = bob.receive_message(&wire).unwrap();
            assert_eq!(received, format!("Message {}", i));
        }

        assert_eq!(alice.messages_sent(), 5);
        assert_eq!(bob.messages_received(), 5);
    }

    #[test]
    fn test_message_too_long() {
        let (mut alice, _bob) = create_test_sessions();

        let long_message = "A".repeat(alice.config().max_message_len + 1);
        let result = alice.send_message(&long_message);

        assert!(matches!(result, Err(ChatError::EncodingFailed(_))));
    }

    #[test]
    fn test_wrong_signature_fails() {
        let (mut alice, mut bob) = create_test_sessions();

        let mut wire = alice.send_message("Hello").unwrap();
        wire.anyhide_code = format!("{}tampered", wire.anyhide_code);

        let result = bob.receive_message(&wire);
        assert!(result.is_err());
    }

    #[test]
    fn test_v1_messages_rejected() {
        let (mut alice, mut bob) = create_test_sessions();

        // Force a v1 wire message to land at Bob — must be rejected at the
        // version check before any ratchet/decryption side-effects.
        let mut wire = alice.send_message("Hello").unwrap();
        wire.version = 1;

        let result = bob.receive_message(&wire);
        assert!(matches!(result, Err(ChatError::VersionMismatch { .. })));
    }

    #[test]
    fn test_extended_back_and_forth() {
        // Stress-test multiple ratchet reversals.
        let (mut alice, mut bob) = create_test_sessions();

        for round in 0..5 {
            let alice_msg = format!("Alice round {}", round);
            let wire = alice.send_message(&alice_msg).unwrap();
            assert_eq!(bob.receive_message(&wire).unwrap(), alice_msg);

            let bob_msg = format!("Bob round {}", round);
            let wire = bob.send_message(&bob_msg).unwrap();
            assert_eq!(alice.receive_message(&wire).unwrap(), bob_msg);
        }
    }
}
