//! Chat session management with zeroize.
//!
//! The `ChatSession` struct holds all cryptographic state for an active chat.
//! All sensitive data is automatically zeroized when the session is dropped.

use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::chat::config::{ChatConfig, CHAT_PROTOCOL_VERSION};
use crate::chat::error::ChatError;
use crate::chat::protocol::{
    advance_carrier_chain, derive_session_keys, dh_ratchet,
    decrypt_header, encrypt_header, kdf_chain, MessageHeader, SignedMessage, WireMessage,
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
/// All sensitive cryptographic material is zeroized on drop.
pub struct ChatSession {
    // === Key Material ===
    /// Header encryption key (derived from initial DH).
    header_key: [u8; 32],

    /// Current sending chain key.
    send_chain: [u8; 32],

    /// Current receiving chain key.
    recv_chain: [u8; 32],

    /// Carrier chain key for selecting carriers.
    carrier_chain: [u8; 32],

    /// My current DH private key bytes.
    my_dh_secret: [u8; 32],

    /// My current DH public key bytes.
    my_dh_public: [u8; 32],

    /// Their current DH public key bytes.
    their_dh_public: [u8; 32],

    /// User-provided passphrase (hashed).
    user_passphrase: [u8; 32],

    /// Derived passphrase component (from DH).
    derived_passphrase: [u8; 32],

    /// My Ed25519 signing key bytes.
    my_signing_key: [u8; 32],

    // === Sequence Numbers ===
    /// Next sequence number to send.
    send_seq: u32,

    /// Expected next sequence number to receive.
    recv_seq: u32,

    /// Previous chain length (for out-of-order handling).
    prev_chain_len: u32,

    /// Last direction of message flow (for ratchet).
    last_direction: Option<Direction>,

    // === Skipped Message Keys ===
    /// Cache of skipped message keys for out-of-order delivery.
    /// Key: (dh_pub_bytes, seq), Value: message_key
    skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>,

    // === Carriers ===
    /// My carriers (initiator = 0, responder = 1).
    my_carriers: Vec<Vec<u8>>,

    /// Their carriers.
    their_carriers: Vec<Vec<u8>>,

    // === Identity ===
    /// Their Ed25519 verifying key.
    their_verifying_key: VerifyingKey,

    // === Config ===
    config: ChatConfig,

    /// My role in the session.
    role: Role,
}

impl Drop for ChatSession {
    fn drop(&mut self) {
        // Manually zeroize the HashMap values
        for (_, key) in self.skipped_keys.drain() {
            let mut key_copy = key;
            key_copy.zeroize();
        }

        // Zeroize carriers
        for carrier in &mut self.my_carriers {
            carrier.zeroize();
        }
        for carrier in &mut self.their_carriers {
            carrier.zeroize();
        }

        // Zeroize header key
        self.header_key.zeroize();
    }
}

impl ChatSession {
    /// Create a new session as the initiator.
    ///
    /// # Arguments
    ///
    /// * `my_ephemeral_secret` - Our ephemeral X25519 secret key.
    /// * `my_signing_key` - Our Ed25519 signing key.
    /// * `their_ephemeral_public` - Their ephemeral X25519 public key.
    /// * `their_verifying_key` - Their Ed25519 verifying key.
    /// * `my_carriers` - Carriers we generated.
    /// * `their_carriers` - Carriers they sent.
    /// * `config` - Negotiated session configuration.
    /// * `user_passphrase` - User-provided passphrase.
    pub fn init_as_initiator(
        my_ephemeral_secret: StaticSecret,
        my_signing_key: &SigningKey,
        their_ephemeral_public: PublicKey,
        their_verifying_key: VerifyingKey,
        my_carriers: Vec<Vec<u8>>,
        their_carriers: Vec<Vec<u8>>,
        config: ChatConfig,
        user_passphrase: &str,
    ) -> Result<Self, ChatError> {
        let my_public = PublicKey::from(&my_ephemeral_secret);

        // DH shared secret
        let shared_secret = my_ephemeral_secret.diffie_hellman(&their_ephemeral_public);

        // Derive session keys (initiator's pubkey first)
        let session_keys = derive_session_keys(
            shared_secret.as_bytes(),
            my_public.as_bytes(),
            their_ephemeral_public.as_bytes(),
        );

        // Hash the user passphrase
        let mut user_pass_hash = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(user_passphrase.as_bytes());
        user_pass_hash.copy_from_slice(&hasher.finalize());

        Ok(Self {
            header_key: session_keys.header_key,
            send_chain: session_keys.send_chain,
            recv_chain: session_keys.recv_chain,
            carrier_chain: session_keys.carrier_chain,
            my_dh_secret: my_ephemeral_secret.to_bytes(),
            my_dh_public: *my_public.as_bytes(),
            their_dh_public: *their_ephemeral_public.as_bytes(),
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

    /// Create a new session as the responder.
    pub fn init_as_responder(
        my_ephemeral_secret: StaticSecret,
        my_signing_key: &SigningKey,
        their_ephemeral_public: PublicKey,
        their_verifying_key: VerifyingKey,
        my_carriers: Vec<Vec<u8>>,
        their_carriers: Vec<Vec<u8>>,
        config: ChatConfig,
        user_passphrase: &str,
    ) -> Result<Self, ChatError> {
        let my_public = PublicKey::from(&my_ephemeral_secret);

        // DH shared secret
        let shared_secret = my_ephemeral_secret.diffie_hellman(&their_ephemeral_public);

        // Derive session keys (initiator's pubkey first, so their pubkey first for responder)
        let session_keys = derive_session_keys(
            shared_secret.as_bytes(),
            their_ephemeral_public.as_bytes(),
            my_public.as_bytes(),
        );

        // Hash the user passphrase
        let mut user_pass_hash = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(user_passphrase.as_bytes());
        user_pass_hash.copy_from_slice(&hasher.finalize());

        // Responder swaps send/recv chains
        Ok(Self {
            header_key: session_keys.header_key,
            send_chain: session_keys.recv_chain, // Swapped
            recv_chain: session_keys.send_chain, // Swapped
            carrier_chain: session_keys.carrier_chain,
            my_dh_secret: my_ephemeral_secret.to_bytes(),
            my_dh_public: *my_public.as_bytes(),
            their_dh_public: *their_ephemeral_public.as_bytes(),
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

    /// Get the session configuration.
    pub fn config(&self) -> &ChatConfig {
        &self.config
    }

    /// Get our role in the session.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Get the number of messages sent.
    pub fn messages_sent(&self) -> u32 {
        self.send_seq
    }

    /// Get the number of messages received.
    pub fn messages_received(&self) -> u32 {
        self.recv_seq
    }

    /// Send a message.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The message to send.
    ///
    /// # Returns
    ///
    /// A `WireMessage` ready to be sent over the transport.
    pub fn send_message(&mut self, plaintext: &str) -> Result<WireMessage, ChatError> {
        // Validate message length
        if plaintext.len() > self.config.max_message_len {
            return Err(ChatError::EncodingFailed(format!(
                "Message too long: {} > {}",
                plaintext.len(),
                self.config.max_message_len
            )));
        }

        // Check if we need to DH ratchet (direction changed to sending)
        if self.last_direction == Some(Direction::Receiving) {
            self.perform_dh_ratchet()?;
        }

        // Derive message key from send chain
        let (new_chain, message_key) = kdf_chain(&self.send_chain);
        self.send_chain = new_chain;

        // Select carrier deterministically from carrier chain
        let (new_carrier_chain, carrier_owner, carrier_index) =
            advance_carrier_chain(&self.carrier_chain, self.config.carriers_per_party);
        self.carrier_chain = new_carrier_chain;

        let carrier = self.get_carrier(carrier_owner, carrier_index)?;

        // Sign the message with Ed25519
        let signing_key = SigningKey::from_bytes(&self.my_signing_key);
        let mut hasher = Sha256::new();
        hasher.update(plaintext.as_bytes());
        hasher.update(&self.send_seq.to_le_bytes());
        let msg_hash = hasher.finalize();
        let signature = signing_key.sign(&msg_hash);

        // Create signed message
        let signed_message = SignedMessage::new(plaintext.to_string(), signature.to_bytes().to_vec());
        let signed_bytes = signed_message
            .to_bytes()
            .map_err(|e| ChatError::SerializationFailed(e.to_string()))?;

        // Combine user passphrase with derived passphrase and message key
        let msg_passphrase = self.combine_passphrases(&message_key);

        // Create a temporary keypair for anyhide encoding
        // We use the message key to derive deterministic keys
        let msg_secret = StaticSecret::from(message_key);
        let msg_public = PublicKey::from(&msg_secret);

        // Encode with anyhide using binary carrier
        let binary_carrier = Carrier::from_bytes(carrier.clone());
        let encoded = encode_bytes_with_carrier(&binary_carrier, &signed_bytes, &msg_passphrase, &msg_public)
            .map_err(|e| ChatError::EncodingFailed(e.to_string()))?;

        // Build header
        let header = MessageHeader {
            seq: self.send_seq,
            dh_public: self.my_dh_public,
            carrier_owner,
            carrier_index,
            prev_chain_len: self.prev_chain_len,
        };

        // Encrypt header
        let (encrypted_header, header_nonce) = encrypt_header(&header, &self.header_key)?;

        // Update state
        self.send_seq += 1;
        self.last_direction = Some(Direction::Sending);

        Ok(WireMessage::new(
            CHAT_PROTOCOL_VERSION,
            header_nonce,
            encrypted_header,
            encoded.code,
        ))
    }

    /// Receive and decrypt a message.
    ///
    /// # Arguments
    ///
    /// * `wire` - The received wire message.
    ///
    /// # Returns
    ///
    /// The decrypted plaintext message.
    pub fn receive_message(&mut self, wire: &WireMessage) -> Result<String, ChatError> {
        // Check version
        if wire.version != CHAT_PROTOCOL_VERSION {
            return Err(ChatError::VersionMismatch {
                expected: CHAT_PROTOCOL_VERSION,
                got: wire.version,
            });
        }

        // Decrypt header
        let header = decrypt_header(&wire.encrypted_header, &wire.header_nonce, &self.header_key)?;

        // Check if DH ratchet needed (their key changed)
        if header.dh_public != self.their_dh_public {
            self.handle_their_ratchet(&header.dh_public, header.prev_chain_len)?;
        }

        // Handle out-of-order messages
        let message_key = if header.seq == self.recv_seq {
            // Expected message - derive from chain
            let (new_chain, message_key) = kdf_chain(&self.recv_chain);
            self.recv_chain = new_chain;
            self.recv_seq += 1;
            message_key
        } else if header.seq > self.recv_seq {
            // Future message - skip ahead and cache intermediate keys
            self.skip_message_keys(header.seq, &header.dh_public)?
        } else {
            // Past message - check cache
            self.get_skipped_key(&header.dh_public, header.seq)?
        };

        // Get carrier
        let carrier = self.get_carrier(header.carrier_owner, header.carrier_index)?;

        // Combine user passphrase with derived passphrase and message key
        let msg_passphrase = self.combine_passphrases(&message_key);

        // Create temporary keypair for decoding
        let msg_secret = StaticSecret::from(message_key);

        // Decode with anyhide
        let binary_carrier = Carrier::from_bytes(carrier.clone());
        let decoded = decode_bytes_with_carrier(&wire.anyhide_code, &binary_carrier, &msg_passphrase, &msg_secret);

        // Deserialize signed message
        let signed_message = SignedMessage::from_bytes(&decoded.data)
            .map_err(|e| ChatError::DecodingFailed(e.to_string()))?;

        // Verify Ed25519 signature
        let mut hasher = Sha256::new();
        hasher.update(signed_message.content.as_bytes());
        hasher.update(&header.seq.to_le_bytes());
        let msg_hash = hasher.finalize();

        let signature = Signature::from_slice(&signed_message.signature)
            .map_err(|_| ChatError::InvalidSignature)?;

        self.their_verifying_key
            .verify(&msg_hash, &signature)
            .map_err(|_| ChatError::SignatureVerificationFailed)?;

        // Update state
        self.last_direction = Some(Direction::Receiving);

        Ok(signed_message.content)
    }

    /// Perform DH ratchet when we switch from receiving to sending.
    ///
    /// This generates a new DH keypair and derives a new send_chain.
    /// The recv_chain is NOT updated here - it will be updated by handle_their_ratchet
    /// when the peer responds with their ratchet step.
    fn perform_dh_ratchet(&mut self) -> Result<(), ChatError> {
        let their_public = PublicKey::from(self.their_dh_public);
        let output = dh_ratchet(&their_public, &self.send_chain);

        self.prev_chain_len = self.send_seq;
        self.send_seq = 0;

        self.my_dh_secret = output.new_secret;
        self.my_dh_public = output.new_public;
        self.send_chain = output.send_chain;
        // NOTE: Do NOT update recv_chain here. It is only updated when we receive
        // a message with a new DH public key from the peer (in handle_their_ratchet).

        Ok(())
    }

    /// Handle their DH ratchet when we receive a new public key.
    fn handle_their_ratchet(
        &mut self,
        new_their_public: &[u8; 32],
        prev_chain_len: u32,
    ) -> Result<(), ChatError> {
        // Skip any remaining message keys from the old chain
        self.skip_remaining_keys(prev_chain_len)?;

        // Update their public key
        self.their_dh_public = *new_their_public;

        // Perform our side of the ratchet
        let their_public = PublicKey::from(*new_their_public);
        let my_secret = StaticSecret::from(self.my_dh_secret);
        let dh_output = my_secret.diffie_hellman(&their_public);

        // Derive new recv chain using SEND label (to match sender's send_chain derivation)
        // The sender derives send_chain with "SEND" label, so receiver must use same label
        // for recv_chain to get the matching key.
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&self.recv_chain), dh_output.as_bytes());
        let mut new_recv_chain = [0u8; 32];
        hk.expand(b"ANYHIDE-CHAT-SEND", &mut new_recv_chain)
            .expect("32 bytes is valid");

        self.recv_chain = new_recv_chain;
        self.recv_seq = 0;

        Ok(())
    }

    /// Skip remaining keys in the current chain up to a target count.
    fn skip_remaining_keys(&mut self, target: u32) -> Result<(), ChatError> {
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
                .insert((self.their_dh_public, self.recv_seq), message_key);
            self.recv_seq += 1;
        }
        Ok(())
    }

    /// Skip message keys up to the target sequence number and return the target's key.
    fn skip_message_keys(&mut self, target_seq: u32, dh_public: &[u8; 32]) -> Result<[u8; 32], ChatError> {
        let skip_count = (target_seq - self.recv_seq) as usize;
        if skip_count > self.config.max_skip {
            return Err(ChatError::TooManySkipped {
                max: self.config.max_skip,
                requested: skip_count,
            });
        }

        // Skip intermediate keys
        while self.recv_seq < target_seq {
            let (new_chain, message_key) = kdf_chain(&self.recv_chain);
            self.recv_chain = new_chain;

            self.skipped_keys
                .insert((*dh_public, self.recv_seq), message_key);
            self.recv_seq += 1;
        }

        // Now derive the target key
        let (new_chain, message_key) = kdf_chain(&self.recv_chain);
        self.recv_chain = new_chain;
        self.recv_seq += 1;

        Ok(message_key)
    }

    /// Get a skipped message key from the cache.
    fn get_skipped_key(&mut self, dh_public: &[u8; 32], seq: u32) -> Result<[u8; 32], ChatError> {
        self.skipped_keys
            .remove(&(*dh_public, seq))
            .ok_or(ChatError::SkippedKeyNotFound(seq))
    }

    /// Combine user passphrase with derived passphrase and message key.
    ///
    /// This produces a unique passphrase for each message by combining:
    /// - User's provided passphrase (hashed)
    /// - Derived passphrase from DH exchange
    /// - Per-message key from the ratchet
    fn combine_passphrases(&self, message_key: &[u8; 32]) -> String {
        use hkdf::Hkdf;

        // Combine all three inputs using HKDF
        let mut combined_input = Vec::with_capacity(96);
        combined_input.extend_from_slice(&self.user_passphrase);
        combined_input.extend_from_slice(&self.derived_passphrase);
        combined_input.extend_from_slice(message_key);

        let hk = Hkdf::<Sha256>::new(None, &combined_input);
        let mut output = [0u8; 32];
        hk.expand(b"ANYHIDE-CHAT-MSG-PASS", &mut output)
            .expect("32 bytes is valid");

        // Convert to a passphrase string (hex encoded)
        hex::encode(output)
    }

    /// Get a carrier by owner and index.
    fn get_carrier(&self, owner: u8, index: u16) -> Result<&Vec<u8>, ChatError> {
        let carriers = match (self.role, owner) {
            (Role::Initiator, 0) | (Role::Responder, 1) => &self.my_carriers,
            (Role::Initiator, 1) | (Role::Responder, 0) => &self.their_carriers,
            _ => {
                return Err(ChatError::InvalidCarrier { owner, index });
            }
        };

        carriers.get(index as usize).ok_or(ChatError::InvalidCarrier { owner, index })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::generate_carriers;

    fn create_test_keypairs() -> (StaticSecret, PublicKey, SigningKey, VerifyingKey) {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        let signing = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying = signing.verifying_key();
        (secret, public, signing, verifying)
    }

    fn create_test_sessions() -> (ChatSession, ChatSession) {
        let (alice_eph_secret, alice_eph_public, alice_sign, alice_verify) = create_test_keypairs();
        let (bob_eph_secret, bob_eph_public, bob_sign, bob_verify) = create_test_keypairs();

        let config = ChatConfig::default();
        let alice_carriers = generate_carriers(config.carriers_per_party, config.carrier_size);
        let bob_carriers = generate_carriers(config.carriers_per_party, config.carrier_size);

        // Both use the same passphrase for testing
        let test_passphrase = "test_passphrase_123";

        let alice_session = ChatSession::init_as_initiator(
            alice_eph_secret,
            &alice_sign,
            bob_eph_public,
            bob_verify,
            alice_carriers.clone(),
            bob_carriers.clone(),
            config.clone(),
            test_passphrase,
        )
        .unwrap();

        let bob_session = ChatSession::init_as_responder(
            bob_eph_secret,
            &bob_sign,
            alice_eph_public,
            alice_verify,
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

        // Alice sends to Bob
        let wire = alice.send_message("Hello, Bob!").unwrap();
        let received = bob.receive_message(&wire).unwrap();

        assert_eq!(received, "Hello, Bob!");
        assert_eq!(alice.messages_sent(), 1);
        assert_eq!(bob.messages_received(), 1);
    }

    #[test]
    fn test_bidirectional_messages() {
        let (mut alice, mut bob) = create_test_sessions();

        // Alice -> Bob
        let wire1 = alice.send_message("Hi Bob").unwrap();
        let msg1 = bob.receive_message(&wire1).unwrap();
        assert_eq!(msg1, "Hi Bob");

        // Bob -> Alice
        let wire2 = bob.send_message("Hi Alice").unwrap();
        let msg2 = alice.receive_message(&wire2).unwrap();
        assert_eq!(msg2, "Hi Alice");

        // Alice -> Bob again
        let wire3 = alice.send_message("How are you?").unwrap();
        let msg3 = bob.receive_message(&wire3).unwrap();
        assert_eq!(msg3, "How are you?");
    }

    #[test]
    fn test_multiple_consecutive_messages() {
        let (mut alice, mut bob) = create_test_sessions();

        // Alice sends multiple messages
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

        // Alice sends a message
        let mut wire = alice.send_message("Hello").unwrap();

        // Tamper with the anyhide code (which contains the signature)
        wire.anyhide_code = format!("{}tampered", wire.anyhide_code);

        // Bob should fail to verify
        let result = bob.receive_message(&wire);
        assert!(result.is_err());
    }
}
