//! Public demo bundle — keys, carrier, and passphrase that anyone running
//! Anyhide already knows. Used by `anyhide demo encode/decode` and the
//! "Test mode" entry in the wizard so newcomers can play with the encoder
//! without first generating identities.
//!
//! # Security model
//!
//! Demo mode is **not private**. All three inputs (carrier, passphrase,
//! recipient key) are baked into the binary and documented publicly. Anyone
//! with the same Anyhide version can decode any code produced in demo mode.
//! This is intentional — demo mode exists to lower the onboarding barrier,
//! not to provide confidentiality.
//!
//! Real encryption flows (`anyhide encode`, `anyhide chat`) remain unchanged
//! and are unaffected by this module.
//!
//! # Determinism
//!
//! The recipient keypair is derived from a fixed seed string by SHA-256 — no
//! random bytes are stored in the source. Anyone can reproduce the demo keys
//! by hashing `KEY_SEED` themselves; this makes the bundle auditable.

use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// Public passphrase used for every demo encode/decode operation.
pub const PASSPHRASE: &str = "anyhide-public-demo";

/// Seed string hashed to produce the demo recipient's secret key. Public by
/// design — anyone can recompute the keypair from this string.
pub const KEY_SEED: &[u8] = b"ANYHIDE-PUBLIC-DEMO-KEY-V1";

/// Public carrier text. Chosen for broad character coverage so arbitrary demo
/// messages can be encoded without hitting min-coverage failures. Includes
/// uppercase, lowercase, digits, and common punctuation.
pub const CARRIER: &str = "Steganography hides messages within ordinary data. From ancient Greek tablets coated in wax to digital steganography embedded in images, secret writing has evolved through millennia. Anyhide combines this art with hybrid post-quantum cryptography (X25519 + ML-KEM-768), using any file as a pre-shared carrier. The order of carriers matters: shuffling them yields N! security combinations. Forward secrecy comes from ephemeral keys; plausible deniability from duress passwords. ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz 0123456789 !?.,;:'\"()[]{}<>+-*/=&%#@~^|\\_";

/// Derive the demo X25519 secret key by hashing `KEY_SEED`. The resulting
/// 32 bytes are clamped by `StaticSecret::from` per the X25519 spec.
pub fn recipient_secret_key() -> StaticSecret {
    let mut hasher = Sha256::new();
    hasher.update(KEY_SEED);
    let bytes: [u8; 32] = hasher.finalize().into();
    StaticSecret::from(bytes)
}

/// The demo recipient's public key, derived from `recipient_secret_key`.
pub fn recipient_public_key() -> PublicKey {
    PublicKey::from(&recipient_secret_key())
}

/// Plain-text warning printed before every demo operation. The wording is
/// deliberately blunt so users cannot mistake demo mode for real privacy.
pub const WARNING: &str = "WARNING: demo mode — this code is decodable by anyone with anyhide.\n         Use `anyhide encode` (or the wizard's Encode flow) for real privacy.";

#[cfg(test)]
mod tests {
    use super::*;

    /// The demo keypair must be deterministic across runs and platforms.
    /// If this test ever changes, every code published in older READMEs or
    /// blog posts becomes undecodable — treat the seed as a wire-format
    /// commitment.
    #[test]
    fn demo_keypair_is_deterministic() {
        let sk1 = recipient_secret_key();
        let sk2 = recipient_secret_key();
        assert_eq!(sk1.to_bytes(), sk2.to_bytes());

        let pk1 = recipient_public_key();
        let pk2 = recipient_public_key();
        assert_eq!(pk1.as_bytes(), pk2.as_bytes());
    }

    /// Spot-check that the public key starts with a non-trivial value (not all
    /// zeros). Catches accidental empty-seed regressions.
    #[test]
    fn demo_public_key_is_nontrivial() {
        let pk = recipient_public_key();
        assert_ne!(pk.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn carrier_has_broad_character_coverage() {
        // Sanity check — demo carrier must contain enough characters to
        // encode common ASCII messages.
        for c in "Hello World 123!".chars() {
            assert!(
                CARRIER.contains(c),
                "demo carrier missing character '{}'",
                c
            );
        }
    }
}
