//! Hybrid post-quantum Key Encapsulation Mechanism (KEM).
//!
//! Combines classical X25519 ECDH with ML-KEM-768 (FIPS 203) into a single
//! KEM primitive that is secure against both classical and quantum adversaries.
//!
//! ## Design
//!
//! Encapsulation produces two independent shared secrets which are mixed via
//! HKDF-SHA256 into a single 32-byte symmetric key:
//!
//! ```text
//! classical_ss = X25519(eph_sk, recipient_classical_pk)
//! pq_ss        = ML-KEM-768.Encapsulate(recipient_pq_pk)
//! shared_key   = HKDF-SHA256(classical_ss || pq_ss, info = "ANYHIDE-HYBRID-KEM-V1")
//! ```
//!
//! As long as either primitive remains secure, the combined shared key
//! remains secret. This is the standard "harvest now, decrypt later" defense.
//!
//! ## Wire format
//!
//! - `HybridPublicKey`:  classical (32B) || pq (1184B) = 1216 bytes
//! - `HybridCiphertext`: classical_eph (32B) || pq_ct (1088B) = 1120 bytes
//! - Decapsulation key seed: 32B classical || 64B pq seed = 96 bytes

use hkdf::Hkdf;
use ml_kem::kem::{Encapsulate, TryDecapsulate};
use ml_kem::{
    Ciphertext as MlKemCiphertext, EncapsulationKey as MlKemEk, Kem, KeyExport, MlKem768,
};
use rand::rngs::OsRng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HKDF info string for combining classical and post-quantum shared secrets.
const COMBINER_INFO: &[u8] = b"ANYHIDE-HYBRID-KEM-V1";

/// Size of the X25519 public key component (bytes).
pub const CLASSICAL_PUBKEY_SIZE: usize = 32;

/// Size of the ML-KEM-768 encapsulation key (bytes).
pub const PQ_PUBKEY_SIZE: usize = 1184;

/// Size of the X25519 ephemeral public key in a ciphertext (bytes).
pub const CLASSICAL_CT_SIZE: usize = 32;

/// Size of the ML-KEM-768 ciphertext (bytes).
pub const PQ_CT_SIZE: usize = 1088;

/// Size of the serialized hybrid public key (bytes).
pub const HYBRID_PUBKEY_SIZE: usize = CLASSICAL_PUBKEY_SIZE + PQ_PUBKEY_SIZE;

/// Size of the serialized hybrid ciphertext (bytes).
pub const HYBRID_CT_SIZE: usize = CLASSICAL_CT_SIZE + PQ_CT_SIZE;

/// Size of the derived shared key (bytes).
pub const SHARED_KEY_SIZE: usize = 32;

/// Errors that can occur during hybrid KEM operations.
#[derive(Error, Debug)]
pub enum HybridKemError {
    #[error("Invalid public key encoding")]
    InvalidPublicKey,

    #[error("Invalid ciphertext encoding")]
    InvalidCiphertext,

    #[error("Decapsulation failed")]
    DecapsulationFailed,

    #[error("Key derivation failed")]
    KeyDerivationFailed,

    #[error("Invalid serialized data length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
}

/// A hybrid public key combining X25519 and ML-KEM-768 encapsulation keys.
#[derive(Clone)]
pub struct HybridPublicKey {
    classical: X25519PublicKey,
    pq: MlKemEk<MlKem768>,
}

impl HybridPublicKey {
    /// Returns the classical X25519 component.
    pub fn classical(&self) -> &X25519PublicKey {
        &self.classical
    }

    /// Serializes the hybrid public key to bytes.
    ///
    /// Format: classical (32) || pq (1184).
    pub fn to_bytes(&self) -> [u8; HYBRID_PUBKEY_SIZE] {
        let mut out = [0u8; HYBRID_PUBKEY_SIZE];
        out[..CLASSICAL_PUBKEY_SIZE].copy_from_slice(self.classical.as_bytes());
        let pq_bytes = self.pq.to_bytes();
        out[CLASSICAL_PUBKEY_SIZE..].copy_from_slice(pq_bytes.as_slice());
        out
    }

    /// Deserializes a hybrid public key from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, HybridKemError> {
        if data.len() != HYBRID_PUBKEY_SIZE {
            return Err(HybridKemError::InvalidLength {
                expected: HYBRID_PUBKEY_SIZE,
                actual: data.len(),
            });
        }

        let mut classical_bytes = [0u8; CLASSICAL_PUBKEY_SIZE];
        classical_bytes.copy_from_slice(&data[..CLASSICAL_PUBKEY_SIZE]);
        let classical = X25519PublicKey::from(classical_bytes);

        let pq_key_array =
            ml_kem::Key::<MlKemEk<MlKem768>>::try_from(&data[CLASSICAL_PUBKEY_SIZE..])
                .map_err(|_| HybridKemError::InvalidPublicKey)?;
        let pq = MlKemEk::<MlKem768>::new(&pq_key_array)
            .map_err(|_| HybridKemError::InvalidPublicKey)?;

        Ok(Self { classical, pq })
    }
}

/// A hybrid secret key combining X25519 and ML-KEM-768 decapsulation keys.
///
/// The classical secret zeroizes on drop via `x25519_dalek::StaticSecret`'s
/// own implementation; the ML-KEM secret zeroizes via the `zeroize` feature
/// enabled on the `ml-kem` crate.
pub struct HybridSecretKey {
    classical: X25519Secret,
    pq: ml_kem::DecapsulationKey<MlKem768>,
}

impl HybridSecretKey {
    /// Returns the classical X25519 component.
    pub fn classical(&self) -> &X25519Secret {
        &self.classical
    }

    /// Derives the matching public key.
    pub fn public_key(&self) -> HybridPublicKey {
        let classical = X25519PublicKey::from(&self.classical);
        let pq = self.pq.encapsulation_key().clone();
        HybridPublicKey { classical, pq }
    }
}

/// A hybrid ciphertext combining the X25519 ephemeral public key and the
/// ML-KEM-768 encapsulation output.
#[derive(Clone)]
pub struct HybridCiphertext {
    classical_ephemeral: [u8; CLASSICAL_CT_SIZE],
    pq: MlKemCiphertext<MlKem768>,
}

impl HybridCiphertext {
    /// Serializes the ciphertext to bytes.
    ///
    /// Format: classical_ephemeral (32) || pq (1088).
    pub fn to_bytes(&self) -> [u8; HYBRID_CT_SIZE] {
        let mut out = [0u8; HYBRID_CT_SIZE];
        out[..CLASSICAL_CT_SIZE].copy_from_slice(&self.classical_ephemeral);
        out[CLASSICAL_CT_SIZE..].copy_from_slice(self.pq.as_slice());
        out
    }

    /// Deserializes a ciphertext from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, HybridKemError> {
        if data.len() != HYBRID_CT_SIZE {
            return Err(HybridKemError::InvalidLength {
                expected: HYBRID_CT_SIZE,
                actual: data.len(),
            });
        }

        let mut classical_ephemeral = [0u8; CLASSICAL_CT_SIZE];
        classical_ephemeral.copy_from_slice(&data[..CLASSICAL_CT_SIZE]);

        let pq = MlKemCiphertext::<MlKem768>::try_from(&data[CLASSICAL_CT_SIZE..])
            .map_err(|_| HybridKemError::InvalidCiphertext)?;

        Ok(Self {
            classical_ephemeral,
            pq,
        })
    }
}

/// A 32-byte shared key derived from a successful hybrid encapsulation.
///
/// Wraps the raw bytes in a `Zeroize`-on-drop container to avoid leaving
/// residual key material in memory after use.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedKey([u8; SHARED_KEY_SIZE]);

impl SharedKey {
    /// Returns the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; SHARED_KEY_SIZE] {
        &self.0
    }
}

/// Generates a new hybrid keypair using the operating system's secure RNG.
pub fn generate_keypair() -> (HybridSecretKey, HybridPublicKey) {
    let classical_secret = X25519Secret::random_from_rng(OsRng);
    let classical_public = X25519PublicKey::from(&classical_secret);

    let (pq_dk, pq_ek) = MlKem768::generate_keypair();

    let secret = HybridSecretKey {
        classical: classical_secret,
        pq: pq_dk,
    };
    let public = HybridPublicKey {
        classical: classical_public,
        pq: pq_ek,
    };

    (secret, public)
}

/// Encapsulates a fresh shared key to the holder of the given public key.
pub fn encapsulate(
    recipient: &HybridPublicKey,
) -> Result<(HybridCiphertext, SharedKey), HybridKemError> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let classical_ss = ephemeral_secret.diffie_hellman(&recipient.classical);

    let (pq_ct, pq_ss) = recipient.pq.encapsulate();

    let shared = combine_secrets(classical_ss.as_bytes(), pq_ss.as_slice())?;

    let ct = HybridCiphertext {
        classical_ephemeral: *ephemeral_public.as_bytes(),
        pq: pq_ct,
    };

    Ok((ct, shared))
}

/// Decapsulates a ciphertext to recover the shared key.
pub fn decapsulate(
    secret: &HybridSecretKey,
    ciphertext: &HybridCiphertext,
) -> Result<SharedKey, HybridKemError> {
    let ephemeral_public = X25519PublicKey::from(ciphertext.classical_ephemeral);
    let classical_ss = secret.classical.diffie_hellman(&ephemeral_public);

    let pq_ss = secret
        .pq
        .try_decapsulate(&ciphertext.pq)
        .map_err(|_| HybridKemError::DecapsulationFailed)?;

    combine_secrets(classical_ss.as_bytes(), pq_ss.as_slice())
}

/// Mixes the two shared secrets into a single 32-byte symmetric key via
/// HKDF-SHA256. The combiner is the security-critical glue: as long as one
/// of `classical_ss` or `pq_ss` is uniformly random and unknown to the
/// adversary, the output is indistinguishable from random.
fn combine_secrets(classical_ss: &[u8], pq_ss: &[u8]) -> Result<SharedKey, HybridKemError> {
    let mut ikm = Vec::with_capacity(classical_ss.len() + pq_ss.len());
    ikm.extend_from_slice(classical_ss);
    ikm.extend_from_slice(pq_ss);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; SHARED_KEY_SIZE];
    hk.expand(COMBINER_INFO, &mut out)
        .map_err(|_| HybridKemError::KeyDerivationFailed)?;

    ikm.zeroize();
    Ok(SharedKey(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encap_decap_roundtrip_returns_same_shared_key() {
        let (sk, pk) = generate_keypair();
        let (ct, sender_key) = encapsulate(&pk).unwrap();
        let receiver_key = decapsulate(&sk, &ct).unwrap();

        assert_eq!(sender_key.as_bytes(), receiver_key.as_bytes());
    }

    #[test]
    fn decapsulate_with_wrong_secret_does_not_recover_shared_key() {
        let (_sk_correct, pk_correct) = generate_keypair();
        let (sk_wrong, _pk_wrong) = generate_keypair();

        let (ct, sender_key) = encapsulate(&pk_correct).unwrap();

        // ML-KEM uses implicit rejection: decapsulate always returns *some*
        // 32-byte value, but with the wrong secret it is a pseudorandom
        // value derived from the ciphertext, not the sender's shared key.
        let wrong_key = decapsulate(&sk_wrong, &ct).unwrap();
        assert_ne!(sender_key.as_bytes(), wrong_key.as_bytes());
    }

    #[test]
    fn public_key_serialization_roundtrip() {
        let (_sk, pk) = generate_keypair();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), HYBRID_PUBKEY_SIZE);

        let restored = HybridPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(restored.to_bytes(), bytes);
    }

    #[test]
    fn ciphertext_serialization_roundtrip() {
        let (sk, pk) = generate_keypair();
        let (ct, sender_key) = encapsulate(&pk).unwrap();

        let bytes = ct.to_bytes();
        assert_eq!(bytes.len(), HYBRID_CT_SIZE);

        let restored = HybridCiphertext::from_bytes(&bytes).unwrap();
        let recovered_key = decapsulate(&sk, &restored).unwrap();
        assert_eq!(sender_key.as_bytes(), recovered_key.as_bytes());
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        let too_short = vec![0u8; HYBRID_PUBKEY_SIZE - 1];
        let too_long = vec![0u8; HYBRID_PUBKEY_SIZE + 1];

        assert!(matches!(
            HybridPublicKey::from_bytes(&too_short),
            Err(HybridKemError::InvalidLength { .. })
        ));
        assert!(matches!(
            HybridPublicKey::from_bytes(&too_long),
            Err(HybridKemError::InvalidLength { .. })
        ));

        let bad_ct = vec![0u8; HYBRID_CT_SIZE - 1];
        assert!(matches!(
            HybridCiphertext::from_bytes(&bad_ct),
            Err(HybridKemError::InvalidLength { .. })
        ));
    }

    #[test]
    fn distinct_encapsulations_produce_distinct_ciphertexts_and_keys() {
        let (_sk, pk) = generate_keypair();
        let (ct1, key1) = encapsulate(&pk).unwrap();
        let (ct2, key2) = encapsulate(&pk).unwrap();

        assert_ne!(ct1.to_bytes(), ct2.to_bytes());
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn combine_secrets_is_deterministic_for_equal_inputs() {
        let classical = [7u8; 32];
        let pq = [9u8; 32];

        let k1 = combine_secrets(&classical, &pq).unwrap();
        let k2 = combine_secrets(&classical, &pq).unwrap();

        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn combine_secrets_diverges_when_either_input_changes() {
        let baseline = combine_secrets(&[1u8; 32], &[2u8; 32]).unwrap();

        let classical_changed = combine_secrets(&[3u8; 32], &[2u8; 32]).unwrap();
        let pq_changed = combine_secrets(&[1u8; 32], &[4u8; 32]).unwrap();

        assert_ne!(baseline.as_bytes(), classical_changed.as_bytes());
        assert_ne!(baseline.as_bytes(), pq_changed.as_bytes());
    }

    #[test]
    fn public_key_derived_from_secret_matches_generated_pair() {
        let (sk, pk) = generate_keypair();
        let derived = sk.public_key();
        assert_eq!(derived.to_bytes(), pk.to_bytes());
    }

    #[test]
    fn size_constants_match_fips203_ml_kem_768_spec() {
        assert_eq!(CLASSICAL_PUBKEY_SIZE, 32);
        assert_eq!(PQ_PUBKEY_SIZE, 1184);
        assert_eq!(CLASSICAL_CT_SIZE, 32);
        assert_eq!(PQ_CT_SIZE, 1088);
        assert_eq!(HYBRID_PUBKEY_SIZE, 1216);
        assert_eq!(HYBRID_CT_SIZE, 1120);
        assert_eq!(SHARED_KEY_SIZE, 32);
    }
}
