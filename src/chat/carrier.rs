//! Random carrier generation for chat sessions.

use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;

/// Minimum carrier size to ensure all 256 byte values are present.
pub const MIN_CARRIER_SIZE: usize = 512;

/// Generate random carriers for a chat session.
///
/// Each carrier is filled with cryptographically random bytes using ChaCha20,
/// with a guaranteed prefix containing all 256 byte values (0x00-0xFF).
/// This ensures anyhide encoding will always find the required byte patterns.
///
/// Carriers are used for steganographic message encoding.
///
/// # Arguments
///
/// * `count` - Number of carriers to generate.
/// * `size` - Size of each carrier in bytes (minimum 512 to fit byte alphabet + random data).
///
/// # Returns
///
/// A vector of random byte vectors, each of the specified size.
///
/// # Panics
///
/// Panics if size < MIN_CARRIER_SIZE (512).
pub fn generate_carriers(count: usize, size: usize) -> Vec<Vec<u8>> {
    assert!(
        size >= MIN_CARRIER_SIZE,
        "Carrier size must be at least {} bytes to ensure all byte values are present",
        MIN_CARRIER_SIZE
    );

    let mut rng = ChaCha20Rng::from_entropy();

    (0..count)
        .map(|_| {
            let mut carrier = vec![0u8; size];

            // First 256 bytes: all possible byte values (ensures encoding always works)
            for (i, byte) in carrier.iter_mut().take(256).enumerate() {
                *byte = i as u8;
            }

            // Remaining bytes: random data
            rng.fill_bytes(&mut carrier[256..]);

            // Shuffle the carrier to distribute the byte alphabet
            shuffle_fisher_yates(&mut carrier, &mut rng);

            carrier
        })
        .collect()
}

/// Fisher-Yates shuffle for in-place array shuffling.
fn shuffle_fisher_yates(data: &mut [u8], rng: &mut ChaCha20Rng) {
    let len = data.len();
    for i in (1..len).rev() {
        // Generate random index in [0, i]
        let mut random_bytes = [0u8; 8];
        rng.fill_bytes(&mut random_bytes);
        let j = (u64::from_le_bytes(random_bytes) as usize) % (i + 1);
        data.swap(i, j);
    }
}

/// Generate carriers with a specific seed (for testing).
///
/// This is deterministic and should only be used in tests.
/// Each carrier contains all 256 byte values shuffled with random data.
///
/// # Panics
///
/// Panics if size < MIN_CARRIER_SIZE (512).
#[cfg(test)]
pub fn generate_carriers_seeded(count: usize, size: usize, seed: [u8; 32]) -> Vec<Vec<u8>> {
    assert!(
        size >= MIN_CARRIER_SIZE,
        "Carrier size must be at least {} bytes to ensure all byte values are present",
        MIN_CARRIER_SIZE
    );

    let mut rng = ChaCha20Rng::from_seed(seed);

    (0..count)
        .map(|_| {
            let mut carrier = vec![0u8; size];

            // First 256 bytes: all possible byte values
            for (i, byte) in carrier.iter_mut().take(256).enumerate() {
                *byte = i as u8;
            }

            // Remaining bytes: random data
            rng.fill_bytes(&mut carrier[256..]);

            // Shuffle the carrier
            shuffle_fisher_yates(&mut carrier, &mut rng);

            carrier
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_generate_carriers_count_and_size() {
        let carriers = generate_carriers(5, 1024);
        assert_eq!(carriers.len(), 5);
        for carrier in &carriers {
            assert_eq!(carrier.len(), 1024);
        }
    }

    #[test]
    fn test_carriers_are_random() {
        let carriers1 = generate_carriers(2, MIN_CARRIER_SIZE);
        let carriers2 = generate_carriers(2, MIN_CARRIER_SIZE);

        // Different calls should produce different carriers
        assert_ne!(carriers1[0], carriers2[0]);
    }

    #[test]
    fn test_seeded_carriers_are_deterministic() {
        let seed = [42u8; 32];

        let carriers1 = generate_carriers_seeded(3, MIN_CARRIER_SIZE, seed);
        let carriers2 = generate_carriers_seeded(3, MIN_CARRIER_SIZE, seed);

        assert_eq!(carriers1, carriers2);
    }

    #[test]
    fn test_different_seeds_produce_different_carriers() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let carriers1 = generate_carriers_seeded(1, MIN_CARRIER_SIZE, seed1);
        let carriers2 = generate_carriers_seeded(1, MIN_CARRIER_SIZE, seed2);

        assert_ne!(carriers1[0], carriers2[0]);
    }

    #[test]
    fn test_empty_carriers_count() {
        let carriers = generate_carriers(0, 1024);
        assert!(carriers.is_empty());
    }

    #[test]
    #[should_panic(expected = "Carrier size must be at least")]
    fn test_too_small_carrier_panics() {
        let _ = generate_carriers(1, 256);
    }

    #[test]
    fn test_carriers_contain_all_byte_values() {
        let carriers = generate_carriers(1, MIN_CARRIER_SIZE);
        let unique_bytes: HashSet<u8> = carriers[0].iter().copied().collect();

        // Must contain all 256 possible byte values
        assert_eq!(unique_bytes.len(), 256);
    }

    #[test]
    fn test_seeded_carriers_contain_all_byte_values() {
        let seed = [99u8; 32];
        let carriers = generate_carriers_seeded(1, MIN_CARRIER_SIZE, seed);
        let unique_bytes: HashSet<u8> = carriers[0].iter().copied().collect();

        // Must contain all 256 possible byte values
        assert_eq!(unique_bytes.len(), 256);
    }

    #[test]
    fn test_min_carrier_size_constant() {
        // MIN_CARRIER_SIZE must be at least 256 to fit all byte values + some random
        assert!(MIN_CARRIER_SIZE >= 256);
    }
}
