//! Various constants used by the Zcash primitives.

use ff::PrimeField;
use group::Group;
use jubjub::SubgroupPoint;
use lazy_static::lazy_static;

use crate::group_hash::group_hash;

fn find_group_hash(m: &[u8], personalization: &[u8; 8]) -> SubgroupPoint {
    let mut tag = m.to_vec();
    let i = tag.len();
    tag.push(0u8);

    loop {
        let gh = group_hash(&tag, personalization);

        // We don't want to overflow and start reusing generators
        assert!(tag[i] != u8::MAX);
        tag[i] += 1;

        if let Some(gh) = gh {
            break gh;
        }
    }
}

/// First 64 bytes of the BLAKE2s input during group hash.
/// This is chosen to be some random string that we couldn't have anticipated when we designed
/// the algorithm, for rigidity purposes.
/// We deliberately use an ASCII hex string of 32 bytes here.
pub const GH_FIRST_BLOCK: &[u8; 64] = b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";

/// Merkle Tree Depth
pub const MERKLE_TREE_DEPTH: usize = 20;

/// BLAKE2s7r Personalization for Merkle Tree
pub const MERKLE_TREE_PERSONALIZATION: &[u8; 8] = b"ZEOStree";

// BLAKE2s invocation personalizations
/// BLAKE2s Personalization for CRH^ivk = BLAKE2s(ak | nk)
pub const CRH_IVK_PERSONALIZATION: &[u8; 8] = b"Zcashivk";

/// BLAKE2s Personalization for PRF^nf = BLAKE2s(nk | rho)
pub const PRF_NF_PERSONALIZATION: &[u8; 8] = b"Zcash_nf";

// Group hash personalizations
/// BLAKE2s Personalization for Pedersen hash generators.
pub const PEDERSEN_HASH_GENERATORS_PERSONALIZATION: &[u8; 8] = b"Zcash_PH";

/// BLAKE2s Personalization for the group hash for key diversification
pub const KEY_DIVERSIFICATION_PERSONALIZATION: &[u8; 8] = b"Zcash_gd";

/// BLAKE2s Personalization for the spending key base point
pub const SPENDING_KEY_GENERATOR_PERSONALIZATION: &[u8; 8] = b"Zcash_G_";

/// BLAKE2s Personalization for the proof generation key base point
pub const PROOF_GENERATION_KEY_BASE_GENERATOR_PERSONALIZATION: &[u8; 8] = b"Zcash_H_";

/// BLAKE2s Personalization for the value commitment generator for the value
pub const VALUE_COMMITMENT_GENERATOR_PERSONALIZATION: &[u8; 8] = b"Zcash_cv";

/// BLAKE2s Personalization for the nullifier position generator (for computing rho)
pub const NULLIFIER_POSITION_IN_TREE_GENERATOR_PERSONALIZATION: &[u8; 8] = b"Zcash_J_";

/// BLAKE2s Personalization for Rseed = BLAKE2s(seed)
pub const RSEED_PERSONALIZATION: &[u8; 8] = b"ZEOSSeed";

/// The memo field of a 'change' note
pub const MEMO_CHANGE_NOTE: [u8; 512] = [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

lazy_static! {
    /// The prover will demonstrate knowledge of discrete log with respect to this base when
    /// they are constructing a proof, in order to authorize proof construction.
    pub static ref PROOF_GENERATION_KEY_GENERATOR: SubgroupPoint =
        find_group_hash(&[], PROOF_GENERATION_KEY_BASE_GENERATOR_PERSONALIZATION);

    /// The note commitment is randomized over this generator.
    pub static ref NOTE_COMMITMENT_RANDOMNESS_GENERATOR: SubgroupPoint =
        find_group_hash(b"r", PEDERSEN_HASH_GENERATORS_PERSONALIZATION);

    /// The nullifier position generator (rho domain separation).
    pub static ref NULLIFIER_POSITION_GENERATOR: SubgroupPoint =
        find_group_hash(&[], NULLIFIER_POSITION_IN_TREE_GENERATOR_PERSONALIZATION);

    /// The value commitment generator for the value.
    pub static ref VALUE_COMMITMENT_VALUE_GENERATOR: SubgroupPoint =
        find_group_hash(b"v", VALUE_COMMITMENT_GENERATOR_PERSONALIZATION);

    /// The value commitment generator for the randomness.
    pub static ref VALUE_COMMITMENT_RANDOMNESS_GENERATOR: SubgroupPoint =
        find_group_hash(b"r", VALUE_COMMITMENT_GENERATOR_PERSONALIZATION);

    /// The spender proves discrete log with respect to this base at spend time.
    pub static ref SPENDING_KEY_GENERATOR: SubgroupPoint =
        find_group_hash(&[], SPENDING_KEY_GENERATOR_PERSONALIZATION);

    /// The generators (for each segment) used in all Pedersen commitments.
    pub static ref PEDERSEN_HASH_GENERATORS: Vec<SubgroupPoint> = {
        // Keep this in sync with the previous hardcoded generator count (6).
        const N: usize = 6;
        (0..N)
            .map(|m| find_group_hash(&(m as u32).to_le_bytes(), PEDERSEN_HASH_GENERATORS_PERSONALIZATION))
            .collect()
    };
}

/// The maximum number of chunks per segment of the Pedersen hash.
pub const PEDERSEN_HASH_CHUNKS_PER_GENERATOR: usize = 63;

/// The window size for exponentiation of Pedersen hash generators outside the circuit.
pub const PEDERSEN_HASH_EXP_WINDOW_SIZE: u32 = 8;

lazy_static! {
    /// The exp table for [`PEDERSEN_HASH_GENERATORS`].
    pub static ref PEDERSEN_HASH_EXP_TABLE: Vec<Vec<Vec<SubgroupPoint>>> =
        generate_pedersen_hash_exp_table();
}

/// Creates the exp table for the Pedersen hash generators.
fn generate_pedersen_hash_exp_table() -> Vec<Vec<Vec<SubgroupPoint>>> {
    let window = PEDERSEN_HASH_EXP_WINDOW_SIZE;

    PEDERSEN_HASH_GENERATORS
        .iter()
        .cloned()
        .map(|mut g| {
            let mut tables = vec![];

            let mut num_bits = 0;
            while num_bits <= jubjub::Fr::NUM_BITS {
                let mut table = Vec::with_capacity(1 << window);
                let mut base = SubgroupPoint::identity();

                for _ in 0..(1 << window) {
                    table.push(base);
                    base += g;
                }

                tables.push(table);
                num_bits += window;

                for _ in 0..window {
                    g = g.double();
                }
            }

            tables
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use jubjub::SubgroupPoint;

    use super::*;
    use crate::group_hash::group_hash;

    fn find_group_hash(m: &[u8], personalization: &[u8; 8]) -> SubgroupPoint {
        let mut tag = m.to_vec();
        let i = tag.len();
        tag.push(0u8);

        loop {
            let gh = group_hash(&tag, personalization);

            // We don't want to overflow and start reusing generators
            assert!(tag[i] != u8::max_value());
            tag[i] += 1;

            if let Some(gh) = gh {
                break gh;
            }
        }
    }

    #[test]
    fn proof_generation_key_base_generator() {
        assert_eq!(
            find_group_hash(&[], PROOF_GENERATION_KEY_BASE_GENERATOR_PERSONALIZATION),
            *PROOF_GENERATION_KEY_GENERATOR,
        );
    }

    #[test]
    fn note_commitment_randomness_generator() {
        assert_eq!(
            find_group_hash(b"r", PEDERSEN_HASH_GENERATORS_PERSONALIZATION),
            *NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
        );
    }

    #[test]
    fn nullifier_position_generator() {
        assert_eq!(
            find_group_hash(&[], NULLIFIER_POSITION_IN_TREE_GENERATOR_PERSONALIZATION),
            *NULLIFIER_POSITION_GENERATOR,
        );
    }

    #[test]
    fn value_commitment_value_generator() {
        assert_eq!(
            find_group_hash(b"v", VALUE_COMMITMENT_GENERATOR_PERSONALIZATION),
            *VALUE_COMMITMENT_VALUE_GENERATOR,
        );
    }

    #[test]
    fn value_commitment_randomness_generator() {
        assert_eq!(
            find_group_hash(b"r", VALUE_COMMITMENT_GENERATOR_PERSONALIZATION),
            *VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
        );
    }

    #[test]
    fn spending_key_generator() {
        assert_eq!(
            find_group_hash(&[], SPENDING_KEY_GENERATOR_PERSONALIZATION),
            *SPENDING_KEY_GENERATOR,
        );
    }

    #[test]
    fn pedersen_hash_generators() {
        for (m, actual) in PEDERSEN_HASH_GENERATORS.iter().enumerate() {
            assert_eq!(
                &find_group_hash(
                    &(m as u32).to_le_bytes(),
                    PEDERSEN_HASH_GENERATORS_PERSONALIZATION
                ),
                actual
            );
        }
    }

    #[test]
    fn no_duplicate_fixed_base_generators() {
        let fixed_base_generators: [&jubjub::SubgroupPoint; 6] = [
            &*PROOF_GENERATION_KEY_GENERATOR,
            &*NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
            &*NULLIFIER_POSITION_GENERATOR,
            &*VALUE_COMMITMENT_VALUE_GENERATOR,
            &*VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
            &*SPENDING_KEY_GENERATOR,
        ];

        // Check for duplicates, far worse than spec inconsistencies!
        for (i, p1) in fixed_base_generators.iter().enumerate() {
            if p1.is_identity().into() {
                panic!("Neutral element!");
            }

            for p2 in fixed_base_generators.iter().skip(i + 1) {
                if *p1 == *p2 {
                    panic!("Duplicate generator!");
                }
            }
        }
    }

    /// Check for simple relations between the generators, that make finding collisions easy;
    /// far worse than spec inconsistencies!
    fn check_consistency_of_pedersen_hash_generators(
        pedersen_hash_generators: &[jubjub::SubgroupPoint],
    ) {
        for (i, p1) in pedersen_hash_generators.iter().enumerate() {
            if p1.is_identity().into() {
                panic!("Neutral element!");
            }
            for p2 in pedersen_hash_generators.iter().skip(i + 1) {
                if p1 == p2 {
                    panic!("Duplicate generator!");
                }
                if *p1 == -p2 {
                    panic!("Inverse generator!");
                }
            }

            // check for a generator being the sum of any other two
            for (j, p2) in pedersen_hash_generators.iter().enumerate() {
                if j == i {
                    continue;
                }
                for (k, p3) in pedersen_hash_generators.iter().enumerate() {
                    if k == j || k == i {
                        continue;
                    }
                    let sum = p2 + p3;
                    if sum == *p1 {
                        panic!("Linear relation between generators!");
                    }
                }
            }
        }
    }

    #[test]
    fn pedersen_hash_generators_consistency() {
        check_consistency_of_pedersen_hash_generators(PEDERSEN_HASH_GENERATORS.as_slice());
    }

    #[test]
    #[should_panic(expected = "Linear relation between generators!")]
    fn test_jubjub_bls12_pedersen_hash_generators_consistency_check_linear_relation() {
        let mut pedersen_hash_generators = PEDERSEN_HASH_GENERATORS.to_vec();

        // Test for linear relation
        pedersen_hash_generators.push(PEDERSEN_HASH_GENERATORS[0] + PEDERSEN_HASH_GENERATORS[1]);

        check_consistency_of_pedersen_hash_generators(&pedersen_hash_generators);
    }
}
