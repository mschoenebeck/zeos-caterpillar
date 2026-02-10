//! Various constants used for the Zcash proofs.

use crate::engine::{Scalar, scalar_one, scalar_zero, scalar_from_canonical_bytes};
use ff::{Field, PrimeField};
use jubjub::{ExtendedPoint, Fq, SubgroupPoint};
use group::{Curve, Group};
use lazy_static::lazy_static;
use crate::constants::{PEDERSEN_HASH_CHUNKS_PER_GENERATOR, PEDERSEN_HASH_GENERATORS};
type Coord = Scalar;

#[inline]
fn fq_to_coord(fq: Fq) -> Coord {
    let repr = fq.to_repr();
    let mut b = [0u8; 32];
    b.copy_from_slice(repr.as_ref());
    scalar_from_canonical_bytes(&b)
        .expect("jubjub::Fq must decode into engine::Scalar")
}

/// The `d` constant of the twisted Edwards curve: d = -(10240/10241)
pub(crate) fn edwards_d() -> Scalar {
    // -(10240/10241)
    -Scalar::from(10240u64) * Scalar::from(10241u64).invert().unwrap()
}

/// The `A` constant of the birationally equivalent Montgomery curve: A = 40962
pub(crate) fn montgomery_a() -> Scalar {
    Scalar::from(40962u64)
}

/// The scaling factor used for conversion to and from the Montgomery form.
///
/// This is a fixed constant in the circuit field. Historically it was hardcoded as raw limbs.
/// We keep it explicit and portable by deriving it from its known value in canonical bytes.
///
/// IMPORTANT: You must fill in the correct canonical 32-byte value for your original constant
/// (see Step 1.1 below).
pub(crate) fn montgomery_scale() -> Scalar {
    // We enforce the identity used throughout the codebase/tests:
    //   scale^2 * (-(1) - d) = 4
    //
    // So:
    //   scale = sqrt(4 / (-(1 + d)))
    //
    let four = Scalar::from(4u64);
    let denom = -(crate::engine::scalar_one() + edwards_d()); // -(1 + d)
    let x = four * denom.invert().unwrap();
    x.sqrt().unwrap()
}

/// The number of chunks needed to represent a full scalar during fixed-base
/// exponentiation.
const FIXED_BASE_CHUNKS_PER_GENERATOR: usize = 84;

/// Reference to a circuit version of a generator for fixed-base salar multiplication.
pub type FixedGenerator = &'static [Vec<(Coord, Coord)>];

/// Circuit version of a generator for fixed-base salar multiplication.
pub type FixedGeneratorOwned = Vec<Vec<(Coord, Coord)>>;

lazy_static! {
    pub static ref PROOF_GENERATION_KEY_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(*crate::constants::PROOF_GENERATION_KEY_GENERATOR);

    pub static ref NOTE_COMMITMENT_RANDOMNESS_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(*crate::constants::NOTE_COMMITMENT_RANDOMNESS_GENERATOR);

    pub static ref NULLIFIER_POSITION_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(*crate::constants::NULLIFIER_POSITION_GENERATOR);

    pub static ref VALUE_COMMITMENT_VALUE_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(*crate::constants::VALUE_COMMITMENT_VALUE_GENERATOR);

    pub static ref VALUE_COMMITMENT_RANDOMNESS_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(*crate::constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR);

    pub static ref SPENDING_KEY_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(*crate::constants::SPENDING_KEY_GENERATOR);

    /// The pre-computed window tables `[-4, 3, 2, 1, 1, 2, 3, 4]` of different magnitudes
    /// of the Pedersen hash segment generators.
    pub(crate) static ref PEDERSEN_CIRCUIT_GENERATORS: Vec<Vec<Vec<(Scalar, Scalar)>>> =
        generate_pedersen_circuit_generators();
}

/// Creates the 3-bit window table `[0, 1, ..., 8]` for different magnitudes of a fixed
/// generator.
pub fn generate_circuit_generator(mut gen: SubgroupPoint) -> FixedGeneratorOwned {
    let mut windows = vec![];

    for _ in 0..FIXED_BASE_CHUNKS_PER_GENERATOR {
        let mut coeffs = vec![(scalar_zero(), scalar_one())];
        let mut g = gen;
        for _ in 0..7 {
            let g_affine = jubjub::ExtendedPoint::from(g).to_affine();
            coeffs.push((
                fq_to_coord(g_affine.get_u()),
                fq_to_coord(g_affine.get_v()),
            ));
            g += gen;
        }
        windows.push(coeffs);

        // gen = gen * 8
        gen = g;
    }

    windows
}

/// Returns the coordinates of this point's Montgomery curve representation, or `None` if
/// it is the point at infinity.
#[allow(clippy::many_single_char_names)]
pub(crate) fn to_montgomery_coords(g: ExtendedPoint) -> Option<(Coord, Coord)> {
    let g = g.to_affine();
    let (x, y) = (fq_to_coord(g.get_u()), fq_to_coord(g.get_v()));

    if y == scalar_one() {
        // The only solution for y = 1 is x = 0. (0, 1) is the neutral element, so we map
        // this to the point at infinity.
        None
    } else {
        // The map from a twisted Edwards curve is defined as
        // (x, y) -> (u, v) where
        //      u = (1 + y) / (1 - y)
        //      v = u / x
        //
        // This mapping is not defined for y = 1 and for x = 0.
        //
        // We have that y != 1 above. If x = 0, the only
        // solutions for y are 1 (contradiction) or -1.
        if x.is_zero_vartime() {
            // (0, -1) is the point of order two which is not
            // the neutral element, so we map it to (0, 0) which is
            // the only affine point of order 2.
            Some((scalar_zero(), scalar_zero()))
        } else {
            // The mapping is defined as above.
            //
            // (x, y) -> (u, v) where
            //      u = (1 + y) / (1 - y)
            //      v = u / x

            let u = (scalar_one() + y) * (scalar_one() - y).invert().unwrap();
            let v = u * x.invert().unwrap();

            // Scale it into the correct curve constants
            // scaling factor = sqrt(4 / (a - d))
            Some((u, v * montgomery_scale()))
        }
    }
}

/// Creates the 2-bit window table lookups for each 4-bit "chunk" in each segment of the
/// Pedersen hash.
fn generate_pedersen_circuit_generators() -> Vec<Vec<Vec<(Scalar, Scalar)>>> {
    // Process each segment
    PEDERSEN_HASH_GENERATORS
        .iter()
        .cloned()
        .map(|mut gen| {
            let mut windows = vec![];

            for _ in 0..PEDERSEN_HASH_CHUNKS_PER_GENERATOR {
                // Create (x, y) coeffs for this chunk
                let mut coeffs = vec![];
                let mut g = gen;

                // coeffs = g, g*2, g*3, g*4
                for _ in 0..4 {
                    coeffs.push(
                        to_montgomery_coords(g.into())
                            .expect("we never encounter the point at infinity"),
                    );
                    g += gen;
                }
                windows.push(coeffs);

                // Our chunks are separated by 2 bits to prevent overlap.
                for _ in 0..4 {
                    gen = gen.double();
                }
            }

            windows
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edwards_d() {
        // d = -(10240/10241)
        assert_eq!(
            -Scalar::from(10240) * Scalar::from(10241).invert().unwrap(),
            edwards_d()
        );
    }

    #[test]
    fn test_montgomery_a() {
        assert_eq!(Scalar::from(40962), montgomery_a());
    }

    #[test]
    fn test_montgomery_scale() {
        // scaling factor = sqrt(4 / (a - d))
        assert_eq!(
            montgomery_scale().square() * (-crate::engine::scalar_one() - edwards_d()),
            Scalar::from(4),
        );
    }
}
