//! Monetary values within the Sapling shielded pool.
//!
//! Values are represented in three places within the Sapling protocol:
//! - [`NoteValue`], the value of an individual note. It is an unsigned 64-bit integer
//!   (with maximum value [`MAX_NOTE_VALUE`]), and is serialized in a note plaintext.
//! - [`ValueSum`], the sum of note values within a Sapling [`Bundle`]. It is represented
//!   as an `i128` and places an upper bound on the maximum number of notes within a
//!   single [`Bundle`].
//! - `valueBalanceSapling`, which is a signed 63-bit integer. This is represented
//!   by a user-defined type parameter on [`Bundle`], returned by
//!   [`Bundle::value_balance`] and [`SaplingBuilder::value_balance`].
//!
//! If your specific instantiation of the Sapling protocol requires a smaller bound on
//! valid note values (for example, Zcash's `MAX_MONEY` fits into a 51-bit integer), you
//! should enforce this in two ways:
//!
//! - Define your `valueBalanceSapling` type to enforce your valid value range. This can
//!   be checked in its `TryFrom<i64>` implementation.
//! - Define your own "amount" type for note values, and convert it to `NoteValue` prior
//!   to calling [`SaplingBuilder::add_output`].
//!
//! Inside the circuit, note values are constrained to be unsigned 64-bit integers.
//!
//! # Caution!
//!
//! An `i64` is _not_ a signed 64-bit integer! The [Rust documentation] calls `i64` the
//! 64-bit signed integer type, which is true in the sense that its encoding in memory
//! takes up 64 bits. Numerically, however, `i64` is a signed 63-bit integer.
//!
//! Fortunately, users of this crate should never need to construct [`ValueSum`] directly;
//! you should only need to interact with [`NoteValue`] (which can be safely constructed
//! from a `u64`) and `valueBalanceSapling` (which can be represented as an `i64`).
//!
//! [`Bundle`]: crate::transaction::components::sapling::Bundle
//! [`Bundle::value_balance`]: crate::transaction::components::sapling::Bundle::value_balance
//! [`SaplingBuilder::value_balance`]: crate::transaction::components::sapling::builder::SaplingBuilder::value_balance
//! [`SaplingBuilder::add_output`]: crate::transaction::components::sapling::builder::SaplingBuilder::add_output
//! [Rust documentation]: https://doc.rust-lang.org/stable/std/primitive.i64.html

use ff::Field;
use group::GroupEncoding;
use rand::RngCore;
use subtle::CtOption;
use core::iter::Sum;
use core::ops::{Add, AddAssign, Sub, SubAssign};
use core::fmt::{self, Debug};

use crate::constants::{VALUE_COMMITMENT_RANDOMNESS_GENERATOR, VALUE_COMMITMENT_VALUE_GENERATOR};


/// A value operation overflowed.
#[derive(Debug)]
pub struct OverflowError;

impl fmt::Display for OverflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sapling value operation overflowed")
    }
}

impl std::error::Error for OverflowError {}

/// The blinding factor for a [`ValueCommitment`].
#[derive(Clone, Debug)]
pub struct ValueCommitTrapdoor(jubjub::Scalar);

impl ValueCommitTrapdoor {
    /// Generates a new value commitment trapdoor.
    ///
    /// This is public for access by `zcash_proofs`.
    pub fn random(rng: impl RngCore) -> Self {
        ValueCommitTrapdoor(jubjub::Scalar::random(rng))
    }

    /// Returns the inner Jubjub scalar representing this trapdoor.
    ///
    /// This is public for access by `zcash_proofs`.
    pub fn inner(&self) -> jubjub::Scalar {
        self.0
    }

    /// Initializes a sum of `ValueCommitTrapdoor`s to zero.
    pub fn zero() -> Self {
        ValueCommitTrapdoor(jubjub::Scalar::zero())
    }
}

impl Add<&ValueCommitTrapdoor> for ValueCommitTrapdoor {
    type Output = ValueCommitTrapdoor;

    fn add(self, rhs: &Self) -> Self::Output {
        ValueCommitTrapdoor(self.0 + rhs.0)
    }
}

impl AddAssign<&ValueCommitTrapdoor> for ValueCommitTrapdoor {
    fn add_assign(&mut self, rhs: &ValueCommitTrapdoor) {
        self.0 += rhs.0;
    }
}

impl Sub<&ValueCommitTrapdoor> for ValueCommitTrapdoor {
    type Output = ValueCommitTrapdoor;

    fn sub(self, rhs: &Self) -> Self::Output {
        ValueCommitTrapdoor(self.0 - rhs.0)
    }
}

impl SubAssign<&ValueCommitTrapdoor> for ValueCommitTrapdoor {
    fn sub_assign(&mut self, rhs: &ValueCommitTrapdoor) {
        self.0 -= rhs.0;
    }
}

impl<'a> Sum<&'a ValueCommitTrapdoor> for ValueCommitTrapdoor {
    fn sum<I: Iterator<Item = &'a ValueCommitTrapdoor>>(iter: I) -> Self {
        iter.fold(ValueCommitTrapdoor::zero(), |acc, cv| acc + cv)
    }
}

/// A commitment to a [`ValueSum`].
///
/// # Consensus rules
///
/// The Zcash Protocol Spec requires Sapling Spend Descriptions and Output Descriptions to
/// not contain a small order `ValueCommitment`. However, the `ValueCommitment` type as
/// specified (and implemented here) may contain a small order point. In practice, it will
/// not occur:
/// - [`ValueCommitment::derive`] will only produce a small order point if both the given
///   [`NoteValue`] and [`ValueCommitTrapdoor`] are zero. However, the only constructor
///   available for `ValueCommitTrapdoor` is [`ValueCommitTrapdoor::random`], which will
///   produce zero with negligible probability (assuming a non-broken PRNG).
/// - [`ValueCommitment::from_bytes_not_small_order`] enforces this by definition, and is
///   the only constructor that can be used with data received over the network.
#[derive(Clone, Debug)]
pub struct ValueCommitment(jubjub::ExtendedPoint);

impl ValueCommitment {
    /// Derives a `ValueCommitment` by $\mathsf{ValueCommit^{Sapling}}$.
    ///
    /// Defined in [Zcash Protocol Spec § 5.4.8.3: Homomorphic Pedersen commitments (Sapling and Orchard)][concretehomomorphiccommit].
    ///
    /// [concretehomomorphiccommit]: https://zips.z.cash/protocol/protocol.pdf#concretehomomorphiccommit
    pub fn derive(value: u64, rcv: ValueCommitTrapdoor) -> Self {
        let cv = (*VALUE_COMMITMENT_VALUE_GENERATOR * jubjub::Scalar::from(value))
            + (*VALUE_COMMITMENT_RANDOMNESS_GENERATOR * rcv.0);

        ValueCommitment(cv.into())
    }

    /// Returns the inner Jubjub point representing this value commitment.
    ///
    /// This is public for access by `zcash_proofs`.
    pub fn as_inner(&self) -> &jubjub::ExtendedPoint {
        &self.0
    }

    /// Deserializes a value commitment from its byte representation.
    ///
    /// Returns `None` if `bytes` is an invalid representation of a Jubjub point, or the
    /// resulting point is of small order.
    ///
    /// This method can be used to enforce the "not small order" consensus rules defined
    /// in [Zcash Protocol Spec § 4.4: Spend Descriptions][spenddesc] and
    /// [§ 4.5: Output Descriptions][outputdesc].
    ///
    /// [spenddesc]: https://zips.z.cash/protocol/protocol.pdf#spenddesc
    /// [outputdesc]: https://zips.z.cash/protocol/protocol.pdf#outputdesc
    pub fn from_bytes_not_small_order(bytes: &[u8; 32]) -> CtOption<ValueCommitment> {
        jubjub::ExtendedPoint::from_bytes(bytes)
            .and_then(|cv| CtOption::new(ValueCommitment(cv), !cv.is_small_order()))
    }

    /// Serializes this value commitment to its canonical byte representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Initializes a sum of `ValueCommitment`s to zero.
    pub fn zero() -> Self {
        ValueCommitment(jubjub::ExtendedPoint::identity())
    }
}

impl Add<&ValueCommitment> for ValueCommitment {
    type Output = ValueCommitment;

    fn add(self, rhs: &Self) -> Self::Output {
        ValueCommitment(self.0 + rhs.0)
    }
}

impl AddAssign<&ValueCommitment> for ValueCommitment {
    fn add_assign(&mut self, rhs: &ValueCommitment) {
        self.0 += rhs.0;
    }
}

impl Sub<&ValueCommitment> for ValueCommitment {
    type Output = ValueCommitment;

    fn sub(self, rhs: &Self) -> Self::Output {
        ValueCommitment(self.0 - rhs.0)
    }
}

impl SubAssign<&ValueCommitment> for ValueCommitment {
    fn sub_assign(&mut self, rhs: &ValueCommitment) {
        self.0 -= rhs.0;
    }
}

impl Sum<ValueCommitment> for ValueCommitment {
    fn sum<I: Iterator<Item = ValueCommitment>>(iter: I) -> Self {
        iter.fold(ValueCommitment::zero(), |acc, cv| acc + &cv)
    }
}

impl<'a> Sum<&'a ValueCommitment> for ValueCommitment {
    fn sum<I: Iterator<Item = &'a ValueCommitment>>(iter: I) -> Self {
        iter.fold(ValueCommitment::zero(), |acc, cv| acc + cv)
    }
}

#[cfg(test)]
mod tests {
    use super::{ValueCommitTrapdoor, ValueCommitment};
    use group::Curve;
    use jubjub::ExtendedPoint;
    use rand::rngs::OsRng;
    use std::ops::{Add, Sub};

    use ff::PrimeField;
    use jubjub::Fq;
    fn fq_to_bytes(fq: &Fq) -> [u8; 32] {
        let repr = fq.to_repr();
        let mut b = [0u8; 32];
        b.copy_from_slice(repr.as_ref());
        b
    }

    #[test]
    fn test_homomorphic_properties()
    {
        let mut rng = OsRng.clone();
        let rcv = ValueCommitTrapdoor::random(&mut rng);

        // Spend
        let s1 = ValueCommitment::derive(3, rcv.clone());
        let s2 = ValueCommitment::derive(7, rcv.clone());
        let s_sum = s1.clone().add(&s2);

        // Output
        let o1 = ValueCommitment::derive(8, rcv.clone());
        let o2 = ValueCommitment::derive(2, rcv.clone());
        let o_sum = o1.clone().add(&o2);

        let b = s_sum.0.eq(&o_sum.0);
        let x = s_sum.0.add(o_sum.0);

        // Balance
        println!("{:?}", (s1.add(&s2).sub(&o1).sub(&o2)).0.eq(&(s_sum.clone().sub(&o_sum)).0));
        println!("{:?}", b);
        println!("{:?}", x);
    }

    #[test]
    fn test_homomorphic_properties_affine()
    {
        let mut rng = OsRng.clone();
        let rcv = ValueCommitTrapdoor::random(&mut rng);

        // Spend
        let s1 = ValueCommitment::derive(3, rcv.clone()).0.to_affine();
        let s2 = ValueCommitment::derive(7, rcv.clone()).0.to_affine();
        println!("{}", hex::encode(fq_to_bytes(&s1.get_u())));
        println!("{}", hex::encode(fq_to_bytes(&s1.get_v())));
        println!("{}", hex::encode(fq_to_bytes(&s2.get_u())));
        println!("{}", hex::encode(fq_to_bytes(&s2.get_v())));
        let s1 = ExtendedPoint::from(s1);
        let s_sum = s1.clone().add(&s2);

        // Output
        let o1 = ValueCommitment::derive(8, rcv.clone()).0.to_affine();
        let o2 = ValueCommitment::derive(2, rcv.clone()).0.to_affine();
        println!("{}", hex::encode(fq_to_bytes(&o1.get_u())));
        println!("{}", hex::encode(fq_to_bytes(&o1.get_v())));
        println!("{}", hex::encode(fq_to_bytes(&o2.get_u())));
        println!("{}", hex::encode(fq_to_bytes(&o2.get_v())));
        let o1 = ExtendedPoint::from(o1);
        let o_sum = o1.clone().add(&o2);

        let b = s_sum.eq(&o_sum);
        //let x = s_sum.add(o_sum);

        // Balance
        //println!("{:?}", (s1.add(&s2).sub(&o1).sub(&o2)).0.eq(&(s_sum.clone().sub(&o_sum)).0));
        println!("{:?}", b);
        //println!("{:?}", x);
    }

    #[test]
    fn test_homomorphic_properties2()
    {
        let mut rng = OsRng.clone();
        let rcv = ValueCommitTrapdoor::random(&mut rng);

        // Spend
        let s1 = ValueCommitment::derive(3, rcv.clone()).0;
        let s2 = ValueCommitment::derive(7, rcv.clone()).0;
        let s3 = ValueCommitment::derive(0, rcv.clone()).0;
        let s4 = ValueCommitment::derive(0, rcv.clone()).0;
        let s_sum = s1.add(&s2).add(&s3).add(&s4);

        // Output
        let o1 = ValueCommitment::derive(3, rcv.clone()).0;
        let o2 = ValueCommitment::derive(2, rcv.clone()).0;
        let o3 = ValueCommitment::derive(1, rcv.clone()).0;
        let o4 = ValueCommitment::derive(4, rcv.clone()).0;
        let o_sum = o1.add(&o2).add(&o3).add(&o4);

        let b = s_sum.eq(&o_sum);

        // Balance
        //println!("{:?}", (s1.add(&s2).sub(&o1).sub(&o2)).0.eq(&(s_sum.clone().sub(&o_sum)).0));
        println!("{:?}", b);
        //println!("{:?}", x);
    }
}
