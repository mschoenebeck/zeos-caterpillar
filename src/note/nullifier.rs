use core::iter;
use rand_core::RngCore;
use bitvec::{array::BitArray, order::Lsb0};
use subtle::{ConstantTimeEq, CtOption};
use group::{ff::PrimeField, GroupEncoding};
use super::NoteCommitment;
use crate::{
    keys::NullifierDerivingKey,
    pedersen_hash::{pedersen_hash, Personalization},
    spec::{mixing_pedersen_hash, extract_p},
};

/// Typesafe wrapper for nullifier values.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Nullifier(pub jubjub::SubgroupPoint);

impl Nullifier
{
    pub fn derive(
        nk: &NullifierDerivingKey,
        cm: NoteCommitment,
        position: u64,
        //rho: ExtractedNullifier
    ) -> Self
    {
        let rho_mix = mixing_pedersen_hash(cm.0, position);
        Nullifier(pedersen_hash(
            Personalization::Nullifier,
            iter::empty()
                .chain(BitArray::<_, Lsb0>::new(nk.0.to_bytes()).iter().by_vals())
                .chain(BitArray::<_, Lsb0>::new(rho_mix.to_bytes()).iter().by_vals()),
                //.chain(BitArray::<_, Lsb0>::new(rho.to_bytes()).iter().by_vals())
        ))
    }

    pub fn dummy(rng: &mut impl RngCore) -> Self {
        let bits: Vec<bool> = (0..32).map(|_| rng.next_u64() % 2 == 1).collect();
        Nullifier(pedersen_hash(Personalization::Nullifier, bits))
    }

    pub fn extract(&self) -> ExtractedNullifier
    {
        ExtractedNullifier(extract_p(&self.0))
    }
}

/// The u-coordinate of the nullifier to a note.
#[derive(Copy, Clone, Debug)]
pub struct ExtractedNullifier(pub bls12_381::Scalar);

impl ExtractedNullifier {
    /// Deserialize the extracted nullifier from a byte array.
    ///
    /// This method enforces the [consensus rule][cmucanon] that the byte representation
    /// of cmu MUST be canonical.
    ///
    /// [cmucanon]: https://zips.z.cash/protocol/protocol.pdf#outputencodingandconsensus
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        bls12_381::Scalar::from_repr(*bytes).map(ExtractedNullifier)
    }

    /// Serialize the extracted nullifier to its canonical byte representation.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }
}

impl From<Nullifier> for ExtractedNullifier {
    fn from(nf: Nullifier) -> Self {
        ExtractedNullifier(extract_p(&nf.0))
    }
}

impl From<&ExtractedNullifier> for [u8; 32] {
    fn from(nfu: &ExtractedNullifier) -> Self {
        nfu.to_bytes()
    }
}

impl ConstantTimeEq for ExtractedNullifier {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for ExtractedNullifier {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for ExtractedNullifier {}
