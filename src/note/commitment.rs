use core::iter;
use bitvec::{array::BitArray, order::Lsb0};
use group::ff::PrimeField;
use subtle::{ConstantTimeEq, CtOption};
use crate::{
    pedersen_hash::Personalization,
    spec::{extract_p, windowed_pedersen_commit}
};

/// The trapdoor for a Sapling note commitment.
#[derive(Clone, Debug)]
pub struct NoteCommitTrapdoor(pub jubjub::Fr);

/// A commitment to a note.
#[derive(Clone, Debug)]
pub struct NoteCommitment(pub jubjub::SubgroupPoint);

impl NoteCommitment
{
    /// $NoteCommit^Sapling$.
    ///
    /// Defined in [Zcash Protocol Spec § 5.4.8.2: Windowed Pedersen commitments][concretewindowedcommit].
    ///
    /// [concretewindowedcommit]: https://zips.z.cash/protocol/protocol.pdf#concretewindowedcommit
    pub fn derive(
        g_d: [u8; 32],
        pk_d: [u8; 32],
        account: u64,
        value: u64,
        symbol: u64,
        code: u64,
        rcm: NoteCommitTrapdoor,
    ) -> Self
    {
        NoteCommitment(windowed_pedersen_commit(
            Personalization::NoteCommitment,
            iter::empty()
                .chain(BitArray::<_, Lsb0>::new(account.to_le_bytes()).iter().by_vals())
                .chain(BitArray::<_, Lsb0>::new(value.to_le_bytes()).iter().by_vals())
                .chain(BitArray::<_, Lsb0>::new(symbol.to_le_bytes()).iter().by_vals())
                .chain(BitArray::<_, Lsb0>::new(code.to_le_bytes()).iter().by_vals())
                .chain(BitArray::<_, Lsb0>::new(g_d).iter().by_vals())
                .chain(BitArray::<_, Lsb0>::new(pk_d).iter().by_vals()),
            rcm.0,
        ))
    }
}

/// The u-coordinate of the commitment to a note.
#[derive(Copy, Clone, Debug)]
pub struct ExtractedNoteCommitment(pub bls12_381::Scalar);

impl ExtractedNoteCommitment {
    /// Deserialize the extracted note commitment from a byte array.
    ///
    /// This method enforces the [consensus rule][cmucanon] that the byte representation
    /// of cmu MUST be canonical.
    ///
    /// [cmucanon]: https://zips.z.cash/protocol/protocol.pdf#outputencodingandconsensus
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        bls12_381::Scalar::from_repr(*bytes).map(ExtractedNoteCommitment)
    }

    /// Serialize the value commitment to its canonical byte representation.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }
}

impl From<NoteCommitment> for ExtractedNoteCommitment {
    fn from(cm: NoteCommitment) -> Self {
        ExtractedNoteCommitment(extract_p(&cm.0))
    }
}

impl From<&ExtractedNoteCommitment> for [u8; 32] {
    fn from(cmu: &ExtractedNoteCommitment) -> Self {
        cmu.to_bytes()
    }
}

impl ConstantTimeEq for ExtractedNoteCommitment {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for ExtractedNoteCommitment {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for ExtractedNoteCommitment {}
