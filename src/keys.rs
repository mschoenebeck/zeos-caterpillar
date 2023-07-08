//! Sapling key components.
//!
//! Implements [section 4.2.2] of the Zcash Protocol Specification.
//!
//! [section 4.2.2]: https://zips.z.cash/protocol/protocol.pdf#saplingkeycomponents

use std::io::{self, Read, Write};
use rand_core::RngCore;
use serde::{Serialize, Serializer, Deserialize, ser::SerializeStruct, Deserializer, de::Visitor, de::SeqAccess, de::MapAccess, de};
use std::fmt;
use crate::{
    address::Address,
    constants::{PROOF_GENERATION_KEY_GENERATOR, SPENDING_KEY_GENERATOR},
    note_encryption::KDF_SAPLING_PERSONALIZATION,
    spec::{
        crh_ivk, diversify_hash, ka_sapling_agree, ka_sapling_agree_prepared,
        ka_sapling_derive_public, ka_sapling_derive_public_subgroup_prepared, PreparedBase,
        PreparedBaseSubgroup, PreparedScalar,
    },
};

use aes::Aes256;
use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use ff::PrimeField;
use fpe::ff1::{BinaryNumeralString, FF1};
use group::{Curve, Group, GroupEncoding};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crate::note_encryption::EphemeralKeyBytes;

pub const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";

/// PRF^expand(sk, t) := BLAKE2b-512("Zcash_ExpandSeed", sk || t)
pub fn prf_expand(sk: &[u8], t: &[u8]) -> Blake2bHash {
    prf_expand_vec(sk, &[t])
}

pub fn prf_expand_vec(sk: &[u8], ts: &[&[u8]]) -> Blake2bHash {
    let mut h = Blake2bParams::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state();
    h.update(sk);
    for t in ts {
        h.update(t);
    }
    h.finalize()
}

/// Errors that can occur in the decoding of Sapling spending keys.
#[derive(Debug)]
pub enum DecodingError {
    /// The length of the byte slice provided for decoding was incorrect.
    LengthInvalid { expected: usize, actual: usize },
    /// Could not decode the `ask` bytes to a jubjub field element.
    InvalidAsk,
    /// Could not decode the `nsk` bytes to a jubjub field element.
    InvalidNsk,
}

/// An outgoing viewing key
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutgoingViewingKey(pub [u8; 32]);

impl From<[u8; 32]> for OutgoingViewingKey {
    fn from(ovk: [u8; 32]) -> Self {
        OutgoingViewingKey(ovk)
    }
}

impl AsRef<[u8; 32]> for OutgoingViewingKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A Sapling expanded spending key
#[derive(Clone)]
pub struct SpendingKey {
    pub dk: DiversifierKey,
    pub ask: jubjub::Fr,
    pub nsk: jubjub::Fr,
    pub ovk: OutgoingViewingKey,
}

impl SpendingKey {
    pub fn from_seed(seed: &[u8]) -> Self {
        let dk = DiversifierKey::master(seed);
        let ask = jubjub::Fr::from_bytes_wide(prf_expand(seed, &[0x00]).as_array());
        let nsk = jubjub::Fr::from_bytes_wide(prf_expand(seed, &[0x01]).as_array());
        let mut ovk = OutgoingViewingKey([0u8; 32]);
        ovk.0.copy_from_slice(&prf_expand(seed, &[0x02]).as_bytes()[..32]);
        SpendingKey { dk, ask, nsk, ovk }
    }

    /// Generates a random spending key.
    pub fn random(rng: &mut impl RngCore) -> Self {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        SpendingKey::from_seed(&bytes)
    }

    pub fn proof_generation_key(&self) -> ProofGenerationKey {
        ProofGenerationKey {
            ak: SPENDING_KEY_GENERATOR * self.ask,
            nsk: self.nsk,
        }
    }

    /// Decodes the expanded spending key from its serialized representation
    /// as part of the encoding of the extended spending key as defined in
    /// [ZIP 32](https://zips.z.cash/zip-0032)
    pub fn from_bytes(b: &[u8]) -> Result<Self, DecodingError> {
        if b.len() != 4 * 32 {
            return Err(DecodingError::LengthInvalid {
                expected: 4 * 32,
                actual: b.len(),
            });
        }

        let dk = DiversifierKey(b[0..32].try_into().unwrap());
        let ask = Option::from(jubjub::Fr::from_repr(b[32..64].try_into().unwrap()))
            .ok_or(DecodingError::InvalidAsk)?;
        let nsk = Option::from(jubjub::Fr::from_repr(b[64..96].try_into().unwrap()))
            .ok_or(DecodingError::InvalidNsk)?;
        let ovk = OutgoingViewingKey(b[96..128].try_into().unwrap());

        Ok(SpendingKey { dk, ask, nsk, ovk })
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut repr = [0u8; 4 * 32];
        reader.read_exact(repr.as_mut())?;
        Self::from_bytes(&repr).map_err(|e| match e {
            DecodingError::InvalidAsk => {
                io::Error::new(io::ErrorKind::InvalidData, "ask not in field")
            }
            DecodingError::InvalidNsk => {
                io::Error::new(io::ErrorKind::InvalidData, "nsk not in field")
            }
            DecodingError::LengthInvalid { .. } => unreachable!(),
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.to_bytes())
    }

    /// Encodes the expanded spending key to the its seralized representation
    /// as part of the encoding of the extended spending key as defined in
    /// [ZIP 32](https://zips.z.cash/zip-0032)
    pub fn to_bytes(&self) -> [u8; 4 * 32] {
        let mut result = [0u8; 4 * 32];
        result[0..32].copy_from_slice(&self.dk.0);
        result[32..64].copy_from_slice(&self.ask.to_repr());
        result[64..96].copy_from_slice(&self.nsk.to_repr());
        result[96..128].copy_from_slice(&self.ovk.0);
        result
    }
}

#[derive(Clone)]
pub struct ProofGenerationKey {
    pub ak: jubjub::SubgroupPoint,
    pub nsk: jubjub::Fr,
}

/// A key used to derive the nullifier for a Sapling note.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NullifierDerivingKey(pub jubjub::SubgroupPoint);

/// A Sapling key that provides the capability to view incoming and outgoing transactions.
#[derive(Debug)]
pub struct FullViewingKey {
    //pub vk: ViewingKey,
    pub dk: DiversifierKey,
    pub ak: jubjub::SubgroupPoint,
    pub nk: NullifierDerivingKey,
    pub ovk: OutgoingViewingKey,
}

impl Clone for FullViewingKey {
    fn clone(&self) -> Self {
        FullViewingKey {
            dk: self.dk,
            ak: self.ak,
            nk: self.nk,
            ovk: self.ovk,
        }
    }
}

impl FullViewingKey {
    pub fn from_spending_key(sk: &SpendingKey) -> Self {
        FullViewingKey {
            dk:  sk.dk,
            ak: SPENDING_KEY_GENERATOR * sk.ask,
            nk: NullifierDerivingKey(PROOF_GENERATION_KEY_GENERATOR * sk.nsk),
            ovk: sk.ovk,
        }
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {

        let mut dk = [0u8; 32];
        reader.read_exact(&mut dk)?;

        let ak = {
            let mut buf = [0u8; 32];
            reader.read_exact(&mut buf)?;
            jubjub::SubgroupPoint::from_bytes(&buf).and_then(|p| CtOption::new(p, !p.is_identity()))
        };
        let nk = {
            let mut buf = [0u8; 32];
            reader.read_exact(&mut buf)?;
            jubjub::SubgroupPoint::from_bytes(&buf)
        };
        if ak.is_none().into() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ak not of prime order",
            ));
        }
        if nk.is_none().into() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nk not in prime-order subgroup",
            ));
        }
        let ak = ak.unwrap();
        let nk = NullifierDerivingKey(nk.unwrap());

        let mut ovk = [0u8; 32];
        reader.read_exact(&mut ovk)?;

        Ok(FullViewingKey {
            dk: DiversifierKey(dk),
            ak,
            nk,
            ovk: OutgoingViewingKey(ovk),
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.dk.0)?;
        writer.write_all(&self.ak.to_bytes())?;
        writer.write_all(&self.nk.0.to_bytes())?;
        writer.write_all(&self.ovk.0)?;

        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; 4 * 32] {
        let mut result = [0u8; 4 * 32];
        self.write(&mut result[..])
            .expect("should be able to serialize a FullViewingKey");
        result
    }

    pub fn ivk(&self) -> IncomingViewingKey {
        IncomingViewingKey::from_fvk(self)
    }

    pub fn to_payment_address(&self, diversifier: Diversifier) -> Option<Address> {
        self.ivk().to_payment_address(diversifier)
    }

    /// Attempts to produce a valid payment address for the given diversifier index.
    ///
    /// Returns `None` if the diversifier index does not produce a valid diversifier for
    /// this `DiversifiableFullViewingKey`.
    pub fn address(&self, j: DiversifierIndex) -> Option<Address> {
        self.dk.diversifier(j)
            .and_then(|d_j| self.to_payment_address(d_j))
    }

    /// Finds the next valid payment address starting from the given diversifier index.
    ///
    /// This searches the diversifier space starting at `j` and incrementing, to find an
    /// index which will produce a valid diversifier (a 50% probability for each index).
    ///
    /// Returns the index at which the valid diversifier was found along with the payment
    /// address constructed using that diversifier, or `None` if the maximum index was
    /// reached and no valid diversifier was found.
    pub fn find_address(&self, j: DiversifierIndex) -> Option<(DiversifierIndex, Address)> {
        let (j, d_j) = self.dk.find_diversifier(j)?;
        self.to_payment_address(d_j).map(|addr| (j, addr))
    }

    /// Returns the payment address corresponding to the smallest valid diversifier index,
    /// along with that index.
    pub fn default_address(&self) -> (DiversifierIndex, Address) {
        // This unwrap is safe, if you have to search the 2^88 space of
        // diversifiers it'll never return anyway.
        self.find_address(DiversifierIndex::new()).unwrap()
    }

    /// Returns the payment address corresponding to the specified diversifier, if any.
    ///
    /// In general, it is preferable to use `find_address` instead, but this method is
    /// useful in some cases for matching keys to existing payment addresses.
    pub fn diversified_address(&self, diversifier: Diversifier) -> Option<Address> {
        self.to_payment_address(diversifier)
    }
}

/// A key that provides the capability to detect and decrypt incoming notes from the block
/// chain, without being able to spend the notes or detect when they are spent.
///
/// This key is useful in situations where you only need the capability to detect inbound
/// payments, such as merchant terminals.
///
/// This key is not suitable for use on its own in a wallet, as it cannot maintain
/// accurate balance. You should use a [`FullViewingKey`] instead.
///
/// Defined in [Zcash Protocol Spec § 5.6.4.3: Orchard Raw Incoming Viewing Keys][orchardinviewingkeyencoding].
///
/// [orchardinviewingkeyencoding]: https://zips.z.cash/protocol/nu5.pdf#orchardinviewingkeyencoding
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomingViewingKey {
    dk: DiversifierKey,
    ivk: jubjub::Fr,
}

impl IncomingViewingKey {
    /// Helper method.
    pub fn from_fvk(fvk: &FullViewingKey) -> Self {
        IncomingViewingKey {
            dk: fvk.dk,
            ivk: crh_ivk(fvk.ak.to_bytes(), fvk.nk.0.to_bytes()),
        }
    }

    /// Serializes an Orchard incoming viewing key to its raw encoding as specified in [Zcash Protocol Spec § 5.6.4.3: Orchard Raw Incoming Viewing Keys][orchardrawinviewingkeys]
    ///
    /// [orchardrawinviewingkeys]: https://zips.z.cash/protocol/protocol.pdf#orchardinviewingkeyencoding
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[..32].copy_from_slice(&self.dk.0);
        result[32..].copy_from_slice(&self.ivk.to_repr());
        result
    }

    /// Parses an Orchard incoming viewing key from its raw encoding.
    pub fn from_bytes(bytes: &[u8; 64]) -> CtOption<Self> {
        jubjub::Fr::from_repr(bytes[32..].try_into().unwrap()).and_then(|ivk| {
            CtOption::new(IncomingViewingKey {
                dk: DiversifierKey(bytes[..32].try_into().unwrap()),
                ivk
            }, 1.into())
        })
    }

    /// Returns the payment address for this key corresponding to the given diversifier.
    pub fn to_payment_address(&self, d: Diversifier) -> Option<Address> {
        let prepared_ivk = PreparedIncomingViewingKey::new(self);
        DiversifiedTransmissionKey::derive(&prepared_ivk, &d)
            .and_then(|pk_d| Address::from_parts(d, pk_d))
    }
}

impl Serialize for IncomingViewingKey
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 3 is the number of fields in the struct.
        let mut state = serializer.serialize_struct("IncomingViewingKey", 2)?;
        state.serialize_field("dk", &hex::encode(self.dk.0))?;
        state.serialize_field("ivk", &hex::encode(self.ivk.to_repr()))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for IncomingViewingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field { Dk, Ivk }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`dk` or `ivk`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "dk" => Ok(Field::Dk),
                            "ivk" => Ok(Field::Ivk),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct IncomingViewingKeyVisitor;

        impl<'de> Visitor<'de> for IncomingViewingKeyVisitor {
            type Value = IncomingViewingKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct IncomingViewingKey")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<IncomingViewingKey, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let dk: String = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let ivk: String = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let dk = hex::decode(dk).unwrap()[0..32].try_into().unwrap();
                let ivk = hex::decode(ivk).unwrap()[0..32].try_into().unwrap();
                Ok(IncomingViewingKey{
                    dk: DiversifierKey::from_bytes(dk),
                    ivk: jubjub::Fr::from_repr(ivk).unwrap()
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<IncomingViewingKey, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut dk = None;
                let mut ivk = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Dk => {
                            if dk.is_some() {
                                return Err(de::Error::duplicate_field("dk"));
                            }
                            dk = Some(map.next_value()?);
                        }
                        Field::Ivk => {
                            if ivk.is_some() {
                                return Err(de::Error::duplicate_field("ivk"));
                            }
                            ivk = Some(map.next_value()?);
                        }
                    }
                }
                let dk: String = dk.ok_or_else(|| de::Error::missing_field("dk"))?;
                let ivk: String = ivk.ok_or_else(|| de::Error::missing_field("ivk"))?;
                let dk = hex::decode(dk).unwrap()[0..32].try_into().unwrap();
                let ivk = hex::decode(ivk).unwrap()[0..32].try_into().unwrap();
                Ok(IncomingViewingKey{
                    dk: DiversifierKey::from_bytes(dk),
                    ivk: jubjub::Fr::from_repr(ivk).unwrap()
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["dk", "ivk"];
        deserializer.deserialize_struct("IncomingViewingKey", FIELDS, IncomingViewingKeyVisitor)
    }
}

/// A Sapling incoming viewing key that has been precomputed for trial decryption.
#[derive(Clone, Debug)]
pub struct PreparedIncomingViewingKey(PreparedScalar);

impl memuse::DynamicUsage for PreparedIncomingViewingKey {
    fn dynamic_usage(&self) -> usize {
        self.0.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        self.0.dynamic_usage_bounds()
    }
}

impl PreparedIncomingViewingKey {
    /// Performs the necessary precomputations to use a `SaplingIvk` for note decryption.
    pub fn new(ivk: &IncomingViewingKey) -> Self {
        Self(PreparedScalar::new(&ivk.ivk))
    }
}

// For deterministic address derivation
// see: https://zips.z.cash/zip-0032
// and: https://github.com/zcash/librustzcash/blob/main/zcash_primitives/src/zip32/sapling.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiversifierIndex(pub [u8; 11]);

impl Default for DiversifierIndex {
    fn default() -> Self {
        DiversifierIndex::new()
    }
}

impl From<u32> for DiversifierIndex {
    fn from(i: u32) -> Self {
        u64::from(i).into()
    }
}

impl From<u64> for DiversifierIndex {
    fn from(i: u64) -> Self {
        let mut result = DiversifierIndex([0; 11]);
        result.0[..8].copy_from_slice(&i.to_le_bytes());
        result
    }
}

impl TryFrom<DiversifierIndex> for u32 {
    type Error = std::num::TryFromIntError;

    fn try_from(di: DiversifierIndex) -> Result<u32, Self::Error> {
        let mut u128_bytes = [0u8; 16];
        u128_bytes[0..11].copy_from_slice(&di.0[..]);
        u128::from_le_bytes(u128_bytes).try_into()
    }
}

impl TryFrom<DiversifierIndex> for u64 {
    type Error = std::num::TryFromIntError;

    fn try_from(di: DiversifierIndex) -> Result<u64, Self::Error> {
        let mut u128_bytes = [0u8; 16];
        u128_bytes[0..11].copy_from_slice(&di.0[..]);
        u128::from_le_bytes(u128_bytes).try_into()
    }
}

impl DiversifierIndex {
    pub fn new() -> Self {
        DiversifierIndex([0; 11])
    }

    pub fn increment(&mut self) -> Result<(), ()> {
        for k in 0..11 {
            self.0[k] = self.0[k].wrapping_add(1);
            if self.0[k] != 0 {
                // No overflow
                return Ok(());
            }
        }
        // Overflow
        Err(())
    }
}

/// A key used to derive diversifiers for a particular child key
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiversifierKey([u8; 32]);

impl DiversifierKey {
    pub fn master(sk_m: &[u8]) -> Self {
        let mut dk_m = [0u8; 32];
        dk_m.copy_from_slice(&prf_expand(sk_m, &[0x10]).as_bytes()[..32]);
        DiversifierKey(dk_m)
    }

    /// Constructs the diversifier key from its constituent bytes.
    pub fn from_bytes(key: [u8; 32]) -> Self {
        DiversifierKey(key)
    }

    /// Returns the byte representation of the diversifier key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[allow(dead_code)]
    fn derive_child(&self, i_l: &[u8]) -> Self {
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&prf_expand_vec(i_l, &[&[0x16], &self.0]).as_bytes()[..32]);
        DiversifierKey(dk)
    }

    fn try_diversifier_internal(ff: &FF1<Aes256>, j: DiversifierIndex) -> Option<Diversifier> {
        // Generate d_j
        let enc = ff
            .encrypt(&[], &BinaryNumeralString::from_bytes_le(&j.0[..]))
            .unwrap();
        let mut d_j = [0; 11];
        d_j.copy_from_slice(&enc.to_bytes_le());
        let diversifier = Diversifier(d_j);

        // validate that the generated diversifier maps to a jubjub subgroup point.
        diversifier.g_d().map(|_| diversifier)
    }

    /// Attempts to produce a diversifier at the given index. Returns None
    /// if the index does not produce a valid diversifier.
    pub fn diversifier(&self, j: DiversifierIndex) -> Option<Diversifier> {
        let ff = FF1::<Aes256>::new(&self.0, 2).unwrap();
        Self::try_diversifier_internal(&ff, j)
    }

    /// Returns the diversifier index to which this key maps the given diversifier.
    ///
    /// This method cannot be used to verify whether the diversifier was originally
    /// generated with this diversifier key, because all valid diversifiers can be
    /// produced by all diversifier keys.
    pub fn diversifier_index(&self, d: &Diversifier) -> DiversifierIndex {
        let ff = FF1::<Aes256>::new(&self.0, 2).unwrap();
        let dec = ff
            .decrypt(&[], &BinaryNumeralString::from_bytes_le(&d.0[..]))
            .unwrap();
        let mut j = DiversifierIndex::new();
        j.0.copy_from_slice(&dec.to_bytes_le());
        j
    }

    /// Returns the first index starting from j that generates a valid
    /// diversifier, along with the corresponding diversifier. Returns
    /// `None` if the diversifier space contains no valid diversifiers
    /// at or above the specified diversifier index.
    pub fn find_diversifier(
        &self,
        mut j: DiversifierIndex,
    ) -> Option<(DiversifierIndex, Diversifier)> {
        let ff = FF1::<Aes256>::new(&self.0, 2).unwrap();
        loop {
            match Self::try_diversifier_internal(&ff, j) {
                Some(d_j) => return Some((j, d_j)),
                None => {
                    if j.increment().is_err() {
                        return None;
                    }
                }
            }
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Diversifier(pub [u8; 11]);

impl Diversifier {
    pub fn g_d(&self) -> Option<jubjub::SubgroupPoint> {
        diversify_hash(&self.0)
    }

    /// Reads a diversifier from a byte array.
    pub fn from_bytes(d: [u8; 11]) -> Self {
        Diversifier(d)
    }

    /// Returns the byte array corresponding to this diversifier.
    pub fn as_array(&self) -> &[u8; 11] {
        &self.0
    }
}

/// The diversified transmission key for a given payment address.
///
/// Defined in [Zcash Protocol Spec § 4.2.2: Sapling Key Components][saplingkeycomponents].
///
/// Note that this type is allowed to be the identity in the protocol, but we reject this
/// in [`PaymentAddress::from_parts`].
///
/// [saplingkeycomponents]: https://zips.z.cash/protocol/protocol.pdf#saplingkeycomponents
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiversifiedTransmissionKey(jubjub::SubgroupPoint);

impl DiversifiedTransmissionKey {
    /// Defined in [Zcash Protocol Spec § 4.2.2: Sapling Key Components][saplingkeycomponents].
    ///
    /// Returns `None` if `d` is an invalid diversifier.
    ///
    /// [saplingkeycomponents]: https://zips.z.cash/protocol/protocol.pdf#saplingkeycomponents
    pub(crate) fn derive(ivk: &PreparedIncomingViewingKey, d: &Diversifier) -> Option<Self> {
        d.g_d()
            .map(PreparedBaseSubgroup::new)
            .map(|g_d| ka_sapling_derive_public_subgroup_prepared(&ivk.0, &g_d))
            .map(DiversifiedTransmissionKey)
    }

    /// $abst_J(bytes)$
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        jubjub::SubgroupPoint::from_bytes(bytes).map(DiversifiedTransmissionKey)
    }

    /// $repr_J(self)$
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Returns true if this is the identity.
    pub(crate) fn is_identity(&self) -> bool {
        self.0.is_identity().into()
    }

    /// Exposes the inner Jubjub point.
    ///
    /// This API is exposed for `zcash_proof` usage, and will be removed when this type is
    /// refactored into the `sapling-crypto` crate.
    pub fn inner(&self) -> jubjub::SubgroupPoint {
        self.0
    }
}

impl ConditionallySelectable for DiversifiedTransmissionKey {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        DiversifiedTransmissionKey(jubjub::SubgroupPoint::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

/// An ephemeral secret key used to encrypt an output note on-chain.
///
/// `esk` is "ephemeral" in the sense that each secret key is only used once. In
/// practice, `esk` is derived deterministically from the note that it is encrypting.
///
/// $\mathsf{KA}^\mathsf{Sapling}.\mathsf{Private} := \mathbb{F}_{r_J}$
///
/// Defined in [section 5.4.5.3: Sapling Key Agreement][concretesaplingkeyagreement].
///
/// [concretesaplingkeyagreement]: https://zips.z.cash/protocol/protocol.pdf#concretesaplingkeyagreement
#[derive(Debug)]
pub struct EphemeralSecretKey(pub(crate) jubjub::Scalar);

impl ConstantTimeEq for EphemeralSecretKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl EphemeralSecretKey {
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        jubjub::Scalar::from_bytes(bytes).map(EphemeralSecretKey)
    }

    pub(crate) fn derive_public(&self, g_d: jubjub::ExtendedPoint) -> EphemeralPublicKey {
        EphemeralPublicKey(ka_sapling_derive_public(&self.0, &g_d))
    }

    pub(crate) fn agree(&self, pk_d: &DiversifiedTransmissionKey) -> SharedSecret {
        SharedSecret(ka_sapling_agree(&self.0, &pk_d.0.into()))
    }
}

/// An ephemeral public key used to encrypt an output note on-chain.
///
/// `epk` is "ephemeral" in the sense that each public key is only used once. In practice,
/// `epk` is derived deterministically from the note that it is encrypting.
///
/// $\mathsf{KA}^\mathsf{Sapling}.\mathsf{Public} := \mathbb{J}$
///
/// Defined in [section 5.4.5.3: Sapling Key Agreement][concretesaplingkeyagreement].
///
/// [concretesaplingkeyagreement]: https://zips.z.cash/protocol/protocol.pdf#concretesaplingkeyagreement
#[derive(Debug)]
pub struct EphemeralPublicKey(jubjub::ExtendedPoint);

impl EphemeralPublicKey
{
    #[allow(dead_code)]
    pub(crate) fn from_affine(epk: jubjub::AffinePoint) -> Self {
        EphemeralPublicKey(epk.into())
    }

    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        jubjub::ExtendedPoint::from_bytes(bytes).map(EphemeralPublicKey)
    }

    pub(crate) fn to_bytes(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.0.to_bytes())
    }
}

/// A Sapling ephemeral public key that has been precomputed for trial decryption.
#[derive(Clone, Debug)]
pub struct PreparedEphemeralPublicKey(PreparedBase);

impl PreparedEphemeralPublicKey {
    pub(crate) fn new(epk: EphemeralPublicKey) -> Self {
        PreparedEphemeralPublicKey(PreparedBase::new(epk.0))
    }

    pub(crate) fn agree(&self, ivk: &PreparedIncomingViewingKey) -> SharedSecret {
        SharedSecret(ka_sapling_agree_prepared(&ivk.0, &self.0))
    }
}

/// $\mathsf{KA}^\mathsf{Sapling}.\mathsf{SharedSecret} := \mathbb{J}^{(r)}$
///
/// Defined in [section 5.4.5.3: Sapling Key Agreement][concretesaplingkeyagreement].
///
/// [concretesaplingkeyagreement]: https://zips.z.cash/protocol/protocol.pdf#concretesaplingkeyagreement
#[derive(Debug)]
pub struct SharedSecret(jubjub::SubgroupPoint);

impl SharedSecret
{
    /// Defined in [Zcash Protocol Spec § 5.4.5.4: Sapling Key Agreement][concretesaplingkdf].
    ///
    /// [concretesaplingkdf]: https://zips.z.cash/protocol/protocol.pdf#concretesaplingkdf
    pub(crate) fn kdf_sapling(self, ephemeral_key: &EphemeralKeyBytes) -> Blake2bHash {
        Self::kdf_sapling_inner(
            jubjub::ExtendedPoint::from(self.0).to_affine(),
            ephemeral_key,
        )
    }

    /// Only for direct use in batched note encryption.
    pub(crate) fn kdf_sapling_inner(
        secret: jubjub::AffinePoint,
        ephemeral_key: &EphemeralKeyBytes,
    ) -> Blake2bHash {
        Blake2bParams::new()
            .hash_length(32)
            .personal(KDF_SAPLING_PERSONALIZATION)
            .to_state()
            .update(&secret.to_bytes())
            .update(ephemeral_key.as_ref())
            .finalize()
    }
}

#[cfg(test)]
mod tests {
    use group::{Group, GroupEncoding};

    use super::{FullViewingKey, DiversifierIndex, SpendingKey};
    use crate::{constants::SPENDING_KEY_GENERATOR, keys::IncomingViewingKey};

    #[test]
    fn ak_must_be_prime_order() {
        let mut buf = [0; 96];
        let identity = jubjub::SubgroupPoint::identity();

        // Set both ak and nk to the identity.
        buf[0..32].copy_from_slice(&identity.to_bytes());
        buf[32..64].copy_from_slice(&identity.to_bytes());

        // ak is not allowed to be the identity.
        assert_eq!(
            FullViewingKey::read(&buf[..]).unwrap_err().to_string(),
            "ak not of prime order"
        );

        // Set ak to a basepoint.
        let basepoint = SPENDING_KEY_GENERATOR;
        buf[0..32].copy_from_slice(&basepoint.to_bytes());

        // nk is allowed to be the identity.
        assert!(FullViewingKey::read(&buf[..]).is_ok());
    }

    #[test]
    fn derive_addresses()
    {
        let sk_alice = SpendingKey::from_seed(b"This is Alice seed string! Usually this is just a listing of words. Here we just use sentences.");
        let fvk_alice = FullViewingKey::from_spending_key(&sk_alice);

        let mut i = 0;
        let mut d = DiversifierIndex::from(0u64);
        while i < 100
        {
            let a;
            (d, a) = fvk_alice.find_address(d).unwrap();
            let du: u64 = d.try_into().unwrap();
            println!("{}: {:02X?}", du, a.to_bytes());
            d.increment().unwrap();
            i += 1;
        }
    }

    #[test]
    fn test_ivk_json_serde()
    {
        let sk = SpendingKey::from_seed(b"This is Alice seed string! Usually this is just a listing of words. Here we just use sentences.");
        let fvk = FullViewingKey::from_spending_key(&sk);
        let ivk = IncomingViewingKey::from_fvk(&fvk);

        let encoded = serde_json::to_string(&ivk).unwrap();
        println!("{}", encoded);
        let decoded: IncomingViewingKey = serde_json::from_str(&encoded).unwrap();
        assert_eq!(ivk.to_bytes(), decoded.to_bytes());
    }
}
