use bellman::groth16::{Proof, VerifyingKey};
use crate::engine::{Bls12, G1Affine, G2Affine};
use serde::{Serialize, Deserialize, Serializer, Deserializer, de::Visitor, de};
use crate::eosio::{Asset, Name, PackedAction, Symbol};
use std::fmt;
use std::convert::TryFrom;
use std::error::Error;

#[derive(Clone, Debug, PartialEq)]
pub struct ScalarBytes(pub [u8; 32]);

impl ScalarBytes
{
    pub fn to_string(&self) -> String
    {
        hex::encode(self.0)
    }

    pub fn from_string(s: &str) -> Result<Self, String>
    {
        // 64 hex chars -> 32 bytes
        if s.len() != 64 {
            return Err(format!("invalid hex length: expected 64, got {}", s.len()));
        }
        let v = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
        let arr: [u8; 32] = v.try_into().map_err(|_| "invalid byte length".to_string())?;
        Ok(ScalarBytes(arr))
    }
}

// serde_json traits
impl Serialize for ScalarBytes
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>
    {
        serializer.serialize_str(&self.to_string())
    }
}
struct ScalarBytesVisitor;
impl<'de> Visitor<'de> for ScalarBytesVisitor {
    type Value = ScalarBytes;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a 64-char hex string (32 bytes)")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        ScalarBytes::from_string(value).map_err(E::custom)
    }
}
impl<'de> Deserialize<'de> for ScalarBytes
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<ScalarBytes, D::Error> {
        deserializer.deserialize_str(ScalarBytesVisitor)
    }
}

impl From<crate::engine::Scalar> for ScalarBytes {
    fn from(s: crate::engine::Scalar) -> Self {
        ScalarBytes(crate::engine::scalar_to_canonical_bytes(&s))
    }
}

impl TryFrom<ScalarBytes> for crate::engine::Scalar {
    type Error = &'static str;
    fn try_from(s: ScalarBytes) -> Result<Self, Self::Error> {
        crate::engine::scalar_from_canonical_bytes(&s.0)
            .ok_or("non-canonical scalar bytes")
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct AffineVerifyingKeyBytesLE(pub Vec<u8>);

impl AffineVerifyingKeyBytesLE
{
    pub fn to_string(&self) -> String
    {
        hex::encode(&self.0)
    }
}

// serde_json traits
impl Serialize for AffineVerifyingKeyBytesLE
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl From<VerifyingKey<Bls12>> for AffineVerifyingKeyBytesLE
{
    fn from(vk: VerifyingKey<Bls12>) -> Self
    {
        // need to reverse endianess for all elements because 'to_uncompressed()' has big-endian byte encoding
        let mut alpha_g1_bytes = vk.alpha_g1.to_uncompressed();
        alpha_g1_bytes[ 0..48].reverse();       // alpha_g1.x
        alpha_g1_bytes[48..96].reverse();       // alpha_g1.y
        let mut beta_g1_bytes = vk.beta_g1.to_uncompressed();
        beta_g1_bytes[ 0..48].reverse();        // beta_g1.x
        beta_g1_bytes[48..96].reverse();        // beta_g1.y
        let mut beta_g2_bytes = vk.beta_g2.to_uncompressed();
        beta_g2_bytes[  0.. 48].reverse();      // beta_g2.x.c1
        beta_g2_bytes[ 48.. 96].reverse();      // beta_g2.x.c0
        beta_g2_bytes[ 96..144].reverse();      // beta_g2.y.c1
        beta_g2_bytes[144..192].reverse();      // beta_g2.y.c0
        let mut gamma_g2_bytes = vk.gamma_g2.to_uncompressed();
        gamma_g2_bytes[  0.. 48].reverse();     // gamma_g2.x.c1
        gamma_g2_bytes[ 48.. 96].reverse();     // gamma_g2.x.c0
        gamma_g2_bytes[ 96..144].reverse();     // gamma_g2.y.c1
        gamma_g2_bytes[144..192].reverse();     // gamma_g2.y.c0
        let mut delta_g1_bytes = vk.delta_g1.to_uncompressed();
        delta_g1_bytes[ 0..48].reverse();       // delta_g1.x
        delta_g1_bytes[48..96].reverse();       // delta_g1.y
        let mut delta_g2_bytes = vk.delta_g2.to_uncompressed();
        delta_g2_bytes[  0.. 48].reverse();     // delta_g2.x.c1
        delta_g2_bytes[ 48.. 96].reverse();     // delta_g2.x.c0
        delta_g2_bytes[ 96..144].reverse();     // delta_g2.y.c1
        delta_g2_bytes[144..192].reverse();     // delta_g2.y.c0
        let mut ic_bytes = vec![0; 4 + vk.ic.len() * 96];
        ic_bytes[0..4].copy_from_slice(&(vk.ic.len() as u32).to_le_bytes());
        for (i, it) in vk.ic.iter().enumerate()
        {
            let mut it_bytes = it.to_uncompressed();
            it_bytes[ 0..48].reverse();         // it.x
            it_bytes[48..96].reverse();         // it.y
            ic_bytes[4+i*96..4+(i+1)*96].copy_from_slice(&it_bytes);
        }

        let mut bytes = vec![0; 96 + 96 + 192 + 192 + 96 + 192 + 4 + vk.ic.len() * 96];
        bytes[  0.. 48].copy_from_slice(&alpha_g1_bytes[  0.. 48]);     // alpha_g1_bytes.x
        bytes[ 48.. 96].copy_from_slice(&alpha_g1_bytes[ 48.. 96]);     // alpha_g1_bytes.y
        bytes[ 96..144].copy_from_slice(&beta_g1_bytes[  0.. 48]);      // beta_g1_bytes.x
        bytes[144..192].copy_from_slice(&beta_g1_bytes[ 48.. 96]);      // beta_g1_bytes.y
        bytes[192..240].copy_from_slice(&beta_g2_bytes[ 48.. 96]);      // beta_g2.x.c0
        bytes[240..288].copy_from_slice(&beta_g2_bytes[  0.. 48]);      // beta_g2.x.c1
        bytes[288..336].copy_from_slice(&beta_g2_bytes[144..192]);      // beta_g2.y.c0
        bytes[336..384].copy_from_slice(&beta_g2_bytes[ 96..144]);      // beta_g2.y.c1
        bytes[384..432].copy_from_slice(&gamma_g2_bytes[ 48.. 96]);     // gamma_g2.x.c0
        bytes[432..480].copy_from_slice(&gamma_g2_bytes[  0.. 48]);     // gamma_g2.x.c1
        bytes[480..528].copy_from_slice(&gamma_g2_bytes[144..192]);     // gamma_g2.y.c0
        bytes[528..576].copy_from_slice(&gamma_g2_bytes[ 96..144]);     // gamma_g2.y.c1
        bytes[576..624].copy_from_slice(&delta_g1_bytes[ 0..48]);       // delta_g1.x
        bytes[624..672].copy_from_slice(&delta_g1_bytes[48..96]);       // delta_g1.y
        bytes[672..720].copy_from_slice(&delta_g2_bytes[ 48.. 96]);     // delta_g2.x.c0
        bytes[720..768].copy_from_slice(&delta_g2_bytes[  0.. 48]);     // delta_g2.x.c1
        bytes[768..816].copy_from_slice(&delta_g2_bytes[144..192]);     // delta_g2.y.c0
        bytes[816..864].copy_from_slice(&delta_g2_bytes[ 96..144]);     // delta_g2.y.c1
        bytes[864..].copy_from_slice(&ic_bytes);

        AffineVerifyingKeyBytesLE(bytes)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AffineProofBytesLE(pub [u8; 384]);

impl AffineProofBytesLE
{
    pub fn to_string(&self) -> String
    {
        hex::encode(self.0)
    }

    pub fn from_string(str: &str) -> Result<Self, String>
    {
        if str.len() != 768 {
            return Err(format!("invalid hex length: expected 768, got {}", str.len()));
        }
        let v = hex::decode(str).map_err(|e| format!("invalid hex: {e}"))?;
        let arr: [u8; 384] = v.try_into().map_err(|_| "invalid byte length")?;
        Ok(AffineProofBytesLE(arr))
    }
}

// serde_json traits
impl Serialize for AffineProofBytesLE
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}
struct AffineProofBytesVisitor;
impl<'de> Visitor<'de> for AffineProofBytesVisitor {
    type Value = AffineProofBytesLE;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a 768-char hex string (384 bytes)")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        AffineProofBytesLE::from_string(value).map_err(E::custom)
    }
}
impl<'de> Deserialize<'de> for AffineProofBytesLE
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<AffineProofBytesLE, D::Error> {
        deserializer.deserialize_str(AffineProofBytesVisitor)
    }
}

#[derive(Debug)]
pub enum ProofConvError {
    InvalidG1,
    InvalidG2,
}
impl fmt::Display for ProofConvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofConvError::InvalidG1 => f.write_str("invalid G1 point"),
            ProofConvError::InvalidG2 => f.write_str("invalid G2 point"),
        }
    }
}
impl Error for ProofConvError {}
impl TryFrom<Proof<Bls12>> for AffineProofBytesLE {
    type Error = ProofConvError;

    fn try_from(p: Proof<Bls12>) -> Result<Self, Self::Error> {
        // big-endian -> little-endian reorders (unchanged logic), no fallible steps here
        let mut a = p.a.to_uncompressed();
        a[..48].reverse(); a[48..96].reverse();
        let mut b = p.b.to_uncompressed();
        b[..48].reverse(); b[48..96].reverse(); b[96..144].reverse(); b[144..192].reverse();
        let mut c = p.c.to_uncompressed();
        c[..48].reverse(); c[48..96].reverse();

        let mut out = [0u8; 384];
        out[  0.. 48].copy_from_slice(&a[  0.. 48]); // a.x (LE)
        out[ 48.. 96].copy_from_slice(&a[ 48.. 96]); // a.y (LE)
        out[ 96..144].copy_from_slice(&b[ 48.. 96]); // b.x.c0 (LE)
        out[144..192].copy_from_slice(&b[  0.. 48]); // b.x.c1 (LE)
        out[192..240].copy_from_slice(&b[144..192]); // b.y.c0 (LE)
        out[240..288].copy_from_slice(&b[ 96..144]); // b.y.c1 (LE)
        out[288..336].copy_from_slice(&c[  0.. 48]); // c.x (LE)
        out[336..384].copy_from_slice(&c[ 48.. 96]); // c.y (LE)

        Ok(AffineProofBytesLE(out))
    }
}

impl TryFrom<AffineProofBytesLE> for Proof<Bls12> {
    type Error = ProofConvError;

    fn try_from(p: AffineProofBytesLE) -> Result<Self, Self::Error> {
        // Rebuild big-endian uncompressed encodings
        let mut a = [0u8; 96];
        a[  0.. 48].copy_from_slice(&p.0[ 0.. 48]); // a.x (LE)
        a[ 48.. 96].copy_from_slice(&p.0[48.. 96]); // a.y (LE)
        a[..48].reverse(); a[48..96].reverse();     // -> big-endian

        let mut b = [0u8; 192];
        b[  0.. 48].copy_from_slice(&p.0[144..192]); // b.x.c1 (LE)
        b[ 48.. 96].copy_from_slice(&p.0[ 96..144]); // b.x.c0 (LE)
        b[ 96..144].copy_from_slice(&p.0[240..288]); // b.y.c1 (LE)
        b[144..192].copy_from_slice(&p.0[192..240]); // b.y.c0 (LE)
        b[..48].reverse(); b[48..96].reverse(); b[96..144].reverse(); b[144..192].reverse();

        let mut c = [0u8; 96];
        c[  0.. 48].copy_from_slice(&p.0[288..336]); // c.x (LE)
        c[ 48.. 96].copy_from_slice(&p.0[336..384]); // c.y (LE)
        c[..48].reverse(); c[48..96].reverse();

        let a = Option::from(G1Affine::from_uncompressed(&a)).ok_or(ProofConvError::InvalidG1)?;
        let b = Option::from(G2Affine::from_uncompressed(&b)).ok_or(ProofConvError::InvalidG2)?;
        let c = Option::from(G1Affine::from_uncompressed(&c)).ok_or(ProofConvError::InvalidG1)?;

        Ok(Proof { a, b, c })
    }
}

// in EOSIO u64 values are encoded as numbers if <= u32 max and encoded as string if > u32 max
fn de_u64_from_str_or_int<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct U64Visitor;

    impl<'de> de::Visitor<'de> for U64Visitor {
        type Value = u64;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a u64 or a decimal string containing a u64")
        }

        fn visit_u64<E>(self, v: u64) -> Result<u64, E> {
            Ok(v)
        }

        fn visit_i64<E>(self, v: i64) -> Result<u64, E>
        where
            E: de::Error,
        {
            if v < 0 {
                return Err(E::custom("negative values not allowed for amount"));
            }
            Ok(v as u64)
        }

        fn visit_u128<E>(self, v: u128) -> Result<u64, E>
        where
            E: de::Error,
        {
            u64::try_from(v).map_err(|_| E::custom("value over u64::MAX"))
        }

        fn visit_str<E>(self, v: &str) -> Result<u64, E>
        where
            E: de::Error,
        {
            v.parse::<u64>()
                .map_err(|_| E::invalid_value(de::Unexpected::Str(v), &"a decimal u64 string"))
        }

        fn visit_string<E>(self, v: String) -> Result<u64, E>
        where
            E: de::Error,
        {
            self.visit_str(&v)
        }
    }

    deserializer.deserialize_any(U64Visitor)
}
fn ser_u64_num_or_string<S>(v: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if *v <= u32::MAX as u64 {
        serializer.serialize_u64(*v)
    } else {
        serializer.serialize_str(&v.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlsMint
{
    pub cm: ScalarBytes,
    #[serde(deserialize_with = "de_u64_from_str_or_int", serialize_with = "ser_u64_num_or_string")]
    pub value: u64,
    // too many wallet don't accept a value of zero for type symbol
    // that's why we change it to a u64 to avoid serialization problems
    // with, for example, eosjs or wharfkit etc
    //pub symbol: Symbol,
    #[serde(deserialize_with = "de_u64_from_str_or_int", serialize_with = "ser_u64_num_or_string")]
    pub symbol: u64,
    pub contract: Name,
    pub proof: AffineProofBytesLE
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlsMintAction
{
    pub actions: Vec<PlsMint>,
    pub note_ct: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlsSpendSequence
{
    pub scm: ScalarBytes,
    pub spend_output: Vec<PlsSpendOutput>,
    pub spend: Vec<PlsSpend>,
    pub output: Vec<PlsOutput>
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlsSpendOutput
{
    pub root: ScalarBytes,
    pub nf: ScalarBytes,
    pub cm_b: ScalarBytes,
    pub cv_net_u: ScalarBytes,
    pub cv_net_v: ScalarBytes,
    #[serde(deserialize_with = "de_u64_from_str_or_int", serialize_with = "ser_u64_num_or_string")]
    pub value_c: u64,
    pub symbol: Symbol,
    pub contract: Name,
    pub cv_eq_gt: u8,
    pub proof: AffineProofBytesLE,
    pub unshielded_outputs: Vec<PlsUnshieldedRecipient>
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlsUnshieldedRecipient
{
    #[serde(deserialize_with = "de_u64_from_str_or_int", serialize_with = "ser_u64_num_or_string")]
    pub amount: u64,
    pub account: Name,
    pub memo: String
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlsSpend
{
    pub root: ScalarBytes,
    pub nf: ScalarBytes,
    pub cv_u: ScalarBytes,
    pub cv_v: ScalarBytes,
    pub proof: AffineProofBytesLE
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlsOutput
{
    pub cm: ScalarBytes,
    pub cv_u: ScalarBytes,
    pub cv_v: ScalarBytes,
    pub proof: AffineProofBytesLE
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlsSpendAction
{
    pub actions: Vec<PlsSpendSequence>,
    pub note_ct: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlsAuthenticate
{
    pub cm: ScalarBytes,
    pub contract: Name,
    pub actions: Vec<PackedAction>,
    pub burn: u8,
    pub proof: AffineProofBytesLE
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlsAuthenticateAction
{
    pub action: PlsAuthenticate
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlsPublishNotesAction
{
    pub note_ct: Vec<String>
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlsWithdraw
{
    pub contract: Name,
    pub quantity: Asset,
    pub memo: String,
    pub to: Name
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlsWithdrawAction
{
    pub actions: Vec<PlsWithdraw>
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlsFtTransfer
{
    pub from: Name,
    pub to: Name,
    pub quantity: Asset,
    pub memo: String
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlsNftTransfer
{
    pub from: Name,
    pub to: Name,
    pub asset_ids: Vec<Asset>,
    pub memo: String
}

// converts a bls12-381 scalar to its raw byte representation (i.e. montgomery form instead of canonical)
pub fn scalar_to_raw_bytes_le(s: &crate::engine::Scalar) -> [u8; 32] {
    let canon = crate::engine::scalar_to_canonical_bytes(s);
    let mont = Scalar::from_bytes(&canon).expect("canonical crate::engine::Scalar must convert");
    mont.to_raw_bytes()
}





// Helper class 'Scalar' copied from bls crate because bytes are not accessible rawly (montgomery form) in
// original version (i.e. without implicitly performing montgomery reduction)

/// Compute a + b + carry, returning the result and the new carry over.
#[inline(always)]
pub const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + (b as u128) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

/// Compute a - (b + borrow), returning the result and the new borrow.
#[inline(always)]
pub const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
    (ret as u64, (ret >> 64) as u64)
}

/// Compute a + (b * c) + carry, returning the result and the new carry over.
#[inline(always)]
pub const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + ((b as u128) * (c as u128)) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

#[derive(Clone, Copy)]
pub struct Scalar(pub [u64; 4]);

/// Constant representing the modulus
/// q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
const MODULUS: Scalar = Scalar([
    0xffff_ffff_0000_0001,
    0x53bd_a402_fffe_5bfe,
    0x3339_d808_09a1_d805,
    0x73ed_a753_299d_7d48,
]);

/// INV = -(q^{-1} mod 2^64) mod 2^64
const INV: u64 = 0xffff_fffe_ffff_ffff;

/// R^2 = 2^512 mod q
const R2: Scalar = Scalar([
    0xc999_e990_f3f2_9c6d,
    0x2b6c_edcb_8792_5c23,
    0x05d3_1496_7254_398f,
    0x0748_d9d9_9f59_ff11,
]);

impl Scalar
{
    /// Attempts to convert a little-endian byte representation of
    /// a scalar into a `Scalar`, failing if the input is not canonical.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
        let mut tmp = Scalar([0, 0, 0, 0]);

        tmp.0[0] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap());
        tmp.0[1] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap());
        tmp.0[2] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap());
        tmp.0[3] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap());

        // Try to subtract the modulus
        let (_, borrow) = sbb(tmp.0[0], MODULUS.0[0], 0);
        let (_, borrow) = sbb(tmp.0[1], MODULUS.0[1], borrow);
        let (_, borrow) = sbb(tmp.0[2], MODULUS.0[2], borrow);
        let (_, borrow) = sbb(tmp.0[3], MODULUS.0[3], borrow);

        // If the element is smaller than MODULUS then the
        // subtraction will underflow, producing a borrow value
        // of 0xffff...ffff. Otherwise, it'll be zero.
        let is_some = (borrow as u8) & 1;

        // Convert to Montgomery form by computing
        // (a.R^0 * R^2) / R = a.R
        tmp = tmp.mul(&R2);

        if is_some == 1
        {
            Some(tmp)
        }
        else
        {
            None
        }
    }

    /// Attempts to convert a little-endian montgomery byte representation of
    /// a scalar into a `Scalar`.
    pub fn from_raw_bytes(bytes: &[u8; 32]) -> Scalar {
        let mut tmp = Scalar([0, 0, 0, 0]);

        tmp.0[0] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap());
        tmp.0[1] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap());
        tmp.0[2] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap());
        tmp.0[3] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap());

        tmp
    }

    /// Converts an element of `Scalar` into a byte representation in
    /// little-endian byte order.
    pub fn to_bytes(&self) -> [u8; 32] {
        // Turn into canonical form by computing
        // (a.R) / R = a
        let tmp = Scalar::montgomery_reduce(self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0);

        let mut res = [0; 32];
        res[0..8].copy_from_slice(&tmp.0[0].to_le_bytes());
        res[8..16].copy_from_slice(&tmp.0[1].to_le_bytes());
        res[16..24].copy_from_slice(&tmp.0[2].to_le_bytes());
        res[24..32].copy_from_slice(&tmp.0[3].to_le_bytes());

        res
    }

    /// Converts an element of `Scalar` into its montgomery byte representation in
    /// little-endian byte order.
    pub fn to_raw_bytes(&self) -> [u8; 32] {
        let mut res = [0; 32];
        res[0..8].copy_from_slice(&self.0[0].to_le_bytes());
        res[8..16].copy_from_slice(&self.0[1].to_le_bytes());
        res[16..24].copy_from_slice(&self.0[2].to_le_bytes());
        res[24..32].copy_from_slice(&self.0[3].to_le_bytes());

        res
    }

    #[inline(always)]
    const fn montgomery_reduce(
        r0: u64,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
        r5: u64,
        r6: u64,
        r7: u64,
    ) -> Self {
        // The Montgomery reduction here is based on Algorithm 14.32 in
        // Handbook of Applied Cryptography
        // <http://cacr.uwaterloo.ca/hac/about/chap14.pdf>.

        let k = r0.wrapping_mul(INV);
        let (_, carry) = mac(r0, k, MODULUS.0[0], 0);
        let (r1, carry) = mac(r1, k, MODULUS.0[1], carry);
        let (r2, carry) = mac(r2, k, MODULUS.0[2], carry);
        let (r3, carry) = mac(r3, k, MODULUS.0[3], carry);
        let (r4, carry2) = adc(r4, 0, carry);

        let k = r1.wrapping_mul(INV);
        let (_, carry) = mac(r1, k, MODULUS.0[0], 0);
        let (r2, carry) = mac(r2, k, MODULUS.0[1], carry);
        let (r3, carry) = mac(r3, k, MODULUS.0[2], carry);
        let (r4, carry) = mac(r4, k, MODULUS.0[3], carry);
        let (r5, carry2) = adc(r5, carry2, carry);

        let k = r2.wrapping_mul(INV);
        let (_, carry) = mac(r2, k, MODULUS.0[0], 0);
        let (r3, carry) = mac(r3, k, MODULUS.0[1], carry);
        let (r4, carry) = mac(r4, k, MODULUS.0[2], carry);
        let (r5, carry) = mac(r5, k, MODULUS.0[3], carry);
        let (r6, carry2) = adc(r6, carry2, carry);

        let k = r3.wrapping_mul(INV);
        let (_, carry) = mac(r3, k, MODULUS.0[0], 0);
        let (r4, carry) = mac(r4, k, MODULUS.0[1], carry);
        let (r5, carry) = mac(r5, k, MODULUS.0[2], carry);
        let (r6, carry) = mac(r6, k, MODULUS.0[3], carry);
        let (r7, _) = adc(r7, carry2, carry);

        // Result may be within MODULUS of the correct value
        (&Scalar([r4, r5, r6, r7])).sub(&MODULUS)
    }

    /// Multiplies `rhs` by `self`, returning the result.
    #[inline]
    pub const fn mul(&self, rhs: &Self) -> Self {
        // Schoolbook multiplication

        let (r0, carry) = mac(0, self.0[0], rhs.0[0], 0);
        let (r1, carry) = mac(0, self.0[0], rhs.0[1], carry);
        let (r2, carry) = mac(0, self.0[0], rhs.0[2], carry);
        let (r3, r4) = mac(0, self.0[0], rhs.0[3], carry);

        let (r1, carry) = mac(r1, self.0[1], rhs.0[0], 0);
        let (r2, carry) = mac(r2, self.0[1], rhs.0[1], carry);
        let (r3, carry) = mac(r3, self.0[1], rhs.0[2], carry);
        let (r4, r5) = mac(r4, self.0[1], rhs.0[3], carry);

        let (r2, carry) = mac(r2, self.0[2], rhs.0[0], 0);
        let (r3, carry) = mac(r3, self.0[2], rhs.0[1], carry);
        let (r4, carry) = mac(r4, self.0[2], rhs.0[2], carry);
        let (r5, r6) = mac(r5, self.0[2], rhs.0[3], carry);

        let (r3, carry) = mac(r3, self.0[3], rhs.0[0], 0);
        let (r4, carry) = mac(r4, self.0[3], rhs.0[1], carry);
        let (r5, carry) = mac(r5, self.0[3], rhs.0[2], carry);
        let (r6, r7) = mac(r6, self.0[3], rhs.0[3], carry);

        Scalar::montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7)
    }

    /// Subtracts `rhs` from `self`, returning the result.
    #[inline]
    pub const fn sub(&self, rhs: &Self) -> Self {
        let (d0, borrow) = sbb(self.0[0], rhs.0[0], 0);
        let (d1, borrow) = sbb(self.0[1], rhs.0[1], borrow);
        let (d2, borrow) = sbb(self.0[2], rhs.0[2], borrow);
        let (d3, borrow) = sbb(self.0[3], rhs.0[3], borrow);

        // If underflow occurred on the final limb, borrow = 0xfff...fff, otherwise
        // borrow = 0x000...000. Thus, we use it as a mask to conditionally add the modulus.
        let (d0, carry) = adc(d0, MODULUS.0[0] & borrow, 0);
        let (d1, carry) = adc(d1, MODULUS.0[1] & borrow, carry);
        let (d2, carry) = adc(d2, MODULUS.0[2] & borrow, carry);
        let (d3, _) = adc(d3, MODULUS.0[3] & borrow, carry);

        Scalar([d0, d1, d2, d3])
    }

    /// Adds `rhs` to `self`, returning the result.
    #[inline]
    pub const fn add(&self, rhs: &Self) -> Self {
        let (d0, carry) = adc(self.0[0], rhs.0[0], 0);
        let (d1, carry) = adc(self.0[1], rhs.0[1], carry);
        let (d2, carry) = adc(self.0[2], rhs.0[2], carry);
        let (d3, _) = adc(self.0[3], rhs.0[3], carry);

        // Attempt to subtract the modulus, to ensure the value
        // is smaller than the modulus.
        (&Scalar([d0, d1, d2, d3])).sub(&MODULUS)
    }
}


// Helper class 'Fp' copied from bls crate because bytes are not accessible rawly (montgomery form) in
// original version (i.e. without implicitly performing montgomery reduction)
/*
#[derive(Copy, Clone)]
pub struct Fp(pub [u64; 6]);

/// p = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
const MODULUS: [u64; 6] = [
    0xb9fe_ffff_ffff_aaab,
    0x1eab_fffe_b153_ffff,
    0x6730_d2a0_f6b0_f624,
    0x6477_4b84_f385_12bf,
    0x4b1b_a7b6_434b_acd7,
    0x1a01_11ea_397f_e69a,
];

/// INV = -(p^{-1} mod 2^64) mod 2^64
const INV: u64 = 0x89f3_fffc_fffc_fffd;

/// R2 = 2^(384*2) mod p
const R2: Fp = Fp([
    0xf4df_1f34_1c34_1746,
    0x0a76_e6a6_09d1_04f1,
    0x8de5_476c_4c95_b6d5,
    0x67eb_88a9_939d_83c0,
    0x9a79_3e85_b519_952d,
    0x1198_8fe5_92ca_e3aa,
]);

/// Compute a + b + carry, returning the result and the new carry over.
#[inline(always)]
pub const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + (b as u128) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

/// Compute a - (b + borrow), returning the result and the new borrow.
#[inline(always)]
pub const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
    (ret as u64, (ret >> 64) as u64)
}

/// Compute a + (b * c) + carry, returning the result and the new carry over.
#[inline(always)]
pub const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + ((b as u128) * (c as u128)) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

impl MulAssign<Fp> for Fp {
    #[inline]
    fn mul_assign(&mut self, rhs: Fp) {
        *self = &*self * &rhs;
    }
}

impl<'b> MulAssign<&'b Fp> for Fp {
    #[inline]
    fn mul_assign(&mut self, rhs: &'b Fp) {
        *self = &*self * rhs;
    }
}

impl<'a, 'b> Mul<&'b Fp> for &'a Fp {
    type Output = Fp;

    #[inline]
    fn mul(self, rhs: &'b Fp) -> Fp {
        self.mul(rhs)
    }
}

impl Fp
{
    /// Attempts to convert a big-endian byte representation of
    /// a scalar into an `Fp`, failing if the input is not canonical.
    pub fn from_bytes(bytes: &[u8; 48]) -> Option<Fp> {
        let mut tmp = Fp([0, 0, 0, 0, 0, 0]);

        tmp.0[5] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap());
        tmp.0[4] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap());
        tmp.0[3] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap());
        tmp.0[2] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap());
        tmp.0[1] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[32..40]).unwrap());
        tmp.0[0] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[40..48]).unwrap());

        // Try to subtract the modulus
        let (_, borrow) = sbb(tmp.0[0], MODULUS[0], 0);
        let (_, borrow) = sbb(tmp.0[1], MODULUS[1], borrow);
        let (_, borrow) = sbb(tmp.0[2], MODULUS[2], borrow);
        let (_, borrow) = sbb(tmp.0[3], MODULUS[3], borrow);
        let (_, borrow) = sbb(tmp.0[4], MODULUS[4], borrow);
        let (_, borrow) = sbb(tmp.0[5], MODULUS[5], borrow);

        // If the element is smaller than MODULUS then the
        // subtraction will underflow, producing a borrow value
        // of 0xffff...ffff. Otherwise, it'll be zero.
        if (borrow as u8) & 1 == 1
        {
            // Convert to Montgomery form by computing
            // (a.R^0 * R^2) / R = a.R
            tmp *= &R2;
            return Some(tmp);
        }

        None
    }

    /// Performs NO montgomery conversion but just writes out the raw bytes
    /// in little-endian byte order.
    pub fn to_raw_le_bytes(self) -> [u8; 48] {
        let mut res = [0; 48];
        res[0..8].copy_from_slice(&self.0[0].to_le_bytes());
        res[8..16].copy_from_slice(&self.0[1].to_le_bytes());
        res[16..24].copy_from_slice(&self.0[2].to_le_bytes());
        res[24..32].copy_from_slice(&self.0[3].to_le_bytes());
        res[32..40].copy_from_slice(&self.0[4].to_le_bytes());
        res[40..48].copy_from_slice(&self.0[5].to_le_bytes());

        res
    }

    #[inline]
    const fn subtract_p(&self) -> Fp {
        let (r0, borrow) = sbb(self.0[0], MODULUS[0], 0);
        let (r1, borrow) = sbb(self.0[1], MODULUS[1], borrow);
        let (r2, borrow) = sbb(self.0[2], MODULUS[2], borrow);
        let (r3, borrow) = sbb(self.0[3], MODULUS[3], borrow);
        let (r4, borrow) = sbb(self.0[4], MODULUS[4], borrow);
        let (r5, borrow) = sbb(self.0[5], MODULUS[5], borrow);

        // If underflow occurred on the final limb, borrow = 0xfff...fff, otherwise
        // borrow = 0x000...000. Thus, we use it as a mask!
        let r0 = (self.0[0] & borrow) | (r0 & !borrow);
        let r1 = (self.0[1] & borrow) | (r1 & !borrow);
        let r2 = (self.0[2] & borrow) | (r2 & !borrow);
        let r3 = (self.0[3] & borrow) | (r3 & !borrow);
        let r4 = (self.0[4] & borrow) | (r4 & !borrow);
        let r5 = (self.0[5] & borrow) | (r5 & !borrow);

        Fp([r0, r1, r2, r3, r4, r5])
    }

    #[inline(always)]
    pub(crate) const fn montgomery_reduce(
        t0: u64,
        t1: u64,
        t2: u64,
        t3: u64,
        t4: u64,
        t5: u64,
        t6: u64,
        t7: u64,
        t8: u64,
        t9: u64,
        t10: u64,
        t11: u64,
    ) -> Self {
        // The Montgomery reduction here is based on Algorithm 14.32 in
        // Handbook of Applied Cryptography
        // <http://cacr.uwaterloo.ca/hac/about/chap14.pdf>.

        let k = t0.wrapping_mul(INV);
        let (_, carry) = mac(t0, k, MODULUS[0], 0);
        let (r1, carry) = mac(t1, k, MODULUS[1], carry);
        let (r2, carry) = mac(t2, k, MODULUS[2], carry);
        let (r3, carry) = mac(t3, k, MODULUS[3], carry);
        let (r4, carry) = mac(t4, k, MODULUS[4], carry);
        let (r5, carry) = mac(t5, k, MODULUS[5], carry);
        let (r6, r7) = adc(t6, 0, carry);

        let k = r1.wrapping_mul(INV);
        let (_, carry) = mac(r1, k, MODULUS[0], 0);
        let (r2, carry) = mac(r2, k, MODULUS[1], carry);
        let (r3, carry) = mac(r3, k, MODULUS[2], carry);
        let (r4, carry) = mac(r4, k, MODULUS[3], carry);
        let (r5, carry) = mac(r5, k, MODULUS[4], carry);
        let (r6, carry) = mac(r6, k, MODULUS[5], carry);
        let (r7, r8) = adc(t7, r7, carry);

        let k = r2.wrapping_mul(INV);
        let (_, carry) = mac(r2, k, MODULUS[0], 0);
        let (r3, carry) = mac(r3, k, MODULUS[1], carry);
        let (r4, carry) = mac(r4, k, MODULUS[2], carry);
        let (r5, carry) = mac(r5, k, MODULUS[3], carry);
        let (r6, carry) = mac(r6, k, MODULUS[4], carry);
        let (r7, carry) = mac(r7, k, MODULUS[5], carry);
        let (r8, r9) = adc(t8, r8, carry);

        let k = r3.wrapping_mul(INV);
        let (_, carry) = mac(r3, k, MODULUS[0], 0);
        let (r4, carry) = mac(r4, k, MODULUS[1], carry);
        let (r5, carry) = mac(r5, k, MODULUS[2], carry);
        let (r6, carry) = mac(r6, k, MODULUS[3], carry);
        let (r7, carry) = mac(r7, k, MODULUS[4], carry);
        let (r8, carry) = mac(r8, k, MODULUS[5], carry);
        let (r9, r10) = adc(t9, r9, carry);

        let k = r4.wrapping_mul(INV);
        let (_, carry) = mac(r4, k, MODULUS[0], 0);
        let (r5, carry) = mac(r5, k, MODULUS[1], carry);
        let (r6, carry) = mac(r6, k, MODULUS[2], carry);
        let (r7, carry) = mac(r7, k, MODULUS[3], carry);
        let (r8, carry) = mac(r8, k, MODULUS[4], carry);
        let (r9, carry) = mac(r9, k, MODULUS[5], carry);
        let (r10, r11) = adc(t10, r10, carry);

        let k = r5.wrapping_mul(INV);
        let (_, carry) = mac(r5, k, MODULUS[0], 0);
        let (r6, carry) = mac(r6, k, MODULUS[1], carry);
        let (r7, carry) = mac(r7, k, MODULUS[2], carry);
        let (r8, carry) = mac(r8, k, MODULUS[3], carry);
        let (r9, carry) = mac(r9, k, MODULUS[4], carry);
        let (r10, carry) = mac(r10, k, MODULUS[5], carry);
        let (r11, _) = adc(t11, r11, carry);

        // Attempt to subtract the modulus, to ensure the value
        // is smaller than the modulus.
        (&Fp([r6, r7, r8, r9, r10, r11])).subtract_p()
    }

    #[inline]
    pub const fn mul(&self, rhs: &Fp) -> Fp {
        let (t0, carry) = mac(0, self.0[0], rhs.0[0], 0);
        let (t1, carry) = mac(0, self.0[0], rhs.0[1], carry);
        let (t2, carry) = mac(0, self.0[0], rhs.0[2], carry);
        let (t3, carry) = mac(0, self.0[0], rhs.0[3], carry);
        let (t4, carry) = mac(0, self.0[0], rhs.0[4], carry);
        let (t5, t6) = mac(0, self.0[0], rhs.0[5], carry);

        let (t1, carry) = mac(t1, self.0[1], rhs.0[0], 0);
        let (t2, carry) = mac(t2, self.0[1], rhs.0[1], carry);
        let (t3, carry) = mac(t3, self.0[1], rhs.0[2], carry);
        let (t4, carry) = mac(t4, self.0[1], rhs.0[3], carry);
        let (t5, carry) = mac(t5, self.0[1], rhs.0[4], carry);
        let (t6, t7) = mac(t6, self.0[1], rhs.0[5], carry);

        let (t2, carry) = mac(t2, self.0[2], rhs.0[0], 0);
        let (t3, carry) = mac(t3, self.0[2], rhs.0[1], carry);
        let (t4, carry) = mac(t4, self.0[2], rhs.0[2], carry);
        let (t5, carry) = mac(t5, self.0[2], rhs.0[3], carry);
        let (t6, carry) = mac(t6, self.0[2], rhs.0[4], carry);
        let (t7, t8) = mac(t7, self.0[2], rhs.0[5], carry);

        let (t3, carry) = mac(t3, self.0[3], rhs.0[0], 0);
        let (t4, carry) = mac(t4, self.0[3], rhs.0[1], carry);
        let (t5, carry) = mac(t5, self.0[3], rhs.0[2], carry);
        let (t6, carry) = mac(t6, self.0[3], rhs.0[3], carry);
        let (t7, carry) = mac(t7, self.0[3], rhs.0[4], carry);
        let (t8, t9) = mac(t8, self.0[3], rhs.0[5], carry);

        let (t4, carry) = mac(t4, self.0[4], rhs.0[0], 0);
        let (t5, carry) = mac(t5, self.0[4], rhs.0[1], carry);
        let (t6, carry) = mac(t6, self.0[4], rhs.0[2], carry);
        let (t7, carry) = mac(t7, self.0[4], rhs.0[3], carry);
        let (t8, carry) = mac(t8, self.0[4], rhs.0[4], carry);
        let (t9, t10) = mac(t9, self.0[4], rhs.0[5], carry);

        let (t5, carry) = mac(t5, self.0[5], rhs.0[0], 0);
        let (t6, carry) = mac(t6, self.0[5], rhs.0[1], carry);
        let (t7, carry) = mac(t7, self.0[5], rhs.0[2], carry);
        let (t8, carry) = mac(t8, self.0[5], rhs.0[3], carry);
        let (t9, carry) = mac(t9, self.0[5], rhs.0[4], carry);
        let (t10, t11) = mac(t10, self.0[5], rhs.0[5], carry);

        Self::montgomery_reduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11)
    }
}
*/

#[cfg(test)]
mod tests
{
    use super::*;
    use bellman::groth16::Parameters;
    use crate::note::Note;
    use std::fs::File;
    use std::io::Read;
    use bellman::groth16::{verify_proof, prepare_verifying_key, create_random_proof};
    use bellman::gadgets::multipack;
    use crate::engine::Scalar;
    use crate::engine::Bls12;
    use crate::circuit::mint::Mint;
    use rand::rngs::OsRng;
    use crate::keys::{SpendingKey, FullViewingKey};
    use crate::note::Rseed;
    use crate::eosio::ExtendedAsset;

    #[test]
    fn test()
    {
        let mut f = File::open("params_mint.bin").expect("params_mint.bin not found");
        let metadata = std::fs::metadata("params_mint.bin").expect("unable to read metadata of params_mint.bin");
        let mut mint_params_bytes = vec![0; metadata.len() as usize];
        f.read(&mut mint_params_bytes).expect("buffer overflow");
        let mint_params = Parameters::<Bls12>::read(mint_params_bytes.as_slice(), false).unwrap();
        println!("{}", AffineVerifyingKeyBytesLE::from(mint_params.vk.clone()).to_string());
        let mut rng = OsRng.clone();

        // create proof
        // key material
        let sk = SpendingKey::from_seed(b"This is Alice seed string! Usually this is just a listing of words. Here we just use sentences.");
        let fvk = FullViewingKey::from_spending_key(&sk);
        let recipient = fvk.default_address().1;
        let note = Note::from_parts(
            0,
            recipient,
            Name(0),
            ExtendedAsset::from_string(&"5000.0000 EOS@eosio.token".to_string()).unwrap(),
            Rseed([42; 32]),
            [0; 512]
        );
        let circuit_instance = Mint {
            account: Some(note.account().raw()),
            auth_hash: Some([0; 4]),
            value: Some(note.amount()),
            symbol: Some(note.symbol().raw()),
            contract: Some(note.contract().raw()),
            address: Some(note.address()),
            rcm: Some(note.rcm()),
            proof_generation_key: Some(sk.proof_generation_key()),
        };
        let proof = create_random_proof(circuit_instance, &mint_params, &mut rng).unwrap();

        let a = PlsMint{
            cm: ScalarBytes(note.commitment().to_bytes()),
            value: note.amount(),
            symbol: note.symbol().raw(),
            contract: note.contract().clone(),
            proof: AffineProofBytesLE::try_from(proof.clone()).unwrap()
        };
        println!("{}", serde_json::to_string(&a).unwrap());

        let mut inputs2_contents = [0; 24];
        inputs2_contents[0..8].copy_from_slice(&note.amount().to_le_bytes());
        inputs2_contents[8..16].copy_from_slice(&note.symbol().raw().to_le_bytes());
        inputs2_contents[16..24].copy_from_slice(&note.contract().raw().to_le_bytes());
        let inputs2_contents = multipack::bytes_to_bits_le(&inputs2_contents);
        let inputs2_contents: Vec<Scalar> = multipack::compute_multipacking(&inputs2_contents);
        assert_eq!(inputs2_contents.len(), 1);
        let mut inputs3_contents = [0; 8];
        inputs3_contents[0..8].copy_from_slice(&note.account().raw().to_le_bytes());
        let inputs3_contents = multipack::bytes_to_bits_le(&inputs3_contents);
        let inputs3_contents: Vec<Scalar> = multipack::compute_multipacking(&inputs3_contents);
        assert_eq!(inputs3_contents.len(), 1);
        let mut inputs = vec![];
        inputs.push(note.commitment().0);
        inputs.extend(inputs2_contents.clone());
        inputs.extend(inputs3_contents.clone());

        let proof_serde = AffineProofBytesLE::try_from(proof.clone()).unwrap();
        let proof_serde = Proof::<Bls12>::try_from(proof_serde).unwrap();
        assert!(proof.eq(&proof_serde));

        assert!(verify_proof(&prepare_verifying_key(&mint_params.vk), &proof, &inputs).is_ok());
    }
}