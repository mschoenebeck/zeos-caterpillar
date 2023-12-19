use bellman::groth16::{Proof, VerifyingKey};
use bls12_381::Bls12;
use pairing::{Engine, MillerLoopResult, MultiMillerLoop};
use serde::{Serialize, Deserialize, Serializer, Deserializer, de::Visitor, de};
use serde_json::Value;
use crate::eosio::{Asset, Name, Symbol};
//use core::ops::{Mul, MulAssign};
use std::ops::{AddAssign, Neg};
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub struct ScalarBytes(pub [u8; 32]);

impl ScalarBytes
{
    pub fn to_string(&self) -> String
    {
        hex::encode(self.0)
    }

    pub fn from_string(str: &String) -> Option<Self>
    {
        let bytes= hex::decode(str);
        if bytes.is_err() { return None; }
        Some(ScalarBytes(bytes.unwrap().try_into().unwrap()))
    }
}

// serde_json traits
impl Serialize for ScalarBytes
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
struct ScalarBytesVisitor;
impl<'de> Visitor<'de> for ScalarBytesVisitor {
    type Value = ScalarBytes;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a hex string with 64 characters")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(ScalarBytes::from_string(&value.to_string()).unwrap())
    }
}
impl<'de> Deserialize<'de> for ScalarBytes
{
    fn deserialize<D>(deserializer: D) -> Result<ScalarBytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ScalarBytesVisitor)
    }
}

impl From<bls12_381::Scalar> for ScalarBytes {
    fn from(s: bls12_381::Scalar) -> Self {
        ScalarBytes(s.to_bytes())
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
}

// serde_json traits
impl Serialize for AffineProofBytesLE
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl From<Proof<Bls12>> for AffineProofBytesLE
{
    //fn from(p: Proof<Bls12>) -> Self
    //{
    //    let a_bytes = p.a.to_uncompressed();
    //    let a_x = Fp::from_bytes(&a_bytes[ 0..48].try_into().unwrap()).unwrap();
    //    let a_y = Fp::from_bytes(&a_bytes[48..96].try_into().unwrap()).unwrap();
    //    let b_bytes = p.b.to_uncompressed();
    //    let b_x_c1 = Fp::from_bytes(&b_bytes[  0.. 48].try_into().unwrap()).unwrap();
    //    let b_x_c0 = Fp::from_bytes(&b_bytes[ 48.. 96].try_into().unwrap()).unwrap();
    //    let b_y_c1 = Fp::from_bytes(&b_bytes[ 96..144].try_into().unwrap()).unwrap();
    //    let b_y_c0 = Fp::from_bytes(&b_bytes[144..192].try_into().unwrap()).unwrap();
    //    let c_bytes = p.c.to_uncompressed();
    //    let c_x = Fp::from_bytes(&c_bytes[ 0..48].try_into().unwrap()).unwrap();
    //    let c_y = Fp::from_bytes(&c_bytes[48..96].try_into().unwrap()).unwrap();
//
    //    let mut bytes = [0; 384];
    //    bytes[  0.. 48].copy_from_slice(&a_x.to_raw_le_bytes());
    //    bytes[ 48.. 96].copy_from_slice(&a_y.to_raw_le_bytes());
    //    bytes[ 96..144].copy_from_slice(&b_x_c0.to_raw_le_bytes());
    //    bytes[144..192].copy_from_slice(&b_x_c1.to_raw_le_bytes());
    //    bytes[192..240].copy_from_slice(&b_y_c0.to_raw_le_bytes());
    //    bytes[240..288].copy_from_slice(&b_y_c1.to_raw_le_bytes());
    //    bytes[288..336].copy_from_slice(&c_x.to_raw_le_bytes());
    //    bytes[336..384].copy_from_slice(&c_y.to_raw_le_bytes());
    //    AffineProofBytes(bytes)
    //}

    fn from(p: Proof<Bls12>) -> Self
    {
        // need to reverse endianess for all elements because 'to_uncompressed()' has big-endian byte encoding
        let mut a_bytes = p.a.to_uncompressed();
        a_bytes[ 0..48].reverse();      // a.x
        a_bytes[48..96].reverse();      // a.y
        let mut b_bytes = p.b.to_uncompressed();
        b_bytes[  0.. 48].reverse();    // b.x.c1
        b_bytes[ 48.. 96].reverse();    // b.x.c0
        b_bytes[ 96..144].reverse();    // b.y.c1
        b_bytes[144..192].reverse();    // b.y.c0
        let mut c_bytes = p.c.to_uncompressed();
        c_bytes[ 0..48].reverse();      // c.x
        c_bytes[48..96].reverse();      // c.y

        let mut bytes = [0; 384];
        bytes[  0.. 48].copy_from_slice(&a_bytes[  0.. 48]);    // a.x
        bytes[ 48.. 96].copy_from_slice(&a_bytes[ 48.. 96]);    // a.y
        bytes[ 96..144].copy_from_slice(&b_bytes[ 48.. 96]);    // b.x.c0
        bytes[144..192].copy_from_slice(&b_bytes[  0.. 48]);    // b.x.c1
        bytes[192..240].copy_from_slice(&b_bytes[144..192]);    // b.y.c0
        bytes[240..288].copy_from_slice(&b_bytes[ 96..144]);    // b.y.c1
        bytes[288..336].copy_from_slice(&c_bytes[  0.. 48]);    // c.x
        bytes[336..384].copy_from_slice(&c_bytes[ 48.. 96]);    // c.y
        AffineProofBytesLE(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PlsMint
{
    pub cm: ScalarBytes,
    pub value: u64,
    pub symbol: Symbol,
    pub code: Name,
    pub proof: AffineProofBytesLE
}

impl From<PlsMint> for Value {
    fn from(s: PlsMint) -> Self {
        serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PlsMintAction
{
    pub actions: Vec<PlsMint>,
    pub note_ct: Vec<String>,
}

impl From<PlsMintAction> for Value {
    fn from(s: PlsMintAction) -> Self {
        serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PlsTransfer
{
    pub root: ScalarBytes,
    pub nf: ScalarBytes,
    pub cm_b: ScalarBytes,
    pub cm_c: ScalarBytes,
    pub proof: AffineProofBytesLE
}

impl From<PlsTransfer> for Value {
    fn from(s: PlsTransfer) -> Self {
        serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PlsTransferAction
{
    pub actions: Vec<PlsTransfer>,
    pub note_ct: Vec<String>,
}

impl From<PlsTransferAction> for Value {
    fn from(s: PlsTransferAction) -> Self {
        serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PlsBurn
{
    pub root: ScalarBytes,
    pub nf: ScalarBytes,
    pub cm_d: ScalarBytes,
    pub value_b: u64,
    pub symbol: Symbol,
    pub code: Name,
    pub account_b: Name,
    pub memo_b: String,
    pub amount_c: u64,
    pub account_c: Name,
    pub memo_c: String,
    pub proof: AffineProofBytesLE
}

impl From<PlsBurn> for Value {
    fn from(s: PlsBurn) -> Self {
        serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PlsBurnAction
{
    pub actions: Vec<PlsBurn>,
    pub note_ct: Vec<String>,
}

impl From<PlsBurnAction> for Value {
    fn from(s: PlsBurnAction) -> Self {
        serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PlsFtTransfer
{
    pub from: Name,
    pub to: Name,
    pub quantity: Asset,
    pub memo: String
}

impl From<PlsFtTransfer> for Value {
    fn from(s: PlsFtTransfer) -> Self {
        serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PlsNftTransfer
{
    pub from: Name,
    pub to: Name,
    pub asset_ids: Vec<Asset>,
    pub memo: String
}

impl From<PlsNftTransfer> for Value {
    fn from(s: PlsNftTransfer) -> Self {
        serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap()
    }
}





// Helper class 'Fp' copied from bls crate because bytes are not accessible rawly in
// original version (i.e. without implicitly performing montgomery reduce)
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
    use crate::Parameters;
    use crate::note::Note;
    use std::fs::File;
    use std::io::Read;
    use bellman::groth16::{verify_proof, prepare_verifying_key};
    use bellman::gadgets::{blake2s, boolean, boolean::Boolean, multipack};
    use bls12_381::Scalar;
    use bls12_381::Bls12;
    use crate::Mint;
    use rand::rngs::OsRng;
    use crate::create_random_proof;
    use crate::SpendingKey;
    use crate::FullViewingKey;
    use crate::Rseed;
    use crate::ExtractedNullifier;

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
            Asset::from_string(&"5000.0000 EOS".to_string()).unwrap(),
            Name::from_string(&"eosio.token".to_string()).unwrap(),
            Rseed([42; 32]),
            ExtractedNullifier(Scalar::one()),
            [0; 512]
        );
        let circuit_instance = Mint {
            value: Some(note.amount()),
            symbol: Some(note.symbol().raw()),
            code: Some(note.code().raw()),
            address: Some(note.address()),
            rcm: Some(note.rcm()),
            proof_generation_key: Some(sk.proof_generation_key()),
        };
        let proof = create_random_proof(circuit_instance, &mint_params, &mut rng).unwrap();

        let a = PlsMint{
            cm: ScalarBytes(note.commitment().to_bytes()),
            value: note.amount(),
            symbol: note.symbol().clone(),
            code: note.code().clone(),
            proof: AffineProofBytesLE::from(proof.clone())
        };
        println!("{}", serde_json::to_string(&a).unwrap());

        let mut asset_contents = [0; 24];
        asset_contents[0..8].copy_from_slice(&note.amount().to_le_bytes());
        asset_contents[8..16].copy_from_slice(&note.symbol().raw().to_le_bytes());
        asset_contents[16..24].copy_from_slice(&note.code().raw().to_le_bytes());
        let asset_contents = multipack::bytes_to_bits_le(&asset_contents);
        let asset_contents: Vec<Scalar> = multipack::compute_multipacking(&asset_contents);
        assert_eq!(asset_contents.len(), 1);
        let mut inputs = vec![];
        inputs.push(note.commitment().0);
        inputs.extend(asset_contents.clone());

        assert!(verify_proof(&prepare_verifying_key(&mint_params.vk), &proof, &inputs).is_ok());
    }
}