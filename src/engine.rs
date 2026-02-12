// src/engine.rs
//
// Goal: single choke point for Groth16/bellman backend types.
// - wasm32: pure Rust bls12_381
// - native: blstrs (blst-accelerated)
//
// IMPORTANT: Do not expose backend-specific scalar constructors at call sites.
// Always use the helper fns below.

use ff::{Field, PrimeField};
use jubjub::Fq;
use subtle::CtOption;

#[cfg(target_arch = "wasm32")]
pub use bls12_381::{Bls12, G1Affine, G2Affine, Scalar};

#[cfg(not(target_arch = "wasm32"))]
pub use blstrs::{Bls12, G1Affine, G2Affine, Scalar};

/// Return Scalar(0) in a backend-safe way.
#[inline]
pub fn scalar_zero() -> Scalar {
    #[cfg(target_arch = "wasm32")]
    {
        Scalar::zero()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Scalar::ZERO
    }
}

/// Return Scalar(1) in a backend-safe way.
#[inline]
pub fn scalar_one() -> Scalar {
    #[cfg(target_arch = "wasm32")]
    {
        Scalar::one()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Scalar::ONE
    }
}

/// Canonical encoding/decoding helpers.
/// We define *canonical bytes* = PrimeField::Repr (32 bytes for BLS12-381 Fr),
/// and we treat it as an opaque 32-byte array.
///
/// DO NOT use backend-specific `from_bytes/from_raw` at call sites.

#[inline]
pub fn scalar_from_canonical_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
    let mut repr = <Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(bytes);
    let ct: CtOption<Scalar> = Scalar::from_repr(repr);
    Option::from(ct)
}

#[inline]
pub fn scalar_to_canonical_bytes(s: &Scalar) -> [u8; 32] {
    // Canonical encoding (same intent as bls12_381::Scalar::to_bytes()).
    let repr = s.to_repr();
    let mut out = [0u8; 32];
    out.copy_from_slice(repr.as_ref());
    out
}

#[inline]
pub fn fq_to_engine_scalar(fq: Fq) -> crate::engine::Scalar {
    let repr = fq.to_repr(); // 32 bytes canonical
    let mut b = [0u8; 32];
    b.copy_from_slice(repr.as_ref());
    crate::engine::scalar_from_canonical_bytes(&b)
        .expect("jubjub::Fq must decode into engine::Scalar (same field)")
}

#[cfg(test)]
#[inline]
pub fn engine_scalar_to_fq(s: crate::engine::Scalar) -> Fq {
    let b = crate::engine::scalar_to_canonical_bytes(&s);
    let mut repr = <Fq as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&b);
    Option::from(Fq::from_repr(repr))
        .expect("engine::Scalar must decode into jubjub::Fq")
}