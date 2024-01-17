use bellman::gadgets::boolean::{Boolean, AllocatedBit};
use bellman::{ConstraintSystem, SynthesisError};
use ff::PrimeField;

mod ecc;
mod pedersen_hash;
mod blake2s7r;
mod constants;
pub mod mint;
pub mod transfer;
pub mod burn;
pub mod spend_output;
pub mod spend;
pub mod output;

trait OrExt
{
    /// Perform OR over two boolean operands
    fn or<'a, Scalar, CS>(cs: CS, a: &'a Self, b: &'a Self) -> Result<Self, SynthesisError>
    where
        Self: Sized,
        Scalar: PrimeField,
        CS: ConstraintSystem<Scalar>;
}

impl OrExt for Boolean
{
    fn or<'a, Scalar, CS>(cs: CS, a: &'a Self, b: &'a Self) -> Result<Self, SynthesisError>
    where
        Self: Sized,
        Scalar: PrimeField,
        CS: ConstraintSystem<Scalar>,
    {
        match (a, b) {
            // false OR x is always x
            (&Boolean::Constant(false), x) | (x, &Boolean::Constant(false)) => {
                Ok(x.clone())
            }
            // true OR x is always true
            (&Boolean::Constant(true), _) | (_, &Boolean::Constant(true)) => Ok(Boolean::Constant(true)),
            // a OR (NOT b) = NOT((NOT a) AND b) = NOT(b AND (NOT a))
            (&Boolean::Is(ref a), &Boolean::Not(ref b))
            | (&Boolean::Not(ref b), &Boolean::Is(ref a)) => {
                Ok(Boolean::Not(AllocatedBit::and_not(cs, b, a)?))
            }
            // (NOT a) OR (NOT b) = NOT(a AND b)
            (&Boolean::Not(ref a), &Boolean::Not(ref b)) => {
                Ok(Boolean::Not(AllocatedBit::and(cs, a, b)?))
            }
            // a OR b = NOT(a NOR b) 
            (&Boolean::Is(ref a), &Boolean::Is(ref b)) => {
                Ok(Boolean::Not(AllocatedBit::nor(cs, a, b)?))
            }
        }
    }
}

pub fn u8_into_boolean_vec_le<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: Option<u8>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let values = match value {
        Some(ref value) => {
            let mut tmp = Vec::with_capacity(8);

            for i in 0..8 {
                tmp.push(Some(*value >> i & 1 == 1));
            }

            tmp
        }
        None => vec![None; 8],
    };

    let bits = values
        .into_iter()
        .enumerate()
        .map(|(i, b)| {
            Ok(Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("bit {}", i)),
                b,
            )?))
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    Ok(bits)
}

pub fn u256_into_boolean_vec_le<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: Option<[u64; 4]>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let values = match value {
        Some(ref value) => {
            let mut tmp = Vec::with_capacity(256);

            for i in 0..64 {
                tmp.push(Some(value[0] >> i & 1 == 1));
            }
            for i in 0..64 {
                tmp.push(Some(value[1] >> i & 1 == 1));
            }
            for i in 0..64 {
                tmp.push(Some(value[2] >> i & 1 == 1));
            }
            for i in 0..64 {
                tmp.push(Some(value[3] >> i & 1 == 1));
            }

            tmp
        }
        None => vec![None; 256],
    };

    let bits = values
        .into_iter()
        .enumerate()
        .map(|(i, b)| {
            Ok(Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("bit {}", i)),
                b,
            )?))
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    Ok(bits)
}

/// Swaps two 256-bit blobs conditionally
pub fn conditionally_swap_u256<Scalar, CS>(
    mut cs: CS,
    lhs: &Vec<Boolean>,
    rhs: &Vec<Boolean>,
    condition: &AllocatedBit,
) -> Result<(Vec<Boolean>, Vec<Boolean>), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(lhs.len(), 256);
    assert_eq!(rhs.len(), 256);

    let mut new_lhs = vec![];
    let mut new_rhs = vec![];

    for (i, (lhs, rhs)) in lhs.iter().zip(rhs.iter()).enumerate() {
        let cs = &mut cs.namespace(|| format!("bit {}", i));

        let x = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| "x"),
            condition
                .get_value()
                .and_then(|v| if v { rhs.get_value() } else { lhs.get_value() }),
        )?);

        // x = (1-condition)lhs + (condition)rhs
        // x = lhs - lhs(condition) + rhs(condition)
        // x - lhs = condition (rhs - lhs)
        // if condition is zero, we don't swap, so
        //   x - lhs = 0
        //   x = lhs
        // if condition is one, we do swap, so
        //   x - lhs = rhs - lhs
        //   x = rhs
        cs.enforce(
            || "conditional swap for x",
            |lc| lc + &rhs.lc(CS::one(), Scalar::ONE) - &lhs.lc(CS::one(), Scalar::ONE),
            |lc| lc + condition.get_variable(),
            |lc| lc + &x.lc(CS::one(), Scalar::ONE) - &lhs.lc(CS::one(), Scalar::ONE),
        );

        let y = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| "y"),
            condition
                .get_value()
                .and_then(|v| if v { lhs.get_value() } else { rhs.get_value() }),
        )?);

        // y = (1-condition)rhs + (condition)lhs
        // y - rhs = condition (lhs - rhs)
        cs.enforce(
            || "conditional swap for y",
            |lc| lc + &lhs.lc(CS::one(), Scalar::ONE) - &rhs.lc(CS::one(), Scalar::ONE),
            |lc| lc + condition.get_variable(),
            |lc| lc + &y.lc(CS::one(), Scalar::ONE) - &rhs.lc(CS::one(), Scalar::ONE),
        );

        new_lhs.push(x);
        new_rhs.push(y);
    }

    Ok((new_lhs, new_rhs))
}

/// Swaps two 128-bit blobs conditionally
pub fn conditionally_swap_u128<Scalar, CS>(
    mut cs: CS,
    lhs: &Vec<Boolean>,
    rhs: &Vec<Boolean>,
    condition: &AllocatedBit,
) -> Result<(Vec<Boolean>, Vec<Boolean>), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(lhs.len(), 128);
    assert_eq!(rhs.len(), 128);

    let mut new_lhs = vec![];
    let mut new_rhs = vec![];

    for (i, (lhs, rhs)) in lhs.iter().zip(rhs.iter()).enumerate() {
        let cs = &mut cs.namespace(|| format!("bit {}", i));

        let x = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| "x"),
            condition
                .get_value()
                .and_then(|v| if v { rhs.get_value() } else { lhs.get_value() }),
        )?);

        // x = (1-condition)lhs + (condition)rhs
        // x = lhs - lhs(condition) + rhs(condition)
        // x - lhs = condition (rhs - lhs)
        // if condition is zero, we don't swap, so
        //   x - lhs = 0
        //   x = lhs
        // if condition is one, we do swap, so
        //   x - lhs = rhs - lhs
        //   x = rhs
        cs.enforce(
            || "conditional swap for x",
            |lc| lc + &rhs.lc(CS::one(), Scalar::ONE) - &lhs.lc(CS::one(), Scalar::ONE),
            |lc| lc + condition.get_variable(),
            |lc| lc + &x.lc(CS::one(), Scalar::ONE) - &lhs.lc(CS::one(), Scalar::ONE),
        );

        let y = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| "y"),
            condition
                .get_value()
                .and_then(|v| if v { lhs.get_value() } else { rhs.get_value() }),
        )?);

        // y = (1-condition)rhs + (condition)lhs
        // y - rhs = condition (lhs - rhs)
        cs.enforce(
            || "conditional swap for y",
            |lc| lc + &lhs.lc(CS::one(), Scalar::ONE) - &rhs.lc(CS::one(), Scalar::ONE),
            |lc| lc + condition.get_variable(),
            |lc| lc + &y.lc(CS::one(), Scalar::ONE) - &rhs.lc(CS::one(), Scalar::ONE),
        );

        new_lhs.push(x);
        new_rhs.push(y);
    }

    Ok((new_lhs, new_rhs))
}

pub fn u8_vec_into_boolean_vec_le<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    vector: Option<[u8; 32]>,
) -> Result<Vec<Boolean>, SynthesisError>
{
    let values = match vector {
        Some(ref vector) => {
            let mut tmp = Vec::with_capacity(8*32);

            for v in vector{
                for i in 0..8 {
                    tmp.push(Some(v >> i & 1 == 1));
                }
            }
            tmp
        }
        None => vec![None; 8 * 32],
    };

    let bits = values
        .into_iter()
        .enumerate()
        .map(|(i, b)| {
            Ok(Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("bit {}", i)),
                b,
            )?))
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    Ok(bits)
}
