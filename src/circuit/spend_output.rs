use bellman::gadgets::boolean::{Boolean, AllocatedBit};
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use crate::note::Note;
use crate::keys::ProofGenerationKey;
use super::{conditionally_swap_u256, conditionally_swap_u128, u8_vec_into_boolean_vec_le, u8_into_boolean_vec_le, u256_into_boolean_vec_le};
use super::ecc;
use super::pedersen_hash;
use super::blake2s7r;
use super::constants::{
    NOTE_COMMITMENT_RANDOMNESS_GENERATOR, NULLIFIER_POSITION_GENERATOR,
    PROOF_GENERATION_KEY_GENERATOR
};
use bellman::gadgets::{blake2s, Assignment};
use bellman::gadgets::boolean;
use bellman::gadgets::multipack;
use bellman::gadgets::num;
use bellman::gadgets::num::AllocatedNum;
use crate::circuit::constants::{
    VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
    VALUE_COMMITMENT_VALUE_GENERATOR,
};

/// This is an instance of the `Spend` circuit.
pub struct SpendOutput
{
    /// The note a which is being spent
    pub note_a: Option<Note>,
    /// Proof Generation Key for note a which is required for spending
    pub proof_generation_key: Option<ProofGenerationKey>,
    /// The authentication path of the commitment of note a in the tree
    pub auth_path: Vec<Option<([u8; 32], bool)>>,
    // The blinding factor of the net value commitment
    pub rcv: Option<jubjub::Fr>,
    /// The bliding factor multiplier
    pub rcv_mul: Option<u8>,
    // The randomness of the symbol commitment
    pub rscm: Option<jubjub::Fr>,

    /// The note b which is being created
    pub note_b: Option<Note>,

    /// The total amount of all unshielded outputs
    pub value_c: Option<u64>,
    /// hash of tuple list: [(account_a, amount_a), (account_b, amount_b), ...] with value_c = amount_a + amount_b + ...
    pub unshielded_outputs_hash: Option<[u64; 4]>
}

impl Circuit<bls12_381::Scalar> for SpendOutput {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError>
    {

        // Prover witnesses ak (ensures that it's on the curve)
        let ak = ecc::EdwardsPoint::witness(
            cs.namespace(|| "ak"),
            self.proof_generation_key.as_ref().map(|k| k.ak.into()),
        )?;
        // There are no sensible attacks on small order points
        // of ak (that we're aware of!) but it's a cheap check,
        // so we do it.
        ak.assert_not_small_order(cs.namespace(|| "ak not small order"))?;
        // Compute nk = [nsk] ProofGenerationKey
        let nk;
        {
            // Witness nsk as bits
            let nsk = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "nsk"),
                self.proof_generation_key.as_ref().map(|k| k.nsk),
            )?;

            // NB: We don't ensure that the bit representation of nsk
            // is "in the field" (jubjub::Fr) because it's not used
            // except to demonstrate the prover knows it. If they know
            // a congruency then that's equivalent.

            // Compute nk = [nsk] ProvingPublicKey
            nk = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of nk"),
                &PROOF_GENERATION_KEY_GENERATOR,
                &nsk,
            )?;
        }
        // This is the "viewing key" preimage for CRH^ivk
        let mut ivk_preimage = vec![];
        // Place ak in the preimage for CRH^ivk
        ivk_preimage.extend(ak.repr(cs.namespace(|| "representation of ak"))?);
        // This is the nullifier preimage for PRF^nf
        let mut nf_preimage = vec![];
        // Extend ivk and nf preimages with the representation of nk.
        {
            let repr_nk = nk.repr(cs.namespace(|| "representation of nk"))?;

            ivk_preimage.extend(repr_nk.iter().cloned());
            nf_preimage.extend(repr_nk);
        }
        assert_eq!(ivk_preimage.len(), 512);
        assert_eq!(nf_preimage.len(), 256);
        // Compute the incoming viewing key ivk
        let mut ivk = blake2s::blake2s(
            cs.namespace(|| "computation of ivk"),
            &ivk_preimage,
            crate::constants::CRH_IVK_PERSONALIZATION,
        )?;
        // drop_5 to ensure it's in the field
        ivk.truncate(jubjub::Fr::CAPACITY as usize);
        // Witness g_d, checking that it's on the curve.
        let g_d = {
            ecc::EdwardsPoint::witness(
                cs.namespace(|| "witness g_d"),
                self.note_a.as_ref().map(|a| {
                    a.address().diversifier()
                        .g_d()
                        .expect("checked at construction")
                        .into()
                }),
            )?
        };
        // Check that g_d is not small order. Technically, this check
        // is already done in the Output circuit, and this proof ensures
        // g_d is bound to a product of that check, but for defense in
        // depth let's check it anyway. It's cheap.
        g_d.assert_not_small_order(cs.namespace(|| "g_d not small order"))?;

        // Compute pk_d = g_d^ivk
        let pk_d = g_d.mul(cs.namespace(|| "compute pk_d"), &ivk)?;

        // Compute note preimage:
        // (account | value | symbol | code | g_d | pk_d | rho)
        let mut note_a_preimage = vec![];
        // Compute symbol preimage:
        // (symbol | code)
        let mut symbol_preimage = vec![];

        // note a account to boolean bit vector
        let account_a_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "account_a"),
            self.note_a.as_ref().map(|a| {
                a.account().raw()
            })
        )?;
        note_a_preimage.extend(account_a_bits.clone());
        // note a value to boolean bit vector
        let value_a_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "value_a"),
            self.note_a.as_ref().map(|a| {
                a.amount()
            })
        )?;
        note_a_preimage.extend(value_a_bits.clone());
        // Compute note a's value as a linear combination of the bits.
        let mut value_a_num = num::Num::zero();
        let mut coeff = bls12_381::Scalar::one();
        for bit in &value_a_bits
        {
            value_a_num = value_a_num.add_bool_with_coeff(CS::one(), bit, coeff);
            coeff = coeff.double();
        }

        // notes' symbol to boolean bit vector
        let symbol_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "symbol"),
            self.note_a.as_ref().map(|a| {
                a.symbol().raw()
            })
        )?;
        note_a_preimage.extend(symbol_bits.clone());
        symbol_preimage.extend(symbol_bits.clone());
        // notes' code to boolean bit vector
        let code_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "code"),
            self.note_a.as_ref().map(|a| {
                a.code().raw()
            })
        )?;
        note_a_preimage.extend(code_bits.clone());
        symbol_preimage.extend(code_bits.clone());
        // Place g_d_a in the preimage of note a
        note_a_preimage.extend(g_d.repr(cs.namespace(|| "representation of g_d a"))?);
        // Place pk_d_a in the preimage of note a
        note_a_preimage.extend(pk_d.repr(cs.namespace(|| "representation of pk_d a"))?);

        assert_eq!(
            note_a_preimage.len(),
            64 +    // account
            64 +    // value
            64 +    // symbol
            64 +    // code
            256 +   // g_d
            256     // pk_d
        );
        assert_eq!(
            symbol_preimage.len(),
            64 +    // symbol
            64      // code
        );

        // Compute the commitment of note a
        let mut cm_a = pedersen_hash::pedersen_hash(
            cs.namespace(|| "note a content hash"),
            pedersen_hash::Personalization::NoteCommitment,
            &note_a_preimage,
        )?;
        {
            // Booleanize the randomness for the note commitment
            let rcm = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "rcm a"),
                self.note_a.as_ref().map(|a|
                    a.rcm()
                ),
            )?;
            // Compute the note commitment randomness in the exponent
            let rcm = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of commitment randomness a"),
                &NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
                &rcm,
            )?;
            // Randomize the note commitment.
            cm_a = cm_a.add(cs.namespace(|| "randomization of note commitment a"), &rcm)?;
        }

        // Compute the symbol commitment
        let mut scm = pedersen_hash::pedersen_hash(
            cs.namespace(|| "symbol content hash"),
            pedersen_hash::Personalization::SymbolCommitment,
            &symbol_preimage,
        )?;
        {
            // Booleanize the randomness for the symbol commitment
            let srcm = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "srcm"),
                self.rscm.as_ref().map(|a| *a),
            )?;
            // Compute the symbol commitment randomness in the exponent
            let srcm = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of symbol commitment randomness"),
                &NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
                &srcm,
            )?;
            // Randomize the symbol commitment.
            scm = scm.add(cs.namespace(|| "randomization of symbol commitment"), &srcm)?;
        }

        // This will store (least significant bit first)
        // the position of the note in the tree, for use
        // in nullifier computation.
        let mut position_bits = vec![];
        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let mut cur = cm_a.get_u().to_bits_le(cs.namespace(|| "cur into bits"))?.clone();
        cur.push(Boolean::Constant(false));
        assert_eq!(cur.len(), 256);
        // Ascend the merkle tree authentication path
        for (i, e) in self.auth_path.into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));
            // Determines if the current subtree is the "right" leaf at this
            // depth of the tree.
            let cur_is_right = boolean::AllocatedBit::alloc(
                cs.namespace(|| "position bit"),
                e.map(|e| e.1),
            )?;
            // Push this boolean for nullifier computation later
            position_bits.push(boolean::Boolean::from(cur_is_right.clone()).clone());
            // Witness the authentication path element adjacent at this depth.
            let path_element = u8_vec_into_boolean_vec_le(cs.namespace(|| "path element"), e.map(|(v, _)| v))?;
            // Swap the two if the current subtree is on the right
            let (ul, ur) = conditionally_swap_u256(
                cs.namespace(|| "conditional reversal of preimage"),
                &cur,
                &path_element,
                &cur_is_right,
            )?;
            // We don't need to be strict, because the function is
            // collision-resistant. If the prover witnesses a congruency,
            // they will be unable to find an authentication path in the
            // tree with high probability.
            let mut preimage = vec![];
            preimage.extend(ul);
            preimage.extend(ur);
            assert_eq!(preimage.len(), 512);
            // Compute the new subtree value
            cur = blake2s7r::blake2s7r(
                cs.namespace(|| "computation of ivk"),
                &preimage,
                crate::constants::MERKLE_TREE_PERSONALIZATION,
            )?;
        }
        // Expose the anchor
        cur.truncate(254);
        multipack::pack_into_inputs(cs.namespace(|| "anchor"), &cur)?;

        // Compute the cm + g^position for preventing faerie gold attacks
        let mut rho_mix = cm_a;
        {
            // Compute the position in the exponent
            let position = ecc::fixed_base_multiplication(
                cs.namespace(|| "g^position"),
                &NULLIFIER_POSITION_GENERATOR,
                &position_bits,
            )?;

            // Add the position to the commitment
            rho_mix = rho_mix.add(cs.namespace(|| "faerie gold prevention"), &position)?;
        }

        // Let's compute nf = pedersen_hash(nk | rho_mix )
        nf_preimage.extend(rho_mix.repr(cs.namespace(|| "representation of rho"))?);
        //nf_preimage.extend(rho_a_bits);

        assert_eq!(nf_preimage.len(), 512);

        // Compute nf
        let nf = pedersen_hash::pedersen_hash(
            cs.namespace(|| "computation of nullifier pedersen hash"),
            pedersen_hash::Personalization::Nullifier,
            &nf_preimage,
        )?;
        // expose the nullifier
        nf.get_u().inputize(cs.namespace(|| "nullifier"))?;

        // expose the symbol commitment
        scm.get_u().inputize(cs.namespace(|| "symbol commitment"))?;

        // note b account to boolean bit vector
        let account_b_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "account_b"),
            self.note_b.as_ref().map(|b| {
                b.account().raw()
            })
        )?;
        // Compute note b's account as a linear combination of the bits.
        let mut account_b_num = num::Num::zero();
        let mut coeff = bls12_381::Scalar::one();
        for bit in &account_b_bits
        {
            account_b_num = account_b_num.add_bool_with_coeff(CS::one(), bit, coeff);
            coeff = coeff.double();
        }
        // To make sure receiving accounts of shielded transfers are zero, enforce: 0 = account_b * 1
        cs.enforce(
            || "conditionally enforce 0 = account_b * 1",
            |lc| lc + CS::one(),
            |lc| lc + &account_b_num.lc(bls12_381::Scalar::one()),
            |lc| lc,
        );
        // note b value to boolean bit vector
        let value_b_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "value_b"),
            self.note_b.as_ref().map(|b| {
                b.amount()
            })
        )?;
        // Compute note b's value as a linear combination of the bits.
        let mut value_b_num = num::Num::zero();
        let mut coeff = bls12_381::Scalar::one();
        for bit in &value_b_bits
        {
            value_b_num = value_b_num.add_bool_with_coeff(CS::one(), bit, coeff);
            coeff = coeff.double();
        }

        // note c value to boolean bit vector
        let value_c_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "value_c"),
            self.value_c
        )?;
        // Compute note c's value as a linear combination of the bits.
        let mut value_c_num = num::Num::zero();
        let mut coeff = bls12_381::Scalar::one();
        for bit in &value_c_bits
        {
            value_c_num = value_c_num.add_bool_with_coeff(CS::one(), bit, coeff);
            coeff = coeff.double();
        }

        // Compute note b preimage:
        // (account | value | symbol | code | g_d | pk_d | rho)
        let mut note_b_preimage = vec![];
        note_b_preimage.extend(account_b_bits);
        note_b_preimage.extend(value_b_bits);
        note_b_preimage.extend(symbol_bits.clone());
        note_b_preimage.extend(code_bits.clone());
        // Witness g_d b, checking that it's on the curve.
        let g_d_b = {
            ecc::EdwardsPoint::witness(
                cs.namespace(|| "witness g_d b"),
                self.note_b.as_ref().map(|b| {
                    b.address().diversifier()
                        .g_d()
                        .expect("checked at construction")
                        .into()
                }),
            )?
        };
        g_d_b.assert_not_small_order(cs.namespace(|| "g_d b not small order"))?;
        note_b_preimage.extend(g_d_b.repr(cs.namespace(|| "representation of g_d b"))?);
        // Witness pk_d b, checking that it's on the curve.
        let pk_d_b = {
            ecc::EdwardsPoint::witness(
                cs.namespace(|| "witness pk_d b"),
                self.note_b.as_ref().map(|b| {
                    b.address().pk_d().inner().into()
                }),
            )?
        };
        pk_d_b.assert_not_small_order(cs.namespace(|| "pk_d b not small order"))?;
        note_b_preimage.extend(pk_d_b.repr(cs.namespace(|| "representation of pk_d b"))?);

        assert_eq!(
            note_b_preimage.len(),
            64 +    // account
            64 +    // value
            64 +    // symbol
            64 +    // code
            256 +   // g_d
            256     // pk_d
        );

        // Compute the commitment of note b
        let mut cm_b = pedersen_hash::pedersen_hash(
            cs.namespace(|| "note b content hash"),
            pedersen_hash::Personalization::NoteCommitment,
            &note_b_preimage,
        )?;
        {
            // Booleanize the randomness for the note commitment
            let rcm = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "rcm b"),
                self.note_b.as_ref().map(|b| {
                    b.rcm()
                })
            )?;

            // Compute the note commitment randomness in the exponent
            let rcm = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of commitment randomness b"),
                &NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
                &rcm,
            )?;

            // Randomize the note commitment.
            cm_b = cm_b.add(cs.namespace(|| "randomization of note commitment b"), &rcm)?;
        }
        // Expose note commit b as input
        cm_b.get_u().inputize(cs.namespace(|| "commitment b"))?;

        // determine the following signals:
        // - is note A an NFT?
        // - is the note A being spent greater than the output of the circuit (note B, amount C)?
        // - does note A equal the output of the circuit (note B, amount C)?
        // the net value of the circuit is then exposed as a pedersen commitment: net_value = note_a - (note_b + value_c)
        let is_nft;
        let is_equal;
        let is_greater;
        let net_value;
        let expose_symbol_code;
        match self.note_a.as_ref() {
            Some(note_a) => {
                match self.note_b.as_ref() {
                    Some(note_b) => {
                        match self.value_c.as_ref() {
                            Some(value_c) => {
                                // check if note being spent is an NFT
                                is_nft = Some(note_a.symbol().raw() == 0);
                                let amount_spent = note_b.amount() + value_c;
                                is_equal = Some(note_a.amount() == amount_spent);
                                is_greater = Some(note_a.amount() > amount_spent);
                                net_value = Some(if note_a.amount() > amount_spent { note_a.amount() - amount_spent } else { amount_spent - note_a.amount() });
                                expose_symbol_code = Some(*value_c > 0);
                            },
                            None => {
                                is_nft = None;
                                is_equal = None;
                                is_greater = None;
                                net_value = None;
                                expose_symbol_code = None;
                            }
                        }
                    },
                    None => {
                        is_nft = None;
                        is_equal = None;
                        is_greater = None;
                        net_value = None;
                        expose_symbol_code = None;
                    }
                }
            },
            None => {
                is_nft = None;
                is_equal = None;
                is_greater = None;
                net_value = None;
                expose_symbol_code = None;
            }
        };

        // calculate the pedersen commitment of the net value of this SpendOutput transfer
        // Booleanize the net value into little-endian bit order
        let net_value_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "net_value_bits"),
            net_value
        )?;
        // Compute the net value in the exponent
        let net_value_exp = ecc::fixed_base_multiplication(
            cs.namespace(|| "compute the net value in the exponent"),
            &VALUE_COMMITMENT_VALUE_GENERATOR,
            &net_value_bits,
        )?;
        // Booleanize the randomness. This does not ensure the bit representation is "in the field" because it doesn't matter for security.
        let rcv_bits = boolean::field_into_boolean_vec_le(
            cs.namespace(|| "rcv"),
            self.rcv.as_ref().map(|c| *c),
        )?;
        // Compute the randomness in the exponent
        let rcv_exp = ecc::fixed_base_multiplication(
            cs.namespace(|| "computation of rcv_exp"),
            &VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
            &rcv_bits,
        )?;
        // Booleanize the randomness multiplier.
        let rcv_mul_bits = u8_into_boolean_vec_le(
            cs.namespace(|| "rcv_mul"),
            self.rcv_mul
        )?;
        // multiply the exponentiated randomness by rcv_mul
        let final_rcv = rcv_exp.mul(cs.namespace(|| "multiplication of rcv_exp"), &rcv_mul_bits)?;
        // Compute the Pedersen commitment to the net value by adding the final randomness
        let cv_net = net_value_exp.add(cs.namespace(|| "computation of cv_net"), &final_rcv)?;
        // Expose the commitment as an input to the circuit
        cv_net.inputize(cs.namespace(|| "cv_net"))?;

        let is_nft_bit = AllocatedBit::alloc(cs.namespace(|| "is_nft bit"), is_nft)?;
        let is_nft_num = num::Num::zero().add_bool_with_coeff(CS::one(), &Boolean::from(is_nft_bit.clone()), bls12_381::Scalar::one());
        let is_equal_bit = AllocatedBit::alloc(cs.namespace(|| "is_equal bit"), is_equal)?;
        let is_greater_bit = AllocatedBit::alloc(cs.namespace(|| "is_greater bit"), is_greater)?;
        let expose_symbol_code_bit = AllocatedBit::alloc(cs.namespace(|| "expose_symbol_code bit"), expose_symbol_code)?;

        // To prevent NFTs from being 'split', make sure that in case of NFT either B or C is zero
        // create helper signals for A, B and C with is_nft_bit acting as chip-enable signal
        let is_nft_anum = AllocatedNum::alloc(cs.namespace(|| "is_nft_anum"), || Ok(*is_nft_num.get_value().get()?))?;
        let value_a_anum = AllocatedNum::alloc(cs.namespace(|| "value_a_anum"), || Ok(*value_a_num.get_value().get()?))?;
        let value_b_anum = AllocatedNum::alloc(cs.namespace(|| "value_b_anum"), || Ok(*value_b_num.get_value().get()?))?;
        let value_c_anum = AllocatedNum::alloc(cs.namespace(|| "value_c_anum"), || Ok(*value_c_num.get_value().get()?))?;
        let a_mul_nft = value_a_anum.mul(cs.namespace(|| "a_mul_nft"), &is_nft_anum)?;
        let b_mul_nft = value_b_anum.mul(cs.namespace(|| "b_mul_nft"), &is_nft_anum)?;
        let c_mul_nft = value_c_anum.mul(cs.namespace(|| "c_mul_nft"), &is_nft_anum)?;
        // enforce A = B xor C <=> (2*B) * C = B + C - A 
        // source: https://github.com/zcash-hackworks/design-of-sapling-book/blob/master/zksnarks/r1cs.md
        cs.enforce(
            || "conditionally enforce nft A = B xor C",
            |lc| lc + b_mul_nft.get_variable() + b_mul_nft.get_variable(),
            |lc| lc + c_mul_nft.get_variable(),
            |lc| lc + b_mul_nft.get_variable() + c_mul_nft.get_variable() - a_mul_nft.get_variable(),
        );

        // pack (value_c | symbol | code | vcm_gt | vcm_eq) as public inputs
        // expose symbol & code only if value_c or value_b are greater zero
        let mut symbol_code_bits = vec![];
        symbol_code_bits.extend(symbol_bits);
        symbol_code_bits.extend(code_bits);
        let symbol_bits_zero = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "symbol zero"),
            Some(0)
        )?;
        let code_bits_zero = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "code zero"),
            Some(0)
        )?;
        let mut symbol_code_bits_zero = vec![];
        symbol_code_bits_zero.extend(symbol_bits_zero);
        symbol_code_bits_zero.extend(code_bits_zero);
        let (symbol_code_bits, _) = conditionally_swap_u128(
            cs.namespace(|| "conditional swap of symbol_code_bits"),
            &symbol_code_bits_zero,
            &symbol_code_bits,
            &expose_symbol_code_bit,
        )?;
        let mut inputs7_bits = vec![];
        inputs7_bits.extend(value_c_bits);
        inputs7_bits.extend(symbol_code_bits);
        inputs7_bits.extend(vec![Boolean::from(is_greater_bit)]);
        inputs7_bits.extend(vec![Boolean::from(is_equal_bit)]);
        multipack::pack_into_inputs(cs.namespace(|| "pack inputs7 contents"), &inputs7_bits)?;

        // unshielded outputs hash to boolean bit vector
        let mut unshielded_outputs_hash_bits = u256_into_boolean_vec_le(
            cs.namespace(|| "unshielded_outputs_hash"),
            self.unshielded_outputs_hash
        )?;
        // erase MSB (truncate to 254)
        unshielded_outputs_hash_bits.truncate(254);
        multipack::pack_into_inputs(cs.namespace(|| "pack inputs8 contents"), &unshielded_outputs_hash_bits)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests
{
    use bls12_381::Scalar;
    use group::Curve;
    use rand::rngs::OsRng;
    use bellman::gadgets::test::TestConstraintSystem;
    use bellman::gadgets::multipack;
    use bellman::Circuit;
    use bellman::groth16::generate_random_parameters;
    use bls12_381::Bls12;
    use crate::contract::AffineVerifyingKeyBytesLE;
    use crate::eosio::Asset;
    use crate::eosio::Name;
    use crate::note::Note;
    use crate::note::Rseed;
    use crate::note::nullifier::ExtractedNullifier;
    use crate::constants::MERKLE_TREE_DEPTH;
    use super::SpendOutput;
    use crate::value::{ValueCommitTrapdoor, ValueCommitment};
    use std::fs;
    use std::fs::File;
    use std::ops::Add;
    use crate::keys::{SpendingKey, FullViewingKey};
    use crate::spec::windowed_pedersen_commit;
    use crate::pedersen_hash::Personalization;
    use crate::spec::extract_p;
    use crate::blake2s7r::Params as Blake2s7rParams;
    use ff::PrimeField;
    use core::iter;
    use bitvec::{array::BitArray, order::Lsb0};

    #[test]
    fn test_spendoutput_circuit()
    {
        let mut rng = OsRng.clone();
        let mut cs = TestConstraintSystem::new();

        // Alice' key material
        let sk_alice = SpendingKey::from_seed(b"This is Alice seed string! Usually this is just a listing of words. Here we just use sentences.");
        let fvk_alice = FullViewingKey::from_spending_key(&sk_alice);
        let sender = fvk_alice.default_address().1;

        let note_a = Note::from_parts(
            0,
            sender,
            Name(0),
            Asset::from_string(&"10.0000 EOS".to_string()).unwrap(),
            Name::from_string(&"eosio.token".to_string()).unwrap(),
            Rseed([42; 32]),
            [0; 512]
        );

        let auth_path = vec![
            Some((hex::decode("0100000000000000000000000000000000000000000000000000000000000000").unwrap().try_into().unwrap(), false)),
            Some((hex::decode("322eb027eb8aee02f2c996a31912d1ae05e251c597ae9bbd5c819b71f080bce9").unwrap().try_into().unwrap(), false)),
            Some((hex::decode("d492e18b60152bd5001335141d8ff86912c9ccd988a8409fec5316ba36df98cc").unwrap().try_into().unwrap(), false))
        ];
        let mut position = 0u64;
        let mut cur = note_a.commitment().to_bytes();

        for (i, val) in auth_path.clone().into_iter().enumerate() {
            let (uncle, b) = val.unwrap();

            let mut lhs = cur;
            let mut rhs = uncle;

            if b {
                ::std::mem::swap(&mut lhs, &mut rhs);
            }
            
            cur = Blake2s7rParams::new()
                .hash_length(32)
                .personal(crate::constants::MERKLE_TREE_PERSONALIZATION)
                .to_state()
                .update(&lhs)
                .update(&rhs)
                .finalize()
                .as_bytes()
                .try_into()
                .expect("output length is correct");

            if b {
                position |= 1 << i;
            }
        }
        // erase MSB (truncate to 254)
        let mut anchor = multipack::bytes_to_bits_le(&cur);
        anchor.truncate(254);
        let anchor = multipack::compute_multipacking(&anchor);
        assert_eq!(anchor.len(), 1);

        let nf = note_a.nullifier(&fvk_alice.nk, position);
        let nf = ExtractedNullifier::from(nf);

        let value_c = 50000u64;
        let unshielded_outputs_hash = [0; 4];
        
        let note_b = Note::from_parts(
            0,
            sender,
            Name(0),
            Asset::from_string(&"11.0000 EOS".to_string()).unwrap(),
            Name::from_string(&"eosio.token".to_string()).unwrap(),
            Rseed([42; 32]),
            [0; 512]
        );

        let rscm = Rseed([21; 32]);
        let scm = windowed_pedersen_commit(
            Personalization::SymbolCommitment,
            iter::empty()
                .chain(BitArray::<_, Lsb0>::new(note_a.symbol().raw().to_le_bytes()).iter().by_vals())
                .chain(BitArray::<_, Lsb0>::new(note_a.code().raw().to_le_bytes()).iter().by_vals()),
                rscm.rcm().0
        );
        let scm = extract_p(&scm);

        let rcv = ValueCommitTrapdoor::random(&mut rng);
        let value_spend = note_b.amount() + value_c;
        let net_value = if note_a.amount() > value_spend { note_a.amount() - value_spend } else { value_spend - note_a.amount() };
        // add one zero value commitment in order to test multiplying rcv by 5 inside the circuit (i.e. setting rcv_mul to 5)
        let cv_net = ValueCommitment::derive(net_value, rcv.clone()).add(&ValueCommitment::derive(0, rcv.clone())).add(&ValueCommitment::derive(0, rcv.clone())).add(&ValueCommitment::derive(0, rcv.clone())).add(&ValueCommitment::derive(0, rcv.clone()));
        let cv_gt = note_a.amount() > value_spend;
        let cv_eq = note_a.amount() == value_spend;

        let instance = SpendOutput {
            note_a: Some(note_a.clone()),
            proof_generation_key: Some(sk_alice.proof_generation_key()),
            auth_path: auth_path.clone(),
            rcv: Some(rcv.inner()),
            rcv_mul: Some(5),
            rscm: Some(rscm.rcm().0),
            note_b: Some(note_b.clone()),
            value_c: Some(value_c),
            unshielded_outputs_hash: Some(unshielded_outputs_hash)
        };

        let mut symbol_code = [0; 16];
        if value_c > 0
        {
            symbol_code[0..8].copy_from_slice(&note_a.symbol().raw().to_le_bytes());
            symbol_code[8..16].copy_from_slice(&note_a.code().raw().to_le_bytes());
        }

        let mut inputs7 = [0; 25];
        inputs7[0..8].copy_from_slice(&value_c.to_le_bytes());
        inputs7[8..24].copy_from_slice(&symbol_code);
        inputs7[24] = if cv_gt {1} else {0} | (if cv_eq {1} else {0} << 1);
        println!("{}", hex::encode(inputs7));
        let inputs7 = multipack::bytes_to_bits_le(&inputs7);
        let inputs7_: Vec<Scalar> = multipack::compute_multipacking(&inputs7);
        assert_eq!(inputs7_.len(), 1);
        let mut inputs7 = vec![];
        inputs7.extend(inputs7_.clone());

        let mut inputs8 = [0; 32];
        inputs8[0..8].copy_from_slice(&unshielded_outputs_hash[0].to_le_bytes());
        inputs8[8..16].copy_from_slice(&unshielded_outputs_hash[1].to_le_bytes());
        inputs8[16..24].copy_from_slice(&unshielded_outputs_hash[2].to_le_bytes());
        inputs8[24..32].copy_from_slice(&unshielded_outputs_hash[3].to_le_bytes());
        let mut inputs8 = multipack::bytes_to_bits_le(&inputs8);
        inputs8.truncate(254);
        let inputs8_: Vec<Scalar> = multipack::compute_multipacking(&inputs8);
        assert_eq!(inputs8_.len(), 1);
        let mut inputs8 = vec![];
        inputs8.extend(inputs8_.clone());

        instance.synthesize(&mut cs).unwrap();
        println!("num constraints: {}", cs.num_constraints());
        
        assert!(cs.is_satisfied());
        assert_eq!(cs.get("randomization of note commitment a/u3/num").to_repr(), note_a.commitment().to_bytes());
        assert_eq!(cs.get_input(0, "ONE"), bls12_381::Scalar::one());
        assert_eq!(cs.get_input(1, "anchor/input 0"), anchor[0]);
        assert_eq!(cs.get_input(2, "nullifier/input variable").to_repr(), nf.to_bytes());
        assert_eq!(cs.get_input(3, "symbol commitment/input variable").to_repr(), scm.to_bytes());
        assert_eq!(cs.get_input(4, "commitment b/input variable").to_repr(), note_b.commitment().to_bytes());
        assert_eq!(cs.get_input(5, "cv_net/u/input variable"), cv_net.as_inner().to_affine().get_u());
        assert_eq!(cs.get_input(6, "cv_net/v/input variable"), cv_net.as_inner().to_affine().get_v());
        assert_eq!(cs.get_input(7, "pack inputs7 contents/input 0"), inputs7[0]);
        assert_eq!(cs.get_input(8, "pack inputs8 contents/input 0"), inputs8[0]);
    }

    #[test]
    fn generate_and_write_params()
    {
        let instance = SpendOutput {
            note_a: None,
            proof_generation_key: None,
            auth_path: vec![None; MERKLE_TREE_DEPTH],
            rcv: None,
            rcv_mul: None,
            rscm: None,
            note_b: None,
            value_c: None,
            unshielded_outputs_hash: None
        };
        let params = generate_random_parameters::<Bls12, _, _>(instance, &mut OsRng).unwrap();
        let f = File::create("params_spendoutput.bin").unwrap();
        params.write(f).unwrap();
        let f = File::create("vk_spendoutput.bin").unwrap();
        params.vk.write(f).unwrap();
        let vk_affine_bytes = AffineVerifyingKeyBytesLE::from(params.vk);
        let res = fs::write("vk_spendoutput.hex", hex::encode(vk_affine_bytes.0));
        assert!(res.is_ok());
    }
}

