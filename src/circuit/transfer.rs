use bellman::gadgets::boolean::Boolean;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use crate::note::Note;
use crate::{
    address::Address,
    keys::ProofGenerationKey,
};

use super::{OrExt, conditionally_swap_u256, u8_vec_into_boolean_vec_le};
use super::ecc;
use super::pedersen_hash;
use super::blake2s7r;
use super::constants::{
    NOTE_COMMITMENT_RANDOMNESS_GENERATOR, NULLIFIER_POSITION_GENERATOR,
    PROOF_GENERATION_KEY_GENERATOR
};
use bellman::gadgets::blake2s;
use bellman::gadgets::boolean;
use bellman::gadgets::multipack;
use bellman::gadgets::num;

/// This is an instance of the `Transfer` circuit.
pub struct Transfer
{
    /// The note a which is being spent
    pub note_a: Option<Note>,
    /// Proof Generation Key for note a which is required for spending
    pub proof_generation_key: Option<ProofGenerationKey>,
    /// The authentication path of the commitment of note a in the tree
    pub auth_path: Vec<Option<([u8; 32], bool)>>,

    /// The value of note b
    pub value_b: Option<u64>,
    /// The payment address of note b
    pub address_b: Option<Address>,
    /// The randomness of the commitment of note b
    pub rcm_b: Option<jubjub::Fr>,

    /// The value of note c
    pub value_c: Option<u64>,
    /// The payment address of note c
    pub address_c: Option<Address>,
    /// The randomness of the commitment of note b
    pub rcm_c: Option<jubjub::Fr>,
}

impl Circuit<bls12_381::Scalar> for Transfer
{
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
        // (value | symbol | contract | g_d | pk_d | rho)
        let mut note_a_preimage = vec![];

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

        // create NFT bit: if symbol == 0 (i.e. if no bit in symbol_bits is set) then NFT = 1 else NFT = 0
        let nft = symbol_bits.clone().into_iter().enumerate().fold(
            Boolean::Constant(false), |acc, (i, bit)| <Boolean as OrExt>::or(
                cs.namespace(|| format!("symbol bits or {}", i)),
                &acc,
                &bit
            ).unwrap()
        ).not();

        // notes' contract to boolean bit vector
        let contract_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "contract"),
            self.note_a.as_ref().map(|a| {
                a.contract().raw()
            })
        )?;
        note_a_preimage.extend(contract_bits.clone());

        // Place g_d_a in the preimage of note a
        note_a_preimage.extend(g_d.repr(cs.namespace(|| "representation of g_d a"))?);
        // Place pk_d_a in the preimage of note a
        note_a_preimage.extend(pk_d.repr(cs.namespace(|| "representation of pk_d a"))?);
        // Place rho_a in the preimage of note a
        //let rho_a_bits = boolean::field_into_boolean_vec_le(
        //    cs.namespace(|| "rho a"),
        //    self.note_a.as_ref().map(|a| {
        //        a.rho().0
        //    })
        //)?;
        //note_a_preimage.extend(rho_a_bits.clone());

        assert_eq!(
            note_a_preimage.len(),
            64 +    // value
            64 +    // symbol
            64 +    // contract
            256 +   // g_d
            256     // pk_d
            //255     // rho
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

        // Let's compute nf = pedersen_hash(nk | rho_mix)
        nf_preimage.extend(rho_mix.repr(cs.namespace(|| "representation of rho"))?);
        //nf_preimage.extend(rho_a_bits);

        assert_eq!(nf_preimage.len(), 512);

        // Compute nf
        let nf = pedersen_hash::pedersen_hash(
            cs.namespace(|| "computation of nullifier pedersen hash"),
            pedersen_hash::Personalization::Nullifier,
            &nf_preimage,
        )?;

        nf.get_u().inputize(cs.namespace(|| "nullifier"))?;

        // note b value to boolean bit vector
        let value_b_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "value_b"),
            self.value_b
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

        // Enforce: A = B + C
        cs.enforce(
            || "conditionally enforce A = B + C",
            |lc| lc + &value_b_num.lc(bls12_381::Scalar::one()) + &value_c_num.lc(bls12_381::Scalar::one()),
            |lc| lc + CS::one(),
            |lc| lc + &value_a_num.lc(bls12_381::Scalar::one()),
        );

        // To prevent NFTs from being 'split', enforce: 0 = NFT * C
        cs.enforce(
            || "conditionally enforce 0 = NFT * C",
            |lc| lc + &value_c_num.lc(bls12_381::Scalar::one()),
            |lc| lc + &nft.lc(CS::one(), bls12_381::Scalar::one()),
            |lc| lc,
        );

        // Compute note b preimage:
        // (value | symbol | contract | g_d | pk_d | rho)
        let mut note_b_preimage = vec![];
        note_b_preimage.extend(value_b_bits);
        note_b_preimage.extend(symbol_bits.clone());
        note_b_preimage.extend(contract_bits.clone());

        // Witness g_d b, checking that it's on the curve.
        let g_d_b = {
            ecc::EdwardsPoint::witness(
                cs.namespace(|| "witness g_d b"),
                self.address_b.as_ref().map(|a| {
                    a.diversifier()
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
                self.address_b.as_ref().map(|a| {
                    a.pk_d().inner().into()
                }),
            )?
        };
        pk_d_b.assert_not_small_order(cs.namespace(|| "pk_d b not small order"))?;
        note_b_preimage.extend(pk_d_b.repr(cs.namespace(|| "representation of pk_d b"))?);

        // rho b is set to the nullifier of note a
        //let nf_bits = boolean::field_into_boolean_vec_le(
        //    cs.namespace(|| "nf bits"),
        //    nf.get_u().get_value()
        //)?;
        //note_b_preimage.extend(nf_bits.clone());

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
                self.rcm_b,
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

        // Compute note c preimage:
        // (value | symbol | contract | g_d | pk_d | rho)
        let mut note_c_preimage = vec![];
        note_c_preimage.extend(value_c_bits);
        note_c_preimage.extend(symbol_bits);
        note_c_preimage.extend(contract_bits);

        // Witness g_d c, checking that it's on the curve.
        let g_d_c = {
            ecc::EdwardsPoint::witness(
                cs.namespace(|| "witness g_d c"),
                self.address_c.as_ref().map(|a| {
                    a.diversifier()
                        .g_d()
                        .expect("checked at construction")
                        .into()
                }),
            )?
        };
        g_d_c.assert_not_small_order(cs.namespace(|| "g_d c not small order"))?;
        note_c_preimage.extend(g_d_c.repr(cs.namespace(|| "representation of g_d c"))?);
        
        // Witness pk_d c, checking that it's on the curve.
        let pk_d_c = {
            ecc::EdwardsPoint::witness(
                cs.namespace(|| "witness pk_d c"),
                self.address_c.as_ref().map(|a| {
                    a.pk_d().inner().into()
                }),
            )?
        };
        pk_d_c.assert_not_small_order(cs.namespace(|| "pk_d c not small order"))?;
        note_c_preimage.extend(pk_d_c.repr(cs.namespace(|| "representation of pk_d c"))?);

        // rho c is set to the nullifier of note a
        //note_c_preimage.extend(nf_bits);

        // Compute the commitment of note c
        let mut cm_c = pedersen_hash::pedersen_hash(
            cs.namespace(|| "note c content hash"),
            pedersen_hash::Personalization::NoteCommitment,
            &note_c_preimage,
        )?;
        {
            // Booleanize the randomness for the note commitment
            let rcm = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "rcm c"),
                self.rcm_c,
            )?;

            // Compute the note commitment randomness in the exponent
            let rcm = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of commitment randomness c"),
                &NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
                &rcm,
            )?;

            // Randomize the note commitment.
            cm_c = cm_c.add(cs.namespace(|| "randomization of note commitment c"), &rcm)?;
        }

        // Expose note commit c as input
        cm_c.get_u().inputize(cs.namespace(|| "commitment c"))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests
{
    use crate::note::{Note, nullifier::ExtractedNullifier, Rseed};
    use crate::keys::{SpendingKey, FullViewingKey};
    use crate::eosio::{Name, ExtendedAsset};
    use crate::constants::MERKLE_TREE_DEPTH;
    use bls12_381::Bls12;
    use rand::rngs::OsRng;
    use rand_core::RngCore;
    use bellman::gadgets::test::TestConstraintSystem;
    use super::Transfer;
    use bellman::Circuit;
    use bellman::gadgets::multipack;
    use ff::PrimeField;
    use crate::blake2s7r::Params as Blake2s7rParams;
    use bellman::groth16::{generate_random_parameters, create_random_proof, prepare_verifying_key, verify_proof};
    use bellman::groth16::Parameters;
    use bellman::groth16::VerifyingKey;
    use std::fs::File;
    use hex;
    use crate::contract::AffineProofBytesLE;

    #[test]
    fn test_transfer_circuit()
    {
        let mut rng = OsRng.clone();
        let (sk_a, fvk_a, note_a) = Note::dummy(
            &mut rng,
            None,
            ExtendedAsset::from_string(&"1234567890987654321@atomicassets".to_string())
        );

        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        let auth_path = vec![Some((bytes, rng.next_u32() % 2 != 0)); MERKLE_TREE_DEPTH];
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

        let nf = note_a.nullifier(&fvk_a.nk, position);
        let nf = ExtractedNullifier::from(nf);

        let (_, _, note_b) = Note::dummy(
            &mut rng,
            None,
            ExtendedAsset::from_string(&"1234567890987654321@atomicassets".to_string())
        );
        let (_, _, note_c) = Note::dummy(
            &mut rng,
            None,
            ExtendedAsset::from_string(&"0@atomicassets".to_string())
        );

        let mut cs = TestConstraintSystem::new();

        let instance = Transfer {
            note_a: Some(note_a.clone()),
            proof_generation_key: Some(sk_a.proof_generation_key()),
            auth_path: auth_path.clone(),
            value_b: Some(note_b.amount()),
            address_b: Some(note_b.address()),
            rcm_b: Some(note_b.rcm()),
            value_c: Some(note_c.amount()),
            address_c: Some(note_c.address()),
            rcm_c: Some(note_c.rcm()),
        };

        instance.synthesize(&mut cs).unwrap();

        assert!(cs.is_satisfied());
        //assert_eq!(cs.num_constraints(), 756028);   // using blake2s, depth 32
        //assert_eq!(cs.num_constraints(), 554364);   // using blake2s7r, depth 32
        //assert_eq!(cs.num_constraints(), 298559);   // using blake2s7r, depth 16
        assert_eq!(cs.num_constraints(), 90710);   // using blake2s7r, depth 3
        //assert_eq!(cs.hash(), "6eb7d6cd759492a4152bcfa0aee0ff8a1a2ab01c37086e16a5852679ba14ff43");  // using blake2s7r, depth 16

        assert_eq!(cs.get("randomization of note commitment a/u3/num").to_repr(), note_a.commitment().to_bytes());

        assert_eq!(cs.num_inputs(), 5);
        assert_eq!(cs.get_input(0, "ONE"), bls12_381::Scalar::one());
        assert_eq!(cs.get_input(1, "anchor/input 0"), anchor[0]);
        assert_eq!(cs.get_input(2, "nullifier/input variable").to_repr(), nf.to_bytes());
        assert_eq!(cs.get_input(3, "commitment b/input variable").to_repr(), note_b.commitment().to_bytes());
        assert_eq!(cs.get_input(4, "commitment c/input variable").to_repr(), note_c.commitment().to_bytes());
    }

    #[test]
    fn generate_and_write_params()
    {
        let instance = Transfer {
            note_a: None,
            proof_generation_key: None,
            auth_path: vec![None; MERKLE_TREE_DEPTH],
            value_b: None,
            address_b: None,
            rcm_b: None,
            value_c: None,
            address_c: None,
            rcm_c: None,
        };
        let params = generate_random_parameters::<Bls12, _, _>(instance, &mut OsRng).unwrap();
        
        let f = File::create("params_transfer.bin").unwrap();
        params.write(f).unwrap();

        let f = File::create("vk_transfer.bin").unwrap();
        params.vk.write(f).unwrap();
    }

    #[test]
    fn prove_and_verify()
    {
        let f = File::open("params_transfer.bin").unwrap();
        let params = Parameters::<Bls12>::read(f, false).unwrap();

        let mut rng = OsRng.clone();
        let (sk_a, fvk_a, note_a) = Note::dummy(
            &mut rng,
            None,
            ExtendedAsset::from_string(&"1234567890987654321@atomicassets".to_string())
        );

        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        let auth_path = vec![Some((bytes, rng.next_u32() % 2 != 0)); MERKLE_TREE_DEPTH];
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

        let nf = note_a.nullifier(&fvk_a.nk, position);
        let nf = ExtractedNullifier::from(nf);

        let (_, _, note_b) = Note::dummy(
            &mut rng,
            None,
            ExtendedAsset::from_string(&"1234567890987654321@atomiassets".to_string())
        );
        let (_, _, note_c) = Note::dummy(
            &mut rng,
            None,
            ExtendedAsset::from_string(&"0@atomiassets".to_string())
        );

        println!("create proof");
        let instance = Transfer {
            note_a: Some(note_a.clone()),
            proof_generation_key: Some(sk_a.proof_generation_key()),
            auth_path: auth_path.clone(),
            value_b: Some(note_b.amount()),
            address_b: Some(note_b.address()),
            rcm_b: Some(note_b.rcm()),
            value_c: Some(note_c.amount()),
            address_c: Some(note_c.address()),
            rcm_c: Some(note_c.rcm()),
        };
        let proof = create_random_proof(instance, &params, &mut OsRng).unwrap();

        let f = File::create("proof_transfer.bin").unwrap();
        proof.write(f).unwrap();

        println!("pack inputs");
        let mut inputs = vec![];
        inputs.push(anchor[0]);
        inputs.push(nf.0);
        inputs.push(note_b.commitment().0);
        inputs.push(note_c.commitment().0);
        // print public inputs
        println!("{}", hex::encode(anchor[0].to_bytes()));
        println!("{}", hex::encode(nf.0.to_bytes()));
        println!("{}", hex::encode(note_b.commitment().0.to_bytes()));
        println!("{}", hex::encode(note_c.commitment().0.to_bytes()));

        println!("verify proof");
        let f = File::open("vk_transfer.bin").unwrap();
        let vk = VerifyingKey::<Bls12>::read(f).unwrap();
        let pvk = prepare_verifying_key(&vk);
        assert!(verify_proof(&pvk, &proof, &inputs).is_ok());
    }

    #[test]
    fn static_prove_and_verify()
    {
        let f = File::open("params_transfer.bin").unwrap();
        let params = Parameters::<Bls12>::read(f, false).unwrap();

        // Alice' key material
        let sk_alice = SpendingKey::from_seed(b"This is Alice seed string! Usually this is just a listing of words. Here we just use sentences.");
        let fvk_alice = FullViewingKey::from_spending_key(&sk_alice);
        let sender = fvk_alice.default_address().1;

        // Bob's key material
        let sk_bob = SpendingKey::from_seed(b"This is Bob's seed string. His seed is a little shorter...");
        let fvk_bob = FullViewingKey::from_spending_key(&sk_bob);
        let recipient = fvk_bob.default_address().1;

        let note_a = Note::from_parts(
            0,
            sender,
            Name(0),
            ExtendedAsset::from_string(&"5000.0000 EOS@eosio.token".to_string()).unwrap(),
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

        let note_b = Note::from_parts(
            0,
            recipient,
            Name(0),
            ExtendedAsset::from_string(&"3000.0000 EOS@eosio.token".to_string()).unwrap(),
            Rseed([42; 32]),
            [0; 512]
        );
        let note_c = Note::from_parts(
            0,
            sender,
            Name(0),
            ExtendedAsset::from_string(&"2000.0000 EOS@eosio.token".to_string()).unwrap(),
            Rseed([42; 32]),
            [0; 512]
        );

        println!("create proof");
        let instance = Transfer {
            note_a: Some(note_a.clone()),
            proof_generation_key: Some(sk_alice.proof_generation_key()),
            auth_path: auth_path.clone(),
            value_b: Some(note_b.amount()),
            address_b: Some(note_b.address()),
            rcm_b: Some(note_b.rcm()),
            value_c: Some(note_c.amount()),
            address_c: Some(note_c.address()),
            rcm_c: Some(note_c.rcm()),
        };
        let proof = create_random_proof(instance, &params, &mut OsRng).unwrap();

        let f = File::create("proof_transfer.bin").unwrap();
        proof.write(f).unwrap();
        println!("{}", AffineProofBytesLE::try_from(proof.clone()).unwrap().to_string());

        println!("pack inputs");
        let mut inputs = vec![];
        inputs.push(anchor[0]);
        inputs.push(nf.0);
        inputs.push(note_b.commitment().0);
        inputs.push(note_c.commitment().0);
        // print public inputs
        println!("{}", hex::encode(anchor[0].to_bytes()));
        println!("{}", hex::encode(nf.0.to_bytes()));
        println!("{}", hex::encode(note_b.commitment().0.to_bytes()));
        println!("{}", hex::encode(note_c.commitment().0.to_bytes()));

        println!("verify proof");
        let f = File::open("vk_transfer.bin").unwrap();
        let vk = VerifyingKey::<Bls12>::read(f).unwrap();
        let pvk = prepare_verifying_key(&vk);
        assert!(verify_proof(&pvk, &proof, &inputs).is_ok());
    }
    
}