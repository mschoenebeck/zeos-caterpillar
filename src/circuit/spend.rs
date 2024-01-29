use bellman::gadgets::boolean::{Boolean, AllocatedBit};
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use crate::note::Note;
use crate::keys::ProofGenerationKey;
use super::{conditionally_swap_u256, u8_vec_into_boolean_vec_le};
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
use crate::circuit::constants::{
    VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
    VALUE_COMMITMENT_VALUE_GENERATOR,
};

/// This is an instance of the `Spend` circuit.
pub struct Spend
{
    /// The note a which is being spent
    pub note_a: Option<Note>,
    /// Proof Generation Key for note a which is required for spending
    pub proof_generation_key: Option<ProofGenerationKey>,
    /// The authentication path of the commitment of note a in the tree
    pub auth_path: Vec<Option<([u8; 32], bool)>>,
    // The blinding factor of the value commitment
    pub rcv: Option<jubjub::Fr>,
    // The randomness of the symbol commitment
    pub rscm: Option<jubjub::Fr>,
}

impl Circuit<bls12_381::Scalar> for Spend
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

        // Compute note a preimage:
        // (account | value | symbol | contract | g_d | pk_d | rho)
        let mut note_a_preimage = vec![];
        // Compute symbol preimage:
        // (symbol | contract)
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
        // notes' contract to boolean bit vector
        let contract_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "contract"),
            self.note_a.as_ref().map(|a| {
                a.contract().raw()
            })
        )?;
        note_a_preimage.extend(contract_bits.clone());
        symbol_preimage.extend(contract_bits.clone());
        // Place g_d_a in the preimage of note a
        note_a_preimage.extend(g_d.repr(cs.namespace(|| "representation of g_d a"))?);
        // Place pk_d_a in the preimage of note a
        note_a_preimage.extend(pk_d.repr(cs.namespace(|| "representation of pk_d a"))?);

        assert_eq!(
            note_a_preimage.len(),
            64 +    // account
            64 +    // value
            64 +    // symbol
            64 +    // contract
            256 +   // g_d
            256     // pk_d
        );
        assert_eq!(
            symbol_preimage.len(),
            64 +    // symbol
            64      // contract
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

        // Let's compute nf = pedersen_hash(nk | rho_mix)
        nf_preimage.extend(rho_mix.repr(cs.namespace(|| "representation of rho"))?);

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

        // determine if this note is an NFT?
        let is_nft;
        match self.note_a.as_ref() {
            Some(note_a) => {
                // check if note being spent is an NFT
                is_nft = Some(note_a.symbol().raw() == 0);
            },
            None => {
                is_nft = None;
            }
        };

        // calculate the pedersen commitment of the value of this Spend
        // Compute the note value in the exponent
        let value_exp = ecc::fixed_base_multiplication(
            cs.namespace(|| "compute the note value in the exponent"),
            &VALUE_COMMITMENT_VALUE_GENERATOR,
            &value_a_bits,
        )?;
        // Booleanize the randomness. This does not ensure the bit representation is "in the field" because it doesn't matter for security.
        let value_rcv = boolean::field_into_boolean_vec_le(
            cs.namespace(|| "value_rcv"),
            self.rcv.as_ref().map(|c| *c),
        )?;
        // Compute the randomness in the exponent
        let value_rcv_exp = ecc::fixed_base_multiplication(
            cs.namespace(|| "computation of value_rcv_exp"),
            &VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
            &value_rcv,
        )?;
        // Compute the Pedersen commitment to the value
        let cv = value_exp.add(cs.namespace(|| "computation of cv"), &value_rcv_exp)?;
        // Expose the commitment as an input to the circuit
        cv.inputize(cs.namespace(|| "commitment point"))?;

        let is_nft_bit = AllocatedBit::alloc(cs.namespace(|| "is_nft bit"), is_nft)?;

        // To prevent NFTs from being 'split', enforce: 0 = is_nft * 1
        cs.enforce(
            || "conditionally enforce 0 = is_nft * 1",
            |lc| lc + CS::one(),
            |lc| lc + is_nft_bit.get_variable(),
            |lc| lc,
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests
{
    use group::Curve;
    use rand::rngs::OsRng;
    use bellman::gadgets::test::TestConstraintSystem;
    use bellman::gadgets::multipack;
    use bellman::Circuit;
    use bellman::groth16::generate_random_parameters;
    use bls12_381::Bls12;
    use crate::constants::MERKLE_TREE_DEPTH;
    use crate::eosio::ExtendedAsset;
    use crate::eosio::Name;
    use crate::note::Note;
    use crate::note::Rseed;
    use crate::note::nullifier::ExtractedNullifier;
    use crate::contract::AffineVerifyingKeyBytesLE;
    use super::Spend;
    use crate::value::{ValueCommitTrapdoor, ValueCommitment};
    use std::fs::File;
    use std::fs;
    use crate::keys::{SpendingKey, FullViewingKey};
    use crate::spec::windowed_pedersen_commit;
    use crate::pedersen_hash::Personalization;
    use crate::spec::extract_p;
    use crate::blake2s7r::Params as Blake2s7rParams;
    use ff::PrimeField;
    use core::iter;
    use bitvec::{array::BitArray, order::Lsb0};

    #[test]
    fn test_spend_circuit()
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
            ExtendedAsset::from_string(&"10.0000 EOS@eosio.token".to_string()).unwrap(),
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

        let srcm = Rseed([21; 32]);
        let scm = windowed_pedersen_commit(
            Personalization::SymbolCommitment,
            iter::empty()
                .chain(BitArray::<_, Lsb0>::new(note_a.symbol().raw().to_le_bytes()).iter().by_vals())
                .chain(BitArray::<_, Lsb0>::new(note_a.contract().raw().to_le_bytes()).iter().by_vals()),
                srcm.rcm().0
        );
        let scm = extract_p(&scm);

        let rcv = ValueCommitTrapdoor::random(&mut rng);
        let cv_net = ValueCommitment::derive(note_a.amount(), rcv.clone());

        let instance = Spend {
            note_a: Some(note_a.clone()),
            proof_generation_key: Some(sk_alice.proof_generation_key()),
            auth_path: auth_path.clone(),
            rcv: Some(rcv.inner()),
            rscm: Some(srcm.rcm().0),
        };

        instance.synthesize(&mut cs).unwrap();
        println!("num constraints: {}", cs.num_constraints());
        
        assert!(cs.is_satisfied());
        assert_eq!(cs.get("randomization of note commitment a/u3/num").to_repr(), note_a.commitment().to_bytes());
        assert_eq!(cs.get_input(0, "ONE"), bls12_381::Scalar::one());
        assert_eq!(cs.get_input(1, "anchor/input 0"), anchor[0]);
        assert_eq!(cs.get_input(2, "nullifier/input variable").to_repr(), nf.to_bytes());
        assert_eq!(cs.get_input(3, "symbol commitment/input variable").to_repr(), scm.to_bytes());
        assert_eq!(cs.get_input(4, "commitment point/u/input variable"), cv_net.as_inner().to_affine().get_u());
        assert_eq!(cs.get_input(5, "commitment point/v/input variable"), cv_net.as_inner().to_affine().get_v());
    }

    #[test]
    fn generate_and_write_params()
    {
        let instance = Spend {
            note_a: None,
            proof_generation_key: None,
            auth_path: vec![None; MERKLE_TREE_DEPTH],
            rcv: None,
            rscm: None,
        };
        let params = generate_random_parameters::<Bls12, _, _>(instance, &mut OsRng).unwrap();
        let f = File::create("params_spend.bin").unwrap();
        params.write(f).unwrap();
        let f = File::create("vk_spend.bin").unwrap();
        params.vk.write(f).unwrap();
        let vk_affine_bytes = AffineVerifyingKeyBytesLE::from(params.vk);
        let res = fs::write("vk_spend.hex", hex::encode(vk_affine_bytes.0));
        assert!(res.is_ok());
    }
}

