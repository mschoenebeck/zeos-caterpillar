use bellman::gadgets::{boolean::AllocatedBit, num::Num};
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use crate::note::Note;
use super::ecc;
use super::pedersen_hash;
use super::constants::NOTE_COMMITMENT_RANDOMNESS_GENERATOR;
use bellman::gadgets::boolean;
use bellman::gadgets::num;
use crate::circuit::constants::{
    VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
    VALUE_COMMITMENT_VALUE_GENERATOR,
};

/// This is an instance of the `Spend` circuit.
pub struct Output
{
    // The blinding factor of the net value commitment
    pub rcv: Option<jubjub::Fr>,
    // The randomness of the symbol commitment
    pub rscm: Option<jubjub::Fr>,

    /// The note b which is being created
    pub note_b: Option<Note>,
}

impl Circuit<bls12_381::Scalar> for Output
{
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError>
    {
        // note b's account to boolean bit vector
        let account_b_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "account_b"),
            self.note_b.as_ref().map(|b| {
                b.account().raw()
            })
        )?;
        // Compute accounts's value as a linear combination of the bits.
        let mut account_b_num = Num::zero();
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

        // Compute symbol preimage:
        // (symbol | contract)
        let mut symbol_preimage = vec![];
        // notes' symbol to boolean bit vector
        let symbol_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "symbol"),
            self.note_b.as_ref().map(|b| {
                b.symbol().raw()
            })
        )?;
        symbol_preimage.extend(symbol_bits.clone());
        // notes' contract to boolean bit vector
        let contract_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "contract"),
            self.note_b.as_ref().map(|b| {
                b.contract().raw()
            })
        )?;
        symbol_preimage.extend(contract_bits.clone());
        assert_eq!(
            symbol_preimage.len(),
            64 +    // symbol
            64      // contract
        );

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
        // expose the symbol commitment
        scm.get_u().inputize(cs.namespace(|| "symbol commitment"))?;

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

        // Compute note b preimage:
        // (account | value | symbol | contract | g_d | pk_d)
        let mut note_b_preimage = vec![];
        note_b_preimage.extend(account_b_bits);
        note_b_preimage.extend(value_b_bits.clone());
        note_b_preimage.extend(symbol_bits.clone());
        note_b_preimage.extend(contract_bits.clone());
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
                self.note_b.as_ref().map(|b|
                    b.rcm()
                ),
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

        // determine if this note is an NFT?
        // the net value of the circuit is then exposed as a pedersen commitment: net_value = note_b
        let is_nft;
        match self.note_b.as_ref() {
            Some(note_b) => {
                // check if note being spent is an NFT
                is_nft = Some(note_b.symbol().raw() == 0);
            },
            None => {
                is_nft = None;
            }
        };

        // calculate the pedersen commitment of the net value of this SpendOutput transfer
        // Compute the note value in the exponent
        let value_b_exp = ecc::fixed_base_multiplication(
            cs.namespace(|| "compute the value_b in the exponent"),
            &VALUE_COMMITMENT_VALUE_GENERATOR,
            &value_b_bits,
        )?;
        // Booleanize the randomness. This does not ensure the bit representation is "in the field" because it doesn't matter for security.
        let rcv_bits = boolean::field_into_boolean_vec_le(
            cs.namespace(|| "rcv_bits"),
            self.rcv.as_ref().map(|c| *c),
        )?;
        // Compute the randomness in the exponent
        let rcv_exp = ecc::fixed_base_multiplication(
            cs.namespace(|| "computation of rcv_exp"),
            &VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
            &rcv_bits,
        )?;
        // Compute the Pedersen commitment to the value
        let cv = value_b_exp.add(cs.namespace(|| "computation of cv"), &rcv_exp)?;
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
    use bellman::Circuit;
    use bellman::groth16::generate_random_parameters;
    use bls12_381::Bls12;
    use crate::address::Address;
    use crate::eosio::ExtendedAsset;
    use crate::eosio::Name;
    use crate::note::Note;
    use crate::note::Rseed;
    use crate::contract::AffineVerifyingKeyBytesLE;
    use super::Output;
    use crate::value::{ValueCommitTrapdoor, ValueCommitment};
    use std::fs::File;
    use std::fs;
    use crate::spec::windowed_pedersen_commit;
    use crate::pedersen_hash::Personalization;
    use crate::spec::extract_p;
    use ff::PrimeField;
    use core::iter;
    use bitvec::{array::BitArray, order::Lsb0};

    #[test]
    fn test_output_circuit()
    {
        let mut rng = OsRng.clone();
        let mut cs = TestConstraintSystem::new();
        
        let note_b = Note::from_parts(
            0,
            Address::dummy(&mut rng),
            Name(0),
            ExtendedAsset::from_string(&"11.0000 EOS@eosio.token".to_string()).unwrap(),
            Rseed([42; 32]),
            [0; 512]
        );

        let srcm = Rseed([21; 32]);
        let scm = windowed_pedersen_commit(
            Personalization::SymbolCommitment,
            iter::empty()
                .chain(BitArray::<_, Lsb0>::new(note_b.symbol().raw().to_le_bytes()).iter().by_vals())
                .chain(BitArray::<_, Lsb0>::new(note_b.contract().raw().to_le_bytes()).iter().by_vals()),
                srcm.rcm().0
        );
        let scm = extract_p(&scm);

        let rcv = ValueCommitTrapdoor::random(&mut rng);
        let cv = ValueCommitment::derive(note_b.amount(), rcv.clone());

        let instance = Output {
            rcv: Some(rcv.inner()),
            rscm: Some(srcm.rcm().0),
            note_b: Some(note_b.clone())
        };

        instance.synthesize(&mut cs).unwrap();
        println!("num constraints: {}", cs.num_constraints());
        println!("cs hash: {}", cs.hash());
        
        assert!(cs.is_satisfied());
        assert_eq!(cs.get("randomization of note commitment b/u3/num").to_repr(), note_b.commitment().to_bytes());
        assert_eq!(cs.get_input(0, "ONE"), bls12_381::Scalar::one());
        assert_eq!(cs.get_input(1, "symbol commitment/input variable").to_repr(), scm.to_bytes());
        assert_eq!(cs.get_input(2, "commitment b/input variable").to_repr(), note_b.commitment().to_bytes());
        assert_eq!(cs.get_input(3, "commitment point/u/input variable"), cv.as_inner().to_affine().get_u());
        assert_eq!(cs.get_input(4, "commitment point/v/input variable"), cv.as_inner().to_affine().get_v());
    }

    #[test]
    fn generate_and_write_params()
    {
        let instance = Output {
            rcv: None,
            rscm: None,
            note_b: None
        };
        let params = generate_random_parameters::<Bls12, _, _>(instance, &mut OsRng).unwrap();
        let f = File::create("params_output.bin").unwrap();
        params.write(f).unwrap();
        let f = File::create("vk_output.bin").unwrap();
        params.vk.write(f).unwrap();
        let vk_affine_bytes = AffineVerifyingKeyBytesLE::from(params.vk);
        let res = fs::write("vk_output.hex", hex::encode(vk_affine_bytes.0));
        assert!(res.is_ok());
    }
}

