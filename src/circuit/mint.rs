use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bellman::gadgets::{blake2s, boolean, boolean::Boolean, multipack, num::Num};
use ff::PrimeField;
use crate::{address::Address, keys::ProofGenerationKey};
use super::constants::{NOTE_COMMITMENT_RANDOMNESS_GENERATOR, PROOF_GENERATION_KEY_GENERATOR};
use super::{ecc, pedersen_hash, OrExt};

/// This is an instance of the `Mint` circuit.
pub struct Mint
{
    /// The EOSIO account this note is associated with (Mint: sender, Transfer: 0, Burn: receiver, Auth: == code)
    pub account: Option<u64>,
    /// The amount (FT) or ID (NFT) of the note, 0 if AT
    pub value: Option<u64>,
    /// The symbl of the note, 0 if NFT/AT
    pub symbol: Option<u64>,
    /// The code of issuing smart contract of the note
    pub code: Option<u64>,

    /// The payment address associated with the note
    pub address: Option<Address>,
    /// The randomness of the note commitment
    pub rcm: Option<jubjub::Fr>,

    /// Proof Generation Key for note a which is required for burn auth
    pub proof_generation_key: Option<ProofGenerationKey>,
}

impl Circuit<bls12_381::Scalar> for Mint
{
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError>
    {
        let mut note_preimage = vec![];
        let mut inputs2_bits = vec![];
        let mut inputs3_bits = vec![];

        // note account to boolean bit vector
        let account_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "account"),
            self.account
        )?;
        inputs3_bits.extend(account_bits.clone());

        // note value to boolean bit vector
        let value_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "value"),
            self.value
        )?;
        inputs2_bits.extend(value_bits.clone());

        // note symbol to boolean bit vector
        let symbol_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "symbol"),
            self.symbol
        )?;
        inputs2_bits.extend(symbol_bits.clone());

        // note code to boolean bit vector
        let code_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "code"),
            self.code
        )?;
        inputs2_bits.extend(code_bits.clone());

        // append inputs bits (account, value, symbol, code) to note preimage
        note_preimage.extend(inputs3_bits.clone());
        note_preimage.extend(inputs2_bits.clone());

        // create AUTH bit: if value == 0 && symbol == 0 (i.e. if no bit in value_bits nor in symbol_bits is set) then AUTH = 1 else AUTH = 0
        let mut value_symbol_bits = vec![];
        value_symbol_bits.extend(value_bits.into_iter());
        value_symbol_bits.extend(symbol_bits.into_iter());
        let auth = value_symbol_bits.into_iter().enumerate().fold(
            Boolean::Constant(false), |acc, (i, bit)| <Boolean as OrExt>::or(
                cs.namespace(|| format!("value_symbol bits or {}", i)),
                &acc,
                &bit
            ).unwrap()
        ).not();

        // Witness g_d, checking that it's on the curve.
        let g_d = {
            ecc::EdwardsPoint::witness(
                cs.namespace(|| "witness g_d"),
                self.address.as_ref().map(|a| {
                    a.diversifier()
                        .g_d()
                        .expect("checked at construction")
                        .into()
                }),
            )?
        };
        // Check that g_d is not small order.
        g_d.assert_not_small_order(cs.namespace(|| "g_d not small order"))?;
        // Place g_d in the note
        note_preimage.extend(g_d.repr(cs.namespace(|| "representation of g_d"))?);

        // Witness pk_d, checking that it's on the curve.
        let pk_d = {
            ecc::EdwardsPoint::witness(
                cs.namespace(|| "witness pk_d"),
                self.address.as_ref().map(|a| {
                    a.pk_d().inner().into()
                }),
            )?
        };
        // Check that pk_d is not small order.
        pk_d.assert_not_small_order(cs.namespace(|| "pk_d not small order"))?;
        // Place pk_d in the note
        note_preimage.extend(pk_d.repr(cs.namespace(|| "representation of pk_d"))?);

        // derive pk_d from spending key: in case of auth token it must equal pk_d of address of this note
        // Prover witnesses ak (ensures that it's on the curve)
        let ak = ecc::EdwardsPoint::witness(
            cs.namespace(|| "ak"),
            self.proof_generation_key.as_ref().map(|k| k.ak.into()),
        )?;
        ak.assert_not_small_order(cs.namespace(|| "ak not small order"))?;
        // Compute nk = [nsk] ProofGenerationKey
        let nk;
        {
            // Witness nsk as bits
            let nsk = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "nsk"),
                self.proof_generation_key.as_ref().map(|k| k.nsk),
            )?;
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
        // Extend ivk and nf preimages with the representation of nk.
        {
            let repr_nk = nk.repr(cs.namespace(|| "representation of nk"))?;
            ivk_preimage.extend(repr_nk.iter().cloned());
        }
        assert_eq!(ivk_preimage.len(), 512);
        // Compute the incoming viewing key ivk
        let mut ivk = blake2s::blake2s(
            cs.namespace(|| "computation of ivk"),
            &ivk_preimage,
            crate::constants::CRH_IVK_PERSONALIZATION,
        )?;
        // drop_5 to ensure it's in the field
        ivk.truncate(jubjub::Fr::CAPACITY as usize);
        // Compute pk_d_ = g_d^ivk
        let pk_d_ = g_d.mul(cs.namespace(|| "compute pk_d_"), &ivk)?;

        // enforce: AUTH * (pk_d - pk_d_) = 0
        cs.enforce(
            || "conditionally enforce 0 = AUTH * (pk_d - pk_d_)",
            |lc| lc + pk_d.get_v().get_variable() - pk_d_.get_v().get_variable(),
            |lc| lc + &auth.lc(CS::one(), bls12_381::Scalar::one()),
            |lc| lc,
        );

        // Compute accounts's value as a linear combination of the bits.
        let mut account_num = Num::zero();
        let mut coeff = bls12_381::Scalar::one();
        for bit in &account_bits
        {
            account_num = account_num.add_bool_with_coeff(CS::one(), bit, coeff);
            coeff = coeff.double();
        }
        // Compute code's value as a linear combination of the bits.
        let mut code_num = Num::zero();
        let mut coeff = bls12_381::Scalar::one();
        for bit in &code_bits
        {
            code_num = code_num.add_bool_with_coeff(CS::one(), bit, coeff);
            coeff = coeff.double();
        }
        // enforce: AUTH * (code - account) = 0
        cs.enforce(
            || "conditionally enforce 0 = AUTH * (code - account)",
            |lc| lc + &account_num.lc(bls12_381::Scalar::one()) - &code_num.lc(bls12_381::Scalar::one()),
            |lc| lc + &auth.lc(CS::one(), bls12_381::Scalar::one()),
            |lc| lc,
        );

        assert_eq!(
            note_preimage.len(),
            64 +    // account
            64 +    // value
            64 +    // symbol
            64 +    // code
            256 +   // g_d
            256     // pk_d
        );

        // Compute the hash of the note contents
        let mut cm = pedersen_hash::pedersen_hash(
            cs.namespace(|| "note content hash"),
            pedersen_hash::Personalization::NoteCommitment,
            &note_preimage,
        )?;

        {
            // Booleanize the randomness for the note commitment
            let rcm = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "rcm"),
                self.rcm,
            )?;

            // Compute the note commitment randomness in the exponent
            let rcm = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of commitment randomness"),
                &NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
                &rcm,
            )?;

            // Randomize the note commitment.
            cm = cm.add(cs.namespace(|| "randomization of note commitment"), &rcm)?;
        }

        // Only the u-coordinate of the commitment is revealed,
        // since we know it is prime order, and we know that
        // the u-coordinate is an injective encoding for
        // elements in the prime-order subgroup.
        cm.get_u().inputize(cs.namespace(|| "commitment"))?;
        // expose inputs2 contents (value, symbol and code) as one input vector
        multipack::pack_into_inputs(cs.namespace(|| "pack inputs2 contents"), &inputs2_bits)?;
        // expose inputs3 contents (account) as one input vector
        multipack::pack_into_inputs(cs.namespace(|| "pack inputs3 contents"), &inputs3_bits)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests
{
    use crate::note::{Note, Rseed};
    use crate::keys::{SpendingKey, FullViewingKey};
    use crate::eosio::{Asset, Name, Symbol};
    use crate::contract::AffineVerifyingKeyBytesLE;
    use bls12_381::Scalar;
    use bls12_381::Bls12;
    use rand::rngs::OsRng;
    use bellman::gadgets::test::TestConstraintSystem;
    use super::Mint;
    use bellman::Circuit;
    use bellman::gadgets::multipack;
    use bellman::groth16::{generate_random_parameters, create_random_proof, prepare_verifying_key, verify_proof};
    use bellman::groth16::Parameters;
    use bellman::groth16::VerifyingKey;
    use ff::PrimeField;
    use std::fs;
    use std::fs::File;

    #[test]
    fn test_mint_circuit()
    {
        let mut rng = OsRng.clone();
        let (sk, _, n) = Note::dummy(
            &mut rng,
            Asset::from_string(&"1234567890987654321".to_string()),
            None
        );
        let (_sk_dummy, _, _) = Note::dummy(&mut rng, None, None);
        let mut inputs2_contents = [0; 24];
        inputs2_contents[0..8].copy_from_slice(&n.amount().to_le_bytes());
        inputs2_contents[8..16].copy_from_slice(&n.symbol().raw().to_le_bytes());
        inputs2_contents[16..24].copy_from_slice(&n.code().raw().to_le_bytes());
        let inputs2_contents = multipack::bytes_to_bits_le(&inputs2_contents);
        let inputs2_contents = multipack::compute_multipacking(&inputs2_contents);
        assert_eq!(inputs2_contents.len(), 1);
        let mut inputs3_contents = [0; 8];
        inputs3_contents[0..8].copy_from_slice(&n.account().raw().to_le_bytes());
        let inputs3_contents = multipack::bytes_to_bits_le(&inputs3_contents);
        let inputs3_contents = multipack::compute_multipacking(&inputs3_contents);
        assert_eq!(inputs3_contents.len(), 1);

        let mut cs = TestConstraintSystem::new();

        let instance = Mint {
            account: Some(n.account().raw()),
            value: Some(n.amount()),
            symbol: Some(n.symbol().raw()),
            code: Some(n.code().raw()),
            address: Some(n.address()),
            rcm: Some(n.rcm()),
            proof_generation_key: Some(sk.proof_generation_key())
        };

        instance.synthesize(&mut cs).unwrap();

        assert!(cs.is_satisfied());
        println!("num constraints: {}", cs.num_constraints());
        println!("cs hash: {}", cs.hash());

        assert_eq!(
            cs.get("randomization of note commitment/u3/num").to_repr(),
            n.commitment().to_bytes()
        );

        assert_eq!(cs.num_inputs(), 4);
        assert_eq!(cs.get_input(0, "ONE"), bls12_381::Scalar::one());
        assert_eq!(cs.get_input(1, "commitment/input variable").to_repr(), n.commitment().to_bytes());
        assert_eq!(cs.get_input(2, "pack inputs2 contents/input 0"), inputs2_contents[0]);
        assert_eq!(cs.get_input(3, "pack inputs3 contents/input 0"), inputs3_contents[0]);
    }

    #[test]
    fn generate_and_write_params()
    {
        let instance = Mint {
            account: None,
            value: None,
            symbol: None,
            code: None,
            address: None,
            rcm: None,
            proof_generation_key: None,
        };
        let params = generate_random_parameters::<Bls12, _, _>(instance, &mut OsRng).unwrap();
        let f = File::create("params_mint.bin").unwrap();
        params.write(f).unwrap();
        let f = File::create("vk_mint.bin").unwrap();
        params.vk.write(f).unwrap();
        let vk_affine_bytes = AffineVerifyingKeyBytesLE::from(params.vk);
        let res = fs::write("vk_mint.hex", hex::encode(vk_affine_bytes.0));
        assert!(res.is_ok());
    }

    #[test]
    fn prove_and_verify()
    {
        let f = File::open("params_mint.bin").unwrap();
        let params = Parameters::<Bls12>::read(f, false).unwrap();

        let mut rng = OsRng.clone();
        let (_sk, _, n) = Note::dummy(&mut rng, Asset::new(0, Symbol(12)), None);
        let (sk_dummy, _, _) = Note::dummy(&mut rng, None, None);

        println!("create proof");
        let instance = Mint {
            account: Some(n.account().raw()),
            value: Some(n.amount()),
            symbol: Some(n.symbol().raw()),
            code: Some(n.code().raw()),
            address: Some(n.address()),
            rcm: Some(n.rcm()),
            proof_generation_key: Some(sk_dummy.proof_generation_key()),
        };
        let proof = create_random_proof(instance, &params, &mut OsRng).unwrap();

        let f = File::create("proof_mint.bin").unwrap();
        proof.write(f).unwrap();

        println!("pack inputs");
        let mut inputs2_contents = [0; 24];
        inputs2_contents[0..8].copy_from_slice(&n.amount().to_le_bytes());
        inputs2_contents[8..16].copy_from_slice(&n.symbol().raw().to_le_bytes());
        inputs2_contents[16..24].copy_from_slice(&n.code().raw().to_le_bytes());
        let inputs2_contents = multipack::bytes_to_bits_le(&inputs2_contents);
        let inputs2_contents: Vec<Scalar> = multipack::compute_multipacking(&inputs2_contents);
        assert_eq!(inputs2_contents.len(), 1);
        let mut inputs3_contents = [0; 8];
        inputs3_contents[0..8].copy_from_slice(&n.account().raw().to_le_bytes());
        let inputs3_contents = multipack::bytes_to_bits_le(&inputs3_contents);
        let inputs3_contents: Vec<Scalar> = multipack::compute_multipacking(&inputs3_contents);
        assert_eq!(inputs3_contents.len(), 1);
        let mut inputs = vec![];
        inputs.push(n.commitment().0);
        inputs.extend(inputs2_contents.clone());
        inputs.extend(inputs3_contents.clone());
        // print public inputs
        println!("{}", hex::encode(n.commitment().0.to_bytes()));
        println!("{}", hex::encode(inputs2_contents[0].to_bytes()));
        println!("{}", hex::encode(inputs3_contents[0].to_bytes()));

        println!("verify proof");
        let f = File::open("vk_mint.bin").unwrap();
        let vk = VerifyingKey::<Bls12>::read(f).unwrap();
        let pvk = prepare_verifying_key(&vk);
        assert!(verify_proof(&pvk, &proof, &inputs).is_ok());
    }

    #[test]
    fn static_prove_and_verify()
    {
        let f = File::open("params_mint.bin").unwrap();
        let params = Parameters::<Bls12>::read(f, false).unwrap();

        // Alice' key material
        let sk_alice = SpendingKey::from_seed(b"This is Alice seed string! Usually this is just a listing of words. Here we just use sentences.");
        let fvk_alice = FullViewingKey::from_spending_key(&sk_alice);
        let recipient = fvk_alice.default_address().1;

        let note = Note::from_parts(
            0,
            recipient,
            Name(0),
            Asset::from_string(&"5000.0000 EOS".to_string()).unwrap(),
            Name::from_string(&"eosio.token".to_string()).unwrap(),
            Rseed([42; 32]),
            [0; 512]
        );

        println!("create proof");
        let instance = Mint {
            account: Some(note.account().raw()),
            value: Some(note.amount()),
            symbol: Some(note.symbol().raw()),
            code: Some(note.code().raw()),
            address: Some(note.address()),
            rcm: Some(note.rcm()),
            proof_generation_key: Some(sk_alice.proof_generation_key()),
        };
        let proof = create_random_proof(instance, &params, &mut OsRng).unwrap();

        let f = File::create("proof_mint.bin").unwrap();
        proof.write(f).unwrap();

        println!("pack inputs");
        let mut inputs2_contents = [0; 24];
        inputs2_contents[0..8].copy_from_slice(&note.amount().to_le_bytes());
        inputs2_contents[8..16].copy_from_slice(&note.symbol().raw().to_le_bytes());
        inputs2_contents[16..24].copy_from_slice(&note.code().raw().to_le_bytes());
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
        // print public inputs
        println!("{}", hex::encode(note.commitment().0.to_bytes()));
        println!("{}", hex::encode(inputs2_contents[0].to_bytes()));
        println!("{}", hex::encode(inputs3_contents[0].to_bytes()));

        println!("verify proof");
        let f = File::open("vk_mint.bin").unwrap();
        let vk = VerifyingKey::<Bls12>::read(f).unwrap();
        let pvk = prepare_verifying_key(&vk);
        assert!(verify_proof(&pvk, &proof, &inputs).is_ok());
    }
}