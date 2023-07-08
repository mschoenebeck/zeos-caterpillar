use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bellman::gadgets::{blake2s, boolean, boolean::Boolean, multipack};
use bls12_381::Scalar;
use ff::PrimeField;
use crate::{address::Address, keys::ProofGenerationKey};
use super::constants::{NOTE_COMMITMENT_RANDOMNESS_GENERATOR, PROOF_GENERATION_KEY_GENERATOR};
use super::{ecc, pedersen_hash, OrExt};

/// This is an instance of the `Mint` circuit.
pub struct Mint
{
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
        let mut asset_bits = vec![];

        // note value to boolean bit vector
        let value_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "value"),
            self.value
        )?;
        asset_bits.extend(value_bits.clone());

        // note symbol to boolean bit vector
        let symbol_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "symbol"),
            self.symbol
        )?;
        asset_bits.extend(symbol_bits.clone());

        // note code to boolean bit vector
        let code_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "code"),
            self.code
        )?;
        asset_bits.extend(code_bits);

        // append asset bit (value, symbol, code) to note preimage
        note_preimage.extend(asset_bits.clone());

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

        // rho is set to Scalar::one() when minting a new note
        let rho_bits = boolean::field_into_boolean_vec_le(
            cs.namespace(|| "rho"),
            Some(Scalar::one())
        )?;
        note_preimage.extend(rho_bits);

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
        // To prevent NFTs from being 'split', enforce: 0 = NFT * C
        cs.enforce(
            || "conditionally enforce 0 = AUTH * (pk_d - pk_d_)",
            |lc| lc + pk_d.get_v().get_variable() - pk_d_.get_v().get_variable(),
            |lc| lc + &auth.lc(CS::one(), bls12_381::Scalar::one()),
            |lc| lc,
        );

        assert_eq!(
            note_preimage.len(),
            64 +    // value
            64 +    // symbol
            64 +    // code
            256 +   // g_d
            256 +   // pk_d
            255     // rho
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

        // expose asset contents (value, symbol and code) as one input vector
        multipack::pack_into_inputs(cs.namespace(|| "pack asset contents"), &asset_bits)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests
{
    use crate::note::{Note, nullifier::ExtractedNullifier, Rseed};
    use crate::keys::{SpendingKey, FullViewingKey};
    use crate::eosio::{Asset, Name, Symbol};
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
    use std::fs::File;

    #[test]
    fn test_mint_circuit()
    {
        let mut rng = OsRng.clone();
        let (sk, _, n) = Note::dummy(
            &mut rng,
            Some(ExtractedNullifier(Scalar::one().clone())),
            Asset::from_string(&"1234567890987654321".to_string()),
            None
        );
        let (_sk_dummy, _, _) = Note::dummy(&mut rng, None, None, None);
        let mut asset_contents = [0; 24];
        asset_contents[0..8].copy_from_slice(&n.amount().to_le_bytes());
        asset_contents[8..16].copy_from_slice(&n.symbol().raw().to_le_bytes());
        asset_contents[16..24].copy_from_slice(&n.code().raw().to_le_bytes());
        let asset_contents = multipack::bytes_to_bits_le(&asset_contents);
        let asset_contents = multipack::compute_multipacking(&asset_contents);
        assert_eq!(asset_contents.len(), 1);

        let mut cs = TestConstraintSystem::new();

        let instance = Mint {
            value: Some(n.amount()),
            symbol: Some(n.symbol().raw()),
            code: Some(n.code().raw()),
            address: Some(n.address()),
            rcm: Some(n.rcm()),
            proof_generation_key: Some(sk.proof_generation_key())
        };

        instance.synthesize(&mut cs).unwrap();

        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 31641); // 4681
        assert_eq!(cs.hash(), "e14b7853dfe901e57af4e0bf09258057f61d6e2ba87deb534ff786ac7f7c0d3a");

        assert_eq!(
            cs.get("randomization of note commitment/u3/num").to_repr(),
            n.commitment().to_bytes()
        );

        assert_eq!(cs.num_inputs(), 3);
        assert_eq!(cs.get_input(0, "ONE"), bls12_381::Scalar::one());
        assert_eq!(cs.get_input(1, "commitment/input variable").to_repr(), n.commitment().to_bytes());
        assert_eq!(cs.get_input(2, "pack asset contents/input 0"), asset_contents[0]);
    }

    #[test]
    fn generate_and_write_params()
    {
        let instance = Mint {
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
    }

    #[test]
    fn prove_and_verify()
    {
        let f = File::open("params_mint.bin").unwrap();
        let params = Parameters::<Bls12>::read(f, false).unwrap();

        let mut rng = OsRng.clone();
        let (_sk, _, n) = Note::dummy(&mut rng, Some(ExtractedNullifier(Scalar::one().clone())), Asset::new(0, Symbol::new(12)), None);
        let (sk_dummy, _, _) = Note::dummy(&mut rng, None, None, None);

        println!("create proof");
        let instance = Mint {
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
        let mut asset_contents = [0; 24];
        asset_contents[0..8].copy_from_slice(&n.amount().to_le_bytes());
        asset_contents[8..16].copy_from_slice(&n.symbol().raw().to_le_bytes());
        asset_contents[16..24].copy_from_slice(&n.code().raw().to_le_bytes());
        let asset_contents = multipack::bytes_to_bits_le(&asset_contents);
        let asset_contents: Vec<Scalar> = multipack::compute_multipacking(&asset_contents);
        assert_eq!(asset_contents.len(), 1);
        let mut inputs = vec![];
        inputs.push(n.commitment().0);
        inputs.extend(asset_contents.clone());
        // print public inputs
        println!("{}", hex::encode(n.commitment().0.to_bytes()));
        println!("{}", hex::encode(asset_contents[0].to_bytes()));

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
            Asset::from_string(&"5000.0000 EOS".to_string()).unwrap(),
            Name::from_string(&"eosio.token".to_string()).unwrap(),
            Rseed([42; 32]),
            ExtractedNullifier(Scalar::one()),
            [0; 512]
        );

        println!("create proof");
        let instance = Mint {
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
        // print public inputs
        println!("{}", hex::encode(note.commitment().0.to_bytes()));
        println!("{}", hex::encode(asset_contents[0].to_bytes()));

        println!("verify proof");
        let f = File::open("vk_mint.bin").unwrap();
        let vk = VerifyingKey::<Bls12>::read(f).unwrap();
        let pvk = prepare_verifying_key(&vk);
        assert!(verify_proof(&pvk, &proof, &inputs).is_ok());
    }
}