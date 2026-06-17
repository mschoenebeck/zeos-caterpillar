use super::{with_mint_witness_overrides, Mint, MintWitnessOverrides};
use bellman::gadgets::test::TestConstraintSystem;
use bellman::Circuit;
use rand::rngs::OsRng;

use crate::address::Address;
use crate::engine::{scalar_one, scalar_zero, Scalar};
use crate::eosio::{Asset, ExtendedAsset, Name, Symbol, SymbolCode};
use crate::keys::{FullViewingKey, SpendingKey};
use crate::note::{Note, Rseed};

fn eos_symbol() -> Symbol {
    Symbol::from_sc_precision(
        SymbolCode::from_string(&"EOS".to_string()).expect("valid test symbol code"),
        4,
    )
}

fn eos_contract() -> Name {
    Name::from_string("eosio.token").expect("valid token contract name")
}

fn auth_contract() -> Name {
    Name::from_string("zeosexchange").expect("valid auth contract name")
}

fn normal_mint_instance() -> Mint {
    let mut rng = OsRng.clone();
    let (sk, _, note) = Note::dummy(
        &mut rng,
        Some(Name::from_string("alice").expect("valid account name")),
        Some(ExtendedAsset::new(
            Asset::new(10, eos_symbol()).expect("valid fungible asset"),
            eos_contract(),
        )),
    );

    Mint {
        account: Some(note.account().raw()),
        auth_hash: Some([0; 4]),
        value: Some(note.amount()),
        symbol: Some(note.symbol().raw()),
        contract: Some(note.contract().raw()),
        address: Some(note.address()),
        rcm: Some(note.rcm()),
        proof_generation_key: Some(sk.proof_generation_key()),
    }
}

fn auth_note_with_address(address: Address) -> (SpendingKey, Note) {
    let sk = SpendingKey::from_seed(
        b"This is Alice seed string! Usually this is just a listing of words. Here we just use sentences.",
    );
    let code = auth_contract();
    let note = Note::from_parts(
        0,
        address,
        code,
        ExtendedAsset::new(Asset::new(0, Symbol(0)).expect("valid auth asset"), code),
        Rseed([42; 32]),
        [0; 512],
    );

    (sk, note)
}

fn honest_auth_mint_instance() -> Mint {
    let sk = SpendingKey::from_seed(
        b"This is Alice seed string! Usually this is just a listing of words. Here we just use sentences.",
    );
    let fvk = FullViewingKey::from_spending_key(&sk);
    let address = fvk.default_address().1;
    let (_, note) = auth_note_with_address(address);

    Mint {
        account: Some(note.account().raw()),
        auth_hash: Some([42; 4]),
        value: Some(note.amount()),
        symbol: Some(note.symbol().raw()),
        contract: Some(note.contract().raw()),
        address: Some(note.address()),
        rcm: Some(note.rcm()),
        proof_generation_key: Some(sk.proof_generation_key()),
    }
}

fn auth_mint_with_wrong_pk_d_u_instance() -> Mint {
    let sk = SpendingKey::from_seed(
        b"This is Alice seed string! Usually this is just a listing of words. Here we just use sentences.",
    );
    let fvk = FullViewingKey::from_spending_key(&sk);
    let honest_address = fvk.default_address().1;

    let mut mutated_address_bytes = honest_address.to_bytes();
    // Address bytes are diversifier || repr_J(pk_d). Flipping the sign bit keeps
    // pk_d.v unchanged but changes pk_d.u to the opposite representative.
    mutated_address_bytes[42] ^= 0x80;
    let mutated_address = Address::from_bytes(&mutated_address_bytes)
        .expect("valid sign-flipped diversified transmission key");
    assert_ne!(honest_address.to_bytes(), mutated_address.to_bytes());

    let (_, note) = auth_note_with_address(mutated_address);

    Mint {
        account: Some(note.account().raw()),
        auth_hash: Some([42; 4]),
        value: Some(note.amount()),
        symbol: Some(note.symbol().raw()),
        contract: Some(note.contract().raw()),
        address: Some(note.address()),
        rcm: Some(note.rcm()),
        proof_generation_key: Some(sk.proof_generation_key()),
    }
}

fn synthesize_with_overrides(
    instance: Mint,
    overrides: Option<MintWitnessOverrides>,
) -> TestConstraintSystem<Scalar> {
    let mut cs = TestConstraintSystem::new();

    if let Some(overrides) = overrides {
        with_mint_witness_overrides(overrides, || {
            instance.synthesize(&mut cs).unwrap();
        });
    } else {
        instance.synthesize(&mut cs).unwrap();
    }

    cs
}

fn assert_mint_satisfied(instance: Mint, overrides: Option<MintWitnessOverrides>, expected: bool) {
    let cs = synthesize_with_overrides(instance, overrides);

    assert_eq!(
        cs.is_satisfied(),
        expected,
        "unexpected mint satisfaction result; failing constraint: {:?}",
        cs.which_is_unsatisfied(),
    );
}

fn different_scalar(current: Scalar) -> Scalar {
    if current == scalar_zero() {
        scalar_one()
    } else {
        scalar_zero()
    }
}

fn mutate_input_and_assert_unsatisfied(input_index: usize, input_name: &str, instance: Mint) {
    let mut cs = synthesize_with_overrides(instance, None);
    assert!(cs.is_satisfied());

    let current = cs.get_input(input_index, input_name);
    cs.set(input_name, different_scalar(current));

    assert!(
        !cs.is_satisfied(),
        "mutating public input {input_name} should make mint unsatisfied"
    );
}

#[test]
fn non_auth_mint_cannot_use_auth_public_input_mode() {
    assert_mint_satisfied(
        normal_mint_instance(),
        Some(MintWitnessOverrides {
            auth_bit: Some(true),
        }),
        false,
    );
}

#[test]
fn auth_mint_cannot_use_normal_account_public_input_mode() {
    assert_mint_satisfied(
        honest_auth_mint_instance(),
        Some(MintWitnessOverrides {
            auth_bit: Some(false),
        }),
        false,
    );
}

#[test]
fn auth_pk_d_u_mismatch_must_fail() {
    assert_mint_satisfied(auth_mint_with_wrong_pk_d_u_instance(), None, false);
}

#[test]
fn honest_normal_mint_still_passes() {
    assert_mint_satisfied(normal_mint_instance(), None, true);
}

#[test]
fn honest_auth_mint_still_passes() {
    assert_mint_satisfied(honest_auth_mint_instance(), None, true);
}

#[test]
fn public_cm_is_bound() {
    mutate_input_and_assert_unsatisfied(1, "commitment/input variable", normal_mint_instance());
}

#[test]
fn public_value_symbol_contract_input_is_bound() {
    mutate_input_and_assert_unsatisfied(2, "pack inputs2 contents/input 0", normal_mint_instance());
}

#[test]
fn public_account_input_is_bound_for_normal_mint() {
    mutate_input_and_assert_unsatisfied(3, "pack inputs3 contents/input 0", normal_mint_instance());
}

#[test]
fn public_auth_hash_input_is_bound_for_auth_mint() {
    mutate_input_and_assert_unsatisfied(
        3,
        "pack inputs3 contents/input 0",
        honest_auth_mint_instance(),
    );
}
