use super::Output;
use bellman::gadgets::test::TestConstraintSystem;
use bellman::Circuit;
use rand::rngs::OsRng;

use crate::address::Address;
use crate::engine::{scalar_one, scalar_zero, Scalar};
use crate::eosio::{Asset, ExtendedAsset, Name, Symbol, SymbolCode};
use crate::note::{Note, Rseed};
use crate::value::ValueCommitTrapdoor;

#[derive(Clone, Copy)]
enum AssetKind {
    Fungible,
    Nft,
}

fn fungible_symbol() -> Symbol {
    Symbol::from_sc_precision(
        SymbolCode::from_string(&"EOS".to_string()).expect("valid test symbol code"),
        4,
    )
}

fn asset(amount: u64, kind: AssetKind) -> ExtendedAsset {
    match kind {
        AssetKind::Fungible => ExtendedAsset::new(
            Asset::new(amount as i64, fungible_symbol()).expect("valid fungible test asset"),
            Name::from_string("eosio.token").expect("valid token contract name"),
        ),
        AssetKind::Nft => ExtendedAsset::new(
            Asset::new(amount as i64, Symbol(0)).expect("valid NFT test asset"),
            Name::from_string("atomicassets").expect("valid NFT contract name"),
        ),
    }
}

fn output_instance(amount: u64, kind: AssetKind, account_b: Name) -> Output {
    let mut rng = OsRng.clone();
    let note_b = Note::from_parts(
        0,
        Address::dummy(&mut rng),
        account_b,
        asset(amount, kind),
        Rseed([42; 32]),
        [0; 512],
    );

    let rcv = ValueCommitTrapdoor::random(&mut rng);
    let rscm = Rseed([21; 32]);

    Output {
        rcv: Some(rcv.inner()),
        rscm: Some(rscm.rcm().0),
        note_b: Some(note_b),
    }
}

fn synthesize_output(
    amount: u64,
    kind: AssetKind,
    account_b: Name,
) -> TestConstraintSystem<Scalar> {
    let instance = output_instance(amount, kind, account_b);
    let mut cs = TestConstraintSystem::new();
    instance.synthesize(&mut cs).unwrap();
    cs
}

fn different_scalar(current: Scalar) -> Scalar {
    if current == scalar_zero() {
        scalar_one()
    } else {
        scalar_zero()
    }
}

fn mutate_input_and_assert_unsatisfied(input_index: usize, input_name: &str) {
    let mut cs = synthesize_output(10, AssetKind::Fungible, Name(0));
    assert!(cs.is_satisfied());

    let current = cs.get_input(input_index, input_name);
    cs.set(input_name, different_scalar(current));

    assert!(
        !cs.is_satisfied(),
        "mutating public input {input_name} should make output unsatisfied"
    );
}

#[test]
fn malicious_symbol_zero_output_must_fail() {
    let cs = synthesize_output(42, AssetKind::Nft, Name(0));

    assert!(
        !cs.is_satisfied(),
        "plain output must reject symbol == 0 notes; failing constraint: {:?}",
        cs.which_is_unsatisfied()
    );
}

#[test]
fn honest_fungible_token_output_still_passes() {
    let cs = synthesize_output(10, AssetKind::Fungible, Name(0));

    assert!(
        cs.is_satisfied(),
        "honest fungible output should satisfy; failing constraint: {:?}",
        cs.which_is_unsatisfied()
    );
}

#[test]
fn account_b_must_be_zero() {
    let account = Name::from_string("alice").expect("valid test account");
    let cs = synthesize_output(10, AssetKind::Fungible, account);

    assert!(
        !cs.is_satisfied(),
        "output with account_b != 0 should be unsatisfied"
    );
}

#[test]
fn public_value_commitment_is_bound() {
    mutate_input_and_assert_unsatisfied(3, "commitment point/u/input variable");
}

#[test]
fn public_symbol_commitment_is_bound() {
    mutate_input_and_assert_unsatisfied(1, "symbol commitment/input variable");
}

#[test]
fn public_cm_b_is_bound() {
    mutate_input_and_assert_unsatisfied(2, "commitment b/input variable");
}
