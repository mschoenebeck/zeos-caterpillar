use super::Spend;
use bellman::gadgets::test::TestConstraintSystem;
use bellman::Circuit;
use rand::rngs::OsRng;

use crate::engine::{scalar_one, scalar_zero, Scalar};
use crate::eosio::{Asset, ExtendedAsset, Name, Symbol, SymbolCode};
use crate::keys::{FullViewingKey, SpendingKey};
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

fn auth_path() -> Vec<Option<([u8; 32], bool)>> {
    vec![
        Some((
            hex::decode("0100000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .try_into()
                .unwrap(),
            false,
        )),
        Some((
            hex::decode("322eb027eb8aee02f2c996a31912d1ae05e251c597ae9bbd5c819b71f080bce9")
                .unwrap()
                .try_into()
                .unwrap(),
            false,
        )),
        Some((
            hex::decode("d492e18b60152bd5001335141d8ff86912c9ccd988a8409fec5316ba36df98cc")
                .unwrap()
                .try_into()
                .unwrap(),
            false,
        )),
    ]
}

fn spend_instance(amount: u64, kind: AssetKind) -> Spend {
    let mut rng = OsRng.clone();
    let sk_alice = SpendingKey::from_seed(
        b"This is Alice seed string! Usually this is just a listing of words. Here we just use sentences.",
    );
    let fvk_alice = FullViewingKey::from_spending_key(&sk_alice);
    let sender = fvk_alice.default_address().1;

    let note_a = Note::from_parts(
        0,
        sender,
        Name(0),
        asset(amount, kind),
        Rseed([42; 32]),
        [0; 512],
    );

    let rcv = ValueCommitTrapdoor::random(&mut rng);
    let rscm = Rseed([21; 32]);

    Spend {
        note_a: Some(note_a),
        proof_generation_key: Some(sk_alice.proof_generation_key()),
        auth_path: auth_path(),
        rcv: Some(rcv.inner()),
        rscm: Some(rscm.rcm().0),
    }
}

fn synthesize_spend(amount: u64, kind: AssetKind) -> TestConstraintSystem<Scalar> {
    let instance = spend_instance(amount, kind);
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
    let mut cs = synthesize_spend(10, AssetKind::Fungible);
    assert!(cs.is_satisfied());

    let current = cs.get_input(input_index, input_name);
    cs.set(input_name, different_scalar(current));

    assert!(
        !cs.is_satisfied(),
        "mutating public input {input_name} should make spend unsatisfied"
    );
}

#[test]
fn malicious_symbol_zero_spend_must_fail() {
    let cs = synthesize_spend(42, AssetKind::Nft);

    assert!(
        !cs.is_satisfied(),
        "plain spend must reject symbol == 0 notes; failing constraint: {:?}",
        cs.which_is_unsatisfied()
    );
}

#[test]
fn honest_fungible_token_spend_still_passes() {
    let cs = synthesize_spend(10, AssetKind::Fungible);

    assert!(
        cs.is_satisfied(),
        "honest fungible spend should satisfy; failing constraint: {:?}",
        cs.which_is_unsatisfied()
    );
}

#[test]
fn public_value_commitment_is_bound() {
    mutate_input_and_assert_unsatisfied(4, "commitment point/u/input variable");
}

#[test]
fn public_symbol_commitment_is_bound() {
    mutate_input_and_assert_unsatisfied(3, "symbol commitment/input variable");
}

#[test]
fn public_anchor_is_bound() {
    mutate_input_and_assert_unsatisfied(1, "anchor/input 0");
}

#[test]
fn public_nullifier_is_bound() {
    mutate_input_and_assert_unsatisfied(2, "nullifier/input variable");
}
