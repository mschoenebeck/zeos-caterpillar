use super::{with_spend_output_witness_overrides, SpendOutput, SpendOutputWitnessOverrides};
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

fn spend_output_instance_with_account_b(
    note_a_amount: u64,
    note_b_amount: u64,
    value_c: u64,
    kind: AssetKind,
    account_b: Name,
) -> SpendOutput {
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
        asset(note_a_amount, kind),
        Rseed([42; 32]),
        [0; 512],
    );

    let note_b = Note::from_parts(
        0,
        sender,
        account_b,
        asset(note_b_amount, kind),
        Rseed([43; 32]),
        [0; 512],
    );

    let rcv = ValueCommitTrapdoor::random(&mut rng);
    let rscm = Rseed([21; 32]);

    SpendOutput {
        note_a: Some(note_a),
        proof_generation_key: Some(sk_alice.proof_generation_key()),
        auth_path: auth_path(),
        rcv: Some(rcv.inner()),
        rcv_mul: Some(1),
        rscm: Some(rscm.rcm().0),
        note_b: Some(note_b),
        value_c: Some(value_c),
        unshielded_outputs_hash: Some([0; 4]),
    }
}

fn spend_output_instance(
    note_a_amount: u64,
    note_b_amount: u64,
    value_c: u64,
    kind: AssetKind,
) -> SpendOutput {
    spend_output_instance_with_account_b(note_a_amount, note_b_amount, value_c, kind, Name(0))
}

fn synthesize_with_overrides(
    instance: SpendOutput,
    overrides: Option<SpendOutputWitnessOverrides>,
) -> TestConstraintSystem<Scalar> {
    let mut cs = TestConstraintSystem::new();

    if let Some(overrides) = overrides {
        with_spend_output_witness_overrides(overrides, || {
            instance.synthesize(&mut cs).unwrap();
        });
    } else {
        instance.synthesize(&mut cs).unwrap();
    }

    cs
}

fn assert_spend_output_satisfied(
    note_a_amount: u64,
    note_b_amount: u64,
    value_c: u64,
    kind: AssetKind,
    overrides: Option<SpendOutputWitnessOverrides>,
    expected: bool,
) {
    let instance = spend_output_instance(note_a_amount, note_b_amount, value_c, kind);
    let cs = synthesize_with_overrides(instance, overrides);

    assert_eq!(
        cs.is_satisfied(),
        expected,
        "unexpected spend_output satisfaction result; failing constraint: {:?}",
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

fn mutate_input_and_assert_unsatisfied(input_index: usize, input_name: &str) {
    let instance = spend_output_instance(10, 5, 5, AssetKind::Fungible);
    let mut cs = synthesize_with_overrides(instance, None);
    assert!(cs.is_satisfied());

    let current = cs.get_input(input_index, input_name);
    cs.set(input_name, different_scalar(current));

    assert!(
        !cs.is_satisfied(),
        "mutating public input {input_name} should make spend_output unsatisfied"
    );
}

#[test]
fn malicious_inflation_must_fail() {
    assert_spend_output_satisfied(
        10,
        1_000_000,
        0,
        AssetKind::Fungible,
        Some(SpendOutputWitnessOverrides {
            net_value: Some(0),
            is_equal: Some(true),
            is_greater: Some(false),
            ..Default::default()
        }),
        false,
    );
}

#[test]
fn wrong_equality_flag_must_fail() {
    assert_spend_output_satisfied(
        10,
        5,
        0,
        AssetKind::Fungible,
        Some(SpendOutputWitnessOverrides {
            net_value: Some(0),
            is_equal: Some(true),
            is_greater: Some(false),
            ..Default::default()
        }),
        false,
    );
}

#[test]
fn wrong_greater_than_flag_must_fail() {
    assert_spend_output_satisfied(
        10,
        20,
        0,
        AssetKind::Fungible,
        Some(SpendOutputWitnessOverrides {
            net_value: Some(10),
            is_equal: Some(false),
            is_greater: Some(true),
            ..Default::default()
        }),
        false,
    );
}

#[test]
fn honest_equal_case_passes() {
    assert_spend_output_satisfied(10, 5, 5, AssetKind::Fungible, None, true);
}

#[test]
fn honest_greater_than_change_case_passes() {
    assert_spend_output_satisfied(10, 6, 0, AssetKind::Fungible, None, true);
}

#[test]
fn honest_less_than_aggregate_output_side_case_passes() {
    assert_spend_output_satisfied(5, 10, 0, AssetKind::Fungible, None, true);
}

#[test]
fn cannot_hide_symbol_contract_when_value_c_is_nonzero() {
    assert_spend_output_satisfied(
        10,
        5,
        5,
        AssetKind::Fungible,
        Some(SpendOutputWitnessOverrides {
            expose_symbol_contract: Some(false),
            ..Default::default()
        }),
        false,
    );
}

#[test]
fn wrong_symbol_is_zero_witness_must_fail_for_ft() {
    assert_spend_output_satisfied(
        10,
        5,
        5,
        AssetKind::Fungible,
        Some(SpendOutputWitnessOverrides {
            symbol_is_zero: Some(true),
            ..Default::default()
        }),
        false,
    );
}

#[test]
fn wrong_symbol_is_zero_witness_must_fail_for_nft() {
    assert_spend_output_satisfied(
        42,
        42,
        0,
        AssetKind::Nft,
        Some(SpendOutputWitnessOverrides {
            symbol_is_zero: Some(false),
            ..Default::default()
        }),
        false,
    );
}

#[test]
fn nft_split_rule_allows_b_or_c_but_not_both_or_partial() {
    assert_spend_output_satisfied(42, 42, 0, AssetKind::Nft, None, true);
    assert_spend_output_satisfied(42, 0, 42, AssetKind::Nft, None, true);
    assert_spend_output_satisfied(42, 42, 42, AssetKind::Nft, None, false);
    assert_spend_output_satisfied(42, 7, 0, AssetKind::Nft, None, false);
}

#[test]
fn account_b_must_be_zero() {
    let instance = spend_output_instance_with_account_b(
        10,
        5,
        5,
        AssetKind::Fungible,
        Name::from_string("alice").unwrap(),
    );
    let cs = synthesize_with_overrides(instance, None);

    assert!(
        !cs.is_satisfied(),
        "account_b != 0 should make spend_output unsatisfied"
    );
}

#[test]
fn public_cm_b_is_bound() {
    mutate_input_and_assert_unsatisfied(4, "commitment b/input variable");
}

#[test]
fn public_cv_net_is_bound() {
    mutate_input_and_assert_unsatisfied(5, "cv_net/u/input variable");
}

#[test]
fn public_anchor_is_bound() {
    mutate_input_and_assert_unsatisfied(1, "anchor/input 0");
}
