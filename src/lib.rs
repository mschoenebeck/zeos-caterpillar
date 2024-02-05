
// helper macros for merkle tree operations
macro_rules! MT_ARR_LEAF_ROW_OFFSET {
    ($d:expr) => ((1<<($d)) - 1)
}
macro_rules! MT_ARR_FULL_TREE_OFFSET {
    ($d:expr) => ((1<<(($d) + 1)) - 1)
}
macro_rules! MT_NUM_LEAVES {
    ($d:expr) => (1<<($d))
}

mod address;
pub mod value;
pub mod circuit;
pub mod constants;
pub mod eosio;
pub mod contract;
pub mod keys;
pub mod note;
pub mod note_encryption;
pub mod pedersen_hash;
pub mod blake2s7r;
pub mod group_hash;
pub mod spec;
pub mod wallet;
pub mod transaction;
pub mod transaction_spend_tests;

use wallet::Wallet;
use eosio::{Name, Symbol, Authorization, ExtendedAsset, Transaction};
#[cfg(target_os = "linux")]
use transaction::{ZTransaction, ResolvedZTransaction, resolve_ztransaction, zsign_transaction, zverify_spend_transaction};
#[cfg(target_os = "linux")]
use keys::IncomingViewingKey;
use std::collections::HashMap;
use bellman::groth16::Parameters;
use bls12_381::Bls12;
#[cfg(target_arch = "wasm32")]
use crate::{
    eosio::Asset,
    transaction::{MintDesc, zsign_transfer_and_mint_transaction},
};
#[cfg(target_os = "linux")]
use std::slice;
#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::ffi::CStr;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

// generalized log function for use in different targets
#[cfg(target_os = "linux")]
pub fn log(msg: &str)
{
    println!("{}", msg);
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C"
{
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log(s: &str);

    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_u32(a: u32);

    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_many(a: &str, b: &str);
}

// WASM Bindgen Resouces:
// https://rustwasm.github.io/wasm-bindgen/examples/hello-world.html
//
// The following class is a wallet-wrapper for use in JS Browser applications

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn js_zsign_transfer_and_mint_transaction(
    mint_zactions_json: String,
    alias_authority_json: String,
    user_authority_json: String,
    protocol_contract_json: String,
    fee_token_contract_json: String,
    fees_json: String,
    mint_params_bytes: &[u8]
) -> Result<String, JsError>
{
    log("execute 'zsign_transfer_and_mint_transaction' - this may take a while...");
    let mint_zactions: Vec<MintDesc> = serde_json::from_str(&mint_zactions_json).unwrap();
    let alias_athority = Authorization::from_string(&alias_authority_json).unwrap();
    let user_athority = Authorization::from_string(&user_authority_json).unwrap();
    let protocol_contract = Name::from_string(&protocol_contract_json).unwrap();
    let fee_token_contract = Name::from_string(&fee_token_contract_json).unwrap();
    let fees: HashMap<Name, Asset> = serde_json::from_str(&fees_json).unwrap();
    let mint_params: Parameters<Bls12> = Parameters::<Bls12>::read(mint_params_bytes, false).unwrap();
    Ok(serde_json::to_string(&zsign_transfer_and_mint_transaction(
        &mint_zactions,
        &alias_athority,
        &user_athority,
        protocol_contract,
        fee_token_contract,
        &fees,
        &mint_params
    ).unwrap()).unwrap())
}

// FFI Resources:
// https://gist.github.com/iskakaushik/1c5b8aa75c77479c33c4320913eebef6
// https://jakegoulding.com/rust-ffi-omnibus/objects/
// https://jakegoulding.com/rust-ffi-omnibus/slice_arguments/
// https://dev.to/kgrech/7-ways-to-pass-a-string-between-rust-and-c-4ieb
// https://rust-unofficial.github.io/patterns/idioms/ffi/accepting-strings.html
//
// The following functions are exposed to C via FFI:

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn wallet_create(
    seed: *const libc::c_char,
    is_ivk: bool,
    chain_id: *const libc::c_char,
    protocol_contract: *const libc::c_char,
    alias_authority: *const libc::c_char,
    p_wallet: &mut *mut Wallet
) -> bool
{
    let seed_str: &str = match std::ffi::CStr::from_ptr(seed).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed (seed)");
            "FFI seed string conversion failed (seed)"
        }
    };
    let chain_id_str: &str = match std::ffi::CStr::from_ptr(chain_id).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed (chain_id)");
            "FFI seed string conversion failed (chain_id)"
        }
    };
    let protocol_contract_str: &str = match std::ffi::CStr::from_ptr(protocol_contract).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed (protocol_contract)");
            "FFI seed string conversion failed (protocol_contract)"
        }
    };
    let alias_authority_str: &str = match std::ffi::CStr::from_ptr(alias_authority).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed (alias_authority)");
            "FFI seed string conversion failed (alias_authority)"
        }
    };

    if is_ivk
    {
        let ivk = IncomingViewingKey::from_bech32m(&seed_str.to_string());
        if ivk.is_err() { return false }
        let ivk = ivk.unwrap();
        let wallet = Wallet::create(
            ivk.to_bytes().to_vec().as_slice(),
            is_ivk,
            hex::decode(chain_id_str).unwrap().try_into().unwrap(),
            Name::from_string(&protocol_contract_str.to_string()).unwrap(),
            Authorization::from_string(&alias_authority_str.to_string()).unwrap()
        );
        if wallet.is_none() { return false }
        *p_wallet = Box::into_raw(Box::new(wallet.unwrap()));
        return true;
    }
    else
    {
        let wallet = Wallet::create(
            seed_str.as_bytes(),
            is_ivk,
            hex::decode(chain_id_str).unwrap().try_into().unwrap(),
            Name::from_string(&protocol_contract_str.to_string()).unwrap(),
            Authorization::from_string(&alias_authority_str.to_string()).unwrap()
        );
        if wallet.is_none() { return false }
        *p_wallet = Box::into_raw(Box::new(wallet.unwrap()));
        return true;
    }
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub extern "C" fn wallet_close(
    p_wallet: *mut Wallet
)
{
    if p_wallet.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(p_wallet));
    }
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn wallet_size(
    p_wallet: *mut Wallet
) -> u64
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };
    wallet.size() as u64
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn wallet_is_ivk(
    p_wallet: *mut Wallet
) -> bool
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };
    wallet.is_ivk()
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub extern fn wallet_chain_id(
    p_wallet: *mut Wallet
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };
    let c_string = CString::new(hex::encode(wallet.chain_id())).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub extern fn wallet_protocol_contract(
    p_wallet: *mut Wallet
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };
    let c_string = CString::new(wallet.protocol_contract().to_string()).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub extern fn wallet_alias_authority(
    p_wallet: *mut Wallet
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };
    let c_string = CString::new(wallet.alias_authority().to_string()).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn wallet_block_num(
    p_wallet: *mut Wallet
) -> u32
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };
    wallet.block_num()
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn wallet_leaf_count(
    p_wallet: *mut Wallet
) -> u64
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };
    wallet.leaf_count()
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn wallet_write(
    p_wallet: *mut Wallet,
    p_bytes: *mut u8
) -> i64
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let mut wallet_bytes = vec![];
    let res = wallet.write(&mut wallet_bytes);
    std::ptr::copy(wallet_bytes.as_ptr().cast(), p_bytes, wallet.size());
    if res.is_err() { -1 } else { 0 }
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn wallet_read(
    p_bytes: *const u8,
    len: libc::size_t,
    p_wallet: &mut *mut Wallet
) -> bool
{
    let bytes = unsafe {
        assert!(!p_bytes.is_null());
        slice::from_raw_parts(p_bytes, len as usize)
    };

    let wallet = Wallet::read(bytes);
    if wallet.is_err() { return false; }
    let wallet = wallet.unwrap();
    *p_wallet = Box::into_raw(Box::new(wallet));
    true
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub extern fn wallet_json(
    p_wallet: *mut Wallet,
    pretty: bool
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let c_string = CString::new(wallet.to_json(pretty)).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub extern fn wallet_balances_json(
    p_wallet: *mut Wallet,
    pretty: bool
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let c_string = CString::new(
        if pretty { serde_json::to_string_pretty(&wallet.balances()).unwrap() }
        else { serde_json::to_string(&wallet.balances()).unwrap() }
    ).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub extern fn wallet_unspent_notes_json(
    p_wallet: *mut Wallet,
    pretty: bool
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let c_string = CString::new(
        if pretty { serde_json::to_string_pretty(&wallet.unspent_notes()).unwrap() }
        else { serde_json::to_string(&wallet.unspent_notes()).unwrap() }
    ).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub extern fn wallet_fungible_tokens_json(
    p_wallet: *mut Wallet,
    symbol: u64,
    contract: u64,
    pretty: bool
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let v: Vec<ExtendedAsset> = wallet.fungible_tokens(&Symbol(symbol), &Name(contract)).iter().map(|n| n.note().asset().clone()).collect();

    let c_string = CString::new(
        if pretty { serde_json::to_string_pretty(&v).unwrap() }
        else { serde_json::to_string(&v).unwrap() }
    ).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub extern fn wallet_non_fungible_tokens_json(
    p_wallet: *mut Wallet,
    contract: u64,
    pretty: bool
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let v: Vec<ExtendedAsset> = wallet.non_fungible_tokens(&Name(contract)).iter().map(|n| n.note().asset().clone()).collect();

    let c_string = CString::new(
        if pretty { serde_json::to_string_pretty(&v).unwrap() }
        else { serde_json::to_string(&v).unwrap() }
    ).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub extern fn wallet_authentication_tokens_json(
    p_wallet: *mut Wallet,
    contract: u64,
    pretty: bool
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let v: Vec<String> = wallet.authentication_tokens(&Name(contract)).iter().map(|n| hex::encode(n.note().commitment().to_bytes()) + "@" + &n.note().contract().to_string()).collect();

    let c_string = CString::new(
        if pretty { serde_json::to_string_pretty(&v).unwrap() }
        else { serde_json::to_string(&v).unwrap() }
    ).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub extern fn wallet_unpublished_notes_json(
    p_wallet: *mut Wallet,
    pretty: bool
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let c_string = CString::new(
        if pretty { serde_json::to_string_pretty(wallet.unpublished_notes()).unwrap() }
        else { serde_json::to_string(wallet.unpublished_notes()).unwrap() }
    ).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub extern fn wallet_transaction_history_json(
    p_wallet: *mut Wallet,
    pretty: bool
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let c_string = CString::new(
        if pretty { serde_json::to_string_pretty(&wallet.transaction_history()).unwrap() }
        else { serde_json::to_string(&wallet.transaction_history()).unwrap() }
    ).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub extern fn wallet_addresses_json(
    p_wallet: *mut Wallet,
    pretty: bool
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let c_string = CString::new(
        if pretty { serde_json::to_string_pretty(&wallet.addresses()).unwrap() }
        else { serde_json::to_string(&wallet.addresses()).unwrap() }
    ).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub extern fn wallet_derive_address(
    p_wallet: *mut Wallet,
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let c_string = CString::new(serde_json::to_string(&wallet.derive_next_address()).unwrap()).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

/// The ptr should be a valid pointer to the string allocated by rust
/// source: https://dev.to/kgrech/7-ways-to-pass-a-string-between-rust-and-c-4ieb
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern fn free_string(ptr: *const libc::c_char)
{
    // Take the ownership back to rust and drop the owner
    let _ = CString::from_raw(ptr as *mut _);
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern fn wallet_add_leaves(
    p_wallet: *mut Wallet,
    leaves: *const libc::c_char
)
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };
    let leaves_str: &str = match std::ffi::CStr::from_ptr(leaves).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed (leaves)");
            "FFI seed string conversion failed (leaves)"
        }
    };

    let bytes = hex::decode(leaves_str).unwrap();
    wallet.add_leaves(bytes.as_slice());
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern fn wallet_add_notes(
    p_wallet: *mut Wallet,
    notes: *const libc::c_char,
)
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };
    let notes_str: &str = match std::ffi::CStr::from_ptr(notes).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed (notes)");
            "FFI seed string conversion failed (notes)"
        }
    };

    let notes_vec: Vec<String> = serde_json::from_str(notes_str).unwrap();
    wallet.add_notes(&notes_vec, 0, 0);
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern fn wallet_add_unpublished_notes(
    p_wallet: *mut Wallet,
    unpublished_notes: *const libc::c_char,
)
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };
    let unpublished_notes_str: &str = match std::ffi::CStr::from_ptr(unpublished_notes).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed (unpublished_notes)");
            "FFI seed string conversion failed (unpublished_notes)"
        }
    };

    let unpublished_notes_map: HashMap<String, Vec<String>> = serde_json::from_str(unpublished_notes_str).unwrap();
    wallet.add_unpublished_notes(&unpublished_notes_map);
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern fn wallet_resolve(
    p_wallet: *mut Wallet,
    ztx_json: *const libc::c_char,
    fee_token_contract_json: *const libc::c_char,
    fees_json: *const libc::c_char
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };
    let ztx_json_str: &str = match std::ffi::CStr::from_ptr(ztx_json).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed (ztx_json)");
            "FFI seed string conversion failed (ztx_json)"
        }
    };
    let fee_token_contract_json_str: &str = match std::ffi::CStr::from_ptr(fee_token_contract_json).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed (fee_token_contract_json)");
            "FFI seed string conversion failed (fee_token_contract_json)"
        }
    };
    let fees_json_str: &str = match std::ffi::CStr::from_ptr(fees_json).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed (fees_json)");
            "FFI seed string conversion failed (fees_json)"
        }
    };

    let fee_token_contract = Name::from_string(&fee_token_contract_json_str.to_string()).unwrap();
    let fees = serde_json::from_str(fees_json_str).unwrap();
    let ztx: ZTransaction = serde_json::from_str(ztx_json_str).unwrap();
    let rztx = resolve_ztransaction(wallet, &fee_token_contract, &fees, &ztx).unwrap();

    let c_string = CString::new(serde_json::to_string(&rztx).unwrap()).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern fn wallet_zsign(
    p_wallet: *mut Wallet,
    rztx_json: *const libc::c_char,
    p_mint_params_bytes: *const u8,
    mint_params_bytes_len: libc::size_t,
    p_spendoutput_params_bytes: *const u8,
    spendoutput_params_bytes_len: libc::size_t,
    p_spend_params_bytes: *const u8,
    spend_params_bytes_len: libc::size_t,
    p_output_params_bytes: *const u8,
    output_params_bytes_len: libc::size_t
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };
    let rztx_json_str: &str = match std::ffi::CStr::from_ptr(rztx_json).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed (ztx_json)");
            "FFI seed string conversion failed (ztx_json)"
        }
    };
    let mint_params_bytes = unsafe {
        assert!(!p_mint_params_bytes.is_null());
        slice::from_raw_parts(p_mint_params_bytes, mint_params_bytes_len as usize)
    };
    let spendoutput_params_bytes = unsafe {
        assert!(!p_spendoutput_params_bytes.is_null());
        slice::from_raw_parts(p_spendoutput_params_bytes, spendoutput_params_bytes_len as usize)
    };
    let spend_params_bytes = unsafe {
        assert!(!p_spend_params_bytes.is_null());
        slice::from_raw_parts(p_spend_params_bytes, spend_params_bytes_len as usize)
    };
    let output_params_bytes = unsafe {
        assert!(!p_output_params_bytes.is_null());
        slice::from_raw_parts(p_output_params_bytes, output_params_bytes_len as usize)
    };

    let mut params = HashMap::new();
    params.insert(Name::from_string(&"mint".to_string()).unwrap(), Parameters::<Bls12>::read(mint_params_bytes, false).unwrap());
    params.insert(Name::from_string(&"spendoutput".to_string()).unwrap(), Parameters::<Bls12>::read(spendoutput_params_bytes, false).unwrap());
    params.insert(Name::from_string(&"spend".to_string()).unwrap(), Parameters::<Bls12>::read(spend_params_bytes, false).unwrap());
    params.insert(Name::from_string(&"output".to_string()).unwrap(), Parameters::<Bls12>::read(output_params_bytes, false).unwrap());

    let rztx: ResolvedZTransaction = serde_json::from_str(rztx_json_str).unwrap();
    let tx = zsign_transaction(wallet, &rztx, &params).unwrap();

    let c_string = CString::new(serde_json::to_string(&tx).unwrap()).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern fn wallet_zverify_spend(
    tx_json: *const libc::c_char,
    p_spendoutput_params_bytes: *const u8,
    spendoutput_params_bytes_len: libc::size_t,
    p_spend_params_bytes: *const u8,
    spend_params_bytes_len: libc::size_t,
    p_output_params_bytes: *const u8,
    output_params_bytes_len: libc::size_t
) -> bool
{
    let tx_json_str: &str = match std::ffi::CStr::from_ptr(tx_json).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed (ztx_json)");
            "FFI seed string conversion failed (ztx_json)"
        }
    };
    let spendoutput_params_bytes = unsafe {
        assert!(!p_spendoutput_params_bytes.is_null());
        slice::from_raw_parts(p_spendoutput_params_bytes, spendoutput_params_bytes_len as usize)
    };
    let spend_params_bytes = unsafe {
        assert!(!p_spend_params_bytes.is_null());
        slice::from_raw_parts(p_spend_params_bytes, spend_params_bytes_len as usize)
    };
    let output_params_bytes = unsafe {
        assert!(!p_output_params_bytes.is_null());
        slice::from_raw_parts(p_output_params_bytes, output_params_bytes_len as usize)
    };

    let mut params = HashMap::new();
    params.insert(Name::from_string(&"spendoutput".to_string()).unwrap(), Parameters::<Bls12>::read(spendoutput_params_bytes, false).unwrap());
    params.insert(Name::from_string(&"spend".to_string()).unwrap(), Parameters::<Bls12>::read(spend_params_bytes, false).unwrap());
    params.insert(Name::from_string(&"output".to_string()).unwrap(), Parameters::<Bls12>::read(output_params_bytes, false).unwrap());

    let tx: Transaction = serde_json::from_str(tx_json_str).unwrap();
    zverify_spend_transaction(&tx, &params)
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern fn wallet_transact(
    p_wallet: *mut Wallet,
    ztx_json: *const libc::c_char,
    fee_token_contract_json: *const libc::c_char,
    fees_json: *const libc::c_char,
    p_mint_params_bytes: *const u8,
    mint_params_bytes_len: libc::size_t,
    p_spendoutput_params_bytes: *const u8,
    spendoutput_params_bytes_len: libc::size_t,
    p_spend_params_bytes: *const u8,
    spend_params_bytes_len: libc::size_t,
    p_output_params_bytes: *const u8,
    output_params_bytes_len: libc::size_t
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };
    let ztx_json_str: &str = match std::ffi::CStr::from_ptr(ztx_json).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed (ztx_json)");
            "FFI seed string conversion failed (ztx_json)"
        }
    };
    let fee_token_contract_json_str: &str = match std::ffi::CStr::from_ptr(fee_token_contract_json).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed (fee_token_contract_json)");
            "FFI seed string conversion failed (fee_token_contract_json)"
        }
    };
    let fees_json_str: &str = match std::ffi::CStr::from_ptr(fees_json).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed (fees_json)");
            "FFI seed string conversion failed (fees_json)"
        }
    };
    let mint_params_bytes = unsafe {
        assert!(!p_mint_params_bytes.is_null());
        slice::from_raw_parts(p_mint_params_bytes, mint_params_bytes_len as usize)
    };
    let spendoutput_params_bytes = unsafe {
        assert!(!p_spendoutput_params_bytes.is_null());
        slice::from_raw_parts(p_spendoutput_params_bytes, spendoutput_params_bytes_len as usize)
    };
    let spend_params_bytes = unsafe {
        assert!(!p_spend_params_bytes.is_null());
        slice::from_raw_parts(p_spend_params_bytes, spend_params_bytes_len as usize)
    };
    let output_params_bytes = unsafe {
        assert!(!p_output_params_bytes.is_null());
        slice::from_raw_parts(p_output_params_bytes, output_params_bytes_len as usize)
    };

    let fee_token_contract = Name::from_string(&fee_token_contract_json_str.to_string()).unwrap();
    let fees = serde_json::from_str(fees_json_str).unwrap();
    let mut params = HashMap::new();
    params.insert(Name::from_string(&"mint".to_string()).unwrap(), Parameters::<Bls12>::read(mint_params_bytes, false).unwrap());
    params.insert(Name::from_string(&"spendoutput".to_string()).unwrap(), Parameters::<Bls12>::read(spendoutput_params_bytes, false).unwrap());
    params.insert(Name::from_string(&"spend".to_string()).unwrap(), Parameters::<Bls12>::read(spend_params_bytes, false).unwrap());
    params.insert(Name::from_string(&"output".to_string()).unwrap(), Parameters::<Bls12>::read(output_params_bytes, false).unwrap());

    let ztx: ZTransaction = serde_json::from_str(ztx_json_str).unwrap();
    let rztx = resolve_ztransaction(wallet, &fee_token_contract, &fees, &ztx).unwrap();
    let tx = zsign_transaction(wallet, &rztx, &params).unwrap();

    let c_string = CString::new(serde_json::to_string(&tx).unwrap()).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern fn wallet_digest_block(
    p_wallet: *mut Wallet,
    block: *const libc::c_char
) -> u64
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let block_str = CStr::from_ptr(block).to_str().expect("Bad encoding").to_owned();
    wallet.digest_block(&block_str)
}

#[cfg(test)]
mod tests
{
    //#[test]
    //fn test_something()
    //{
    //}
}