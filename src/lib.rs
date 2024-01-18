
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

use eosio::{Name, Symbol, Authorization};
#[cfg(target_arch = "wasm32")]
use crate::{
    eosio::Asset,
    transaction::{MintDesc, zsign_transfer_and_mint_transaction},
};
#[cfg(target_arch = "wasm32")]
use std::collections::HashMap;
#[cfg(target_arch = "wasm32")]
use bellman::groth16::Parameters;
#[cfg(target_arch = "wasm32")]
use bls12_381::Bls12;

use wallet::Wallet;
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
    seed: *const libc::c_char
) -> *mut Wallet
{
    let seed_str: &str = match std::ffi::CStr::from_ptr(seed).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed");
            "FFI seed string conversion failed"
        }
    };

    Box::into_raw(Box::new(Wallet::create(
        seed_str.as_bytes(),
        false,
        [0; 32],
        Name(0),
        Authorization { actor: Name(0), permission: Name(0) }
    ).unwrap()))
}

#[no_mangle]
pub extern "C" fn wallet_close(p_wallet: *mut Wallet)
{
    if p_wallet.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(p_wallet));
    }
}

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
    len: libc::size_t
) -> *mut Wallet
{
    let bytes = unsafe {
        assert!(!p_bytes.is_null());
        slice::from_raw_parts(p_bytes, len as usize)
    };

    let wallet = Wallet::read(bytes);
    assert!(wallet.is_ok());
    let wallet = wallet.unwrap();

    Box::into_raw(Box::new(wallet))
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
pub extern fn wallet_notes_json(
    p_wallet: *mut Wallet,
    pretty: bool
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let c_string = CString::new(
        if pretty { serde_json::to_string_pretty(&wallet.unspent_notes(&Symbol(0), &Name(0))).unwrap() }
        else { serde_json::to_string(&wallet.unspent_notes(&Symbol(0), &Name(0))).unwrap() }
    ).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub extern fn wallet_addresses_bech32m(
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
    p_bytes: *const u8,
    len: libc::size_t
)
{
    let bytes = unsafe {
        assert!(!p_bytes.is_null());
        slice::from_raw_parts(p_bytes, len as usize)
    };
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    wallet.add_leaves(bytes);
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern fn wallet_process_block(
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