
mod address;
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

use wallet::Wallet;
use std::slice;
use std::ffi::CString;
use std::ffi::CStr;
use rand_core::OsRng;

// generalized log function for use in different targets
pub fn log(msg: &String)
{
    println!("{}", msg);
}
pub fn clog(msg: &str)
{
    println!("{}", msg);
}

// FFI Resources:
// https://gist.github.com/iskakaushik/1c5b8aa75c77479c33c4320913eebef6
// https://jakegoulding.com/rust-ffi-omnibus/objects/
//
// The following functions are exposed to C via FFI:

#[no_mangle]
pub unsafe extern "C" fn wallet_create(
    seed: *const libc::c_char,
    auth: *const libc::c_char
) -> *mut Wallet
{
    let seed_str: &str = match std::ffi::CStr::from_ptr(seed).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed");
            "FFI seed string conversion failed"
        }
    };
    let auth_str: &str = match std::ffi::CStr::from_ptr(auth).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI auth string conversion failed");
            "FFI auth string conversion failed"
        }
    };

    Box::into_raw(Box::new(Wallet::create(
        seed_str.as_bytes(),
        false,
        &auth_str.to_string()
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
        if pretty { serde_json::to_string_pretty(&wallet.notes()).unwrap() }
        else { serde_json::to_string(&wallet.notes()).unwrap() }
    ).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

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
#[no_mangle]
pub unsafe extern fn free_string(ptr: *const libc::c_char)
{
    // Take the ownership back to rust and drop the owner
    let _ = CString::from_raw(ptr as *mut _);
}

#[no_mangle]
pub unsafe extern fn wallet_move(
    p_wallet: *mut Wallet,
    auth: *const libc::c_char,
    descs: *const libc::c_char
) -> *const libc::c_char
{
    let mut rng = OsRng.clone();
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let auth_str = CStr::from_ptr(auth).to_str().expect("Bad encoding").to_owned();
    let descs_str = CStr::from_ptr(descs).to_str().expect("Bad encoding").to_owned();
    let descs_parts: Vec<String> = descs_str.split("|").map(|s| s.to_string()).collect();
    let tx = wallet.move_asset(&mut rng, auth_str, descs_parts);
    if tx.is_none() { return CString::new("Error: ".to_string()).unwrap().into_raw(); }
    CString::new(serde_json::to_string(&tx.unwrap()).unwrap()).expect("CString::new failed").into_raw()
}

#[no_mangle]
pub unsafe extern fn wallet_transfer(
    p_wallet: *mut Wallet,
    descs: *const libc::c_char
) -> *const libc::c_char
{
    let mut rng = OsRng.clone();
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let descs_str = CStr::from_ptr(descs).to_str().expect("Bad encoding").to_owned();
    let descs_parts: Vec<String> = descs_str.split("|").map(|s| s.to_string()).collect();
    let tx = wallet.transfer_asset(&mut rng, descs_parts);
    if tx.is_none() { return CString::new("Error: ".to_string()).unwrap().into_raw(); }
    CString::new(serde_json::to_string(&tx.unwrap()).unwrap()).expect("CString::new failed").into_raw()
}

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
    wallet.process_block(&block_str)
}
