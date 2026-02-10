
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

mod engine;
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
pub mod wallet_encryption;
pub mod transaction;
pub mod transaction_spend_tests;

use wallet::Wallet;
use crate::address::Address;
use eosio::{Name, Symbol, Asset, Authorization, ExtendedAsset, Transaction};
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
use transaction::{ZTransaction, ResolvedZTransaction, resolve_ztransaction, zsign_transaction, zverify_spend_transaction, create_auth_token};
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
use keys::IncomingViewingKey;
use std::collections::HashMap;
use bellman::groth16::Parameters;
use crate::engine::Bls12;
#[cfg(target_arch = "wasm32")]
use crate::transaction::{MintDesc, zsign_transfer_and_mint_transaction};
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
use std::slice;
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
use std::ffi::CString;
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
use std::ffi::CStr;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use std::cell::RefCell;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
fn set_last_error(msg: &str) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(msg.to_string());
    });
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_last_error() -> *const libc::c_char {
    LAST_ERROR.with(|e| {
        if let Some(ref msg) = *e.borrow() {
            // allocate a new C string; caller must free with free_string
            CString::new(msg.clone()).unwrap().into_raw()
        } else {
            std::ptr::null()
        }
    })
}

/// The ptr should be a valid pointer to the string allocated by rust
/// source: https://dev.to/kgrech/7-ways-to-pass-a-string-between-rust-and-c-4ieb
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub unsafe extern "C" fn free_string(ptr: *const libc::c_char)
{
    // Take the ownership back to rust and drop the owner
    let _ = CString::from_raw(ptr as *mut _);
}

// generalized log function for use in different targets
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
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

#[cfg(feature = "multicore")]
// see: https://github.com/GoogleChromeLabs/wasm-bindgen-rayon
// only enable this when build as wasm since wasm_bindgen_rayon
// conflicts in build for default target (like for unit tests)
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use wasm_bindgen_rayon::init_thread_pool;

// WASM Bindgen Resouces:
// https://rustwasm.github.io/wasm-bindgen/examples/hello-world.html
//
// The following function is for easy use (EOSIO account => ZEOS wallet) in JS Browser applications

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

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub unsafe extern "C" fn wallet_create(
    seed: *const libc::c_char,
    is_ivk: bool,
    chain_id: *const libc::c_char,
    protocol_contract: *const libc::c_char,
    vault_contract: *const libc::c_char,
    alias_authority: *const libc::c_char,
    out_p_wallet: &mut *mut Wallet,
) -> bool
{
    *out_p_wallet = std::ptr::null_mut();

    if seed.is_null() {
        set_last_error("wallet_create: seed is null");
        return false;
    }
    if chain_id.is_null() {
        set_last_error("wallet_create: chain_id is null");
        return false;
    }
    if protocol_contract.is_null() {
        set_last_error("wallet_create: protocol_contract is null");
        return false;
    }
    if vault_contract.is_null() {
        set_last_error("wallet_create: vault_contract is null");
        return false;
    }
    if alias_authority.is_null() {
        set_last_error("wallet_create: alias_authority is null");
        return false;
    }

    let seed_str = match std::ffi::CStr::from_ptr(seed).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("wallet_create: invalid UTF-8 in seed");
            return false;
        }
    };
    let chain_id_str = match std::ffi::CStr::from_ptr(chain_id).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("wallet_create: invalid UTF-8 in chain_id");
            return false;
        }
    };
    let protocol_contract_str = match std::ffi::CStr::from_ptr(protocol_contract).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("wallet_create: invalid UTF-8 in protocol_contract");
            return false;
        }
    };
    let vault_contract_str = match std::ffi::CStr::from_ptr(vault_contract).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("wallet_create: invalid UTF-8 in vault_contract");
            return false;
        }
    };
    let alias_authority_str = match std::ffi::CStr::from_ptr(alias_authority).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("wallet_create: invalid UTF-8 in alias_authority");
            return false;
        }
    };
    let chain_id_vec = match hex::decode(chain_id_str) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(&format!("wallet_create: invalid chain_id hex: {e}"));
            return false;
        }
    };
    let chain_id_bytes: [u8; 32] = match chain_id_vec.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            set_last_error("wallet_create: chain_id must decode to 32 bytes");
            return false;
        }
    };

    if is_ivk {
        let ivk = match IncomingViewingKey::from_bech32m(seed_str) {
            Ok(ivk) => ivk,
            Err(e) => {
                set_last_error(&format!("wallet_create: invalid incoming viewing key: {e}"));
                return false;
            }
        };
        let protocol_name = match Name::from_string(&protocol_contract_str.to_string()) {
            Ok(n) => n,
            Err(e) => {
                set_last_error(&format!("wallet_create: invalid protocol_contract: {e}"));
                return false;
            }
        };
        let vault_name = match Name::from_string(&vault_contract_str.to_string()) {
            Ok(n) => n,
            Err(e) => {
                set_last_error(&format!("wallet_create: invalid vault_contract: {e}"));
                return false;
            }
        };
        let alias_auth = match Authorization::from_string(&alias_authority_str.to_string()) {
            Ok(a) => a,
            Err(e) => {
                set_last_error(&format!("wallet_create: invalid alias_authority: {e}"));
                return false;
            }
        };
        let wallet_opt = Wallet::create(
            ivk.to_bytes().as_slice(),
            true,
            chain_id_bytes,
            protocol_name,
            vault_name,
            alias_auth,
        );
        let wallet = match wallet_opt {
            Some(w) => w,
            None => {
                set_last_error("wallet_create: Wallet::create returned None (ivk)");
                return false;
            }
        };

        *out_p_wallet = Box::into_raw(Box::new(wallet));
        true
    } else {
        let protocol_name = match Name::from_string(&protocol_contract_str.to_string()) {
            Ok(n) => n,
            Err(e) => {
                set_last_error(&format!("wallet_create: invalid protocol_contract: {e}"));
                return false;
            }
        };
        let vault_name = match Name::from_string(&vault_contract_str.to_string()) {
            Ok(n) => n,
            Err(e) => {
                set_last_error(&format!("wallet_create: invalid vault_contract: {e}"));
                return false;
            }
        };
        let alias_auth = match Authorization::from_string(&alias_authority_str.to_string()) {
            Ok(a) => a,
            Err(e) => {
                set_last_error(&format!("wallet_create: invalid alias_authority: {e}"));
                return false;
            }
        };
        let wallet_opt = Wallet::create(
            seed_str.as_bytes(),
            false,
            chain_id_bytes,
            protocol_name,
            vault_name,
            alias_auth,
        );
        let wallet = match wallet_opt {
            Some(w) => w,
            None => {
                set_last_error("wallet_create: Wallet::create returned None (seed)");
                return false;
            }
        };

        *out_p_wallet = Box::into_raw(Box::new(wallet));
        true
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
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

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_seed_hex(
    p_wallet: *mut Wallet,
    out_seed_hex: &mut *const libc::c_char,
) -> bool {
    if p_wallet.is_null() {
        set_last_error("wallet_seed_hex: p_wallet is null");
        return false;
    }
    let wallet = unsafe { &mut *p_wallet };
    let encoded = hex::encode(wallet.seed());

    match CString::new(encoded) {
        Ok(c_string) => {
            *out_seed_hex = c_string.into_raw(); // transfer ownership to caller
            true
        }
        Err(_) => {
            set_last_error("wallet_seed_hex: CString::new failed (unexpected null byte)");
            *out_seed_hex = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_size(
    p_wallet: *mut Wallet,
    out_size: &mut u64,
) -> bool {
    *out_size = 0;

    if p_wallet.is_null() {
        set_last_error("wallet_size: p_wallet is null");
        return false;
    }
    let wallet = unsafe { &mut *p_wallet };
    *out_size = wallet.size() as u64;
    true
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_is_ivk(
    p_wallet: *mut Wallet,
    out_is_ivk: &mut bool,
) -> bool {
    *out_is_ivk = false;

    if p_wallet.is_null() {
        set_last_error("wallet_is_ivk: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    *out_is_ivk = wallet.is_ivk();
    true
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_chain_id(
    p_wallet: *mut Wallet,
    out_chain_id: &mut *const libc::c_char,
) -> bool {
    *out_chain_id = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_chain_id: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let encoded = hex::encode(wallet.chain_id());

    match CString::new(encoded) {
        Ok(c_string) => {
            *out_chain_id = c_string.into_raw(); // transfer ownership to caller
            true
        }
        Err(_) => {
            set_last_error("wallet_chain_id: CString::new failed (unexpected null byte)");
            *out_chain_id = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_protocol_contract(
    p_wallet: *mut Wallet,
    out_protocol_contract: &mut *const libc::c_char,
) -> bool {
    *out_protocol_contract = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_protocol_contract: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let contract_str = wallet.protocol_contract().to_string();

    match CString::new(contract_str) {
        Ok(c_string) => {
            *out_protocol_contract = c_string.into_raw(); // caller must free with free_string
            true
        }
        Err(_) => {
            set_last_error("wallet_protocol_contract: CString::new failed (unexpected null byte)");
            *out_protocol_contract = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_vault_contract(
    p_wallet: *mut Wallet,
    out_vault_contract: &mut *const libc::c_char,
) -> bool {
    *out_vault_contract = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_vault_contract: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let contract_str = wallet.vault_contract().to_string();

    match CString::new(contract_str) {
        Ok(c_string) => {
            *out_vault_contract = c_string.into_raw(); // caller frees with free_string
            true
        }
        Err(_) => {
            set_last_error("wallet_vault_contract: CString::new failed (unexpected null byte)");
            *out_vault_contract = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_alias_authority(
    p_wallet: *mut Wallet,
    out_alias_authority: &mut *const libc::c_char,
) -> bool {
    *out_alias_authority = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_alias_authority: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let alias_str = wallet.alias_authority().to_string();

    match CString::new(alias_str) {
        Ok(c_string) => {
            *out_alias_authority = c_string.into_raw(); // caller frees with free_string
            true
        }
        Err(_) => {
            set_last_error("wallet_alias_authority: CString::new failed (unexpected null byte)");
            *out_alias_authority = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_block_num(
    p_wallet: *mut Wallet,
    out_block_num: &mut u32,
) -> bool {
    *out_block_num = 0;

    if p_wallet.is_null() {
        set_last_error("wallet_block_num: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    *out_block_num = wallet.block_num();
    true
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_leaf_count(
    p_wallet: *mut Wallet,
    out_leaf_count: &mut u64,
) -> bool {
    *out_leaf_count = 0;

    if p_wallet.is_null() {
        set_last_error("wallet_leaf_count: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    *out_leaf_count = wallet.leaf_count();
    true
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_auth_count(
    p_wallet: *mut Wallet,
    out_auth_count: &mut u64,
) -> bool {
    *out_auth_count = 0;

    if p_wallet.is_null() {
        set_last_error("wallet_auth_count: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    *out_auth_count = wallet.auth_count();
    true
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_set_auth_count(
    p_wallet: *mut Wallet,
    count: u64,
) -> bool {
    if p_wallet.is_null() {
        set_last_error("wallet_set_auth_count: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    wallet.set_auth_count(count);
    true
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_write(
    p_wallet: *mut Wallet,
    out_bytes: *mut u8,
) -> bool {
    if p_wallet.is_null() {
        set_last_error("wallet_write: p_wallet is null");
        return false;
    }
    if out_bytes.is_null() {
        set_last_error("wallet_write: out_bytes is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let mut wallet_bytes = Vec::new();
    if let Err(e) = wallet.write(&mut wallet_bytes) {
        set_last_error(&format!("wallet_write: wallet.write failed: {e:?}"));
        return false;
    }

    let expected_size = wallet.size();
    if wallet_bytes.len() != expected_size {
        // This shouldn't normally happen, but let's defend against it.
        set_last_error(&format!(
            "wallet_write: serialized size mismatch (expected {}, got {})",
            expected_size,
            wallet_bytes.len()
        ));
        return false;
    }

    // SAFETY: caller must have allocated at least `wallet_size` bytes at out_bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(wallet_bytes.as_ptr(), out_bytes, wallet_bytes.len());
    }

    true
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_read(
    p_bytes: *const u8,
    len: libc::size_t,
    out_p_wallet: &mut *mut Wallet,
) -> bool {
    *out_p_wallet = std::ptr::null_mut();

    if p_bytes.is_null() {
        set_last_error("wallet_read: p_bytes is null");
        return false;
    }
    if len == 0 {
        set_last_error("wallet_read: len is zero");
        return false;
    }

    // SAFETY: we checked for null and a non-zero length; caller must guarantee
    // that p_bytes points to a valid buffer of at least `len` bytes.
    let bytes: &[u8] = unsafe { slice::from_raw_parts(p_bytes, len as usize) };
    let wallet_res = Wallet::read(bytes);
    let wallet = match wallet_res {
        Ok(w) => w,
        Err(e) => {
            set_last_error(&format!("wallet_read: Wallet::read failed: {e:?}"));
            return false;
        }
    };

    *out_p_wallet = Box::into_raw(Box::new(wallet));
    true
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_is_encrypted(
    p_bytes: *const u8,
    len: libc::size_t,
    out_is_encrypted: &mut bool,
) -> bool {
    *out_is_encrypted = false;

    if p_bytes.is_null() {
        set_last_error("wallet_is_encrypted: p_bytes is null");
        return false;
    }
    if len == 0 {
        set_last_error("wallet_is_encrypted: len is zero");
        return false;
    }

    let bytes: &[u8] = unsafe { slice::from_raw_parts(p_bytes, len as usize) };
    *out_is_encrypted = wallet_encryption::is_encrypted_wallet(bytes);
    true
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_encrypt_size(
    plain_len: u64,
    out_size: &mut u64,
) -> bool {
    *out_size = wallet_encryption::encrypted_size(plain_len as usize) as u64;
    true
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_encrypt_bytes(
    p_plain: *const u8,
    plain_len: libc::size_t,
    password: *const libc::c_char,
    out_bytes: *mut u8,
) -> bool {
    if p_plain.is_null() {
        set_last_error("wallet_encrypt_bytes: p_plain is null");
        return false;
    }
    if plain_len == 0 {
        set_last_error("wallet_encrypt_bytes: plain_len is zero");
        return false;
    }
    if password.is_null() {
        set_last_error("wallet_encrypt_bytes: password is null");
        return false;
    }
    if out_bytes.is_null() {
        set_last_error("wallet_encrypt_bytes: out_bytes is null");
        return false;
    }

    let plain: &[u8] = unsafe { slice::from_raw_parts(p_plain, plain_len as usize) };
    let pw = unsafe { CStr::from_ptr(password) }.to_bytes(); // best-effort

    let enc = match wallet_encryption::encrypt_wallet_bytes(
        plain,
        pw,
        wallet_encryption::KdfParams::default(),
    ) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(&format!("wallet_encrypt_bytes: encrypt failed: {e:?}"));
            return false;
        }
    };

    // SAFETY: caller must allocate exactly wallet_encrypt_size(plain_len) bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(enc.as_ptr(), out_bytes, enc.len());
    }

    true
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_decrypt_size(
    p_enc: *const u8,
    enc_len: libc::size_t,
    out_size: &mut u64,
) -> bool {
    *out_size = 0;

    if p_enc.is_null() {
        set_last_error("wallet_decrypt_size: p_enc is null");
        return false;
    }
    if enc_len == 0 {
        set_last_error("wallet_decrypt_size: enc_len is zero");
        return false;
    }

    let enc: &[u8] = unsafe { slice::from_raw_parts(p_enc, enc_len as usize) };
    match wallet_encryption::decrypted_size(enc) {
        Ok(sz) => {
            *out_size = sz as u64;
            true
        }
        Err(e) => {
            set_last_error(&format!("wallet_decrypt_size: invalid encrypted wallet: {e:?}"));
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_decrypt_bytes(
    p_enc: *const u8,
    enc_len: libc::size_t,
    password: *const libc::c_char,
    out_plain: *mut u8,
) -> bool {
    if p_enc.is_null() {
        set_last_error("wallet_decrypt_bytes: p_enc is null");
        return false;
    }
    if enc_len == 0 {
        set_last_error("wallet_decrypt_bytes: enc_len is zero");
        return false;
    }
    if password.is_null() {
        set_last_error("wallet_decrypt_bytes: password is null");
        return false;
    }
    if out_plain.is_null() {
        set_last_error("wallet_decrypt_bytes: out_plain is null");
        return false;
    }

    let enc: &[u8] = unsafe { slice::from_raw_parts(p_enc, enc_len as usize) };
    let pw = unsafe { CStr::from_ptr(password) }.to_bytes();

    let plain = match wallet_encryption::decrypt_wallet_bytes(enc, pw) {
        Ok(v) => v,
        Err(e) => {
            // Wrong password and corrupted file look the same; that's fine.
            set_last_error(&format!("wallet_decrypt_bytes: decrypt failed: {e:?}"));
            return false;
        }
    };

    unsafe {
        std::ptr::copy_nonoverlapping(plain.as_ptr(), out_plain, plain.len());
    }

    true
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_json(
    p_wallet: *mut Wallet,
    pretty: bool,
    out_json: &mut *const libc::c_char,
) -> bool {
    *out_json = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_json: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let json = wallet.to_json(pretty);

    match CString::new(json) {
        Ok(c_string) => {
            *out_json = c_string.into_raw(); // caller must free with free_string()
            true
        }
        Err(_) => {
            set_last_error("wallet_json: CString::new failed (unexpected null byte)");
            *out_json = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_balances_json(
    p_wallet: *mut Wallet,
    pretty: bool,
    out_json: &mut *const libc::c_char,
) -> bool {
    *out_json = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_balances_json: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let balances = wallet.balances();
    let json_result = if pretty {
        serde_json::to_string_pretty(&balances)
    } else {
        serde_json::to_string(&balances)
    };
    let json = match json_result {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!("wallet_balances_json: serialization failed: {e}"));
            return false;
        }
    };

    match CString::new(json) {
        Ok(c_string) => {
            *out_json = c_string.into_raw(); // caller must free with free_string
            true
        }
        Err(_) => {
            set_last_error("wallet_balances_json: CString::new failed (unexpected null byte)");
            *out_json = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_unspent_notes_json(
    p_wallet: *mut Wallet,
    pretty: bool,
    out_json: &mut *const libc::c_char,
) -> bool {
    *out_json = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_unspent_notes_json: p_wallet is null");
        return false;
    }

    // SAFETY: pointer checked for null; caller must ensure it's a valid Wallet*
    let wallet = unsafe { &mut *p_wallet };
    let unspent = wallet.unspent_notes();
    let json_result = if pretty {
        serde_json::to_string_pretty(&unspent)
    } else {
        serde_json::to_string(&unspent)
    };
    let json = match json_result {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!("wallet_unspent_notes_json: serialization failed: {e}"));
            return false;
        }
    };

    match CString::new(json) {
        Ok(c_string) => {
            *out_json = c_string.into_raw(); // caller must free with free_string
            true
        }
        Err(_) => {
            set_last_error("wallet_unspent_notes_json: CString::new failed (unexpected null byte)");
            *out_json = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_fungible_tokens_json(
    p_wallet: *mut Wallet,
    symbol: u64,
    contract: u64,
    pretty: bool,
    out_json: &mut *const libc::c_char,
) -> bool {
    *out_json = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_fungible_tokens_json: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    // Build the list of assets
    let tokens = wallet
        .fungible_tokens(&Symbol(symbol), &Name(contract))
        .iter()
        .map(|n| n.note().asset().clone())
        .collect::<Vec<ExtendedAsset>>();
    let json_result = if pretty {
        serde_json::to_string_pretty(&tokens)
    } else {
        serde_json::to_string(&tokens)
    };
    let json = match json_result {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!(
                "wallet_fungible_tokens_json: serialization failed: {e}"
            ));
            return false;
        }
    };

    match CString::new(json) {
        Ok(c_string) => {
            *out_json = c_string.into_raw(); // caller must free with free_string
            true
        }
        Err(_) => {
            set_last_error(
                "wallet_fungible_tokens_json: CString::new failed (unexpected null byte)",
            );
            *out_json = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_non_fungible_tokens_json(
    p_wallet: *mut Wallet,
    contract: u64,
    pretty: bool,
    out_json: &mut *const libc::c_char,
) -> bool {
    *out_json = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_non_fungible_tokens_json: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let tokens = wallet
        .non_fungible_tokens(&Name(contract))
        .iter()
        .map(|n| n.note().asset().clone())
        .collect::<Vec<ExtendedAsset>>();
    let json_result = if pretty {
        serde_json::to_string_pretty(&tokens)
    } else {
        serde_json::to_string(&tokens)
    };
    let json = match json_result {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!(
                "wallet_non_fungible_tokens_json: serialization failed: {e}"
            ));
            return false;
        }
    };

    match CString::new(json) {
        Ok(c_string) => {
            *out_json = c_string.into_raw(); // caller must free with free_string
            true
        }
        Err(_) => {
            set_last_error(
                "wallet_non_fungible_tokens_json: CString::new failed (unexpected null byte)",
            );
            *out_json = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_authentication_tokens_json(
    p_wallet: *mut Wallet,
    contract: u64,
    spent: bool,
    seed: bool,
    pretty: bool,
    out_json: &mut *const libc::c_char,
) -> bool {
    *out_json = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_authentication_tokens_json: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let tokens = wallet
        .authentication_tokens(&Name(contract), spent)
        .iter()
        .map(|n| {
            // "<commitment_hex>@<contract_name>|<seed_phrase>"
            if seed {
                format!(
                    "{}@{}|{}",
                    hex::encode(n.note().commitment().to_bytes()),
                    n.note().contract().to_string(),
                    n.note().memo_string()
                )
            // "<commitment_hex>@<contract_name>"
            } else {
                format!(
                    "{}@{}",
                    hex::encode(n.note().commitment().to_bytes()),
                    n.note().contract().to_string()
                )
            }
        })
        .collect::<Vec<String>>();
    let json_result = if pretty {
        serde_json::to_string_pretty(&tokens)
    } else {
        serde_json::to_string(&tokens)
    };
    let json = match json_result {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!(
                "wallet_authentication_tokens_json: serialization failed: {e}"
            ));
            return false;
        }
    };

    match CString::new(json) {
        Ok(c_string) => {
            *out_json = c_string.into_raw(); // caller frees with free_string
            true
        }
        Err(_) => {
            set_last_error(
                "wallet_authentication_tokens_json: CString::new failed (unexpected null byte)",
            );
            *out_json = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_unpublished_notes_json(
    p_wallet: *mut Wallet,
    pretty: bool,
    out_json: &mut *const libc::c_char,
) -> bool {
    *out_json = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_unpublished_notes_json: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let unpublished = wallet.unpublished_notes();
    let json_result = if pretty {
        serde_json::to_string_pretty(&unpublished)
    } else {
        serde_json::to_string(&unpublished)
    };
    let json = match json_result {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!(
                "wallet_unpublished_notes_json: serialization failed: {e}"
            ));
            return false;
        }
    };

    match CString::new(json) {
        Ok(c_string) => {
            *out_json = c_string.into_raw(); // caller frees with free_string
            true
        }
        Err(_) => {
            set_last_error(
                "wallet_unpublished_notes_json: CString::new failed (unexpected null byte)",
            );
            *out_json = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_transaction_history_json(
    p_wallet: *mut Wallet,
    pretty: bool,
    out_json: &mut *const libc::c_char,
) -> bool {
    *out_json = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_transaction_history_json: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let history = wallet.transaction_history();
    let json_result = if pretty {
        serde_json::to_string_pretty(&history)
    } else {
        serde_json::to_string(&history)
    };
    let json = match json_result {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!(
                "wallet_transaction_history_json: serialization failed: {e}"
            ));
            return false;
        }
    };

    match CString::new(json) {
        Ok(c_string) => {
            *out_json = c_string.into_raw(); // caller must free with free_string
            true
        }
        Err(_) => {
            set_last_error(
                "wallet_transaction_history_json: CString::new failed (unexpected null byte)",
            );
            *out_json = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_addresses_json(
    p_wallet: *mut Wallet,
    pretty: bool,
    out_json: &mut *const libc::c_char,
) -> bool {
    *out_json = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_addresses_json: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let addresses = wallet.addresses();
    let json_result = if pretty {
        serde_json::to_string_pretty(&addresses)
    } else {
        serde_json::to_string(&addresses)
    };
    let json = match json_result {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!(
                "wallet_addresses_json: serialization failed: {e}"
            ));
            return false;
        }
    };

    match CString::new(json) {
        Ok(c_string) => {
            *out_json = c_string.into_raw(); // caller frees with free_string
            true
        }
        Err(_) => {
            set_last_error(
                "wallet_addresses_json: CString::new failed (unexpected null byte)",
            );
            *out_json = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_derive_address(
    p_wallet: *mut Wallet,
    out_address: &mut *const libc::c_char,
) -> bool {
    *out_address = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_derive_address: p_wallet is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let addr = wallet.derive_next_address();
    let json = match serde_json::to_string(&addr) {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!(
                "wallet_derive_address: serialization failed: {e}"
            ));
            return false;
        }
    };

    match CString::new(json) {
        Ok(c_string) => {
            *out_address = c_string.into_raw(); // caller frees with free_string
            true
        }
        Err(_) => {
            set_last_error(
                "wallet_derive_address: CString::new failed (unexpected null byte)",
            );
            *out_address = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_add_leaves(
    p_wallet: *mut Wallet,
    leaves: *const libc::c_char,
) -> bool {
    if p_wallet.is_null() {
        set_last_error("wallet_add_leaves: p_wallet is null");
        return false;
    }
    if leaves.is_null() {
        set_last_error("wallet_add_leaves: leaves is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let leaves_str: &str = match unsafe { std::ffi::CStr::from_ptr(leaves) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("wallet_add_leaves: invalid UTF-8 in leaves");
            return false;
        }
    };
    let bytes = match hex::decode(leaves_str) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(&format!("wallet_add_leaves: invalid hex in leaves: {e}"));
            return false;
        }
    };

    wallet.add_leaves(bytes.as_slice());
    true
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_add_notes(
    p_wallet: *mut Wallet,
    notes: *const libc::c_char,
) -> bool {
    if p_wallet.is_null() {
        set_last_error("wallet_add_notes: p_wallet is null");
        return false;
    }
    if notes.is_null() {
        set_last_error("wallet_add_notes: notes is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let notes_str: &str = match unsafe { std::ffi::CStr::from_ptr(notes) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("wallet_add_notes: invalid UTF-8 in notes");
            return false;
        }
    };
    let notes_vec: Vec<String> = match serde_json::from_str(notes_str) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(&format!("wallet_add_notes: invalid JSON in notes: {e}"));
            return false;
        }
    };

    wallet.add_notes(&notes_vec, 0, 0);
    true
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_add_unpublished_notes(
    p_wallet: *mut Wallet,
    unpublished_notes: *const libc::c_char,
) -> bool {
    if p_wallet.is_null() {
        set_last_error("wallet_add_unpublished_notes: p_wallet is null");
        return false;
    }
    if unpublished_notes.is_null() {
        set_last_error("wallet_add_unpublished_notes: unpublished_notes is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let unpublished_notes_str: &str =
        match unsafe { std::ffi::CStr::from_ptr(unpublished_notes) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error(
                    "wallet_add_unpublished_notes: invalid UTF-8 in unpublished_notes",
                );
                return false;
            }
        };
    let unpublished_notes_map: HashMap<String, Vec<String>> =
        match serde_json::from_str(unpublished_notes_str) {
            Ok(m) => m,
            Err(e) => {
                set_last_error(&format!(
                    "wallet_add_unpublished_notes: invalid JSON in unpublished_notes: {e}"
                ));
                return false;
            }
        };

    wallet.add_unpublished_notes(&unpublished_notes_map);
    true
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_create_unpublished_auth_note(
    p_wallet: *mut Wallet,
    seed: *const libc::c_char,
    contract: u64,
    address: *const libc::c_char,
    out_unpublished_notes: &mut *const libc::c_char,
) -> bool {
    *out_unpublished_notes = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_create_unpublished_auth_note: p_wallet is null");
        return false;
    }
    if seed.is_null() {
        set_last_error("wallet_create_unpublished_auth_note: seed is null");
        return false;
    }
    if address.is_null() {
        set_last_error("wallet_create_unpublished_auth_note: address is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let seed_str: &str =
        match unsafe { std::ffi::CStr::from_ptr(seed) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error(
                    "wallet_create_unpublished_auth_note: invalid UTF-8 in seed",
                );
                return false;
            }
        };
    let address_str: &str =
        match unsafe { std::ffi::CStr::from_ptr(address) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error(
                    "wallet_create_unpublished_auth_note: invalid UTF-8 in address",
                );
                return false;
            }
        };
    let addr = match Address::from_bech32m(&address_str.to_string()) {
        Ok(a) => a,
        Err(e) => {
            set_last_error(&format!(
                "wallet_create_unpublished_auth_note: invalid bech32m address: {e}"
            ));
            return false;
        }
    };
    let unpublished_notes_map: HashMap<String, Vec<String>> = match create_auth_token(
        wallet,
        seed_str.to_string(),
        Name(contract),
        addr,
    ) {
        Ok(m) => m,
        Err(e) => {
            set_last_error(&format!(
                "wallet_create_unpublished_auth_note: create_auth_token failed: {e:?}"
            ));
            return false;
        }
    };
    let json = match serde_json::to_string(&unpublished_notes_map) {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!(
                "wallet_create_unpublished_auth_note: serialization failed: {e}"
            ));
            return false;
        }
    };

    match CString::new(json) {
        Ok(c_string) => {
            *out_unpublished_notes = c_string.into_raw(); // caller frees with free_string
            true
        }
        Err(_) => {
            set_last_error(
                "wallet_create_unpublished_auth_note: CString::new failed (unexpected null byte)",
            );
            *out_unpublished_notes = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_resolve(
    p_wallet: *mut Wallet,
    ztx_json: *const libc::c_char,
    fee_token_contract_json: *const libc::c_char,
    fees_json: *const libc::c_char,
    out_rztx_json: &mut *const libc::c_char,
) -> bool {
    *out_rztx_json = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_resolve: p_wallet is null");
        return false;
    }
    if ztx_json.is_null() {
        set_last_error("wallet_resolve: ztx_json is null");
        return false;
    }
    if fee_token_contract_json.is_null() {
        set_last_error("wallet_resolve: fee_token_contract_json is null");
        return false;
    }
    if fees_json.is_null() {
        set_last_error("wallet_resolve: fees_json is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let ztx_json_str: &str = match unsafe { std::ffi::CStr::from_ptr(ztx_json) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("wallet_resolve: invalid UTF-8 in ztx_json");
            return false;
        }
    };
    let fee_token_contract_json_str: &str =
        match unsafe { std::ffi::CStr::from_ptr(fee_token_contract_json) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error("wallet_resolve: invalid UTF-8 in fee_token_contract_json");
                return false;
            }
        };
    let fees_json_str: &str =
        match unsafe { std::ffi::CStr::from_ptr(fees_json) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error("wallet_resolve: invalid UTF-8 in fees_json");
                return false;
            }
        };
    let fee_token_contract = match Name::from_string(&fee_token_contract_json_str.to_string()) {
        Ok(name) => name,
        Err(e) => {
            set_last_error(&format!(
                "wallet_resolve: invalid fee_token_contract_json: {e}"
            ));
            return false;
        }
    };
    let fees: HashMap<Name, Asset> = match serde_json::from_str(fees_json_str) {
        Ok(f) => f,
        Err(e) => {
            set_last_error(&format!("wallet_resolve: invalid JSON in fees_json: {e}"));
            return false;
        }
    };
    let ztx: ZTransaction = match serde_json::from_str(ztx_json_str) {
        Ok(z) => z,
        Err(e) => {
            set_last_error(&format!("wallet_resolve: invalid JSON in ztx_json: {e}"));
            return false;
        }
    };
    let rztx = match resolve_ztransaction(wallet, &fee_token_contract, &fees, &ztx) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(&format!("wallet_resolve: resolve_ztransaction failed: {e}"));
            return false;
        }
    };
    let json = match serde_json::to_string(&rztx) {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!(
                "wallet_resolve: failed to serialize ResolvedZTransaction: {e}"
            ));
            return false;
        }
    };

    match CString::new(json) {
        Ok(c_string) => {
            *out_rztx_json = c_string.into_raw(); // caller must free with free_string
            true
        }
        Err(_) => {
            set_last_error("wallet_resolve: CString::new failed (unexpected null byte)");
            *out_rztx_json = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_zsign(
    p_wallet: *mut Wallet,
    rztx_json: *const libc::c_char,
    p_mint_params_bytes: *const u8,
    mint_params_bytes_len: libc::size_t,
    p_spendoutput_params_bytes: *const u8,
    spendoutput_params_bytes_len: libc::size_t,
    p_spend_params_bytes: *const u8,
    spend_params_bytes_len: libc::size_t,
    p_output_params_bytes: *const u8,
    output_params_bytes_len: libc::size_t,
    out_tx_json: &mut *const libc::c_char,
) -> bool {
    *out_tx_json = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_zsign: p_wallet is null");
        return false;
    }
    if rztx_json.is_null() {
        set_last_error("wallet_zsign: rztx_json is null");
        return false;
    }
    if p_mint_params_bytes.is_null() {
        set_last_error("wallet_zsign: p_mint_params_bytes is null");
        return false;
    }
    if p_spendoutput_params_bytes.is_null() {
        set_last_error("wallet_zsign: p_spendoutput_params_bytes is null");
        return false;
    }
    if p_spend_params_bytes.is_null() {
        set_last_error("wallet_zsign: p_spend_params_bytes is null");
        return false;
    }
    if p_output_params_bytes.is_null() {
        set_last_error("wallet_zsign: p_output_params_bytes is null");
        return false;
    }
    if mint_params_bytes_len == 0
        || spendoutput_params_bytes_len == 0
        || spend_params_bytes_len == 0
        || output_params_bytes_len == 0
    {
        set_last_error("wallet_zsign: one or more params byte slices have length 0");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let rztx_json_str: &str =
        match unsafe { std::ffi::CStr::from_ptr(rztx_json) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error("wallet_zsign: invalid UTF-8 in rztx_json");
                return false;
            }
        };
    let mint_params_bytes: &[u8] = unsafe {
        slice::from_raw_parts(p_mint_params_bytes, mint_params_bytes_len as usize)
    };
    let spendoutput_params_bytes: &[u8] = unsafe {
        slice::from_raw_parts(p_spendoutput_params_bytes, spendoutput_params_bytes_len as usize)
    };
    let spend_params_bytes: &[u8] = unsafe {
        slice::from_raw_parts(p_spend_params_bytes, spend_params_bytes_len as usize)
    };
    let output_params_bytes: &[u8] = unsafe {
        slice::from_raw_parts(p_output_params_bytes, output_params_bytes_len as usize)
    };
    let mut params = HashMap::new();
    let mint_name = match Name::from_string(&"mint".to_string()) {
        Ok(n) => n,
        Err(e) => {
            set_last_error(&format!("wallet_zsign: failed to construct Name(\"mint\"): {e}"));
            return false;
        }
    };
    let spendoutput_name = match Name::from_string(&"spendoutput".to_string()) {
        Ok(n) => n,
        Err(e) => {
            set_last_error(&format!(
                "wallet_zsign: failed to construct Name(\"spendoutput\"): {e}"
            ));
            return false;
        }
    };
    let spend_name = match Name::from_string(&"spend".to_string()) {
        Ok(n) => n,
        Err(e) => {
            set_last_error(&format!("wallet_zsign: failed to construct Name(\"spend\"): {e}"));
            return false;
        }
    };
    let output_name = match Name::from_string(&"output".to_string()) {
        Ok(n) => n,
        Err(e) => {
            set_last_error(&format!("wallet_zsign: failed to construct Name(\"output\"): {e}"));
            return false;
        }
    };
    let mint_params = match Parameters::<Bls12>::read(mint_params_bytes, false) {
        Ok(p) => p,
        Err(e) => {
            set_last_error(&format!("wallet_zsign: failed to read mint params: {e:?}"));
            return false;
        }
    };
    let spendoutput_params =
        match Parameters::<Bls12>::read(spendoutput_params_bytes, false) {
            Ok(p) => p,
            Err(e) => {
                set_last_error(&format!(
                    "wallet_zsign: failed to read spendoutput params: {e:?}"
                ));
                return false;
            }
        };
    let spend_params = match Parameters::<Bls12>::read(spend_params_bytes, false) {
        Ok(p) => p,
        Err(e) => {
            set_last_error(&format!("wallet_zsign: failed to read spend params: {e:?}"));
            return false;
        }
    };
    let output_params = match Parameters::<Bls12>::read(output_params_bytes, false) {
        Ok(p) => p,
        Err(e) => {
            set_last_error(&format!("wallet_zsign: failed to read output params: {e:?}"));
            return false;
        }
    };
    params.insert(mint_name, mint_params);
    params.insert(spendoutput_name, spendoutput_params);
    params.insert(spend_name, spend_params);
    params.insert(output_name, output_params);
    let rztx: ResolvedZTransaction = match serde_json::from_str(rztx_json_str) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(&format!("wallet_zsign: invalid JSON in rztx_json: {e}"));
            return false;
        }
    };
    let tx = match zsign_transaction(wallet, &rztx, &params) {
        Ok(t) => t,
        Err(e) => {
            set_last_error(&format!("wallet_zsign: zsign_transaction failed: {e:?}"));
            return false;
        }
    };
    let json = match serde_json::to_string(&tx) {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!("wallet_zsign: failed to serialize transaction: {e}"));
            return false;
        }
    };

    match CString::new(json) {
        Ok(c_string) => {
            *out_tx_json = c_string.into_raw(); // caller must free with free_string
            true
        }
        Err(_) => {
            set_last_error(
                "wallet_zsign: CString::new failed (unexpected null byte in JSON)",
            );
            *out_tx_json = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_zverify_spend(
    tx_json: *const libc::c_char,
    p_spendoutput_params_bytes: *const u8,
    spendoutput_params_bytes_len: libc::size_t,
    p_spend_params_bytes: *const u8,
    spend_params_bytes_len: libc::size_t,
    p_output_params_bytes: *const u8,
    output_params_bytes_len: libc::size_t,
    out_is_valid: &mut bool,
) -> bool {
    *out_is_valid = false;

    if tx_json.is_null() {
        set_last_error("wallet_zverify_spend: tx_json is null");
        return false;
    }
    if p_spendoutput_params_bytes.is_null() {
        set_last_error("wallet_zverify_spend: p_spendoutput_params_bytes is null");
        return false;
    }
    if p_spend_params_bytes.is_null() {
        set_last_error("wallet_zverify_spend: p_spend_params_bytes is null");
        return false;
    }
    if p_output_params_bytes.is_null() {
        set_last_error("wallet_zverify_spend: p_output_params_bytes is null");
        return false;
    }
    if spendoutput_params_bytes_len == 0
        || spend_params_bytes_len == 0
        || output_params_bytes_len == 0
    {
        set_last_error("wallet_zverify_spend: one or more params byte slices have length 0");
        return false;
    }

    let tx_json_str: &str =
        match unsafe { std::ffi::CStr::from_ptr(tx_json) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error("wallet_zverify_spend: invalid UTF-8 in tx_json");
                return false;
            }
        };

    let spendoutput_params_bytes: &[u8] = unsafe {
        slice::from_raw_parts(
            p_spendoutput_params_bytes,
            spendoutput_params_bytes_len as usize,
        )
    };
    let spend_params_bytes: &[u8] = unsafe {
        slice::from_raw_parts(p_spend_params_bytes, spend_params_bytes_len as usize)
    };
    let output_params_bytes: &[u8] = unsafe {
        slice::from_raw_parts(p_output_params_bytes, output_params_bytes_len as usize)
    };
    let mut params = HashMap::new();
    let spendoutput_name = match Name::from_string(&"spendoutput".to_string()) {
        Ok(n) => n,
        Err(e) => {
            set_last_error(&format!(
                "wallet_zverify_spend: failed to construct Name(\"spendoutput\"): {e}"
            ));
            return false;
        }
    };
    let spend_name = match Name::from_string(&"spend".to_string()) {
        Ok(n) => n,
        Err(e) => {
            set_last_error(&format!(
                "wallet_zverify_spend: failed to construct Name(\"spend\"): {e}"
            ));
            return false;
        }
    };
    let output_name = match Name::from_string(&"output".to_string()) {
        Ok(n) => n,
        Err(e) => {
            set_last_error(&format!(
                "wallet_zverify_spend: failed to construct Name(\"output\"): {e}"
            ));
            return false;
        }
    };
    let spendoutput_params = match Parameters::<Bls12>::read(spendoutput_params_bytes, false) {
        Ok(p) => p,
        Err(e) => {
            set_last_error(&format!(
                "wallet_zverify_spend: failed to read spendoutput params: {e:?}"
            ));
            return false;
        }
    };
    let spend_params = match Parameters::<Bls12>::read(spend_params_bytes, false) {
        Ok(p) => p,
        Err(e) => {
            set_last_error(&format!(
                "wallet_zverify_spend: failed to read spend params: {e:?}"
            ));
            return false;
        }
    };
    let output_params = match Parameters::<Bls12>::read(output_params_bytes, false) {
        Ok(p) => p,
        Err(e) => {
            set_last_error(&format!(
                "wallet_zverify_spend: failed to read output params: {e:?}"
            ));
            return false;
        }
    };
    params.insert(spendoutput_name, spendoutput_params);
    params.insert(spend_name, spend_params);
    params.insert(output_name, output_params);
    let tx: Transaction = match serde_json::from_str(tx_json_str) {
        Ok(t) => t,
        Err(e) => {
            set_last_error(&format!("wallet_zverify_spend: invalid JSON in tx_json: {e}"));
            return false;
        }
    };

    *out_is_valid = zverify_spend_transaction(&tx, &params).is_ok();
    true
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_transact(
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
    output_params_bytes_len: libc::size_t,
    out_tx_json: &mut *const libc::c_char,
) -> bool {
    *out_tx_json = std::ptr::null();

    if p_wallet.is_null() {
        set_last_error("wallet_transact: p_wallet is null");
        return false;
    }
    if ztx_json.is_null() {
        set_last_error("wallet_transact: ztx_json is null");
        return false;
    }
    if fee_token_contract_json.is_null() {
        set_last_error("wallet_transact: fee_token_contract_json is null");
        return false;
    }
    if fees_json.is_null() {
        set_last_error("wallet_transact: fees_json is null");
        return false;
    }
    if p_mint_params_bytes.is_null() {
        set_last_error("wallet_transact: p_mint_params_bytes is null");
        return false;
    }
    if p_spendoutput_params_bytes.is_null() {
        set_last_error("wallet_transact: p_spendoutput_params_bytes is null");
        return false;
    }
    if p_spend_params_bytes.is_null() {
        set_last_error("wallet_transact: p_spend_params_bytes is null");
        return false;
    }
    if p_output_params_bytes.is_null() {
        set_last_error("wallet_transact: p_output_params_bytes is null");
        return false;
    }
    if mint_params_bytes_len == 0
        || spendoutput_params_bytes_len == 0
        || spend_params_bytes_len == 0
        || output_params_bytes_len == 0
    {
        set_last_error("wallet_transact: one or more params byte slices have length 0");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let ztx_json_str: &str =
        match unsafe { std::ffi::CStr::from_ptr(ztx_json) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error("wallet_transact: invalid UTF-8 in ztx_json");
                return false;
            }
        };
    let fee_token_contract_json_str: &str = match unsafe {
        std::ffi::CStr::from_ptr(fee_token_contract_json)
    }
    .to_str()
    {
        Ok(s) => s,
        Err(_) => {
            set_last_error("wallet_transact: invalid UTF-8 in fee_token_contract_json");
            return false;
        }
    };
    let fees_json_str: &str =
        match unsafe { std::ffi::CStr::from_ptr(fees_json) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error("wallet_transact: invalid UTF-8 in fees_json");
                return false;
            }
        };
    let mint_params_bytes: &[u8] = unsafe {
        slice::from_raw_parts(p_mint_params_bytes, mint_params_bytes_len as usize)
    };
    let spendoutput_params_bytes: &[u8] = unsafe {
        slice::from_raw_parts(
            p_spendoutput_params_bytes,
            spendoutput_params_bytes_len as usize,
        )
    };
    let spend_params_bytes: &[u8] = unsafe {
        slice::from_raw_parts(p_spend_params_bytes, spend_params_bytes_len as usize)
    };
    let output_params_bytes: &[u8] = unsafe {
        slice::from_raw_parts(p_output_params_bytes, output_params_bytes_len as usize)
    };
    let fee_token_contract = match Name::from_string(&fee_token_contract_json_str.to_string()) {
        Ok(name) => name,
        Err(e) => {
            set_last_error(&format!(
                "wallet_transact: invalid fee_token_contract_json: {e}"
            ));
            return false;
        }
    };
    let fees = match serde_json::from_str(fees_json_str) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(&format!("wallet_transact: invalid JSON in fees_json: {e}"));
            return false;
        }
    };
    let mut params = HashMap::new();
    let mint_name = match Name::from_string(&"mint".to_string()) {
        Ok(n) => n,
        Err(e) => {
            set_last_error(&format!("wallet_transact: Name(\"mint\") failed: {e}"));
            return false;
        }
    };
    let spendoutput_name = match Name::from_string(&"spendoutput".to_string()) {
        Ok(n) => n,
        Err(e) => {
            set_last_error(&format!(
                "wallet_transact: Name(\"spendoutput\") failed: {e}"
            ));
            return false;
        }
    };
    let spend_name = match Name::from_string(&"spend".to_string()) {
        Ok(n) => n,
        Err(e) => {
            set_last_error(&format!("wallet_transact: Name(\"spend\") failed: {e}"));
            return false;
        }
    };
    let output_name = match Name::from_string(&"output".to_string()) {
        Ok(n) => n,
        Err(e) => {
            set_last_error(&format!("wallet_transact: Name(\"output\") failed: {e}"));
            return false;
        }
    };
    let mint_params = match Parameters::<Bls12>::read(mint_params_bytes, false) {
        Ok(p) => p,
        Err(e) => {
            set_last_error(&format!("wallet_transact: failed to read mint params: {e:?}"));
            return false;
        }
    };
    let spendoutput_params =
        match Parameters::<Bls12>::read(spendoutput_params_bytes, false) {
            Ok(p) => p,
            Err(e) => {
                set_last_error(&format!(
                    "wallet_transact: failed to read spendoutput params: {e:?}"
                ));
                return false;
            }
        };
    let spend_params = match Parameters::<Bls12>::read(spend_params_bytes, false) {
        Ok(p) => p,
        Err(e) => {
            set_last_error(&format!(
                "wallet_transact: failed to read spend params: {e:?}"
            ));
            return false;
        }
    };
    let output_params = match Parameters::<Bls12>::read(output_params_bytes, false) {
        Ok(p) => p,
        Err(e) => {
            set_last_error(&format!(
                "wallet_transact: failed to read output params: {e:?}"
            ));
            return false;
        }
    };
    params.insert(mint_name, mint_params);
    params.insert(spendoutput_name, spendoutput_params);
    params.insert(spend_name, spend_params);
    params.insert(output_name, output_params);
    let ztx: ZTransaction = match serde_json::from_str(ztx_json_str) {
        Ok(z) => z,
        Err(e) => {
            set_last_error(&format!("wallet_transact: invalid JSON in ztx_json: {e}"));
            return false;
        }
    };
    let rztx = match resolve_ztransaction(wallet, &fee_token_contract, &fees, &ztx) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(&format!("wallet_transact: resolve_ztransaction failed: {e:?}"));
            return false;
        }
    };
    let tx = match zsign_transaction(wallet, &rztx, &params) {
        Ok(t) => t,
        Err(e) => {
            set_last_error(&format!("wallet_transact: zsign_transaction failed: {e:?}"));
            return false;
        }
    };
    let json = match serde_json::to_string(&tx) {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!(
                "wallet_transact: failed to serialize transaction: {e}"
            ));
            return false;
        }
    };

    match CString::new(json) {
        Ok(c_string) => {
            *out_tx_json = c_string.into_raw(); // caller must free with free_string
            true
        }
        Err(_) => {
            set_last_error(
                "wallet_transact: CString::new failed (unexpected null byte in JSON)",
            );
            *out_tx_json = std::ptr::null();
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[no_mangle]
pub extern "C" fn wallet_digest_block(
    p_wallet: *mut Wallet,
    block: *const libc::c_char,
    out_digest: &mut u64,
) -> bool {
    *out_digest = 0;

    if p_wallet.is_null() {
        set_last_error("wallet_digest_block: p_wallet is null");
        return false;
    }
    if block.is_null() {
        set_last_error("wallet_digest_block: block is null");
        return false;
    }

    let wallet = unsafe { &mut *p_wallet };
    let block_str: &str = match unsafe { CStr::from_ptr(block) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("wallet_digest_block: invalid UTF-8 in block");
            return false;
        }
    };

    *out_digest = wallet.digest_block(block_str);
    true
}

#[cfg(test)]
mod tests
{
    //#[test]
    //fn test_something()
    //{
    //}
}