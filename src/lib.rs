
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
#[cfg(target_os = "linux")]
use std::slice;
#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::ffi::CStr;
use rand_core::OsRng;
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
pub struct JSWallet
{
    wallet: Wallet
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl JSWallet
{
    pub fn create(
        seed: &[u8]
    ) -> Result<JSWallet, JsError>
    {
        let w = Wallet::create(seed, false);
        if w.is_none() { return Err(JsError::new("error creating wallet")) }
        Ok(JSWallet{
            wallet: w.unwrap()
        })
    }

    pub fn write(&self, bytes: &mut [u8]) -> Result<(), JsError>
    {
        let res = self.wallet.write(bytes);
        if res.is_err() { return Err(JsError::new("error writing wallet")); }
        Ok(())
    }

    pub fn read(bytes: &[u8]) -> Result<JSWallet, JsError>
    {
        let w = Wallet::read(bytes);
        if w.is_err() { return Err(JsError::new("error reading wallet")); }
        Ok(JSWallet { wallet: w.unwrap() })
    }

    pub fn to_json(&self, pretty: bool) -> String
    {
        self.wallet.to_json(pretty)
    }

    pub fn from_json(json: String) -> Result<JSWallet, JsError>
    {
        let w = Wallet::from_json(&json);
        if w.is_err() { return Err(JsError::new("error reading wallet")); }
        Ok(JSWallet { wallet: w.unwrap() })
    }

    pub fn size(&self) -> u32
    {
        self.wallet.size() as u32
    }

    pub fn block_num(&self) -> u32
    {
        self.wallet.block_num()
    }

    pub fn leaf_count(&self) -> u32
    {
        self.wallet.leaf_count() as u32
    }

    pub fn move_asset(
        &self,
        authorization: String,
        descs: String
    ) -> Result<String, JsError>
    {
        let mut rng = OsRng.clone();
        let descs_parts: Vec<String> = descs.split("|").map(|s| s.to_string()).collect();
        let tx = self.wallet.move_asset(&mut rng, authorization, descs_parts);
        if tx.is_none() { return Err(JsError::new("error creating transaction")) }
        Ok(serde_json::to_string(&tx.unwrap()).unwrap())
    }

    pub fn transfer_asset(
        &self,
        descs: String
    ) -> Result<String, JsError>
    {
        let mut rng = OsRng.clone();
        let descs_parts: Vec<String> = descs.split("|").map(|s| s.to_string()).collect();
        let tx = self.wallet.transfer_asset(&mut rng, descs_parts);
        if tx.is_none() { return Err(JsError::new("error creating transaction")) }
        Ok(serde_json::to_string(&tx.unwrap()).unwrap())
    }

    pub fn peers(&self) -> String
    {
        serde_json::to_string(&self.wallet.settings().peers).unwrap()
    }

    pub fn balances(&self, pretty: bool) -> String
    {
        if pretty { serde_json::to_string_pretty(&self.wallet.balances()).unwrap() }
        else { serde_json::to_string(&self.wallet.balances()).unwrap() }
    }

    pub fn notes(&self, pretty: bool) -> String
    {
        if pretty { serde_json::to_string_pretty(&self.wallet.notes()).unwrap() }
        else { serde_json::to_string(&self.wallet.notes()).unwrap() }
    }

    pub fn addresses(&self, pretty: bool) -> String
    {
        if pretty { serde_json::to_string_pretty(&self.wallet.addresses()).unwrap() }
        else { serde_json::to_string(&self.wallet.addresses()).unwrap() }
    }

    pub fn derive_address(&mut self) -> String
    {
        serde_json::to_string(&self.wallet.derive_next_address()).unwrap()
    }

    pub fn add_leaves(&mut self, leaves: &[u8])
    {
        self.wallet.add_leaves(leaves);
    }

    pub fn process_block(&mut self, block: String)
    {
        self.wallet.process_block(&block);
    }
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
        false
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
pub extern fn wallet_peers_json(
    p_wallet: *mut Wallet
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let peers = serde_json::to_string(&wallet.settings().peers).unwrap();
    let c_string = CString::new(peers).expect("CString::new failed");
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
        if pretty { serde_json::to_string_pretty(&wallet.notes()).unwrap() }
        else { serde_json::to_string(&wallet.notes()).unwrap() }
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

#[cfg(target_os = "linux")]
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
    wallet.process_block(&block_str)
}
