
mod address;
pub mod value;
//pub mod redjubjub;
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

use crate::eosio::{Name, Symbol, Asset, Authorization, Action, Transaction};
use crate::contract::{PlsFtTransfer, PlsMint, PlsNftTransfer, PlsMintAction, ScalarBytes, AffineProofBytesLE};
use crate::address::Address;
use crate::note::{Rseed, Note};
use crate::note_encryption::{NoteEncryption, TransmittedNoteCiphertext, derive_esk, ka_derive_public};
use crate::circuit::mint::Mint;
use keys::{SpendingKey, FullViewingKey};
use rand_core::RngCore;
use std::cmp::min;
use bellman::groth16::{create_random_proof, Parameters};
use bls12_381::Bls12;
use serde_json::json;

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

// desc format: <contract> <asset> <address> [<memo>]
// examples:
//      eosio.token 10.0000 EOS za1qa92vppxewu2s5p9k8ha396490xs5llgl5md8pt0scyv9t27a4f9nx4mvvpj2kkxq6t35cfdu93 "this is a memo"
//      thezeostoken 5400.5000 za1qa92vppxewu2s5p9k8ha396490xs5llgl5md8pt0scyv9t27a4f9nx4mvvpj2kkxq6t35cfdu93 ZEOS ""
//      eosio.token 22.2500 EOS za1qa92vppxewu2s5p9k8ha396490xs5llgl5md8pt0scyv9t27a4f9nx4mvvpj2kkxq6t35cfdu93 ""
//      atomicassets 1234567890987654321 za1qa92vppxewu2s5p9k8ha396490xs5llgl5md8pt0scyv9t27a4f9nx4mvvpj2kkxq6t35cfdu93 "NFT mint memo"
// returns:
// Name: token contract
// Asset: the actual FT or NFT
// String: the memo
fn process_move_in_desc(desc: &String) -> Option<(Name, Asset, Address, String)>
{
    // extract the memo first, so we can split the remaining string by spaces
    let mut parts: Vec<String> = desc.split("\"").map(|s| s.to_string()).collect();
    if parts.len() != 3 { log("move_in desc invalid:"); log(desc); return None; }
    let memo = parts[1].clone();
    parts[0].pop(); // remove trailing whitespace

    // split the remaining string by spaces
    let parts: Vec<String> = parts[0].split(" ").map(|s| s.to_string()).collect();

    // process <contract> part
    let contract = Name::from_string(&parts[0]);
    if contract.is_err() { log("move_in desc <contract> invalid:"); log(&parts[0]); return None; }

    // process <asset> <address> part
    if parts.len() == 3 // NFT
    {
        let asset = Asset::from_string(&parts[1]);
        if asset.is_none() { log("move_in desc NFT <asset> invalid:"); log(&parts[1]); return None; }
        let address = Address::from_bech32m(&parts[2]);
        if address.is_err() { log("move_in desc NFT <address> invalid:"); log(&parts[2]); return None; }
        return Some((contract.unwrap(), asset.unwrap(), address.unwrap(), memo));
    }
    if parts.len() == 4 // FT
    {
        let asset_str = parts[1].clone() + " " + &parts[2];
        let asset = Asset::from_string(&asset_str);
        if asset.is_none() { log("move_in desc FT <asset> invalid:"); log(&asset_str); return None; }
        let address = Address::from_bech32m(&parts[3]);
        if address.is_err() { log("move_in desc FT <address> invalid:"); log(&parts[3]); return None; }

        return Some((contract.unwrap(), asset.unwrap(), address.unwrap(), memo));
    }
    None
}

fn move_asset_in(
    rng: &mut impl RngCore,
    authorization: String,
    descs: Vec<String>,
    protocol_contract: String,
    alias_authority: String,
    fee_token_contract: String,
    fee_token_symbol: String,
    fee_begin: u32,
    fee_mint: u32,
    mint_params_bytes: &[u8]
) -> Option<Transaction>
{
    if descs.is_empty() { log("descs is empty"); return None; }
    let protocol_contract_ = Name::from_string(&protocol_contract);
    if protocol_contract_.is_err() { log("protocol_contract invalid:"); log(&protocol_contract); return None; }
    let protocol_contract = protocol_contract_.unwrap();
    let alias_authority_ = Authorization::from_string(&alias_authority);
    if alias_authority_.is_none() { log("alias_authority invalid:"); log(&alias_authority); return None; }
    let alias_authority = alias_authority_.unwrap();
    let fee_token_contract_ = Name::from_string(&fee_token_contract);
    if fee_token_contract_.is_err() { log("fee_token_contract invalid:"); log(&fee_token_contract); return None; }
    let fee_token_contract = fee_token_contract_.unwrap();
    let fee_token_symbol_ = Symbol::from_string(&fee_token_symbol);
    if fee_token_symbol_.is_none() { log("fee_token_symbol invalid:"); log(&fee_token_symbol); return None; }
    let fee_token_symbol = fee_token_symbol_.unwrap();

    // read params files for zk-snark creation
    let mint_params = Parameters::<Bls12>::read(mint_params_bytes, false).unwrap();

    let auth = Authorization::from_string(&authorization);
    if auth.is_none() { log("authorization string invalid:"); log(&authorization); return None; }
    let auth = auth.unwrap();

    let mut fts_to_mint = vec![];
    let mut nfts_to_mint = vec![];

    // process action descriptors
    for desc in descs
    {
        let processed_desc = process_move_in_desc(&desc);
        if processed_desc.is_none() { log("move_in desc invalid:"); log(&desc); return None; }
        let (contract, asset, address, memo) = processed_desc.unwrap();

        if asset.is_nft()
        {
            nfts_to_mint.push((contract, asset, address, memo));
        }
        else
        {
            if asset.amount() <= 0 { log("move_in desc invalid [asset amount]:"); log(&asset.to_string()); return None; }
            fts_to_mint.push((contract, asset, address, memo));
        }
    }

    // process MINT actions
    let sk = SpendingKey::random(rng);
    let mut transaction = Transaction{ actions: vec![] };
    let mut notes_to_mint = vec![];
    let mut pls_mint_vec = vec![];

    // add 'begin' action
    transaction.actions.push(Action {
        account: alias_authority.actor.clone(),
        name: Name::from_string(&format!("begin")).unwrap(),
        authorization: vec![alias_authority.clone()],
        data: json!({})
    });

    // process fungible tokens to mint
    for (contract, asset, address, memo) in &fts_to_mint
    {
        // add transfer action for this asset to the transaction
        transaction.actions.push(Action{
            account: contract.clone(),
            name: Name::from_string(&"transfer".to_string()).unwrap(),
            authorization: vec![auth.clone()],
            data: serde_json::to_value(PlsFtTransfer{
                from: auth.actor.clone(),
                to: protocol_contract.clone(),
                quantity: asset.clone(),
                memo: "ZEOS MINT".to_string()
            }).unwrap()
        });

        // convert memo string to bytes
        let mut memo_bytes = [0; 512];
        memo_bytes[0..min(512, memo.len())].copy_from_slice(&memo.as_bytes()[0..min(512, memo.len())]);

        // create note
        let note = Note::from_parts(
            0,
            address.clone(),
            auth.actor.clone(),
            asset.clone(),
            contract.clone(),
            Rseed::new(rng),
            //ExtractedNullifier(bls12_381::Scalar::one()),
            memo_bytes
        );

        // create proof
        let circuit_instance = Mint {
            account: Some(note.account().raw()),
            value: Some(note.amount()),
            symbol: Some(note.symbol().raw()),
            code: Some(note.code().raw()),
            address: Some(note.address()),
            rcm: Some(note.rcm()),
            proof_generation_key: Some(sk.proof_generation_key()),
        };
        let proof = create_random_proof(circuit_instance, &mint_params, rng).unwrap();

        // add mint payload struct at the front of the list (inverse order than transfer actions)
        let mut stack = vec![PlsMint{
            cm: ScalarBytes(note.commitment().to_bytes()),
            value: note.amount(),
            symbol: note.symbol().clone(),
            code: contract.clone(),
            proof: AffineProofBytesLE::from(proof)
        }];
        stack.append(&mut pls_mint_vec);
        pls_mint_vec = stack;

        notes_to_mint.push(note);
    }

    // process non-fungible tokens to mint
    for (contract, asset, address, memo) in &nfts_to_mint
    {
        // add transfer action for this NFT asset to the transaction
        transaction.actions.push(Action{
            account: contract.clone(),
            name: Name::from_string(&"transfer".to_string()).unwrap(),
            authorization: vec![auth.clone()],
            data: serde_json::to_value(PlsNftTransfer{
                from: auth.actor.clone(),
                to: protocol_contract.clone(),
                asset_ids: vec![asset.clone()],
                memo: "ZEOS MINT".to_string()
            }).unwrap()
        });

        // convert memo string to bytes
        let mut memo_bytes = [0; 512];
        memo_bytes[0..min(512, memo.len())].copy_from_slice(&memo.as_bytes()[0..min(512, memo.len())]);

        // create note
        let note = Note::from_parts(
            0,
            address.clone(),
            auth.actor.clone(),
            asset.clone(),
            contract.clone(),
            Rseed::new(rng),
            memo_bytes
        );

        // create proof
        let circuit_instance = Mint {
            account: Some(note.account().raw()),
            value: Some(note.amount()),
            symbol: Some(note.symbol().raw()),
            code: Some(note.code().raw()),
            address: Some(note.address()),
            rcm: Some(note.rcm()),
            proof_generation_key: Some(sk.proof_generation_key()),
        };
        let proof = create_random_proof(circuit_instance, &mint_params, rng).unwrap();

        // add mint payload struct at the front of the list (inverse order than transfer actions)
        let mut stack = vec![PlsMint{
            cm: ScalarBytes(note.commitment().to_bytes()),
            value: note.amount(),
            symbol: note.symbol().clone(),
            code: contract.clone(),
            proof: AffineProofBytesLE::from(proof)
        }];
        stack.append(&mut pls_mint_vec);
        pls_mint_vec = stack;

        notes_to_mint.push(note);
    }

    // pay transaction fee for mint actions
    if !notes_to_mint.is_empty()
    {
        transaction.actions.push(Action{
            account: fee_token_contract.clone(),
            name: Name::from_string(&"transfer".to_string()).unwrap(),
            authorization: vec![auth.clone()],
            data: serde_json::to_value(PlsFtTransfer{
                from: auth.actor.clone(),
                to: alias_authority.actor.clone(),
                quantity: Asset::new(
                    fee_begin as i64 + notes_to_mint.len() as i64 * fee_mint as i64,
                    fee_token_symbol.clone()
                ).unwrap(),
                memo: "tx fee".to_string()
            }).unwrap()
        });
    }

    let mut note_ct_mint = vec![];

    // encrypt notes to mint
    for note in notes_to_mint
    {
        let esk = derive_esk(&note).unwrap();
        let epk = ka_derive_public(&note, &esk);
        let ne = NoteEncryption::new(Some(FullViewingKey::from_spending_key(&sk).ovk), note.clone());
        let encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: epk.to_bytes().0,
            enc_ciphertext: ne.encrypt_note_plaintext(),
            out_ciphertext: ne.encrypt_outgoing_plaintext(rng),
        };
        note_ct_mint.push(encrypted_note.to_base64());
    }

    // add the stack of mint payload structs and encrypted note ciphertexts as one action to the transaction
    if !pls_mint_vec.is_empty()
    {
        transaction.actions.push(Action {
            account: alias_authority.actor.clone(),
            name: Name::from_string(&format!("mint")).unwrap(),
            authorization: vec![alias_authority.clone()],
            data: serde_json::to_value(PlsMintAction{
                actions: pls_mint_vec,
                note_ct: note_ct_mint
            }).unwrap()
        });
    }

    // add 'end' action
    transaction.actions.push(Action {
        account: alias_authority.actor.clone(),
        name: Name::from_string(&format!("end")).unwrap(),
        authorization: vec![alias_authority.clone()],
        data: json!({})
    });

    Some(transaction)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn js_move_asset_in(
    authorization: String,
    descs: String,
    protocol_contract: String,
    alias_authority: String,
    fee_token_contract: String,
    fee_token_symbol: String,
    fee_begin: u32,
    fee_mint: u32,
    mint_params_bytes: &[u8]
) -> Result<String, JsError>
{
    let mut rng = OsRng.clone();
    let descs_parts: Vec<String> = descs.split("|").map(|s| s.to_string()).collect();
    let tx = move_asset_in(&mut rng, authorization, descs_parts, protocol_contract, alias_authority, fee_token_contract, fee_token_symbol, fee_begin, fee_mint, mint_params_bytes);
    if tx.is_none() { return Err(JsError::new("error creating transaction")) }
    Ok(serde_json::to_string(&tx.unwrap()).unwrap())
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
        descs: String,
        mint_params_bytes: &[u8],
        burn_params_bytes: &[u8]
    ) -> Result<String, JsError>
    {
        let mut rng = OsRng.clone();
        let descs_parts: Vec<String> = descs.split("|").map(|s| s.to_string()).collect();
        let tx = self.wallet.move_asset(&mut rng, authorization, descs_parts, mint_params_bytes, burn_params_bytes);
        if tx.is_none() { return Err(JsError::new("error creating transaction")) }
        Ok(serde_json::to_string(&tx.unwrap()).unwrap())
    }

    pub fn transfer_asset(
        &self,
        descs: String,
        transfer_params_bytes: &[u8],
        burn_params_bytes: &[u8]
    ) -> Result<String, JsError>
    {
        let mut rng = OsRng.clone();
        let descs_parts: Vec<String> = descs.split("|").map(|s| s.to_string()).collect();
        let tx = self.wallet.transfer_asset(&mut rng, descs_parts, transfer_params_bytes, burn_params_bytes);
        if tx.is_none() { return Err(JsError::new("error creating transaction")) }
        Ok(serde_json::to_string(&tx.unwrap()).unwrap())
    }

    pub fn settings(&self, pretty: bool) -> String
    {
        if pretty { serde_json::to_string_pretty(&self.wallet.settings()).unwrap() }
        else { serde_json::to_string(&self.wallet.settings()).unwrap() }
    }

    pub fn update_settings(&mut self, settings_json: String)
    {
        self.wallet.update_settings(serde_json::from_str(&settings_json).unwrap());
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
/*
#[cfg(target_os = "linux")]
#[no_mangle]
pub extern fn wallet_settings_json(
    p_wallet: *mut Wallet,
    pretty: bool
) -> *const libc::c_char
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let c_string = CString::new(
        if pretty { serde_json::to_string_pretty(&wallet.settings()).unwrap() }
        else { serde_json::to_string(&wallet.settings()).unwrap() }
    ).expect("CString::new failed");
    c_string.into_raw() // Move ownership to C
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern fn wallet_update_settings(
    p_wallet: *mut Wallet,
    settings_json: *const libc::c_char
)
{
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };

    let settings_json_str: &str = match std::ffi::CStr::from_ptr(settings_json).to_str() {
        Ok(s) => s,
        Err(_e) => {
            println!("FFI seed string conversion failed");
            "FFI seed string conversion failed"
        }
    };

    wallet.update_settings(serde_json::from_str(settings_json_str).unwrap());
}
*/
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
/*
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern fn wallet_move(
    p_wallet: *mut Wallet,
    auth: *const libc::c_char,
    descs: *const libc::c_char,
    p_mint_params_bytes: *const u8,
    mint_params_bytes_len: libc::size_t,
    p_burn_params_bytes: *const u8,
    burn_params_bytes_len: libc::size_t
) -> *const libc::c_char
{
    let mut rng = OsRng.clone();
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };
    let mint_params_bytes = unsafe {
        assert!(!p_mint_params_bytes.is_null());
        slice::from_raw_parts(p_mint_params_bytes, mint_params_bytes_len as usize)
    };
    let burn_params_bytes = unsafe {
        assert!(!p_burn_params_bytes.is_null());
        slice::from_raw_parts(p_burn_params_bytes, burn_params_bytes_len as usize)
    };
    let auth_str = CStr::from_ptr(auth).to_str().expect("Bad encoding").to_owned();
    let descs_str = CStr::from_ptr(descs).to_str().expect("Bad encoding").to_owned();
    let descs_parts: Vec<String> = descs_str.split("|").map(|s| s.to_string()).collect();
    let tx = wallet.move_asset(&mut rng, auth_str, descs_parts, mint_params_bytes, burn_params_bytes);
    if tx.is_none() { return CString::new("Error: ".to_string()).unwrap().into_raw(); }
    CString::new(serde_json::to_string(&tx.unwrap()).unwrap()).expect("CString::new failed").into_raw()
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern fn wallet_transfer(
    p_wallet: *mut Wallet,
    descs: *const libc::c_char,
    p_transfer_params_bytes: *const u8,
    transfer_params_bytes_len: libc::size_t,
    p_burn_params_bytes: *const u8,
    burn_params_bytes_len: libc::size_t
) -> *const libc::c_char
{
    let mut rng = OsRng.clone();
    let wallet = unsafe {
        assert!(!p_wallet.is_null());
        &mut *p_wallet
    };
    let transfer_params_bytes = unsafe {
        assert!(!p_transfer_params_bytes.is_null());
        slice::from_raw_parts(p_transfer_params_bytes, transfer_params_bytes_len as usize)
    };
    let burn_params_bytes = unsafe {
        assert!(!p_burn_params_bytes.is_null());
        slice::from_raw_parts(p_burn_params_bytes, burn_params_bytes_len as usize)
    };
    let descs_str = CStr::from_ptr(descs).to_str().expect("Bad encoding").to_owned();
    let descs_parts: Vec<String> = descs_str.split("|").map(|s| s.to_string()).collect();
    let tx = wallet.transfer_asset(&mut rng, descs_parts, transfer_params_bytes, burn_params_bytes);
    if tx.is_none() { return CString::new("Error: ".to_string()).unwrap().into_raw(); }
    CString::new(serde_json::to_string(&tx.unwrap()).unwrap()).expect("CString::new failed").into_raw()
}
*/
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
    use super::{process_move_in_desc, move_asset_in};
    use rand::rngs::OsRng;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn test_process_move_in_desc()
    {
        let desc = String::from("eosio.token 10.0000 EOS za1qa92vppxewu2s5p9k8ha396490xs5llgl5md8pt0scyv9t27a4f9nx4mvvpj2kkxq6t35cfdu93 \"this is a memo\"");
        println!("{:?}", process_move_in_desc(&desc));
        let desc = String::from("thezeostoken 5400.5000 ZEOS za1qa92vppxewu2s5p9k8ha396490xs5llgl5md8pt0scyv9t27a4f9nx4mvvpj2kkxq6t35cfdu93 \"\"");
        println!("{:?}", process_move_in_desc(&desc));
        let desc = String::from("atomicassets 1234567890987654321 za1qa92vppxewu2s5p9k8ha396490xs5llgl5md8pt0scyv9t27a4f9nx4mvvpj2kkxq6t35cfdu93 \"NFT mint memo\"");
        println!("{:?}", process_move_in_desc(&desc));
    }

    #[test]
    fn test_move_asset_in()
    {
        let mut rng = OsRng.clone();
        let authorization = String::from("mschoenebeck");
        let descs = vec![
            String::from("eosio.token 10.0000 EOS za1qa92vppxewu2s5p9k8ha396490xs5llgl5md8pt0scyv9t27a4f9nx4mvvpj2kkxq6t35cfdu93 \"this is a memo\""),
            String::from("thezeostoken 5400.5000 ZEOS za1qa92vppxewu2s5p9k8ha396490xs5llgl5md8pt0scyv9t27a4f9nx4mvvpj2kkxq6t35cfdu93 \"\""),
            String::from("atomicassets 1234567890987654321 za1qa92vppxewu2s5p9k8ha396490xs5llgl5md8pt0scyv9t27a4f9nx4mvvpj2kkxq6t35cfdu93 \"NFT mint memo\""),
            String::from("atomicassets 9999999999999999999 za1qa92vppxewu2s5p9k8ha396490xs5llgl5md8pt0scyv9t27a4f9nx4mvvpj2kkxq6t35cfdu93 \"NFT mint memo\""),
            String::from("atomicasset1 5555555555555555555 za1qa92vppxewu2s5p9k8ha396490xs5llgl5md8pt0scyv9t27a4f9nx4mvvpj2kkxq6t35cfdu93 \"NFT mint memo\""),
            String::from("atomicasset1 4444444444444444444 za1qa92vppxewu2s5p9k8ha396490xs5llgl5md8pt0scyv9t27a4f9nx4mvvpj2kkxq6t35cfdu93 \"NFT mint memo\"")
        ];
        let protocol_contract = String::from("zeos4privacy");
        let alias_authority = String::from("thezeosalias@public");
        let fee_token_contract = String::from("thezeostoken");
        let fee_token_symbol = String::from("4,ZEOS");
        let fee_begin = 50000;
        let fee_mint = 10000;
        let mut f = File::open("params_mint.bin").expect("params_mint.bin not found");
        let metadata = std::fs::metadata("params_mint.bin").expect("unable to read metadata of params_mint.bin");
        let mut mint_params_bytes = vec![0; metadata.len() as usize];
        f.read(&mut mint_params_bytes).expect("buffer overflow");
        let tx = move_asset_in(&mut rng, authorization, descs, protocol_contract, alias_authority, fee_token_contract, fee_token_symbol, fee_begin, fee_mint, &mint_params_bytes);
        assert!(tx.is_some());
        println!("{}", serde_json::to_string(&tx.unwrap()).unwrap());
    }
}