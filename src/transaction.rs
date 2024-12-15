use crate::address::Address;
use crate::eosio::{pack, Action, Asset, Authorization, ExtendedAsset, Name, PackedAction, Symbol, Transaction};
use crate::keys::{FullViewingKey, SpendingKey};
use crate::note::nullifier::ExtractedNullifier;
use crate::note::{Note, NoteEx, Rseed, ExtractedNoteCommitment};
use crate::wallet::Wallet;
use crate::contract::{PlsMint, PlsMintAction, PlsSpendSequence, PlsSpendOutput, PlsSpend, PlsOutput, PlsSpendAction, AffineProofBytesLE, ScalarBytes, scalar_to_raw_bytes_le, PlsUnshieldedRecipient, PlsAuthenticateAction, PlsPublishNotesAction, PlsWithdrawAction, PlsAuthenticate, PlsWithdraw, self, PlsNftTransfer, PlsFtTransfer};
use crate::circuit::{mint::Mint, spend_output::SpendOutput, spend::Spend, output::Output};
use crate::note_encryption::{NoteEncryption, derive_esk, ka_derive_public, TransmittedNoteCiphertext};
use crate::spec::{windowed_pedersen_commit, extract_p};
use crate::pedersen_hash::Personalization;
use crate::value::{ValueCommitment, ValueCommitTrapdoor};
use crate::blake2s7r::Params as Blake2s7rParams;
use crate::constants::MEMO_CHANGE_NOTE;
use jubjub::AffinePoint;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use serde_json::json;
use std::{error::Error, fmt, cmp::min};
use std::collections::HashMap;
use std::ops::{Add, AddAssign};
use rand::rngs::OsRng;
use bellman::groth16::{Parameters, create_random_proof};
use bls12_381::Bls12;
use core::iter;
use bitvec::{array::BitArray, order::Lsb0};
use group::Curve;
use bellman::groth16::{Proof, verify_proof, prepare_verifying_key};
use bellman::gadgets::multipack;
use bls12_381::Scalar;

#[derive(Debug)]
pub enum TransactionError
{
    InvalidActionName,
    InvalidChainIDLength,
    IvkWallet,
    AuthTokenContractAccount,
    NFTNotFound,
    InsufficientFunds,
    InvalidAuthToken,
    MintParams,
    SpendOutputParams,
    SpendParams,
    OutputParams,
    InvalidNote,
    InvalidProtocolContractOrAliasAuthority
}
impl Error for TransactionError {}
impl fmt::Display for TransactionError
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        match self
        {
            Self::InvalidActionName => write!(f, "invalid action name"),
            Self::InvalidChainIDLength => write!(f, "invalid chain_id length (must equal 32 bytes)"),
            Self::IvkWallet => write!(f, "Read-Only Wallet (spending not possible)"),
            Self::AuthTokenContractAccount => write!(f, "For Auth tokens 'from' account must equal 'contract' account"),
            Self::NFTNotFound => write!(f, "NFT not found!"),
            Self::InsufficientFunds => write!(f, "Insufficient funds!"),
            Self::InvalidAuthToken => write!(f, "invalid auth token"),
            Self::MintParams => write!(f, "invalid mint params"),
            Self::SpendOutputParams => write!(f, "invalid spend_output params"),
            Self::SpendParams => write!(f, "invalid spend params"),
            Self::OutputParams => write!(f, "invalid output params"),
            Self::InvalidNote => write!(f, "note invalid"),
            Self::InvalidProtocolContractOrAliasAuthority => write!(f, "protocol contract or alias authority invalid"),
        }
    }
}


#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ZTransaction
{
    pub chain_id: String,
    pub protocol_contract: Name,
    pub alias_authority: String,
    pub add_fee: bool,
    pub publish_fee_note: bool,
    pub zactions: Vec<ZAction>
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ZAction
{
    pub name: Name,
    pub data: Value
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MintDesc
{
    pub to: String,
    pub contract: Name,
    pub quantity: Asset,
    pub memo: String,
    pub from: Name,
    pub publish_note: bool
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpendSequenceDesc
{
    pub contract: Name,
    pub change_to: String,
    pub publish_change_note: bool,
    pub to: Vec<SpendRecipientDesc>
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpendRecipientDesc
{
    pub to: String,
    pub quantity: Asset,
    pub memo: String,
    pub publish_note: bool
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthenticateDesc
{
    pub auth_token: String,
    pub actions: Vec<PackedActionDesc>,
    pub burn: bool
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PackedActionDesc
{
    pub account: Name,
    pub name: Name,
    pub authorization: Vec<String>,
    pub data: String
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PublishNotesDesc
{
    pub notes: Vec<String>
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WithdrawDesc
{
    pub contract: Name,
    pub quantity: Asset,
    pub memo: String,
    pub to: Name
}

pub fn insert_vars(memo: &String, default_address: &String, auth_tokens: &Vec<Note>) -> String
{
    let mut new_memo = memo.clone();
    // insert default address
    new_memo = new_memo.replace(&"$SELF", &default_address);
    // a maximum of 10 auth tokens is supported
    let num = min(10, auth_tokens.len());
    for i in 0..num
    {
        let mut pattern = "$AUTH".to_string();
        pattern.push(char::from_digit(i as u32, 10).unwrap());
        new_memo = new_memo.replace(&pattern, &hex::encode(&auth_tokens[i].commitment().to_bytes()));
    }
    new_memo
}

fn select_nft_note(unspent_notes: &mut Vec<NoteEx>, asset: &Asset) -> Option<NoteEx>
{
    if !asset.is_nft() || asset.amount() == 0
    {
        return None;
    }

    for i in (0..unspent_notes.len()).rev()
    {
        if unspent_notes[i].note().symbol().raw() == 0
        {
            if asset.amount() as u64 == unspent_notes[i].note().amount()
            {
                // found NFT
                return Some(unspent_notes.remove(i));
            }
        }
    }
    None
}

/// Very simple note selection algorithm: walk through all notes and pick notes of the demanded type until the sum
/// is equal or greater than the requested 'amount'. Returns tuple of vector of notes to be spent and the change that
/// is left over from the last note. Returns 'None' if there are not enough notes to reach 'amount'.
fn select_ft_notes(unspent_notes: &mut Vec<NoteEx>, asset: &Asset, contract: &Name) -> Option<(Vec<NoteEx>, u64)>
{
    // sort 'notes' by note amount, ascending order and walk backwards through them in order to be able to safely remove elements
    unspent_notes.sort_by(|a, b| a.note().amount().cmp(&b.note().amount()));
    let mut res = Vec::new();
    let mut sum = 0;
    for i in (0..unspent_notes.len()).rev()
    {
        if contract.eq(unspent_notes[i].note().contract()) &&               // same contract
            asset.symbol().eq(unspent_notes[i].note().symbol()) &&  // same symbol
            !unspent_notes[i].note().quantity().is_nft()               // no nft or auth token
        {
            sum += unspent_notes[i].note().amount() as u64;
            res.push(unspent_notes.remove(i));
            if sum >= asset.amount() as u64
            {
                // collected enough fungible notes, return notes & change amount
                return Some((res, sum - asset.amount() as u64));
            }
        }
    }
    // Not enough notes! Move picked notes in 'res' back to 'notes' and return 'None'.
    unspent_notes.append(&mut res);
    None
}

fn select_auth_note(unspent_notes: &mut Vec<NoteEx>, cm: &ExtractedNoteCommitment) -> Option<NoteEx>
{
    for i in (0..unspent_notes.len()).rev()
    {
        if unspent_notes[i].note().symbol().raw() == 0 && unspent_notes[i].note().amount() == 0
        {
            if unspent_notes[i].note().commitment().eq(&cm)
            {
                // found AT
                return Some(unspent_notes.remove(i));
            }
        }
    }
    None
}

fn select_fee_notes(unspent_notes: &mut Vec<NoteEx>, fees: &HashMap<Name, Asset>, contract: &Name, change: u64, fee: u64, num_outputs: usize) -> Option<(Vec<NoteEx>, u64, u64)>
{
    if change >= fee
    {
        return Some((vec![], change - fee, fee));
    }
    // sort 'notes' by note amount, ascending order and walk backwards through them in order to be able to safely remove elements
    unspent_notes.sort_by(|a, b| a.note().amount().cmp(&b.note().amount()));
    let mut res = Vec::new();
    let mut sum = change;
    let mut fee = fee;
    let mut no = num_outputs;
    for i in (0..unspent_notes.len()).rev()
    {
        if contract.eq(unspent_notes[i].note().contract()) &&                                       // fee contract
            fees.values().next().unwrap().symbol().eq(unspent_notes[i].note().symbol()) &&  // fee symbol
            !unspent_notes[i].note().quantity().is_nft()                                       // no nft or auth token
        {
            sum += unspent_notes[i].note().amount() as u64;
            fee += if no > 0 { 
                // output is being replaced with a spend_output => subtract output fee and add spend_output fee, reduce 'no' by one
                no -= 1;
                (fees.get(&Name::from_string(&"spendoutput".to_string()).unwrap()).unwrap().amount() - fees.get(&Name::from_string(&"output".to_string()).unwrap()).unwrap().amount()) as u64
            } else {
                fees.get(&Name::from_string(&"spend".to_string()).unwrap()).unwrap().amount() as u64
            };
            res.push(unspent_notes.remove(i));
            if sum >= fee
            {
                // collected enough fungible notes, return notes & change amount
                return Some((res, sum - fee, fee));
            }
        }
    }
    // Not enough notes! Move picked notes in 'res' back to 'notes' and return 'None'.
    unspent_notes.append(&mut res);
    None
}

pub fn resolve_ztransaction(wallet: &Wallet, fee_token_contract: &Name, fees: &HashMap<Name, Asset>, ztx: &ZTransaction) -> Result<ResolvedZTransaction, Box<dyn Error>>
{
    if wallet.is_ivk()
    {
        Err(TransactionError::IvkWallet)?
    }
    if !wallet.protocol_contract().eq(&ztx.protocol_contract) || !wallet.alias_authority().eq(&Authorization::from_string(&ztx.alias_authority).unwrap())
    {
        Err(TransactionError::InvalidProtocolContractOrAliasAuthority)?
    }

    let mut rng = OsRng.clone();
    let mut rztx = ResolvedZTransaction{
        chain_id: hex::decode(ztx.chain_id.clone())?.try_into().unwrap_or_else(|v: Vec<u8>| panic!("chain_id: expected a Vec of length {} but it was {}", 32, v.len())),
        protocol_contract: ztx.protocol_contract,
        alias_authority: Authorization::from_string(&ztx.alias_authority).unwrap(),
        rzactions: vec![]
    };

    // buffer auth tokens for use within this transaction
    let mut auth_tokens = vec![];
    // get all unspent notes of this wallet
    let mut unspent_notes = wallet.unspent_notes().clone();
    // track the fee amount for this transaction
    let mut fee = fees.get(&Name::from_string(&"begin".to_string()).unwrap()).unwrap().amount();

    for za in ztx.zactions.iter()
    {
        rztx.rzactions.push(
            match za.name
            {
                // mint
                Name(10639630974360485888) => Ok(ResolvedZAction{
                    name: za.name,
                    data: {
                        let desc: MintDesc = serde_json::from_value(za.data.clone())?;

                        let n = Note::from_parts(
                            0,
                            if desc.to.eq(&"$SELF") { wallet.default_address().unwrap() } else { Address::from_bech32m(&desc.to)? },
                            desc.from,
                            ExtendedAsset::new(desc.quantity, desc.contract),
                            Rseed::new(&mut rng),
                            {
                                let memo = insert_vars(&desc.memo, &wallet.default_address().unwrap().to_bech32m()?, &auth_tokens);
                                let mut memo_bytes = [0; 512];
                                memo_bytes[0..min(512, memo.len())].copy_from_slice(&memo.as_bytes()[0..min(512, memo.len())]);
                                memo_bytes
                            }
                        );

                        // check if this note is an auth token
                        if n.quantity().eq(&Asset::from_string(&"0".to_string()).unwrap())
                        {
                            if !n.contract().eq(&n.account()) { Err(TransactionError::AuthTokenContractAccount)?; }
                            if desc.to.eq(&"$SELF") { auth_tokens.push(n.clone()); }
                            // if this auth note shall be published we need to add the 'publishnotes' fee
                            if desc.publish_note { fee += fees.get(&Name::from_string(&"publishnotes".to_string()).unwrap()).unwrap().amount(); }
                        }
                        else
                        {
                            // add mint fee
                            fee += fees.get(&Name::from_string(&"mint".to_string()).unwrap()).unwrap().amount();
                        }

                        serde_json::to_value(ResolvedMintDesc{
                            note: n,
                            publish_note: desc.publish_note
                        })?
                    }
                }),

                // spend
                Name(14219329122852667392) => Ok(ResolvedZAction{
                    name: za.name,
                    data: {
                        let desc: SpendSequenceDesc = serde_json::from_value(za.data.clone())?;

                        let mut spend_output = vec![];
                        let mut spend = vec![];
                        let mut output = vec![];

                        // determine symbol of this 'spend' sequence from the first recipient (must have at least one)
                        assert!(desc.to.len() > 0);
                        let symbol = desc.to[0].quantity.symbol();
                        if symbol.raw() == 0 // NFT case
                        {
                            for srd in desc.to.iter()
                            {
                                let nft = select_nft_note(&mut unspent_notes, &srd.quantity);
                                if nft.is_none() { Err(TransactionError::NFTNotFound)? }
                                // NFTs are always spent via the SpendOutput circuit (to prevent "splitting")
                                let nft = nft.unwrap();
                                let note = Note::from_parts(
                                    0,
                                    if srd.to.eq(&"$SELF") { wallet.default_address().unwrap() } else if srd.to.len() <= 12 { Address::dummy(&mut rng) } else { Address::from_bech32m(&srd.to)? },
                                    if !srd.to.eq(&"$SELF") && srd.to.len() <= 12 { Name::from_string(&srd.to)? } else { Name(0) },
                                    ExtendedAsset::new(nft.note().quantity().clone(), nft.note().contract().clone()),
                                    Rseed::new(&mut rng),
                                    {
                                        let memo = insert_vars(&srd.memo, &wallet.default_address().unwrap().to_bech32m()?, &auth_tokens);
                                        let mut memo_bytes = [0; 512];
                                        memo_bytes[0..min(512, memo.len())].copy_from_slice(&memo.as_bytes()[0..min(512, memo.len())]);
                                        memo_bytes
                                    }
                                );

                                // add fee
                                fee += fees.get(&Name::from_string(&"spendoutput".to_string()).unwrap()).unwrap().amount();

                                spend_output.push(ResolvedSpendOutputDesc{
                                    note_a: nft.clone(),
                                    note_b: if note.account().eq(&Name(0)) { note.clone() } else { Note::dummy(&mut rng, None, Some(ExtendedAsset::new(Asset::new(0, symbol.clone()).unwrap(), desc.contract))).2 },
                                    publish_note_b: if note.account().eq(&Name(0)) { srd.publish_note } else { false },
                                    unshielded_outputs: if note.account().eq(&Name(0)) { vec![] } else { vec![(note, srd.publish_note)] },
                                })
                            }
                        }
                        else // FT case
                        {
                            let mut total_amount_out = 0;
                            let mut shielded_outputs = vec![];
                            let mut unshielded_outputs = vec![];

                            for srd in desc.to.iter()
                            {
                                total_amount_out += srd.quantity.amount();

                                if !srd.to.eq(&"$SELF") && srd.to.len() <= 12 // unshielded recipient
                                {
                                    unshielded_outputs.push((
                                        Note::from_parts(
                                            0,
                                            Address::dummy(&mut rng),
                                            Name::from_string(&srd.to)?,
                                            ExtendedAsset::new(srd.quantity.clone(), desc.contract.clone()),
                                            Rseed::new(&mut rng),
                                            {
                                                let memo = insert_vars(&srd.memo, &wallet.default_address().unwrap().to_bech32m()?, &auth_tokens);
                                                let mut memo_bytes = [0; 512];
                                                memo_bytes[0..min(512, memo.len())].copy_from_slice(&memo.as_bytes()[0..min(512, memo.len())]);
                                                memo_bytes
                                            }
                                        ),
                                        srd.publish_note
                                    ));
                                }
                                else // shielded recipient
                                {
                                    shielded_outputs.push((
                                        Note::from_parts(
                                            0,
                                            if srd.to.eq(&"$SELF") { wallet.default_address().unwrap() } else { Address::from_bech32m(&srd.to)? },
                                            Name(0),
                                            ExtendedAsset::new(srd.quantity.clone(), desc.contract.clone()),
                                            Rseed::new(&mut rng),
                                            {
                                                let memo = insert_vars(&srd.memo, &wallet.default_address().unwrap().to_bech32m()?, &auth_tokens);
                                                let mut memo_bytes = [0; 512];
                                                memo_bytes[0..min(512, memo.len())].copy_from_slice(&memo.as_bytes()[0..min(512, memo.len())]);
                                                memo_bytes
                                            }
                                        ),
                                        srd.publish_note
                                    ));
                                }
                            }

                            // select notes to spend
                            let notes_to_spend = select_ft_notes(&mut unspent_notes, &Asset::new(total_amount_out as i64, symbol.clone()).unwrap(), &desc.contract);
                            if notes_to_spend.is_none() { Err(TransactionError::InsufficientFunds)? }
                            let (notes_to_spend, change_amount) = notes_to_spend.unwrap();

                            // add change note to shielded_outputs
                            shielded_outputs.push((
                                Note::from_parts(
                                    0,
                                    if desc.change_to.eq(&"$SELF") { wallet.default_address().unwrap() } else { Address::from_bech32m(&desc.change_to)? },
                                    Name(0),
                                    ExtendedAsset::new(Asset::new(change_amount as i64, symbol.clone()).unwrap(), desc.contract.clone()),
                                    Rseed::new(&mut rng),
                                    MEMO_CHANGE_NOTE
                                ),
                                desc.publish_change_note
                            ));

                            // determine number of spend_outputs, spends and outputs (shielded_outputs because of change)
                            let num_spend_outputs = min(shielded_outputs.len(), notes_to_spend.len());
                            let num_spends = notes_to_spend.len() - num_spend_outputs;
                            let num_outputs = shielded_outputs.len() - num_spend_outputs;
                            assert!((num_spends == 0) || (num_outputs == 0), "either num_spends == 0 or num_outputs == 0 or both are zero");

                            // add fee
                            fee += fees.get(&Name::from_string(&"spendoutput".to_string()).unwrap()).unwrap().amount() * num_spend_outputs as i64;
                            fee += fees.get(&Name::from_string(&"spend".to_string()).unwrap()).unwrap().amount() * num_spends as i64;
                            fee += fees.get(&Name::from_string(&"output".to_string()).unwrap()).unwrap().amount() * num_outputs as i64;

                            for i in 0..num_spend_outputs
                            {
                                spend_output.push(ResolvedSpendOutputDesc{
                                    note_a: notes_to_spend[i].clone(),
                                    note_b: if i < shielded_outputs.len() { shielded_outputs[i].0.clone() } else { Note::dummy(&mut rng, None, Some(ExtendedAsset::new(Asset::new(0, symbol.clone()).unwrap(), desc.contract))).2 },
                                    publish_note_b: if i < shielded_outputs.len() { shielded_outputs[i].1 } else { false },
                                    // add unshielded outputs to first spend_output
                                    unshielded_outputs: if i == 0 { unshielded_outputs.clone() } else { vec![] },
                                });
                            }
                            for i in 0..num_spends
                            {
                                spend.push(ResolvedSpendDesc{
                                    note_a: notes_to_spend[num_spend_outputs + i].clone()
                                });
                            }
                            for i in 0..num_outputs
                            {
                                output.push(ResolvedOutputDesc{
                                    note_b: shielded_outputs[num_spend_outputs + i].0.clone(),
                                    publish_note_b: shielded_outputs[num_spend_outputs + i].1.clone()
                                });
                            }
                        }

                        serde_json::to_value(ResolvedSpendSequenceDesc{
                            spend_output,
                            spend,
                            output
                        })?
                    }
                }),

                // authenticate
                Name(3941447159957795488) => Ok(ResolvedZAction{
                    name: za.name,
                    data: {
                        let desc: AuthenticateDesc = serde_json::from_value(za.data.clone())?;

                        // select auth token either from wallet's unspent_notes or from auth_tokens vector of this transaction
                        let auth_token = if desc.auth_token.len() == 6 {
                            let auth_token_str_bytes = desc.auth_token.as_bytes();
                            if !auth_token_str_bytes[0..5].eq("$AUTH".as_bytes()) { Err(TransactionError::InvalidAuthToken)? }
                            let auth_idx = (auth_token_str_bytes[5] as char).to_digit(10).unwrap() as usize;
                            if auth_idx >= auth_tokens.len() { Err(TransactionError::InvalidAuthToken)? }
                            auth_tokens[auth_idx].clone()
                        } else if desc.auth_token.len() == 64 {
                            let mut cm_bytes = [0; 32];
                            cm_bytes.copy_from_slice(hex::decode(desc.auth_token)?.as_slice());
                            let auth_token = select_auth_note(&mut unspent_notes, &ExtractedNoteCommitment::from_bytes(&cm_bytes).unwrap());
                            if auth_token.is_none() { Err(TransactionError::InvalidAuthToken)? }
                            auth_token.unwrap().note().clone()
                        } else {
                            Err(TransactionError::InvalidAuthToken)?
                        };

                        // add fee
                        fee += fees.get(&Name::from_string(&"authenticate".to_string()).unwrap()).unwrap().amount();

                        // TODO: proper error handling with '?' instead of 'unwrap()'
                        serde_json::to_value(ResolvedAuthenticateDesc{
                            auth_note: auth_token,
                            actions: desc.actions.iter().map(|pad| PackedAction{
                                account: pad.account,
                                name: pad.name,
                                authorization: pad.authorization.iter().map(|auth| Authorization::from_string(auth).unwrap()).collect(),
                                data: hex::decode(pad.data.clone()).unwrap()
                            }).collect(),
                            burn: desc.burn
                        })?
                    }
                }),

                // publishnotes
                Name(12578297992662373760) => Ok(ResolvedZAction{
                    name: za.name,
                    data: {
                        let desc: PublishNotesDesc = serde_json::from_value(za.data.clone())?;

                        // TODO: perform check on all Strings reagrding correct length

                        // add fee
                        fee += fees.get(&Name::from_string(&"publishnotes".to_string()).unwrap()).unwrap().amount();

                        serde_json::to_value(ResolvedPublishNotesDesc{
                            notes: desc.notes
                        })?
                    }
                }),

                // withdraw
                Name(16407410437513019392) => Ok(ResolvedZAction{
                    name: za.name,
                    data: {
                        let desc: WithdrawDesc = serde_json::from_value(za.data.clone())?;

                        // add fee
                        fee += fees.get(&Name::from_string(&"withdraw".to_string()).unwrap()).unwrap().amount();

                        serde_json::to_value(ResolvedWithdrawDesc{
                            contract: desc.contract,
                            quantity: desc.quantity,
                            memo: insert_vars(&desc.memo, &wallet.default_address().unwrap().to_bech32m()?, &auth_tokens),
                            to: desc.to
                        })?
                    }
                }),

                _ => Err(TransactionError::InvalidActionName)
            }?
        );
    }

    // add transaction fees
    if ztx.add_fee
    {
        // walk throug rztx and look for a SpendSequence with fee token symbol
        let mut found = false;
        for rza in rztx.rzactions.iter_mut()
        {
            if rza.name == Name(14219329122852667392) // spend
            {
                let mut data: ResolvedSpendSequenceDesc = serde_json::from_value(rza.data.clone())?;

                if data.spend_output[0].note_a.note().contract().eq(&fee_token_contract) &&
                    data.spend_output[0].note_a.note().symbol().eq(fees.values().next().unwrap().symbol())
                {
                    // This spend sequence has the fee token symbol => add the tx fee into it
                    found = true;

                    // find change note (last shielded output in either 'output' or 'spend_output')
                    if data.output.len() == 0
                    {
                        // the change note is always the last shielded output
                        let idx = data.spend_output.len() - 1;
                        let mut note_b = data.spend_output[idx].note_b.clone();

                        let notes_to_spend = select_fee_notes(&mut unspent_notes, &fees, &fee_token_contract, note_b.amount(), fee as u64, 0);
                        if notes_to_spend.is_none() { Err(TransactionError::InsufficientFunds)? }
                        let (notes_to_spend, change, fee) = notes_to_spend.unwrap();

                        // add new unshielded output for tx fee to first spend_output in sequence
                        data.spend_output[0].unshielded_outputs.push((
                            Note::from_parts(
                                0,
                                Address::dummy(&mut rng),
                                rztx.alias_authority.actor,
                                ExtendedAsset::new(Asset::new(fee as i64, note_b.symbol().clone()).unwrap(), note_b.contract().clone()),
                                Rseed::new(&mut rng),
                                [0; 512]
                            ),
                            ztx.publish_fee_note
                        ));

                        // update change amount of last shielded output
                        note_b.set_amount(change);
                        data.spend_output[idx].note_b = note_b;

                        // add additional 'spend's to sequence
                        for nts in notes_to_spend.iter()
                        {
                            data.spend.push(ResolvedSpendDesc{
                                note_a: nts.clone()
                            });
                        }
                    }
                    else // change note is the last note in 'output' vector
                    {
                        // the change note is always the last shielded output
                        let idx = data.output.len() - 1;
                        let mut note_b = data.output[idx].note_b.clone();

                        let notes_to_spend = select_fee_notes(&mut unspent_notes, &fees, &fee_token_contract, note_b.amount(), fee as u64, data.output.len());
                        if notes_to_spend.is_none() { Err(TransactionError::InsufficientFunds)? }
                        let (notes_to_spend, change, fee) = notes_to_spend.unwrap();

                        // add new unshielded output for tx fee to first spend_output in sequence
                        data.spend_output[0].unshielded_outputs.push((
                            Note::from_parts(
                                0,
                                Address::dummy(&mut rng),
                                rztx.alias_authority.actor,
                                ExtendedAsset::new(Asset::new(fee as i64, note_b.symbol().clone()).unwrap(), note_b.contract().clone()),
                                Rseed::new(&mut rng),
                                [0; 512]
                            ),
                            ztx.publish_fee_note
                        ));

                        // update change amount of last shielded output
                        note_b.set_amount(change);
                        data.output[idx].note_b = note_b;

                        // add additional 'spend's to sequence while replacing as many 'output's with 'spend_output's as possible
                        for nts in notes_to_spend.iter()
                        {
                            if data.output.len() > 0
                            {
                                let o = data.output.remove(data.output.len() - 1);
                                data.spend_output.push(ResolvedSpendOutputDesc{
                                    note_a: nts.clone(),
                                    note_b: o.note_b,
                                    publish_note_b: o.publish_note_b,
                                    unshielded_outputs: vec![]
                                })
                            }
                            else
                            {
                                data.spend.push(ResolvedSpendDesc{
                                    note_a: nts.clone()
                                });
                            }
                        }
                    }

                    rza.data = serde_json::to_value(data)?;
                }
            }
        }

        // if not found, add one additional spend sequence for the fee only
        if !found
        {
            rztx.rzactions.push(ResolvedZAction{
                name: Name(14219329122852667392), // spend
                data: {
                    // maximal 1 spend_output (to pay tx fee and change) and potentially more spends
                    // set initial fee amount & number of outputs to exactly one 'output' so it will automatically be replaced with one 'spend_output' by the first 'spend' note
                    let notes_to_spend = select_fee_notes(&mut unspent_notes, &fees, &fee_token_contract, 0, (fee + fees.get(&Name::from_string(&"output".to_string()).unwrap()).unwrap().amount()) as u64, 1);
                    if notes_to_spend.is_none() { Err(TransactionError::InsufficientFunds)? }
                    let (mut notes_to_spend, change, fee) = notes_to_spend.unwrap();

                    // add one 'spend_output'
                    let spend_output = vec![ResolvedSpendOutputDesc{
                        note_a: notes_to_spend.remove(0),
                        note_b: Note::from_parts(
                            0,
                            wallet.default_address().unwrap(),
                            Name(0),
                            ExtendedAsset::new(Asset::new(change as i64, fees.values().next().unwrap().symbol().clone()).unwrap(), fee_token_contract.clone()),
                            Rseed::new(&mut rng),
                            MEMO_CHANGE_NOTE
                        ),
                        publish_note_b: ztx.publish_fee_note, // set boolean for 'change' note to same as fee note assuming the user wants either both published or none of them
                        unshielded_outputs: vec![(
                            Note::from_parts(
                                0,
                                Address::dummy(&mut rng),
                                rztx.alias_authority.actor,
                                ExtendedAsset::new(Asset::new(fee as i64, fees.values().next().unwrap().symbol().clone()).unwrap(), fee_token_contract.clone()),
                                Rseed::new(&mut rng),
                                [0; 512]
                            ),
                            ztx.publish_fee_note
                        )]
                    }];

                    // add the potential additional 'spend's
                    let mut spend = vec![];
                    for nts in notes_to_spend.iter()
                    {
                        spend.push(ResolvedSpendDesc{
                            note_a: nts.clone()
                        });
                    }

                    serde_json::to_value(ResolvedSpendSequenceDesc{
                        spend_output,
                        spend,
                        output: vec![]
                    })?
                }
            });
        }
    }

    Ok(rztx)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedZTransaction
{
    pub chain_id: [u8; 32],
    pub protocol_contract: Name,
    pub alias_authority: Authorization,
    pub rzactions: Vec<ResolvedZAction>
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedZAction
{
    pub name: Name,
    pub data: Value
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedMintDesc
{
    pub note: Note,
    pub publish_note: bool
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedSpendSequenceDesc
{
    pub spend_output: Vec<ResolvedSpendOutputDesc>,
    pub spend: Vec<ResolvedSpendDesc>,
    pub output: Vec<ResolvedOutputDesc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedSpendOutputDesc
{
    pub note_a: NoteEx,
    pub note_b: Note,
    pub publish_note_b: bool,
    pub unshielded_outputs: Vec<(Note, bool)>
}
impl ResolvedSpendOutputDesc
{
    pub fn net_val(&self) -> i64
    {
        let mut value_c = 0;
        for uo in self.unshielded_outputs.iter()
        {
            value_c += uo.0.amount();
        }
        self.note_a.note().amount() as i64 - (self.note_b.amount() as i64 + value_c as i64)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedSpendDesc
{
    pub note_a: NoteEx
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedOutputDesc
{
    pub note_b: Note,
    pub publish_note_b: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedAuthenticateDesc
{
    pub auth_note: Note,
    pub actions: Vec<PackedAction>,
    pub burn: bool
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedPublishNotesDesc
{
    pub notes: Vec<String>
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedWithdrawDesc
{
    pub contract: Name,
    pub quantity: Asset,
    pub memo: String,
    pub to: Name
}

pub fn zsign_transaction(wallet: &Wallet, rztx: &ResolvedZTransaction, params: &HashMap<Name, Parameters::<Bls12>>) -> Result<(Transaction, HashMap<String, Vec<String>>), Box<dyn Error>>
{
    if wallet.is_ivk()
    {
        Err(TransactionError::IvkWallet)?
    }
    let pgk = wallet.spending_key().unwrap().proof_generation_key();
    let fvk = FullViewingKey::from_spending_key(&wallet.spending_key().unwrap());

    let mint_params = params.get(&Name::from_string(&"mint".to_string()).unwrap());
    if mint_params.is_none() { Err(TransactionError::MintParams)? }
    let mint_params = mint_params.unwrap();
    let spend_output_params = params.get(&Name::from_string(&"spendoutput".to_string()).unwrap());
    if spend_output_params.is_none() { Err(TransactionError::SpendOutputParams)? }
    let spend_output_params = spend_output_params.unwrap();
    let spend_params = params.get(&Name::from_string(&"spend".to_string()).unwrap());
    if spend_params.is_none() { Err(TransactionError::SpendParams)? }
    let spend_params = spend_params.unwrap();
    let output_params = params.get(&Name::from_string(&"output".to_string()).unwrap());
    if output_params.is_none() { Err(TransactionError::OutputParams)? }
    let output_params = output_params.unwrap();

    let mut rng = OsRng.clone();
    let mut tx = Transaction{
        actions: vec![
            Action {
                account: wallet.alias_authority().actor.clone(),
                name: Name::from_string(&format!("begin")).unwrap(),
                authorization: vec![wallet.alias_authority().clone()],
                data: json!({})
            }
        ]
    };
    let mut unpublished_notes: HashMap<String, Vec<String>> = HashMap::new();

    let mut i = 0;
    while i < rztx.rzactions.len()
    {
        match rztx.rzactions[i].name
        {
            // mint
            Name(10639630974360485888) => {
                // bundle all consecutive mints into one sequence
                let mut mints = vec![];
                let mut note_cts = vec![];
                let mut auth_note_cts = vec![];
                while i < rztx.rzactions.len() && rztx.rzactions[i].name == Name(10639630974360485888)
                {
                    let data: ResolvedMintDesc = serde_json::from_value(rztx.rzactions[i].data.clone())?;

                    // only add a mint action if this is NOT an auth note
                    if !data.note.quantity().eq(&Asset::from_string(&"0".to_string()).unwrap())
                    {
                        mints.push(PlsMint{
                            cm: crate::contract::ScalarBytes(data.note.commitment().to_bytes()),
                            value: data.note.amount(),
                            symbol: data.note.symbol().clone(),
                            contract: data.note.contract().clone(),
                            proof: {
                                let instance = Mint {
                                    account: Some(data.note.account().raw()),
                                    auth_hash: Some([0; 4]),
                                    value: Some(data.note.amount()),
                                    symbol: Some(data.note.symbol().raw()),
                                    contract: Some(data.note.contract().raw()),
                                    address: Some(data.note.address()),
                                    rcm: Some(data.note.rcm()),
                                    proof_generation_key: Some(pgk.clone()),
                                };
                                AffineProofBytesLE::from(create_random_proof(instance, mint_params, &mut OsRng)?)
                            }
                        });
                    }

                    let note_ct = {
                        let esk = derive_esk(&data.note).unwrap();
                        let epk = ka_derive_public(&data.note, &esk);
                        let ne = NoteEncryption::new(Some(fvk.ovk), data.note.clone());
                        let encrypted_note = TransmittedNoteCiphertext {
                            epk_bytes: epk.to_bytes().0,
                            enc_ciphertext: ne.encrypt_note_plaintext(),
                            out_ciphertext: ne.encrypt_outgoing_plaintext(&mut rng),
                        };
                        encrypted_note.to_base64()
                    };

                    if data.publish_note
                    {
                        if data.note.quantity().eq(&Asset::from_string(&"0".to_string()).unwrap()) { auth_note_cts.push(note_ct); }
                        else { note_cts.push(note_ct); }
                    }
                    else
                    {
                        let recipient = data.note.address().to_bech32m()?;
                        // check if recipient == self in order to not add this note twice: 1) as recipient note and 2) as "self" note below
                        if recipient != wallet.default_address().unwrap().to_bech32m()?
                        {
                            if unpublished_notes.contains_key(&recipient)
                            {
                                unpublished_notes.get_mut(&recipient).unwrap().push(note_ct.clone());
                            }
                            else
                            {
                                unpublished_notes.insert(recipient, vec![note_ct.clone()]);
                            }
                        }
                        if unpublished_notes.contains_key(&"self".to_string())
                        {
                            unpublished_notes.get_mut(&"self".to_string()).unwrap().push(note_ct);
                        }
                        else
                        {
                            unpublished_notes.insert("self".to_string(), vec![note_ct]);
                        }
                    }

                    i = i + 1;
                }

                if !mints.is_empty()
                {
                    tx.actions.push(Action{
                        account: rztx.alias_authority.actor,
                        name: Name(10639630974360485888), // mint
                        authorization: vec![rztx.alias_authority.clone()],
                        data: serde_json::to_value(PlsMintAction{
                            actions: mints,
                            note_ct: note_cts
                        })?
                    });
                }

                if !auth_note_cts.is_empty()
                {
                    tx.actions.push(Action{
                        account: rztx.alias_authority.actor,
                        name: Name(12578297992662373760), // publishnotes
                        authorization: vec![rztx.alias_authority.clone()],
                        data: serde_json::to_value(PlsPublishNotesAction{
                            note_ct: auth_note_cts
                        })?
                    });
                }
            }

            // spend
            Name(14219329122852667392) => {
                // bundle all consecutive spend sequences into one sequence
                let mut spend_seqs = vec![];
                let mut note_cts = vec![];
                while i < rztx.rzactions.len() && rztx.rzactions[i].name == Name(14219329122852667392)
                {
                    let data: ResolvedSpendSequenceDesc = serde_json::from_value(rztx.rzactions[i].data.clone())?;

                    // define the symbol commitment for this spend sequence
                    let rscm = Rseed::new(&mut rng);
                    let scm = {
                        let scm = windowed_pedersen_commit(
                            Personalization::SymbolCommitment,
                            iter::empty()
                                // at least one spend_output must always exist
                                .chain(BitArray::<_, Lsb0>::new(data.spend_output[0].note_a.note().symbol().raw().to_le_bytes()).iter().by_vals())
                                .chain(BitArray::<_, Lsb0>::new(data.spend_output[0].note_a.note().contract().raw().to_le_bytes()).iter().by_vals()),
                                rscm.rcm().0
                        );
                        ScalarBytes(extract_p(&scm).to_bytes())
                    };

                    // define blinding factor for pedersen commitments of this spend sequence and the multipliers for all spend_outputs
                    let rcv = ValueCommitTrapdoor::random(&mut rng);
                    // determine rcv_muls to balance the blinding factors in pedersen commitment sum
                    let rcv_muls = {
                        let mut num_spends = 0;
                        let mut num_outputs = 0;
                        for so in data.spend_output.iter()
                        {
                            if so.net_val() < 0
                            {
                                num_outputs = num_outputs + 1;
                            }
                            else if so.net_val() > 0
                            {
                                num_spends = num_spends + 1;
                            }
                        }
                        num_spends = num_spends + data.spend.len();
                        num_outputs = num_outputs + data.output.len();
                        let mut is_balanced = num_spends == num_outputs;
                        let mut rcv_muls = vec![1; data.spend_output.len()];
                        if num_spends > num_outputs
                        {
                            // need to balance output side => find first spend_output that is a net output and set it's rcv_mul to the balancing factor
                            for (i, so) in data.spend_output.iter().enumerate()
                            {
                                if so.net_val() < 0 && !is_balanced
                                {
                                    rcv_muls[i] = 1 + num_spends - num_outputs;
                                    is_balanced = true;
                                }
                            }
                        }
                        else if num_outputs > num_spends
                        {
                            // need to balance input side => find first spend_output that is a net spend and set it's rcv_mul to the balancing factor
                            for (i, so) in data.spend_output.iter().enumerate()
                            {
                                if so.net_val() > 0 && !is_balanced
                                {
                                    rcv_muls[i] = 1 + num_outputs - num_spends;
                                    is_balanced = true;
                                }
                            }
                        }
                        rcv_muls
                    };

                    let mut spend_output = vec![];
                    let mut spend = vec![];
                    let mut output = vec![];

                    for (i, so) in data.spend_output.iter().enumerate()
                    {
                        let sister_path_and_root = wallet.get_sister_path_and_root(&so.note_a);
                        if sister_path_and_root.is_none() { Err(TransactionError::InvalidNote)? }
                        let (sister_path, root) = sister_path_and_root.unwrap();

                        let value_spend = so.note_b.amount() + so.unshielded_outputs.iter().map(|uo| uo.0.amount()).sum::<u64>();
                        let value_c = value_spend - so.note_b.amount();
                        let net_value = if so.note_a.note().amount() > value_spend { so.note_a.note().amount() - value_spend } else { value_spend - so.note_a.note().amount() };
                        let mut cv_net = ValueCommitment::derive(net_value, rcv.clone());
                        // add rcv_mul times zero value commitments in order to effectively multiply rcv by rcv_mul
                        for _j in 1..rcv_muls[i]
                        {
                            cv_net = cv_net.add(&ValueCommitment::derive(0, rcv.clone()));
                        }
                        let cv_eq_gt = if so.note_a.note().amount() == value_spend {2} else {0} | if so.note_a.note().amount() > value_spend {1} else {0};

                        spend_output.push(PlsSpendOutput{
                            root,
                            nf: ScalarBytes(ExtractedNullifier::from(so.note_a.note().nullifier(&fvk.nk, so.note_a.position())).to_bytes()),
                            cm_b: ScalarBytes(so.note_b.commitment().to_bytes()),
                            cv_net_u: ScalarBytes(scalar_to_raw_bytes_le(&cv_net.as_inner().to_affine().get_u())),
                            cv_net_v: ScalarBytes(scalar_to_raw_bytes_le(&cv_net.as_inner().to_affine().get_v())),
                            value_c,
                            symbol: if value_c == 0 { Symbol(0) } else { so.note_a.note().symbol().clone() },
                            contract: if value_c == 0 { Name(0) } else { so.note_a.note().contract().clone() },
                            cv_eq_gt,
                            proof: {
                                let instance = SpendOutput {
                                    note_a: Some(so.note_a.note().clone()),
                                    proof_generation_key: Some(pgk.clone()),
                                    auth_path: sister_path,
                                    rcv: Some(rcv.inner()),
                                    rcv_mul: Some(rcv_muls[i] as u8),
                                    rscm: Some(rscm.rcm().0),
                                    note_b: Some(so.note_b.clone()),
                                    value_c: Some(value_spend - so.note_b.amount()),
                                    unshielded_outputs_hash: {
                                        let mut state = Blake2s7rParams::new().hash_length(32).personal(&[0; 8]).to_state();
                                        for uo in so.unshielded_outputs.iter()
                                        {
                                            state.update(&uo.0.amount().to_le_bytes());
                                            state.update(&uo.0.account().raw().to_le_bytes());
                                            state.update(&uo.0.memo()[0..{let len = uo.0.memo().iter().position(|&c| c == 0); if len.is_none() {512} else {len.unwrap()}}]);
                                        }
                                        let hash: [u8; 32] = state.finalize().as_bytes().try_into()?;
                                        let hash = [u64::from_le_bytes(hash[0..8].try_into()?), u64::from_le_bytes(hash[8..16].try_into()?), u64::from_le_bytes(hash[16..24].try_into()?), u64::from_le_bytes(hash[24..32].try_into()?)];
                                        Some(hash)
                                    }
                                };
                                AffineProofBytesLE::from(create_random_proof(instance, spend_output_params, &mut OsRng)?)
                            },
                            unshielded_outputs: so.unshielded_outputs.iter().map(|uo| PlsUnshieldedRecipient{
                                amount: uo.0.amount(),
                                account: uo.0.account(),
                                memo: String::from_utf8(uo.0.memo()[0..{let len = uo.0.memo().iter().position(|&c| c == 0); if len.is_none() {512} else {len.unwrap()}}].to_vec()).unwrap()
                            }).collect()
                        });

                        // only create note b ciphertext if it is not a dummy note (which it is in case of NFT and unshielded_outputs.len() == 1)
                        if !(so.note_a.note().symbol().raw() == 0 && so.unshielded_outputs.len() == 1)
                        {
                            let note_b_ct = {
                                let esk = derive_esk(&so.note_b).unwrap();
                                let epk = ka_derive_public(&so.note_b, &esk);
                                let ne = NoteEncryption::new(Some(fvk.ovk), so.note_b.clone());
                                let encrypted_note = TransmittedNoteCiphertext {
                                    epk_bytes: epk.to_bytes().0,
                                    enc_ciphertext: ne.encrypt_note_plaintext(),
                                    out_ciphertext: ne.encrypt_outgoing_plaintext(&mut rng),
                                };
                                encrypted_note.to_base64()
                            };
                            if so.publish_note_b
                            {
                                note_cts.push(note_b_ct);
                            }
                            else
                            {
                                let recipient = so.note_b.address().to_bech32m()?;
                                // check if recipient == self in order to not add this note twice: 1) as recipient note and 2) as "self" note below
                                if recipient != wallet.default_address().unwrap().to_bech32m()?
                                {
                                    if unpublished_notes.contains_key(&recipient)
                                    {
                                        unpublished_notes.get_mut(&recipient).unwrap().push(note_b_ct.clone());
                                    }
                                    else
                                    {
                                        unpublished_notes.insert(recipient, vec![note_b_ct.clone()]);
                                    }
                                }
                                if unpublished_notes.contains_key(&"self".to_string())
                                {
                                    unpublished_notes.get_mut(&"self".to_string()).unwrap().push(note_b_ct);
                                }
                                else
                                {
                                    unpublished_notes.insert("self".to_string(), vec![note_b_ct]);
                                }
                            }
                        }
                        // create note ciphertexts for unshielded outputs
                        for (note, publish_note) in so.unshielded_outputs.iter()
                        {
                            let note_ct = {
                                let esk = derive_esk(note).unwrap();
                                let epk = ka_derive_public(note, &esk);
                                let ne = NoteEncryption::new(Some(fvk.ovk), note.clone());
                                let encrypted_note = TransmittedNoteCiphertext {
                                    epk_bytes: epk.to_bytes().0,
                                    enc_ciphertext: ne.encrypt_note_plaintext(),
                                    out_ciphertext: ne.encrypt_outgoing_plaintext(&mut rng),
                                };
                                encrypted_note.to_base64()
                            };
                            if *publish_note
                            {
                                note_cts.push(note_ct);
                            }
                            else
                            {
                                if unpublished_notes.contains_key(&"self".to_string())
                                {
                                    unpublished_notes.get_mut(&"self".to_string()).unwrap().push(note_ct);
                                }
                                else
                                {
                                    unpublished_notes.insert("self".to_string(), vec![note_ct]);
                                }
                            }
                        }
                    }
                    for s in data.spend.iter()
                    {
                        let sister_path_and_root = wallet.get_sister_path_and_root(&s.note_a);
                        if sister_path_and_root.is_none() { Err(TransactionError::InvalidNote)? }
                        let (sister_path, root) = sister_path_and_root.unwrap();

                        let cv = ValueCommitment::derive(s.note_a.note().amount(), rcv.clone());

                        spend.push(PlsSpend{
                            root,
                            nf: ScalarBytes(ExtractedNullifier::from(s.note_a.note().nullifier(&fvk.nk, s.note_a.position())).to_bytes()),
                            cv_u: ScalarBytes(scalar_to_raw_bytes_le(&cv.as_inner().to_affine().get_u())),
                            cv_v: ScalarBytes(scalar_to_raw_bytes_le(&cv.as_inner().to_affine().get_v())),
                            proof: {
                                let instance = Spend {
                                    note_a: Some(s.note_a.note().clone()),
                                    proof_generation_key: Some(pgk.clone()),
                                    auth_path: sister_path,
                                    rcv: Some(rcv.inner()),
                                    rscm: Some(rscm.rcm().0),
                                };
                                AffineProofBytesLE::from(create_random_proof(instance, spend_params, &mut OsRng)?)
                            }
                        });
                    }
                    for o in data.output.iter()
                    {
                        let cv = ValueCommitment::derive(o.note_b.amount(), rcv.clone());

                        output.push(PlsOutput{
                            cm: ScalarBytes(o.note_b.commitment().to_bytes()),
                            cv_u: ScalarBytes(scalar_to_raw_bytes_le(&cv.as_inner().to_affine().get_u())),
                            cv_v: ScalarBytes(scalar_to_raw_bytes_le(&cv.as_inner().to_affine().get_v())),
                            proof: {
                                let instance = Output {
                                    rcv: Some(rcv.inner()),
                                    rscm: Some(rscm.rcm().0),
                                    note_b: Some(o.note_b.clone())
                                };
                                AffineProofBytesLE::from(create_random_proof(instance, output_params, &mut OsRng)?)
                            }
                        });

                        let note_ct = {
                            let esk = derive_esk(&o.note_b).unwrap();
                            let epk = ka_derive_public(&o.note_b, &esk);
                            let ne = NoteEncryption::new(Some(fvk.ovk), o.note_b.clone());
                            let encrypted_note = TransmittedNoteCiphertext {
                                epk_bytes: epk.to_bytes().0,
                                enc_ciphertext: ne.encrypt_note_plaintext(),
                                out_ciphertext: ne.encrypt_outgoing_plaintext(&mut rng),
                            };
                            encrypted_note.to_base64()
                        };
    
                        if o.publish_note_b
                        {
                            note_cts.push(note_ct);
                        }
                        else
                        {
                            let recipient = o.note_b.address().to_bech32m()?;
                            // check if recipient == self in order to not add this note twice: 1) as recipient note and 2) as "self" note below
                            if recipient != wallet.default_address().unwrap().to_bech32m()?
                            {
                                if unpublished_notes.contains_key(&recipient)
                                {
                                    unpublished_notes.get_mut(&recipient).unwrap().push(note_ct.clone());
                                }
                                else
                                {
                                    unpublished_notes.insert(recipient, vec![note_ct.clone()]);
                                }
                            }
                            if unpublished_notes.contains_key(&"self".to_string())
                            {
                                unpublished_notes.get_mut(&"self".to_string()).unwrap().push(note_ct);
                            }
                            else
                            {
                                unpublished_notes.insert("self".to_string(), vec![note_ct]);
                            }
                        }
                    }

                    spend_seqs.push(PlsSpendSequence{
                        scm,
                        spend_output,
                        spend,
                        output
                    });

                    i = i + 1;
                }

                tx.actions.push(Action{
                    account: rztx.alias_authority.actor,
                    name: Name(14219329122852667392), // spend
                    authorization: vec![rztx.alias_authority.clone()],
                    data: serde_json::to_value(PlsSpendAction{
                        actions: spend_seqs,
                        note_ct: note_cts
                    })?
                });
            }

            // authenticate
            Name(3941447159957795488) => {

                let data: ResolvedAuthenticateDesc = serde_json::from_value(rztx.rzactions[i].data.clone())?;

                tx.actions.push(Action{
                    account: rztx.alias_authority.actor,
                    name: Name(3941447159957795488), // authenticate
                    authorization: vec![rztx.alias_authority.clone()],
                    data: serde_json::to_value(PlsAuthenticateAction{
                        action: PlsAuthenticate{
                            cm: ScalarBytes(data.auth_note.commitment().to_bytes()),
                            contract: data.auth_note.contract().clone(),
                            actions: data.actions.clone(),
                            burn: if data.burn { 1 } else { 0 },
                            proof: {
                                let instance = Mint {
                                    account: Some(data.auth_note.account().raw()),
                                    auth_hash: {
                                        let mut state = Blake2s7rParams::new().hash_length(32).personal(&[0; 8]).to_state();
                                        state.update(&pack(data.actions));
                                        let hash: [u8; 32] = state.finalize().as_bytes().try_into()?;
                                        let hash = [u64::from_le_bytes(hash[0..8].try_into()?), u64::from_le_bytes(hash[8..16].try_into()?), u64::from_le_bytes(hash[16..24].try_into()?), u64::from_le_bytes(hash[24..32].try_into()?)];
                                        Some(hash)
                                    },
                                    value: Some(data.auth_note.amount()),
                                    symbol: Some(data.auth_note.symbol().raw()),
                                    contract: Some(data.auth_note.contract().raw()),
                                    address: Some(data.auth_note.address()),
                                    rcm: Some(data.auth_note.rcm()),
                                    proof_generation_key: Some(pgk.clone()),
                                };
                                AffineProofBytesLE::from(create_random_proof(instance, mint_params, &mut OsRng)?)
                            }
                        }
                    })?
                });

                i = i + 1;
            }

            // publishnotes
            Name(12578297992662373760) => {

                let data: ResolvedPublishNotesDesc = serde_json::from_value(rztx.rzactions[i].data.clone())?;

                tx.actions.push(Action{
                    account: rztx.alias_authority.actor,
                    name: Name(12578297992662373760), // publishnotes
                    authorization: vec![rztx.alias_authority.clone()],
                    data: serde_json::to_value(PlsPublishNotesAction{
                        note_ct: data.notes
                    })?
                });

                i = i + 1;
            }

            // withdraw
            Name(16407410437513019392) => {
                // bundle all consecutive withdraws into one sequence
                let mut withdraws = vec![];
                while i < rztx.rzactions.len() && rztx.rzactions[i].name == Name(16407410437513019392)
                {
                    let data: ResolvedWithdrawDesc = serde_json::from_value(rztx.rzactions[i].data.clone())?;

                    withdraws.push(PlsWithdraw{
                        contract: data.contract,
                        quantity: data.quantity,
                        memo: data.memo,
                        to: data.to
                    });

                    i = i + 1;
                }

                tx.actions.push(Action{
                    account: rztx.alias_authority.actor,
                    name: Name(16407410437513019392), // withdraw
                    authorization: vec![rztx.alias_authority.clone()],
                    data: serde_json::to_value(PlsWithdrawAction{
                        actions: withdraws
                    })?
                });
            }

            _ => Err(TransactionError::InvalidActionName)?
        }
    }

    // add end action
    tx.actions.push(Action{
        account: wallet.alias_authority().actor,
        name: Name::from_string(&"end".to_string()).unwrap(),
        authorization: vec![wallet.alias_authority().clone()],
        data: json!({})
    });

    Ok((tx, unpublished_notes))
}

pub fn zverify_spend_transaction(tx: &Transaction, params: &HashMap<Name, Parameters::<Bls12>>) -> bool
{
    let spend_output_params = params.get(&Name::from_string(&"spendoutput".to_string()).unwrap());
    assert!(spend_output_params.is_some());
    let spend_output_params = spend_output_params.unwrap();
    let spend_params = params.get(&Name::from_string(&"spend".to_string()).unwrap());
    assert!(spend_params.is_some());
    let spend_params = spend_params.unwrap();
    let output_params = params.get(&Name::from_string(&"output".to_string()).unwrap());
    assert!(output_params.is_some());
    let output_params = output_params.unwrap();

    for a in tx.actions.iter()
    {
        match a.name
        {
            // spend
            Name(14219329122852667392) => {
                let data: PlsSpendAction = serde_json::from_value(a.data.clone()).unwrap();

                let mut spend_sum = AffinePoint::from_raw_unchecked(Scalar::zero(), Scalar::zero()).to_extended();
                let mut spend_sum_begin = true;
                let mut output_sum = AffinePoint::from_raw_unchecked(Scalar::zero(), Scalar::zero()).to_extended();
                let mut output_sum_begin = true;

                for a in data.actions.iter()
                {
                    for so in a.spend_output.iter()
                    {
                        let mut inputs7 = [0; 25];
                        inputs7[ 0.. 8].copy_from_slice(&so.value_c.to_le_bytes());
                        inputs7[ 8..16].copy_from_slice(&so.symbol.raw().to_le_bytes());
                        inputs7[16..24].copy_from_slice(&so.contract.raw().to_le_bytes());
                        inputs7[24] = so.cv_eq_gt;
                        let inputs7 = multipack::bytes_to_bits_le(&inputs7);
                        let inputs7_: Vec<Scalar> = multipack::compute_multipacking(&inputs7);
                        assert_eq!(inputs7_.len(), 1);
                        let mut inputs7 = vec![];
                        inputs7.extend(inputs7_.clone());
                        let inputs8 = {
                            let mut state = Blake2s7rParams::new().hash_length(32).personal(&[0; 8]).to_state();
                            for uo in so.unshielded_outputs.iter()
                            {
                                state.update(&uo.amount.to_le_bytes());
                                state.update(&uo.account.raw().to_le_bytes());
                                state.update(&uo.memo.as_bytes());
                            }
                            let hash: [u8; 32] = state.finalize().as_bytes().try_into().unwrap();
                            hash
                        };
                        let mut inputs8 = multipack::bytes_to_bits_le(&inputs8);
                        inputs8.truncate(254);
                        let inputs8_: Vec<Scalar> = multipack::compute_multipacking(&inputs8);
                        assert_eq!(inputs8_.len(), 1);
                        let mut inputs8 = vec![];
                        inputs8.extend(inputs8_.clone());
                        let mut inputs = vec![];
                        inputs.push(Scalar::from(so.root.clone()));
                        inputs.push(Scalar::from(so.nf.clone()));
                        inputs.push(Scalar::from(a.scm.clone()));
                        inputs.push(Scalar::from(so.cm_b.clone()));
                        inputs.push(Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&so.cv_net_u.0).to_bytes()).unwrap());
                        inputs.push(Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&so.cv_net_v.0).to_bytes()).unwrap());
                        inputs.extend(inputs7.clone());
                        inputs.extend(inputs8.clone());

                        let pvk = prepare_verifying_key(&spend_output_params.vk);
                        let proof = Proof::<Bls12>::from(so.proof.clone());
                        if !verify_proof(&pvk, &proof, &inputs).is_ok() { return false; }

                        if !((so.cv_eq_gt & 2) == 2)
                        {
                            if (so.cv_eq_gt & 1) == 1
                            {
                                if spend_sum_begin
                                {
                                    spend_sum = AffinePoint::from_raw_unchecked(
                                        Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&so.cv_net_u.0).to_bytes()).unwrap(),
                                        Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&so.cv_net_v.0).to_bytes()).unwrap()
                                    ).to_extended();
                                    spend_sum_begin = false;
                                }
                                else
                                {
                                    spend_sum.add_assign(AffinePoint::from_raw_unchecked(
                                        Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&so.cv_net_u.0).to_bytes()).unwrap(),
                                        Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&so.cv_net_v.0).to_bytes()).unwrap()
                                    ));
                                }
                            }
                            else
                            {
                                if output_sum_begin
                                {
                                    output_sum = AffinePoint::from_raw_unchecked(
                                        Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&so.cv_net_u.0).to_bytes()).unwrap(),
                                        Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&so.cv_net_v.0).to_bytes()).unwrap()
                                    ).to_extended();
                                    output_sum_begin = false;
                                }
                                else
                                {
                                    output_sum.add_assign(AffinePoint::from_raw_unchecked(
                                        Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&so.cv_net_u.0).to_bytes()).unwrap(),
                                        Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&so.cv_net_v.0).to_bytes()).unwrap()
                                    ));
                                }
                            }
                        }
                    }

                    for s in a.spend.iter()
                    {
                        let mut inputs = vec![];
                        inputs.push(Scalar::from(s.root.clone()));
                        inputs.push(Scalar::from(s.nf.clone()));
                        inputs.push(Scalar::from(a.scm.clone()));
                        inputs.push(Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&s.cv_u.0).to_bytes()).unwrap());
                        inputs.push(Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&s.cv_v.0).to_bytes()).unwrap());

                        let pvk = prepare_verifying_key(&spend_params.vk);
                        let proof = Proof::<Bls12>::from(s.proof.clone());
                        if !verify_proof(&pvk, &proof, &inputs).is_ok() { return false; }

                        if spend_sum_begin
                        {
                            spend_sum = AffinePoint::from_raw_unchecked(
                                Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&s.cv_u.0).to_bytes()).unwrap(),
                                Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&s.cv_v.0).to_bytes()).unwrap()
                            ).to_extended();
                            spend_sum_begin = false;
                        }
                        else
                        {
                            spend_sum.add_assign(AffinePoint::from_raw_unchecked(
                                Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&s.cv_u.0).to_bytes()).unwrap(),
                                Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&s.cv_v.0).to_bytes()).unwrap()
                            ));
                        }
                    }

                    for o in a.output.iter()
                    {
                        let mut inputs = vec![];
                        inputs.push(Scalar::from(a.scm.clone()));
                        inputs.push(Scalar::from(o.cm.clone()));
                        inputs.push(Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&o.cv_u.0).to_bytes()).unwrap());
                        inputs.push(Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&o.cv_v.0).to_bytes()).unwrap());

                        let pvk = prepare_verifying_key(&output_params.vk);
                        let proof = Proof::<Bls12>::from(o.proof.clone());
                        if !verify_proof(&pvk, &proof, &inputs).is_ok() { return false; }

                        if output_sum_begin
                        {
                            output_sum = AffinePoint::from_raw_unchecked(
                                Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&o.cv_u.0).to_bytes()).unwrap(),
                                Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&o.cv_v.0).to_bytes()).unwrap()
                            ).to_extended();
                            output_sum_begin = false;
                        }
                        else
                        {
                            output_sum.add_assign(AffinePoint::from_raw_unchecked(
                                Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&o.cv_u.0).to_bytes()).unwrap(),
                                Scalar::from_bytes(&contract::Scalar::from_raw_bytes(&o.cv_v.0).to_bytes()).unwrap()
                            ));
                        }
                    }

                    // check pedersen sums (are tx inputs and outputs balanced?)
                    if !spend_sum.eq(&output_sum) { return false; }
                }
            }

            _ => {}
        }
    }

    true
}

pub fn zsign_transfer_and_mint_transaction(
    mint_zactions: &Vec<MintDesc>,
    alias_authority: &Authorization,
    user_authority: &Authorization,
    protocol_contract: Name,
    fee_token_contract: Name,
    fees: &HashMap<Name, Asset>,
    mint_params: &Parameters<Bls12>
) -> Result<(Transaction, HashMap<String, Vec<String>>), Box<dyn Error>>
{
    let mut rng = OsRng.clone();
    let mut tx = Transaction{
        actions: vec![
            Action {
                account: alias_authority.actor.clone(),
                name: Name::from_string(&format!("begin")).unwrap(),
                authorization: vec![alias_authority.clone()],
                data: json!({})
            }
        ]
    };
    let mut resolved_mints = vec![];
    for desc in mint_zactions.iter()
    {
        let n = Note::from_parts(
            0,
            Address::from_bech32m(&desc.to)?,
            desc.from,
            ExtendedAsset::new(desc.quantity.clone(), desc.contract),
            Rseed::new(&mut rng),
            {
                let mut memo_bytes = [0; 512];
                memo_bytes[0..min(512, desc.memo.len())].copy_from_slice(&desc.memo.as_bytes()[0..min(512, desc.memo.len())]);
                memo_bytes
            }
        );

        // skip Auth token
        if n.quantity().eq(&Asset::from_string(&"0".to_string()).unwrap())
        {
            continue;
        }

        // add transfer action for this asset
        if n.symbol().raw() == 0
        {
            tx.actions.push(Action{
                account: n.contract().clone(),
                name: Name::from_string(&"transfer".to_string()).unwrap(),
                authorization: vec![user_authority.clone()],
                data: serde_json::to_value(PlsNftTransfer{
                    from: n.account(),
                    to: protocol_contract.clone(),
                    asset_ids: vec![n.quantity().clone()],
                    memo: "ZEOS transfer & mint".to_string()
                }).unwrap()
            });
        }
        else
        {
            tx.actions.push(Action{
                account: n.contract().clone(),
                name: Name::from_string(&"transfer".to_string()).unwrap(),
                authorization: vec![user_authority.clone()],
                data: serde_json::to_value(PlsFtTransfer{
                    from: n.account(),
                    to: protocol_contract.clone(),
                    quantity: n.quantity().clone(),
                    memo: "ZEOS transfer & mint".to_string()
                }).unwrap()
            });
        }

        // add mint action for this asset
        resolved_mints.push(ResolvedMintDesc{
            note: n,
            publish_note: desc.publish_note
        });
    }

    // calculate total fee amount and add transfer action to pay fee
    let fee = fees.get(&Name::from_string(&"begin".to_string()).unwrap()).unwrap().amount() + fees.get(&Name::from_string(&"mint".to_string()).unwrap()).unwrap().amount() * mint_zactions.len() as i64;
    tx.actions.push(Action{
        account: fee_token_contract.clone(),
        name: Name::from_string(&"transfer".to_string()).unwrap(),
        authorization: vec![user_authority.clone()],
        data: serde_json::to_value(PlsFtTransfer{
            from: user_authority.actor.clone(),
            to: alias_authority.actor.clone(),
            quantity: Asset::new(fee, fees.values().next().unwrap().symbol().clone()).unwrap(),
            memo: "tx fee".to_string()
        }).unwrap()
    });

    // reverse mint order, zsign mint actions and encrypt notes for receiver using a dummy spending key
    resolved_mints.reverse();
    let sk = SpendingKey::random(&mut rng);
    let mut unpublished_notes: HashMap<String, Vec<String>> = HashMap::new();
    let mut mints = vec![];
    let mut note_cts = vec![];
    for rm in resolved_mints.iter()
    {
        mints.push(PlsMint{
            cm: ScalarBytes(rm.note.commitment().to_bytes()),
            value: rm.note.amount(),
            symbol: rm.note.symbol().clone(),
            contract: rm.note.contract().clone(),
            proof: {
                let circuit_instance = Mint {
                    account: Some(rm.note.account().raw()),
                    auth_hash: Some([0; 4]),
                    value: Some(rm.note.amount()),
                    symbol: Some(rm.note.symbol().raw()),
                    contract: Some(rm.note.contract().raw()),
                    address: Some(rm.note.address()),
                    rcm: Some(rm.note.rcm()),
                    proof_generation_key: Some(sk.proof_generation_key()),
                };
                AffineProofBytesLE::from(create_random_proof(circuit_instance, mint_params, &mut rng)?)
            }
        });

        let note_ct = {
            let esk = derive_esk(&rm.note).unwrap();
            let epk = ka_derive_public(&rm.note, &esk);
            let ne = NoteEncryption::new(Some(FullViewingKey::from_spending_key(&sk).ovk), rm.note.clone());
            let encrypted_note = TransmittedNoteCiphertext {
                epk_bytes: epk.to_bytes().0,
                enc_ciphertext: ne.encrypt_note_plaintext(),
                out_ciphertext: ne.encrypt_outgoing_plaintext(&mut rng),
            };
            encrypted_note.to_base64()
        };

        if rm.publish_note
        {
            note_cts.push(note_ct);
        }
        else
        {
            let recipient = rm.note.address().to_bech32m()?;
            if unpublished_notes.contains_key(&recipient)
            {
                unpublished_notes.get_mut(&recipient).unwrap().push(note_ct.clone());
            }
            else
            {
                unpublished_notes.insert(recipient, vec![note_ct.clone()]);
            }
        }
    }

    // add mint actions as one sequence to transaction
    tx.actions.push(Action{
        account: alias_authority.actor,
        name: Name::from_string(&"mint".to_string()).unwrap(),
        authorization: vec![alias_authority.clone()],
        data: serde_json::to_value(PlsMintAction{
            actions: mints,
            note_ct: note_cts
        })?
    });

    // add end action
    tx.actions.push(Action{
        account: alias_authority.actor,
        name: Name::from_string(&"end".to_string()).unwrap(),
        authorization: vec![alias_authority.clone()],
        data: json!({})
    });

    Ok((tx, unpublished_notes))
}

#[cfg(test)]
mod tests
{
    use crate::{transaction::{ZTransaction, resolve_ztransaction, zverify_spend_transaction}, note::{Note, Rseed}, address::Address, eosio::{Asset, Authorization, ExtendedAsset}, wallet::Wallet, keys::{SpendingKey, FullViewingKey}, note_encryption::{NoteEncryption, derive_esk, ka_derive_public, TransmittedNoteCiphertext}};
    use super::{Name, insert_vars, zsign_transaction};
    use rand::rngs::OsRng;
    use bellman::groth16::Parameters;
    use bls12_381::Bls12;
    use std::fs::File;
    use std::collections::HashMap;

    #[test]
    fn test_insert_auth_into_memo()
    {
        //println!("{:?}", Name::from_string(&"mint".to_string()));
        //println!("{:?}", Name::from_string(&"spend".to_string()));
        //println!("{:?}", Name::from_string(&"authenticate".to_string()));
        //println!("{:?}", Name::from_string(&"publishnotes".to_string()));
        //println!("{:?}", Name::from_string(&"withdraw".to_string()));
        
        let mut rng = OsRng.clone();
        let memo = "AUTH:$AUTH0 This is a sample memo string with random $AUTH2 values $AUTH1 inserted into it $AUTH0$AUTH plus the default address: $SELF".to_string();
        let auth_tokens = vec![
            Note::from_parts(0, Address::dummy(&mut rng), Name(0), ExtendedAsset::new(Asset::from_string(&"0".to_string()).unwrap(), Name(9999)), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, Address::dummy(&mut rng), Name(0), ExtendedAsset::new(Asset::from_string(&"0".to_string()).unwrap(), Name(9999)), Rseed::new(&mut rng), [0; 512])
        ];
        let new_memo = insert_vars(&memo, &"<default_address>".to_string(), &auth_tokens);
        println!("{}", new_memo);

        let mut m = HashMap::new();
        m.insert(Name::from_string(&"begin".to_string()).unwrap(), Asset::from_string(&"5.0000 ZEOS".to_string()).unwrap());
        m.insert(Name::from_string(&"mint".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        println!("{}", serde_json::to_string(&m).unwrap());
    }

    #[test]
    fn test_mint_auth_publish_withdraw()
    {
        let w = Wallet::create(
            b"this is a sample seed which should be at least 32 bytes long...",
            false,
            [0; 32],
            Name::from_string(&format!("zeos4privacy")).unwrap(),
            Authorization::from_string(&format!("thezeosalias@public")).unwrap()
        ).unwrap();

        let json = r#"{
            "chain_id": "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906",
            "protocol_contract": "zeos4privacy",
            "alias_authority": "thezeosalias@public",
            "add_fee": false,
            "publish_fee_note": true,
            "zactions": [
                {
                    "name": "mint",
                    "data": {
                        "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                        "contract": "eosio.token",
                        "quantity": "10.0000 EOS",
                        "memo": "",
                        "from": "zeosexchange",
                        "publish_note": true
                    }
                },
                {
                    "name": "mint",
                    "data": {
                        "to": "$SELF",
                        "contract": "zeosexchange",
                        "quantity": "0",
                        "memo": "",
                        "from": "zeosexchange",
                        "publish_note": true
                    }
                },
                {
                    "name": "mint",
                    "data": {
                        "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                        "contract": "atomicassets",
                        "quantity": "12345678987654321",
                        "memo": "This is my address: $SELF and this was the auth token: $AUTH0",
                        "from": "zeosexchange",
                        "publish_note": true
                    }
                },
                {
                    "name": "authenticate",
                    "data": {
                        "contract": "zeosexchange",
                        "auth_token": "$AUTH0",
                        "actions": [
                            {
                                "account": "eosio.token",
                                "name": "transfer",
                                "authorization": ["zeosexchange@active"],
                                "data": "a0d8340d7585a9fae091d9ee5682a9faa08601000000000004454f53000000000474657374"
                            }
                        ],
                        "burn": true
                    }
                },
                {
                    "name": "publishnotes",
                    "data": {
                        "notes": [
                            "YWxrc2RqYWtsc2pkYWxrc2pkYWtsc2pka2xhanNkYXNzZA=="
                        ]
                    }
                },
                {
                    "name": "withdraw",
                    "data": {
                        "contract": "eosio.token",
                        "quantity": "10.0000 EOS",
                        "memo": "test memo",
                        "to": "zeosexchange"
                    }
                }
            ]
        }"#;

        let fee_token_contract = Name::from_string(&"thezeostoken".to_string()).unwrap();
        let mut fees = HashMap::new();
        fees.insert(Name::from_string(&"begin".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"mint".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"spendoutput".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"spend".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"output".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"authenticate".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"publishnotes".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"withdraw".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        println!("{}", serde_json::to_string_pretty(&fees).unwrap());

        let ztx: ZTransaction = serde_json::from_str(&json).unwrap();
        let rztx = resolve_ztransaction(&w, &fee_token_contract, &fees, &ztx);
        let rztx = match rztx {
            Err(e) => panic!("Error: {:?}", e),
            Ok(x) => x
        };
        println!("{}", serde_json::to_string_pretty(&rztx).unwrap());
    }

    #[test]
    fn test_spend()
    {
        let mut rng = OsRng.clone();
        let seed = b"this is a sample seed which should be at least 32 bytes long...";
        let fvk = FullViewingKey::from_spending_key(&SpendingKey::from_seed(seed));
        let mut w = Wallet::create(
            seed,
            false,
            [0; 32],
            Name::from_string(&format!("zeos4privacy")).unwrap(),
            Authorization::from_string(&format!("thezeosalias@public")).unwrap()
        ).unwrap();

        let notes = vec![
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"7.0000 ZEOS@thezeostoken".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"7.0000 ZEOS@thezeostoken".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"10.0000 EOS@thezeostoken".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"5.0000 EOS@thezeostoken".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"4.0000 EOS@thezeostoken".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"4.0000 EOS@thezeostoken".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"3.0000 EOS@thezeostoken".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"3.0000 EOS@thezeostoken".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"2.0000 EOS@thezeostoken".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"2.0000 EOS@thezeostoken".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"2.0000 EOS@thezeostoken".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"2.0000 EOS@thezeostoken".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"12345678987654321@atomicassets".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512])
        ];

        for n in notes.iter()
        {
            let esk = derive_esk(n).unwrap();
            let epk = ka_derive_public(n, &esk);
            let ne = NoteEncryption::new(Some(fvk.ovk), n.clone());
            let encrypted_note = TransmittedNoteCiphertext {
                epk_bytes: epk.to_bytes().0,
                enc_ciphertext: ne.encrypt_note_plaintext(),
                out_ciphertext: ne.encrypt_outgoing_plaintext(&mut rng),
            };
            w.add_leaves(&n.commitment().to_bytes());
            w.add_notes(&vec![encrypted_note.to_base64()], 0, 0);
        }

        let json = r#"{
            "chain_id": "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906",
            "protocol_contract": "zeos4privacy",
            "alias_authority": "thezeosalias@public",
            "add_fee": true,
            "publish_fee_note": true,
            "zactions": [
                {
                    "name": "spend",
                    "data": {
                        "contract": "thezeostoken",
                        "change_to": "$SELF",
                        "publish_change_note": true,
                        "to": [
                            {
                                "to": "mschoenebeck",
                                "quantity": "10.0000 EOS",
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "2.0000 EOS",
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "2.0000 EOS",
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "1.0000 EOS",
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "1.0000 EOS",
                                "memo": "",
                                "publish_note": true
                            }
                        ]
                    }
                },
                {
                    "name": "spend",
                    "data": {
                        "contract": "atomicassets",
                        "change_to": "$SELF",
                        "publish_change_note": true,
                        "to": [
                            {
                                "to": "$SELF",
                                "quantity": "12345678987654321",
                                "memo": "",
                                "publish_note": true
                            }
                        ]
                    }
                }
            ]
        }"#;

        let fee_token_contract = Name::from_string(&"thezeostoken".to_string()).unwrap();
        let mut fees = HashMap::new();
        fees.insert(Name::from_string(&"begin".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"mint".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"spendoutput".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"spend".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"output".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"authenticate".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"publishnotes".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"withdraw".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());

        let ztx: ZTransaction = serde_json::from_str(&json).unwrap();
        let rztx = resolve_ztransaction(&w, &fee_token_contract, &fees, &ztx);
        let rztx = match rztx {
            Err(e) => panic!("Error: {:?}", e),
            Ok(x) => x
        };
        //println!("{}", serde_json::to_string_pretty(&rztx).unwrap());

        println!("read params...");
        let mut params = HashMap::new();
        let f = File::open("params_mint.bin").unwrap();
        params.insert(Name::from_string(&"mint".to_string()).unwrap(), Parameters::<Bls12>::read(f, false).unwrap());
        let f = File::open("params_spendoutput.bin").unwrap();
        params.insert(Name::from_string(&"spendoutput".to_string()).unwrap(), Parameters::<Bls12>::read(f, false).unwrap());
        let f = File::open("params_spend.bin").unwrap();
        params.insert(Name::from_string(&"spend".to_string()).unwrap(), Parameters::<Bls12>::read(f, false).unwrap());
        let f = File::open("params_output.bin").unwrap();
        params.insert(Name::from_string(&"output".to_string()).unwrap(), Parameters::<Bls12>::read(f, false).unwrap());

        println!("zsign...");
        let tx = zsign_transaction(&w, &rztx, &params);
        let tx = match tx {
            Err(e) => panic!("Error: {:?}", e),
            Ok(x) => x
        };
        println!("{}", serde_json::to_string_pretty(&tx).unwrap());

        println!("zverify...");
        assert!(zverify_spend_transaction(&tx.0, &params));
    }

    use crate::transaction::Blake2s7rParams;
    use std::cmp::min;
    use crate::Symbol;
    #[test]
    fn test_hash()
    {
        let mut rng = OsRng.clone();
        let note = Note::from_parts(0, Address::dummy(&mut rng), Name(0), ExtendedAsset::new(Asset::new(0, Symbol(0)).unwrap(), Name(0)), Rseed::new(&mut rng), {
            let memo = "this is a memo string".to_string();
            let mut memo_bytes = [0; 512];
            memo_bytes[0..min(512, memo.len())].copy_from_slice(&memo.as_bytes()[0..min(512, memo.len())]);
            memo_bytes
        });
        println!("{:?}", note.memo());

        let mut state = Blake2s7rParams::new().hash_length(32).personal(&[0; 8]).to_state();
        state.update(&note.amount().to_le_bytes());
        state.update(&note.account().raw().to_le_bytes());
        state.update(&note.memo()[0..{let len = note.memo().iter().position(|&c| c == 0); if len.is_none() {512} else {len.unwrap()}}]);
        println!("{}", String::from_utf8(note.memo().to_vec()).unwrap().len());
        println!("{}", {let len = note.memo().iter().position(|&c| c == 0); if len.is_none() {512} else {len.unwrap()}});
        let hash: [u8; 32] = state.finalize().as_bytes().try_into().unwrap();
        //let hash = [u64::from_le_bytes(hash[0..8].try_into().unwrap()), u64::from_le_bytes(hash[8..16].try_into().unwrap()), u64::from_le_bytes(hash[16..24].try_into().unwrap()), u64::from_le_bytes(hash[24..32].try_into().unwrap())];
        println!("{:?}", hash);
    }

    use super::MintDesc;
    use super::zsign_transfer_and_mint_transaction;
    #[test]
    fn test_zsign_transfer_and_mint_transaction()
    {
        let json = r#"[
            {
                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                "contract": "eosio.token",
                "quantity": "10.0000 EOS",
                "memo": "EOS tokens into wallet",
                "from": "mschoenebeck",
                "publish_note": false
            },
            {
                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                "contract": "thezeostoken",
                "quantity": "100.0000 ZEOS",
                "memo": "miau miau",
                "from": "mschoenebeck",
                "publish_note": false
            },
            {
                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                "contract": "atomicassets",
                "quantity": "12345678987654321",
                "memo": "This is my address: $SELF and this was the auth token: $AUTH0",
                "from": "mschoenebeck",
                "publish_note": false
            }
        ]"#;
        let mint_zactions: Vec<MintDesc> = serde_json::from_str(json).unwrap();

        let mut fees = HashMap::new();
        fees.insert(Name::from_string(&"begin".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"mint".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());

        let f = File::open("params_mint.bin").unwrap();
        let mint_params = Parameters::<Bls12>::read(f, false).unwrap();

        let x = zsign_transfer_and_mint_transaction(
            &mint_zactions,
            &Authorization { actor: Name::from_string(&"thezeosalias".to_string()).unwrap(), permission: Name::from_string(&"public".to_string()).unwrap() },
            &Authorization { actor: Name::from_string(&"mschoenebeck".to_string()).unwrap(), permission: Name::from_string(&"active".to_string()).unwrap() },
            Name::from_string(&"zeos4privacy".to_string()).unwrap(),
            Name::from_string(&"thezeostoken".to_string()).unwrap(),
            &fees,
            &mint_params
        ).unwrap();
        println!("{}", serde_json::to_string_pretty(&x).unwrap());
    }
}