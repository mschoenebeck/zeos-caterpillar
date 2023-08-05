use bellman::groth16::{create_random_proof, Parameters};
use bls12_381::Bls12;
use chrono::DateTime;
use std::{cmp::min, collections::HashMap, fs::File};
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use serde_json::{Value, json};
use rand_core::RngCore;
use crate::{
    address::Address,
    blake2s7r::Params as Blake2s7rParams,
    circuit::{burn::Burn, transfer::Transfer, mint::Mint},
    constants::MERKLE_TREE_DEPTH,
    contract::{ScalarBytes, PlsFtTransfer, PlsNftTransfer, PlsMint, AffineProofBytes, PlsMintAction, PlsBurn, PlsBurnAction, PlsTransfer, PlsTransferAction},
    eosio::{Asset, Authorization, Name, SymbolCode, Transaction, Action, Symbol},
    keys::{IncomingViewingKey, SpendingKey, FullViewingKey, PreparedIncomingViewingKey},
    note::{Note, Rseed, nullifier::ExtractedNullifier},
    note_encryption::{derive_esk, ka_derive_public, try_note_decryption, try_output_recovery_with_ovk, NoteEncryption, TransmittedNoteCiphertext},
    log
};

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

// empty merkle tree roots
lazy_static! {
    static ref EMPTY_ROOTS: Vec<ScalarBytes> = {
        let mut v = vec![ScalarBytes(bls12_381::Scalar::one().to_bytes())];
        for d in 0..MERKLE_TREE_DEPTH
        {
            let next = Blake2s7rParams::new()
                .hash_length(32)
                .personal(crate::constants::MERKLE_TREE_PERSONALIZATION)
                .to_state()
                .update(&v[d].0)
                .update(&v[d].0)
                .finalize()
                .as_bytes()
                .try_into()
                .expect("output length is correct");
            v.push(ScalarBytes(next));
        }
        v
    };
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NoteEx
{
    block_num: u32,
    block_ts: u64,
    wallet_ts: u64,
    leaf_idx_arr: u64,
    note: Note,
}

impl NoteEx
{
    pub fn from_parts(
        block_num: u32,
        block_ts: u64,
        wallet_ts: u64,
        leaf_idx_arr: u64,
        note: Note
    ) -> Self
    {
        NoteEx{
            block_num,
            block_ts,
            wallet_ts,
            leaf_idx_arr,
            note
        }
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()>
    {
        writer.write_u32::<LittleEndian>(self.block_num)?;      // 4
        writer.write_u64::<LittleEndian>(self.block_ts)?;       // 8
        writer.write_u64::<LittleEndian>(self.wallet_ts)?;      // 8
        writer.write_u64::<LittleEndian>(self.leaf_idx_arr)?;   // 8
        self.note.write(&mut writer)?;                          // 651

        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self>
    {
        let block_num = reader.read_u32::<LittleEndian>()?;
        let block_ts = reader.read_u64::<LittleEndian>()?;
        let wallet_ts = reader.read_u64::<LittleEndian>()?;
        let leaf_idx_arr = reader.read_u64::<LittleEndian>()?;
        let note = Note::read(&mut reader)?;

        Ok(NoteEx::from_parts(block_num, block_ts, wallet_ts, leaf_idx_arr, note))
    }

    pub fn position(&self) -> u64
    {
        self.leaf_idx_arr % MT_ARR_FULL_TREE_OFFSET!(MERKLE_TREE_DEPTH) - MT_ARR_LEAF_ROW_OFFSET!(MERKLE_TREE_DEPTH)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Settings
{
    // list of EOSIO full nodes
    pub peers: Vec<String>,
    // maps symbol code (=key) to (contract code, symbol precision) tuple (=value) of known fungible token contracts
    pub ft_symbols: HashMap<SymbolCode, (Name, u8)>,
    // the NFT contract account
    pub nft_contract: Name,

    pub protocol_contract: Name,
    pub alias_authority: Authorization,
    pub fee_token_symbol: Symbol
}

impl Settings
{
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()>
    {
        writer.write_u8(self.peers.len() as u8)?;
        for p in self.peers.iter()
        {
            writer.write_u8(p.len() as u8)?;
            writer.write_all(p.as_bytes().as_ref())?;
        }

        writer.write_u8(self.ft_symbols.len() as u8)?;
        for s in self.ft_symbols.iter()
        {
            writer.write_u64::<LittleEndian>(s.0.raw())?;
            writer.write_u64::<LittleEndian>(s.1.0.raw())?;
            writer.write_u8(s.1.1)?;
        }

        writer.write_u64::<LittleEndian>(self.nft_contract.raw())?;
        writer.write_u64::<LittleEndian>(self.protocol_contract.raw())?;
        writer.write_u64::<LittleEndian>(self.alias_authority.actor.raw())?;
        writer.write_u64::<LittleEndian>(self.alias_authority.permission.raw())?;
        writer.write_u64::<LittleEndian>(self.fee_token_symbol.raw())?;

        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self>
    {
        let peers_len = reader.read_u8()?;
        let mut peers = vec![];
        for _ in 0..peers_len
        {
            let l = reader.read_u8()?;
            let mut bytes = vec![0; l as usize];
            reader.read_exact(&mut bytes)?;
            peers.push(String::from_utf8(bytes).unwrap());
        }

        let ft_symbols_len = reader.read_u8()?;
        let mut ft_symbols = HashMap::new();
        for _ in 0..ft_symbols_len
        {
            let symbol_code = SymbolCode::new(reader.read_u64::<LittleEndian>()?);
            let contract_code = Name::new(reader.read_u64::<LittleEndian>()?);
            let precision = reader.read_u8()?;
            ft_symbols.insert(symbol_code, (contract_code, precision));
        }

        let nft_contract = Name::new(reader.read_u64::<LittleEndian>()?);
        let protocol_contract = Name::new(reader.read_u64::<LittleEndian>()?);
        let alias_actor = Name::new(reader.read_u64::<LittleEndian>()?);
        let alias_permission = Name::new(reader.read_u64::<LittleEndian>()?);
        let alias_authority = Authorization{ actor: alias_actor, permission: alias_permission };
        let fee_token_symbol = Symbol::new(reader.read_u64::<LittleEndian>()?);

        Ok(Settings {
            peers,
            ft_symbols,
            nft_contract,
            protocol_contract,
            alias_authority,
            fee_token_symbol
        })
    }

    pub fn size(&self) -> usize
    {
        let mut nb = 0;
        for p in self.peers.iter()
        {
            nb += 1 + p.len();
        }

        1 +
        nb +
        1 +
        self.ft_symbols.len() * (8 + 8 + 1) +
        8 +
        8 +
        16 +
        8
    }
}

impl Default for Settings
{
    fn default() -> Self
    {
        Settings{
            peers: vec![
                "http://localhost:8888".to_string(),
                "http://api.eostitan.com".to_string()
            ],
            ft_symbols: HashMap::from([
                (SymbolCode::from_string(&"EOS".to_string()).unwrap(), (Name::from_string(&"eosio.token".to_string()).unwrap(), 4)),
                (SymbolCode::from_string(&"ZEOS".to_string()).unwrap(), (Name::from_string(&"thezeostoken".to_string()).unwrap(), 4)),
            ]),
            nft_contract: Name::from_string(&"atomicassets".to_string()).unwrap(),
            protocol_contract: Name::from_string(&"zeoscontract".to_string()).unwrap(),
            alias_authority: Authorization { actor: Name::from_string(&"thezeosproxy".to_string()).unwrap(), permission: Name::from_string(&"public".to_string()).unwrap() },
            fee_token_symbol: Symbol::from_string(&"4,ZEOS".to_string()).unwrap()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Wallet
{
    // keys & addresses
    seed: Vec<u8>,
    ivk: IncomingViewingKey, // READ-ONLY WALLET: only valid if seed == ""
    diversifiers: Vec<u64>,
    
    // contract global data
    block_num: u32,
    leaf_count: u64,

    // wallet specific settings
    settings: Settings,

    // the different note pools
    unspent_notes: Vec<NoteEx>,
    spent_notes: Vec<NoteEx>,
    outgoing_notes: Vec<NoteEx>,

    // merkle tree leaves
    merkle_tree: HashMap<u64, ScalarBytes>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct SpendAction
{
    kind: char, // either 'T' (transfer) or 'B' (burn)
    note_a: NoteEx,
    note_b: Note,
    note_c: Note,
    note_d: Note,
    account_b: Name,
    account_c: Name,
    memo_b: String,
    memo_c: String
}



// TODO: add_notes(note_ct: [String])

impl Wallet
{
    pub fn create(
        seed: &[u8],
        is_ivk: bool
    ) -> Option<Self>
    {
        if is_ivk { if seed.len() != 64 { log("ivk seed length must equal 64 bytes"); return None; } }
        else      { if seed.len() < 32  { log("seed length must equal at least 32 bytes"); return None; } }

        let ivk = if is_ivk {
            let ivk = IncomingViewingKey::from_bytes(&seed.try_into().unwrap());
            if ivk.is_none().into() { log("ivk invalid"); return None; }
            ivk.unwrap()
        } else {
            FullViewingKey::from_spending_key(&SpendingKey::from_seed(seed)).ivk()
        };

        let diversifiers = if is_ivk {
            vec![]
        } else {
            vec![u64::try_from(FullViewingKey::from_spending_key(&SpendingKey::from_seed(seed)).default_address().0).unwrap()]
        };

        Some(Wallet{
            seed: seed.to_vec(),
            ivk,
            diversifiers,
            block_num: 0,
            leaf_count: 0,
            settings: Default::default(),
            unspent_notes: vec![],
            spent_notes: vec![],
            outgoing_notes: vec![],
            merkle_tree: HashMap::new()
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()>
    {
        writer.write_u32::<LittleEndian>(self.seed.len() as u32)?;
        writer.write_all(self.seed.as_ref())?;
        writer.write_all(self.ivk.to_bytes().as_ref())?;
        writer.write_u32::<LittleEndian>(self.diversifiers.len() as u32)?;
        for d in self.diversifiers.iter()
        {
            writer.write_u64::<LittleEndian>(*d)?;
        }
        writer.write_u32::<LittleEndian>(self.block_num)?;
        writer.write_u64::<LittleEndian>(self.leaf_count)?;
        self.settings.write(&mut writer)?;
        writer.write_u32::<LittleEndian>(self.unspent_notes.len() as u32)?;
        for n in self.unspent_notes.iter()
        {
            n.write(&mut writer)?;
        }
        writer.write_u32::<LittleEndian>(self.spent_notes.len() as u32)?;
        for n in self.spent_notes.iter()
        {
            n.write(&mut writer)?;
        }
        writer.write_u32::<LittleEndian>(self.outgoing_notes.len() as u32)?;
        for n in self.outgoing_notes.iter()
        {
            n.write(&mut writer)?;
        }
        for li in 0..self.leaf_count
        {
            // calculate array index of this leaf in current tree
            let idx = MT_ARR_LEAF_ROW_OFFSET!(MERKLE_TREE_DEPTH) + li % MT_NUM_LEAVES!(MERKLE_TREE_DEPTH);
            // calculate tree offset to translate local array indices of current tree to absolute array indices of global array
            let tos = li / MT_NUM_LEAVES!(MERKLE_TREE_DEPTH) * MT_ARR_FULL_TREE_OFFSET!(MERKLE_TREE_DEPTH);
            let idx = tos + idx;
            assert!(self.merkle_tree.contains_key(&idx));
            writer.write_all(self.merkle_tree.get(&idx).unwrap().0.as_ref())?;
        }

        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self>
    {
        let seed_len = reader.read_u32::<LittleEndian>()? as usize;
        let mut seed = vec![];
        seed.resize(seed_len, 0);
        reader.read_exact(&mut seed)?;

        let mut ivk = [0; 64];
        reader.read_exact(&mut ivk)?;
        let ivk = IncomingViewingKey::from_bytes(&ivk);
        assert!(bool::from(ivk.is_some()));
        let ivk = ivk.unwrap();

        let diversifiers_len = reader.read_u32::<LittleEndian>()? as usize;
        let mut diversifiers = vec![];
        for _ in 0..diversifiers_len
        {
            let d = reader.read_u64::<LittleEndian>()?;
            diversifiers.push(d);
        }

        let block_num = reader.read_u32::<LittleEndian>()?;
        let leaf_count = reader.read_u64::<LittleEndian>()?;
        let settings = Settings::read(&mut reader)?;

        let unspent_notes_len = reader.read_u32::<LittleEndian>()? as usize;
        let mut unspent_notes = vec![];
        for _ in 0..unspent_notes_len
        {
            let n = NoteEx::read(&mut reader)?;
            unspent_notes.push(n);
        }

        let spent_notes_len = reader.read_u32::<LittleEndian>()? as usize;
        let mut spent_notes = vec![];
        for _ in 0..spent_notes_len
        {
            let n = NoteEx::read(&mut reader)?;
            spent_notes.push(n);
        }

        let outgoing_notes_len = reader.read_u32::<LittleEndian>()? as usize;
        let mut outgoing_notes = vec![];
        for _ in 0..outgoing_notes_len
        {
            let n = NoteEx::read(&mut reader)?;
            outgoing_notes.push(n);
        }

        let merkle_tree = HashMap::new();

        let mut wallet = Wallet {
            seed,
            ivk,
            diversifiers,
            block_num,
            leaf_count: 0,
            settings,
            unspent_notes,
            spent_notes,
            outgoing_notes,
            merkle_tree
        };

        for _ in 0..leaf_count
        {
            let mut leaf = [0; 32];
            reader.read_exact(&mut leaf)?;
            wallet.insert_into_merkle_tree(&ScalarBytes(leaf));
        }

        Ok(wallet)
    }

    pub fn to_json(&self, pretty: bool) -> String
    {
        if pretty { serde_json::to_string_pretty(self).unwrap() }
        else { serde_json::to_string(self).unwrap() }
    }

    pub fn from_json(json: &String) -> Result<Self, serde_json::error::Error>
    {
        serde_json::from_str(&json)
    }

    pub fn size(&self) -> usize
    {
        4 +                                 // seed.len()
        self.seed.len() +
        64 +                                // Incoming Viewing Key
        4 +                                 // diversifiers.len()
        self.diversifiers.len() * 8 +
        4 +                                 // latest block number
        8 +                                 // leaf count
        self.settings.size() +
        4 +                                 // unspent_notes.len()
        self.unspent_notes.len() * 679 +
        4 +                                 // spent_notes.len()
        self.spent_notes.len() * 679 +
        4 +                                 // outgoing_notes.len()
        self.outgoing_notes.len() * 679 +
        self.leaf_count as usize * 32       // merkle tree leaves only

        // less verbose but much heavier alternative:
        //let mut v = vec![];
        //assert!(self.write(&mut v).is_ok());
        //v.len()
    }

    pub fn block_num(&self) -> u32
    {
        self.block_num
    }

    pub fn leaf_count(&self) -> u64
    {
        self.leaf_count
    }

    pub fn settings(&self) -> &Settings
    {
        &self.settings
    }

    // desc format: <(+/- | i/o | in/out)> <asset> [<memo>]
    // examples:
    //      + 10 EOS "this is an optional memo"
    //      - 5400.5 ZEOS
    //      o 22.25 EOS
    //      in 1234567890987654321 "NFT mint memo"
    // returns:
    // bool: is asset in?
    // Asset: the actual FT or NFT
    // String: the memo which is optional and could be empty
    fn process_move_desc(&self, desc: &String) -> Option<(bool, Asset, String)>
    {
        // the minimum desc length is 3 (in case of mint/burn NFT with single digit ID: "+ 1")
        if desc.len() < 3 { log("desc invalid:"); log(&desc); return None; }

        // extract the memo first, so we can split the remaining string by spaces
        let mut desc = desc.clone();
        let memo = self.subtract_memo_str(&mut desc);
        let parts: Vec<String> = desc.split(" ").map(|s| s.to_string()).collect();

        // process "in/out" part
        let is_mint = parts[0].eq("+") || parts[0].eq("i") || parts[0].eq("in");
        if !is_mint && !(parts[0].eq("-") || parts[0].eq("o") || parts[0].eq("out"))
        { log("desc invalid [in/out part]:"); log(&parts[0]); return None; }

        // process asset part
        if parts.len() == 2 // NFT
        {
            let asset = Asset::from_string(&parts[1]);
            if asset.is_none() { return None; }
            return Some((is_mint, asset.unwrap(), memo));
        }
        if parts.len() == 3 // FT
        {
            let asset_str = parts[1].clone() + " " + &parts[2];
            let asset = self.process_asset_desc(&asset_str);
            if asset.is_none() { return None; }

            return Some((is_mint, asset.unwrap(), memo));
        }
        None
    }

    // desc format: <asset> <(account | address)> [<memo>]
    // examples:
    //      24.5 EOS mschoenebeck "this is a memo"
    //      15780 ZEOS za16ntxhkfgdw2yv3wqk3p0ceunnqq2u2txwg52du6qp84v8cq2dae2d0rhfu2k8w57zdhvw3n4u6f
    //      1234567890987654321 aliceaccount "memo for NFT transfer"
    // returns:
    // Asset: the actual FT or NFT
    // String: receiver which is either an EOS account name (<= 12 characters) or a ZEOS address (long Bech32m-encoded wallet address)
    // String: the memo which is optional and could be empty
    fn process_transfer_desc(&self, desc: &String) -> Option<(Asset, String, String)>
    {
        // the minimum desc length is 3 (in case of burn NFT with single digit ID to an EOS account with just one letter): "1 a")
        if desc.len() < 3 { log("desc invalid:"); log(&desc); return None; }

        // extract the memo first, so we can split the remaining string by spaces
        let mut desc = desc.clone();
        let memo = self.subtract_memo_str(&mut desc);
        let parts: Vec<String> = desc.split(" ").map(|s| s.to_string()).collect();

        // process asset part
        if parts.len() == 2 // NFT
        {
            let asset = Asset::from_string(&parts[0]);
            if asset.is_none() { log("desc invalid [NFT asset]:"); log(&parts[0]); return None; }
            return Some((asset.unwrap(), parts[1].clone(), memo));
        }
        if parts.len() == 3 // FT
        {
            let asset_str = parts[0].clone() + " " + &parts[1];
            let asset = self.process_asset_desc(&asset_str);
            if asset.is_none() { log("desc invalid [FT asset]:"); log(&asset_str); return None; }

            return Some((asset.unwrap(), parts[2].clone(), memo));
        }
        None
    }

    fn subtract_memo_str(&self, desc: &mut String) -> String
    {
        let mut memo = "".to_string();
        let mut memo_pos = desc.len() - 1;
        let mut pos = desc.find('"');
        if pos.is_some() { if desc.as_bytes()[desc.len()-1] as char != '"' { return memo; } }
        if pos.is_none()
        {
            pos = desc.find('\'');
            if pos.is_some() { if desc.as_bytes()[desc.len()-1] as char != '\'' { return memo; } }
        }
        if pos.is_some()
        {
            memo_pos = pos.unwrap();
            memo = desc[memo_pos+1..desc.len()-1].to_string();
            loop
            {
                // walk backwards as long as there are whitespaces
                memo_pos -= 1;
                if desc.as_bytes()[memo_pos] as char != ' ' { break; }
            }
        }
        // reduce remaining desc string to exclude memo and split it into parts by whitespaces
        *desc = desc[..=memo_pos].to_string();
        memo
    }

    fn process_asset_desc(&self, desc: &String) -> Option<Asset>
    {
        let mut parts: Vec<String> = desc.split(" ").map(|s| s.to_string()).collect();

        // process asset part
        if parts.len() == 1 // NFT
        {
            return Asset::from_string(&parts[0]);
        }
        if parts.len() == 2 // FT
        {
            let sc = SymbolCode::from_string(&parts[1]);
            if sc.is_none() { log("asset desc invalid [symbol code]:"); log(&parts[1]); return None; }
            let sc = sc.unwrap();
            let code_precision = self.settings.ft_symbols.get(&sc);
            if code_precision.is_none() { log("asset desc invalid [symbol code]:"); log(&sc.to_string()); return None; }
            let precision = code_precision.unwrap().1;

            if precision > 0
            {
                let pos = parts[0].find('.');
                let mut num_zeros_to_append;
                if pos.is_none()
                {
                    num_zeros_to_append = precision as i32;
                    parts[0].push('.');
                }
                else
                {
                    let pos = pos.unwrap();
                    let num_decimals_given = parts[0].len()-1 - pos;
                    num_zeros_to_append = precision as i32 - num_decimals_given as i32;
                }
                while num_zeros_to_append > 0
                {
                    parts[0].push('0');
                    num_zeros_to_append -= 1;
                }
                while num_zeros_to_append < 0
                {
                    parts[0].pop();
                    num_zeros_to_append += 1;
                }
            }
            let asset_str = parts[0].clone() + " " + &parts[1];
            return Asset::from_string(&asset_str);
        }
        log("asset desc invalid:");
        log(&desc);
        None
    }

    // create sequence of spend actions to perform the requested spending of assets
    fn spend_notes(
        &self,
        rng: &mut impl RngCore,
        assets_to_transfer: &mut HashMap<Symbol, Vec<(Asset, Address, String)>>,
        assets_to_burn: &mut HashMap<Symbol, Vec<(Asset, Name, String)>>,
        add_fee: bool,
        initial_fee_amount: i64
    ) -> Option<(Vec<SpendAction>, i64)>
    {
        let sk = SpendingKey::from_seed(&self.seed);
        let fvk = FullViewingKey::from_spending_key(&sk);
        let mut spend_actions = vec![];
        let mut unspent_notes = self.unspent_notes.clone();

        // insert NFT transfer actions first
        if assets_to_transfer.contains_key(&Symbol::new(0))
        {
            for (asset, address, memo) in assets_to_transfer.get(&Symbol::new(0)).unwrap()
            {
                let nft = self.find_nft(&mut unspent_notes, &asset);
                if nft.is_none() { log("note selection error [NFT transfer]:"); log(&asset.to_string()); return None; }
                let note_a = nft.unwrap();
                let nf = note_a.note.nullifier(&fvk.nk, note_a.position()).into();

                // convert memo string to bytes
                let mut memo_bytes = [0; 512];
                memo_bytes[0..min(512, memo.len())].copy_from_slice(&memo.as_bytes()[0..min(512, memo.len())]);

                let note_b = Note::from_parts(
                    0,
                    address.clone(),
                    note_a.note.asset().clone(),
                    note_a.note.code().clone(),
                    Rseed::new(rng),
                    nf,
                    memo_bytes
                );
                let note_c = Note::dummy(rng, Some(nf), Asset::new(0, Symbol::new(0)), Some(note_a.note.code().clone())).2;
                let note_d = Note::dummy(rng, Some(nf), Asset::new(0, Symbol::new(0)), Some(note_a.note.code().clone())).2;

                spend_actions.push(SpendAction {
                    kind: 'T',
                    note_a,
                    note_b,
                    note_c,
                    note_d,
                    account_b: Name::new(0),
                    account_c: Name::new(0),
                    memo_b: "".to_string(),
                    memo_c: "".to_string()
                });
            }
            assets_to_transfer.remove(&Symbol::new(0));
        }

        // insert NFT burn actions next
        if assets_to_burn.contains_key(&Symbol::new(0))
        {
            for (asset, account, memo) in assets_to_burn.get(&Symbol::new(0)).unwrap()
            {
                let nft = self.find_nft(&mut unspent_notes, &asset);
                if nft.is_none() { log("note selection error [NFT burn]:"); log(&asset.to_string()); return None; }
                let note_a = nft.unwrap();
                let nf = note_a.note.nullifier(&fvk.nk, note_a.position()).into();

                // convert memo string to bytes
                let mut memo_bytes = [0; 512];
                memo_bytes[0..min(512, memo.len())].copy_from_slice(&memo.as_bytes()[0..min(512, memo.len())]);

                let note_b = Note::from_parts(
                    1 << 63, // set burn flag
                    Address::dummy(rng),
                    note_a.note.asset().clone(),
                    note_a.note.code().clone(),
                    Rseed::new(rng),
                    nf,
                    memo_bytes
                );
                let note_c = Note::dummy(rng, Some(nf), Asset::new(0, Symbol::new(0)), Some(note_a.note.code().clone())).2;
                let note_d = Note::dummy(rng, Some(nf), Asset::new(0, Symbol::new(0)), Some(note_a.note.code().clone())).2;

                spend_actions.push(SpendAction {
                    kind: 'B',
                    note_a,
                    note_b,
                    note_c,
                    note_d,
                    account_b: account.clone(),
                    account_c: Name::new(0),
                    memo_b: memo.to_string(),
                    memo_c: "".to_string()
                });
            }
            assets_to_burn.remove(&Symbol::new(0));
        }

        // transfer & burn FTs (except fee token symbol)
        for (sym, att) in assets_to_transfer.clone()
        {
            if !sym.eq(&self.settings.fee_token_symbol)
            {
                // remove assets of this symbol from the burn hash map, to avoid double spending in the second loop
                let atb = if assets_to_burn.contains_key(&sym) { assets_to_burn.remove(&sym).unwrap() } else { vec![] };
                let seq = self.spend_notes_sym(rng, &sym, &att, &atb, false, 0);
                if seq.is_none() { log("note selection error [FT transfer/burn]:"); log(&sym.to_string()); return None; }
                spend_actions.append(&mut seq.unwrap());
            }
        }
        // burn FTs only (if there are assets to burn that were'nt in the transfer hash map)
        for (sym, atb) in assets_to_burn.clone()
        {
            if !sym.eq(&self.settings.fee_token_symbol)
            {
                let seq = self.spend_notes_sym(rng, &sym,  &vec![], &atb, false, 0);
                if seq.is_none() { log("note selection error [FT burn]:"); log(&sym.to_string()); return None; }
                spend_actions.append(&mut seq.unwrap());
            }
        }

        // calculate fee for this sequence of spend actions (excluding the notes of fee symbol to be spend)
        let fee_amount = initial_fee_amount + spend_actions.len() as i64 * 10000;

        // no assets of fee token symbol are to be 'transferred' or 'burned' => spend only transaction fee
        if add_fee && !assets_to_transfer.contains_key(&self.settings.fee_token_symbol) && !assets_to_burn.contains_key(&self.settings.fee_token_symbol)
        {
            let seq = self.spend_notes_sym(rng, &self.settings.fee_token_symbol, &vec![], &vec![], true, fee_amount);
            if seq.is_none() { log("note selection error [FT fee only]:"); log(&self.settings.fee_token_symbol.to_string()); return None; }
            spend_actions.append(&mut seq.unwrap());
        }
        // transfer & burn fee token symbol
        if assets_to_transfer.contains_key(&self.settings.fee_token_symbol)
        {
            let atb = if assets_to_burn.contains_key(&self.settings.fee_token_symbol) { assets_to_burn.remove(&self.settings.fee_token_symbol).unwrap() } else { vec![] };
            let seq = self.spend_notes_sym(rng, &self.settings.fee_token_symbol, &assets_to_transfer.get(&self.settings.fee_token_symbol).unwrap(), &atb, add_fee, fee_amount);
            if seq.is_none() { log("note selection error [FT transfer/burn fee]:"); log(&self.settings.fee_token_symbol.to_string()); return None; }
            spend_actions.append(&mut seq.unwrap());
        }
        // burn fee token symbol only (if there were no transfers of this symbol)
        if assets_to_burn.contains_key(&self.settings.fee_token_symbol)
        {
            let seq = self.spend_notes_sym(rng, &self.settings.fee_token_symbol,  &vec![], &assets_to_burn.get(&self.settings.fee_token_symbol).unwrap(), add_fee, fee_amount);
            if seq.is_none() { log("note selection error [FT burn fee]:"); log(&self.settings.fee_token_symbol.to_string()); return None; }
            spend_actions.append(&mut seq.unwrap());
        }

        // calculate final fee amount for return value
        let final_fee_amount = initial_fee_amount + spend_actions.len() as i64 * 10000;

        Some((spend_actions, final_fee_amount))
    }

    // 3-stage backtracking algorithm
    // for a particular token symbol:
    // find all subsets of unspent_notes
    // sort them by number of elements (smallest subsets first as we want to spent as few notes as possible)
    // for each subset:
    //     try all T/B permutations
    //     for each T/B permutation:
    //         try all receiver permutations (transparent and shielded separately)
    fn spend_notes_sym(
        &self,
        rng: &mut impl RngCore,
        sym: &Symbol,
        assets_to_transfer: &Vec<(Asset, Address, String)>,
        assets_to_burn: &Vec<(Asset, Name, String)>,
        add_fee: bool,
        inital_fee_amount: i64
    ) -> Option<Vec<SpendAction>>
    {
        // find all subsets of unspent notes for this particular token symbol
        let unspent_notes_sym: Vec<NoteEx> = self.unspent_notes.iter().filter(|&n| n.note.symbol().eq(&sym)).cloned().collect();
        let sets_sym = Self::subsets(&unspent_notes_sym);

        // find all recipients for this particular token symbol
        let assets_to_transfer_sym: Vec<(Asset, Address, String)> = assets_to_transfer.iter().filter(|&e| e.0.symbol().eq(&sym)).cloned().collect();
        let assets_to_burn_sym: Vec<(Asset, Name, String)> = assets_to_burn.iter().filter(|&e| e.0.symbol().eq(&sym)).cloned().collect();

        // as long as the list of sets is ordered from small sets to large sets, the first combination found is (one of) the cheapest
        for set in sets_sym
        {
            let final_fee_amount = inital_fee_amount + set.len() as i64 * 10000;

            let seq = self.find_combination(
                rng,
                &set,
                &assets_to_transfer_sym,
                &{
                    if add_fee
                    {
                        let mut atb_plus_fee = assets_to_burn_sym.clone();
                        atb_plus_fee.push((
                            Asset::new(final_fee_amount, sym.clone()).unwrap(),
                            self.settings.alias_authority.actor.clone(),
                            "tx fee".to_string()
                        ));
                        atb_plus_fee
                    }
                    else
                    {
                        assets_to_burn_sym.clone()
                    }
                }
            );

            if seq.is_some()
            {
                return seq;
            }
        }

        None
    }

    fn find_combination(
        &self,
        rng: &mut impl RngCore,
        set: &Vec<NoteEx>,
        assets_to_transfer: &Vec<(Asset, Address, String)>,
        assets_to_burn: &Vec<(Asset, Name, String)>,
    ) -> Option<Vec<SpendAction>>
    {
        // find all permutations of both recipient lists
        let mut transfer_permutations = vec![];
        let mut burn_permutations = vec![];
        Self::permutations(assets_to_transfer.len(), &mut assets_to_transfer.clone(), &mut transfer_permutations);
        Self::permutations(assets_to_burn.len(), &mut assets_to_burn.clone(), &mut burn_permutations);

        // for all possible transfer recipient permutations...
            // for all possible burn recipient permutations...
                // try all possible combinations of 'burn' and 'transfer' actions:
                // each note in 'set' can either be 'transferred' or 'burned'
                // the bit representation of 'i' is used to determine if the note at a particular bit position within the
                // set is being transferred (0) or burned (1). For example, a set of two notes (note_0, note_1) has 2^2 possible T/B combinations:
                // T T <-> (00)
                // T B <-> (01)
                // B T <-> (10)
                // B B <-> (11)

        let mut inner_loop = |tp: &Vec<(Asset, Address, String)> , bp: &Vec<(Asset, Name, String)>| {
            let base: u64 = 2;
            for i in 0..base.pow(set.len() as u32)
            {
                // clone permutations as attempts to find valid combinations might modify the recipient's values
                let seq = self.try_combination(
                    rng,
                    &set,
                    &mut tp.clone(),
                    &mut bp.clone(),
                    i
                );

                if seq.is_some()
                {
                    return seq;
                }
            }
            None
        };

        if transfer_permutations.is_empty()
        {
            for bp in burn_permutations.clone()
            {
                let seq = inner_loop(&vec![], &bp);
                if seq.is_some() { return seq; }
            }
        }
        else
        {
            if burn_permutations.is_empty()
            {
                for tp in transfer_permutations.clone()
                {
                    let seq = inner_loop(&tp, &vec![]);
                    if seq.is_some() { return seq; }
                }
            }
            else
            {
                for tp in transfer_permutations.clone()
                {
                    for bp in burn_permutations.clone()
                    {
                        let seq = inner_loop(&tp, &bp);
                        if seq.is_some() { return seq; }
                    }
                }
            }
        }

        None
    }

    fn try_combination(
        &self,
        rng: &mut impl RngCore,
        set: &Vec<NoteEx>,
        tp: &mut Vec<(Asset, Address, String)>,
        bp: &mut Vec<(Asset, Name, String)>,
        tb_bit_pattern: u64
    ) -> Option<Vec<SpendAction>>
    {
        let sk = SpendingKey::from_seed(&self.seed);
        let fvk = FullViewingKey::from_spending_key(&sk);
        let mut seq = vec![];

        // walk through all notes in the set
        for j in 0..set.len()
        {
            // the note to be spent
            let note_a = &set[j];
            let nf = note_a.note.nullifier(&fvk.nk, note_a.position()).into();

            // if the position bit of this note is set, it is being 'burned'
            if (tb_bit_pattern & (1 << j)) != 0
            {
                // Note B (burn recipient)
                let (note_b, account_b, memo_b) = {
                    // this case should actually only occur for invalid combinations
                    if bp.is_empty()
                    {
                        (
                            Note::dummy(rng, Some(nf), Asset::new(0, note_a.note.symbol().clone()), Some(note_a.note.code().clone())).2,
                            Name::new(0),
                            "".to_string()
                        )
                    }
                    else
                    {
                        // look at the next 'burn' recipient and check if note A gets fully consumed by serving him
                        assert!(note_a.note.symbol().eq(bp[0].0.symbol()));
                        if bp[0].0.amount() as u64 >= note_a.note.amount()
                        {
                            // note a gets fully consumed: subtract amount from recipient and remove from list if fully served
                            bp[0].0.sub_assign(note_a.note.asset());
                            let (_, account_b, memo_b) = if bp[0].0.amount() == 0 {
                                bp.remove(0)
                            } else {
                                bp[0].clone()
                            };

                            // convert memo string to bytes
                            let mut memo_bytes = [0; 512];
                            memo_bytes[0..min(512, memo_b.len())].copy_from_slice(&memo_b.as_bytes()[0..min(512, memo_b.len())]);

                            (
                                Note::from_parts(
                                    1 << 63, // set burn flag
                                    Address::dummy(rng),
                                    note_a.note.asset().clone(),
                                    note_a.note.code().clone(),
                                    Rseed::new(rng),
                                    nf,
                                    memo_bytes
                                ),
                                account_b,
                                memo_b
                            )
                        }
                        // note_a fully consumes this recipient
                        else
                        {
                            let (asset_b, account_b, memo_b) = bp.remove(0);

                            // convert memo string to bytes
                            let mut memo_bytes = [0; 512];
                            memo_bytes[0..min(512, memo_b.len())].copy_from_slice(&memo_b.as_bytes()[0..min(512, memo_b.len())]);

                            (
                                Note::from_parts(
                                    1 << 63, // set burn flag
                                    Address::dummy(rng),
                                    asset_b,
                                    note_a.note.code().clone(),
                                    Rseed::new(rng),
                                    nf,
                                    memo_bytes
                                ),
                                account_b,
                                memo_b
                            )
                        }
                    }
                };

                // Note C (burn recipient)
                let (note_c, account_c, memo_c) = {
                    // in case note A is fully consumed OR
                    // in case there is no further recipient
                    if bp.is_empty() || 0 == (note_a.note.amount() - note_b.amount())
                    {
                        (
                            Note::dummy(rng, Some(nf), Asset::new(0, note_a.note.symbol().clone()), Some(note_a.note.code().clone())).2,
                            Name::new(0),
                            "".to_string()
                        )
                    }
                    else
                    {
                        // look at the next 'burn' recipient and check if note A gets fully consumed by serving him
                        assert!(note_a.note.symbol().eq(bp[0].0.symbol()));
                        if bp[0].0.amount() as u64 >= (note_a.note.amount() - note_b.amount())
                        {
                            // note a gets fully consumed: subtract note a leftover (amount A - amount B) from recipient and remove from list if fully served
                            bp[0].0.sub_assign(&note_a.note.asset().sub(&note_b.asset()));
                            let (_, account_c, memo_c) = if bp[0].0.amount() == 0 {
                                bp.remove(0)
                            } else {
                                bp[0].clone()
                            };

                            // convert memo string to bytes
                            let mut memo_bytes = [0; 512];
                            memo_bytes[0..min(512, memo_c.len())].copy_from_slice(&memo_c.as_bytes()[0..min(512, memo_c.len())]);

                            (
                                Note::from_parts(
                                    1 << 63, // set burn flag
                                    Address::dummy(rng),
                                    note_a.note.asset().sub(note_b.asset()),
                                    note_a.note.code().clone(),
                                    Rseed::new(rng),
                                    nf,
                                    memo_bytes
                                ),
                                account_c,
                                memo_c
                            )
                        }
                        // note_a fully consumes this recipient
                        else
                        {
                            let (asset_c, account_c, memo_c) = bp.remove(0);

                            // convert memo string to bytes
                            let mut memo_bytes = [0; 512];
                            memo_bytes[0..min(512, memo_c.len())].copy_from_slice(&memo_c.as_bytes()[0..min(512, memo_c.len())]);

                            (
                                Note::from_parts(
                                    1 << 63, // set burn flag
                                    Address::dummy(rng),
                                    asset_c,
                                    note_a.note.code().clone(),
                                    Rseed::new(rng),
                                    nf,
                                    memo_bytes
                                ),
                                account_c,
                                memo_c
                            )
                        }
                    }
                };

                // Note D (transfer recipient)
                let note_d = {
                    // in case note A is fully consumed OR
                    // in case there is no further recipient
                    if tp.is_empty() || 0 == (note_a.note.amount() - note_b.amount() - note_c.amount())
                    {
                        // send leftover back into our wallet
                        if (note_a.note.amount() - note_b.amount() - note_c.amount()) > 0
                        {
                            Note::from_parts(
                                0,
                                note_a.note.address(),
                                note_a.note.asset().sub(&note_b.asset().add(&note_c.asset())),
                                note_a.note.code().clone(),
                                Rseed::new(rng),
                                nf,
                                [0; 512]
                            )
                        }
                        // leftover equals zero
                        else
                        {
                            Note::dummy(rng, Some(nf), Asset::new(0, note_a.note.symbol().clone()), Some(note_a.note.code().clone())).2
                        }
                    }
                    else
                    {
                        // only if the leftover of note A is smaller or equal than what goes to the next recipient we're gonna send it
                        // otherwise it goes back into our own wallet (because we cannot split the UTXO further and thus couldn't handle the change)
                        if (note_a.note.amount() - note_b.amount() - note_c.amount()) <= tp[0].0.amount() as u64
                        {
                            assert!(note_a.note.symbol().eq(tp[0].0.symbol()));

                            tp[0].0.sub_assign(&note_a.note.asset().sub(&note_b.asset().add(&note_c.asset())));
                            let (_, address_d, memo_d) = if tp[0].0.amount() == 0 {
                                tp.remove(0)
                            } else {
                                tp[0].clone()
                            };

                            // convert memo string to bytes
                            let mut memo_bytes = [0; 512];
                            memo_bytes[0..min(512, memo_d.len())].copy_from_slice(&memo_d.as_bytes()[0..min(512, memo_d.len())]);

                            Note::from_parts(
                                0,
                                address_d,
                                note_a.note.asset().sub(&note_b.asset().add(&note_c.asset())),
                                note_a.note.code().clone(),
                                Rseed::new(rng),
                                nf,
                                memo_bytes
                            )
                        }
                        // send leftover back into our wallet (as change)
                        else
                        {
                            Note::from_parts(
                                0,
                                note_a.note.address(),
                                note_a.note.asset().sub(&note_b.asset().add(&note_c.asset())),
                                note_a.note.code().clone(),
                                Rseed::new(rng),
                                nf,
                                [0; 512]
                            )
                        }
                    }
                };

                seq.push(SpendAction {
                    kind: 'B',
                    note_a: note_a.clone(),
                    note_b,
                    note_c,
                    note_d,
                    account_b,
                    account_c,
                    memo_b,
                    memo_c
                });
            }
            // if the position bit of this note is not set, it is being 'transferred'
            else
            {
                // Note B
                let note_b = {
                    // this case should actually only occur for invalid combinations
                    if tp.is_empty()
                    {
                        Note::dummy(rng, Some(nf), Asset::new(0, note_a.note.symbol().clone()), Some(note_a.note.code().clone())).2
                    }
                    else
                    {
                        // look at the next 'transfer' recipient and check if note A gets fully consumed by serving him
                        assert!(note_a.note.symbol().eq(tp[0].0.symbol()));
                        if tp[0].0.amount() as u64 >= note_a.note.amount()
                        {
                            // note A gets fully consumed: subtract amount from recipient and remove from list if fully served
                            tp[0].0.sub_assign(note_a.note.asset());
                            let (_, address_b, memo_b) = if tp[0].0.amount() == 0 {
                                tp.remove(0)
                            } else {
                                tp[0].clone()
                            };

                            // convert memo string to bytes
                            let mut memo_bytes = [0; 512];
                            memo_bytes[0..min(512, memo_b.len())].copy_from_slice(&memo_b.as_bytes()[0..min(512, memo_b.len())]);

                            Note::from_parts(
                                0,
                                address_b,
                                note_a.note.asset().clone(),
                                note_a.note.code().clone(),
                                Rseed::new(rng),
                                nf,
                                memo_bytes
                            )
                        }
                        // note A fully consumes this recipient
                        else
                        {
                            let (asset_b, address_b, memo_b) = tp.remove(0);

                            // convert memo string to bytes
                            let mut memo_bytes = [0; 512];
                            memo_bytes[0..min(512, memo_b.len())].copy_from_slice(&memo_b.as_bytes()[0..min(512, memo_b.len())]);

                            Note::from_parts(
                                0,
                                address_b,
                                asset_b,
                                note_a.note.code().clone(),
                                Rseed::new(rng),
                                nf,
                                memo_bytes
                            )
                        }
                    }
                };

                // Note C
                let note_c = {
                    // in case note A is fully consumed OR
                    // in case there is no further recipient
                    if tp.is_empty() || 0 == (note_a.note.amount() - note_b.amount())
                    {
                        // send leftover back into our wallet
                        if (note_a.note.amount() - note_b.amount()) > 0
                        {
                            Note::from_parts(
                                0,
                                note_a.note.address(),
                                note_a.note.asset().sub(&note_b.asset()),
                                note_a.note.code().clone(),
                                Rseed::new(rng),
                                nf,
                                [0; 512]
                            )
                        }
                        // leftover equals zero
                        else
                        {
                            Note::dummy(rng, Some(nf), Asset::new(0, note_a.note.symbol().clone()), Some(note_a.note.code().clone())).2
                        }
                    }
                    else
                    {
                        // only if the leftover of note A is smaller or equal than what goes to the next recipient we're gonna send it
                        // otherwise it goes back into our own wallet, since we cannot split the UTXO further
                        if (note_a.note.amount() - note_b.amount()) <= tp[0].0.amount() as u64
                        {
                            assert!(note_a.note.symbol().eq(tp[0].0.symbol()));

                            tp[0].0.sub_assign(&note_a.note.asset().sub(&note_b.asset()));
                            let (_, address_c, memo_c) = if tp[0].0.amount() == 0 {
                                tp.remove(0)
                            } else {
                                tp[0].clone()
                            };

                            // convert memo string to bytes
                            let mut memo_bytes = [0; 512];
                            memo_bytes[0..min(512, memo_c.len())].copy_from_slice(&memo_c.as_bytes()[0..min(512, memo_c.len())]);

                            Note::from_parts(
                                0,
                                address_c,
                                note_a.note.asset().sub(&note_b.asset()),
                                note_a.note.code().clone(),
                                Rseed::new(rng),
                                nf,
                                memo_bytes
                            )
                        }
                        // send leftover back into our wallet (as change)
                        else
                        {
                            Note::from_parts(
                                0,
                                note_a.note.address(),
                                note_a.note.asset().sub(&note_b.asset()),
                                note_a.note.code().clone(),
                                Rseed::new(rng),
                                nf,
                                [0; 512]
                            )
                        }
                    }
                };

                seq.push(SpendAction {
                    kind: 'T',
                    note_a: note_a.clone(),
                    note_b,
                    note_c,
                    note_d: Note::dummy(rng, Some(nf), Asset::new(0, note_a.note.symbol().clone()), Some(note_a.note.code().clone())).2,
                    account_b: Name::new(0),
                    account_c: Name::new(0),
                    memo_b: "".to_string(),
                    memo_c: "".to_string()
                });
            }
        }

        // if and only if both recipient lists are empty (i.e. all of them have successfully been served) the sequence
        // of actions can be considered valid
        if tp.len() == 0 && bp.len() == 0
        {
            return Some(seq);
        }

        None
    }

    // borrowed from: https://www.educative.io/answers/how-to-find-nonidentical-subsets-of-the-given-input
    fn subsets<T: Clone>(notes: &Vec<T>) -> Vec<Vec<T>>
    {
        let n = notes.len();
        let pow_size = 1 << n;
        let mut res = vec![];

        // start counter at one in order to skip the first, empty set
        for counter in 1..pow_size
        {
            let mut set = vec![];
            for j in 0..n
            {
                if (counter & (1 << j)) != 0
                {
                    set.push(notes[j].clone())
                }
            }
            res.push(set);
        }

        res.sort_by(|a, b| a.len().cmp(&b.len()));
        res
    }

    // heap's permutations, borrowed from: https://gist.github.com/RichardJohnn/8e6af62e7272cf39e8b6#file-heapsalgorithmforpermutationgeneration-rs
    fn permutations<T: Clone>(n: usize, a: &mut Vec<T>, out: &mut Vec<Vec<T>>)
    {
        if n == 0
        {
            return;
        }
        if n == 1
        {
            out.push(a.clone());
        }
        else
        {
            for i in  0 .. n - 1
            {
                Self::permutations(n - 1, a, out);
                if n % 2 == 0
                {
                    a.swap(i, n - 1);
                }
                else
                {
                    a.swap(0, n - 1);
                }
            }
            Self::permutations(n - 1, a, out);
        }
    }

    pub fn move_asset(
        &self,
        rng: &mut impl RngCore,
        authorization: String,
        descs: Vec<String>
    ) -> Option<Transaction>
    {
        // read params files for zk-snark creation
        // TODO: params file names should be set under settings or something..
        let f = File::open("params_mint.bin").unwrap();
        let mint_params = Parameters::<Bls12>::read(f, false).unwrap();
        let f = File::open("params_burn.bin").unwrap();
        let burn_params = Parameters::<Bls12>::read(f, false).unwrap();

        let auth = Authorization::from_string(&authorization);
        if auth.is_none() { log("authorization string invalid:"); log(&authorization); return None; }
        let auth = auth.unwrap();

        let mut fts_to_mint = vec![];
        let mut nfts_to_mint = vec![];
        let mut fts_to_burn = vec![];
        let mut nfts_to_burn = vec![];

        // process action descriptors
        for desc in descs
        {
            let processed_desc = self.process_move_desc(&desc);
            if processed_desc.is_none() { log("move desc invalid:"); log(&desc); return None; }
            let (is_mint, asset, memo) = processed_desc.unwrap();

            if is_mint
            {
                if asset.is_nft()
                {
                    nfts_to_mint.push((asset, memo));
                }
                else
                {
                    if asset.amount() <= 0 { log("move desc invalid [asset amount]:"); log(&asset.to_string()); return None; }
                    fts_to_mint.push((asset, memo));
                }
            }
            else
            {
                if asset.is_nft()
                {
                    nfts_to_burn.push((asset, memo));
                }
                else
                {
                    if asset.amount() <= 0 { log("move desc invalid [asset amount]:"); log(&asset.to_string()); return None; }
                    fts_to_burn.push((asset, memo));
                }
            }
        }

        // process MINT actions
        let sk = SpendingKey::from_seed(&self.seed);
        let fvk = FullViewingKey::from_spending_key(&sk);
        let mut transaction = Transaction{ actions: vec![] };
        let mut notes_to_mint = vec![];
        let mut pls_mint_vec = vec![];

        // process fungible tokens to mint
        for (asset, memo) in fts_to_mint
        {
            let scp = self.settings.ft_symbols.get(&asset.symbol().code());
            if scp.is_none() { return  None; }
            let scp = scp.unwrap();

            // add transfer action for this asset to the transaction
            transaction.actions.push(Action{
                account: scp.0.clone(),
                name: Name::from_string(&"transfer".to_string()).unwrap(),
                authorization: vec![auth.clone()],
                data: PlsFtTransfer{
                    from: auth.actor.clone(),
                    to: self.settings.protocol_contract.clone(),
                    quantity: asset.clone(),
                    memo: "ZEOS MINT".to_string()
                }.into()
            });

            // convert memo string to bytes
            let mut memo_bytes = [0; 512];
            memo_bytes[0..min(512, memo.len())].copy_from_slice(&memo.as_bytes()[0..min(512, memo.len())]);

            // create note
            let note = Note::from_parts(
                0,
                fvk.default_address().1,
                asset,
                scp.0.clone(),
                Rseed::new(rng),
                ExtractedNullifier(bls12_381::Scalar::one()),
                memo_bytes
            );

            // create proof
            let circuit_instance = Mint {
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
                code: scp.0.clone(),
                proof: AffineProofBytes::from(proof)
            }];
            stack.append(&mut pls_mint_vec);
            pls_mint_vec = stack;

            notes_to_mint.push(note);
        }

        // process non-fungible tokens to mint
        for (asset, memo) in &nfts_to_mint
        {
            // convert memo string to bytes
            let mut memo_bytes = [0; 512];
            memo_bytes[0..min(512, memo.len())].copy_from_slice(&memo.as_bytes()[0..min(512, memo.len())]);

            // create note
            let note = Note::from_parts(
                0,
                fvk.default_address().1,
                asset.clone(),
                self.settings.nft_contract.clone(),
                Rseed::new(rng),
                ExtractedNullifier(bls12_381::Scalar::one()),
                memo_bytes
            );

            // create proof
            let circuit_instance = Mint {
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
                code: self.settings.nft_contract.clone(),
                proof: AffineProofBytes::from(proof)
            }];
            stack.append(&mut pls_mint_vec);
            pls_mint_vec = stack;

            notes_to_mint.push(note);
        }

        if !nfts_to_mint.is_empty()
        {
            // add transfer action for all NFT assets to the transaction
            let (nfts, _): (Vec<_>, Vec<_>) = nfts_to_mint.into_iter().unzip();
            transaction.actions.push(Action{
                account: self.settings.nft_contract.clone(),
                name: Name::from_string(&"transfer".to_string()).unwrap(),
                authorization: vec![auth.clone()],
                data: PlsNftTransfer{
                    from: auth.actor.clone(),
                    to: self.settings.protocol_contract.clone(),
                    asset_ids: nfts,
                    memo: "ZEOS MINT".to_string()
                }.into()
            });
        }

        let mut note_ct_mint = vec![];

        // encrypt notes to mint
        for note in notes_to_mint
        {
            let esk = derive_esk(&note).unwrap();
            let epk = ka_derive_public(&note, &esk);
            let ne = NoteEncryption::new(Some(fvk.ovk), note.clone());
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
                account: self.settings.protocol_contract.clone(),
                name: Name::from_string(&format!("mint")).unwrap(),
                authorization: vec![auth.clone()],
                data: PlsMintAction{
                    actions: pls_mint_vec,
                    note_ct: note_ct_mint
                }.into()
            });
        }

        // process BURN actions
        let mut unspent_notes = self.unspent_notes.clone();
        let mut notes_to_mint = vec![];
        let mut pls_burn_vec = vec![];

        // process fungible tokens to burn
        for (asset, memo) in fts_to_burn
        {
            let note_selection = self.select_notes(&mut unspent_notes, &asset);
            if note_selection.is_none() { log("note selection error [FT burn]:"); log(&asset.to_string()); return None; }
            let (notes_to_spend, change) = note_selection.unwrap();

            for i in 0..notes_to_spend.len()
            {
                let nf = notes_to_spend[i].note.nullifier(&fvk.nk, notes_to_spend[i].position()).into();
                let note_b = Note::from_parts(
                    1 << 63, // set burn flag
                    Address::dummy(rng),
                    Asset::new(
                        if i == notes_to_spend.len()-1 {
                            notes_to_spend[i].note.amount() - change
                        } else {
                            notes_to_spend[i].note.amount()
                        } as i64,
                        notes_to_spend[i].note.symbol().clone()
                    ).unwrap(),
                    notes_to_spend[i].note.code().clone(),
                    Rseed::new(rng),
                    nf,
                    [0; 512]
                );
                let note_d = Note::from_parts(
                    0,
                    if i == notes_to_spend.len()-1 && change > 0 {
                        notes_to_spend[i].note.address()
                    } else {
                        Address::dummy(rng) // send the zero notes to dummy addresses
                    },
                    Asset::new(
                        if i == notes_to_spend.len()-1 {
                            change
                        } else {
                            0
                        } as i64,
                        notes_to_spend[i].note.symbol().clone()
                    ).unwrap(),
                    notes_to_spend[i].note.code().clone(),
                    Rseed::new(rng),
                    nf,
                    [0; 512]
                );

                // create proof
                let (sister_path, root) = self.get_sister_path_and_root(&notes_to_spend[i]).unwrap();
                let circuit_instance = Burn {
                    note_a: Some(notes_to_spend[i].note.clone()),
                    proof_generation_key: Some(sk.proof_generation_key()),
                    auth_path: sister_path,
                    value_b: Some(note_b.amount()),
                    account_b: Some(auth.actor.raw()),
                    value_c: Some(0),
                    account_c: Some(0),
                    value_d: Some(note_d.amount()),
                    address_d: Some(note_d.address()),
                    rcm_d: Some(note_d.rcm()),
                };
                let proof = create_random_proof(circuit_instance, &burn_params, rng).unwrap();

                pls_burn_vec.push(PlsBurn{
                    root,
                    nf: ScalarBytes(nf.to_bytes()),
                    cm_d: ScalarBytes(note_d.commitment().to_bytes()),
                    value_b: note_b.amount(),
                    symbol: note_b.symbol().clone(),
                    code: note_b.code().clone(),
                    account_b: auth.actor.clone(),
                    memo_b: memo.clone(),
                    amount_c: 0,
                    account_c: Name::new(0),
                    memo_c: "".to_string(),
                    proof: AffineProofBytes::from(proof)
                });

                notes_to_mint.push(note_b);
                notes_to_mint.push(note_d);
            }
        }

        // process non-fungible tokens to burn
        for (asset, memo) in nfts_to_burn
        {
            let note_selection = self.select_notes(&mut unspent_notes, &asset);
            if note_selection.is_none() { log("note selection error [NFT burn]:"); log(&asset.to_string()); return None; }
            let (notes_to_spend, _) = note_selection.unwrap();
            assert!(notes_to_spend.len() == 1); // there can only be one NFT of it's type
            let note_a = &notes_to_spend[0];

            let nf = note_a.note.nullifier(&fvk.nk, note_a.position()).into();
            let note_b = Note::from_parts(
                1 << 63, // set burn flag
                Address::dummy(rng),
                note_a.note.asset().clone(),
                note_a.note.code().clone(),
                Rseed::new(rng),
                nf,
                [0; 512]
            );
            let note_d = Note::dummy(rng, Some(nf), Asset::new(0, Symbol::new(0)), Some(note_a.note.code().clone())).2;

            // create proof
            let (sister_path, root) = self.get_sister_path_and_root(&note_a).unwrap();
            let circuit_instance = Burn {
                note_a: Some(note_a.note.clone()),
                proof_generation_key: Some(sk.proof_generation_key()),
                auth_path: sister_path,
                value_b: Some(note_b.amount()),
                account_b: Some(auth.actor.raw()),
                value_c: Some(0),
                account_c: Some(0),
                value_d: Some(note_d.amount()),
                address_d: Some(note_d.address()),
                rcm_d: Some(note_d.rcm()),
            };
            let proof = create_random_proof(circuit_instance, &burn_params, rng).unwrap();

            pls_burn_vec.push(PlsBurn{
                root,
                nf: ScalarBytes(nf.to_bytes()),
                cm_d: ScalarBytes(note_d.commitment().to_bytes()),
                value_b: note_b.amount(),
                symbol: note_b.symbol().clone(),
                code: note_b.code().clone(),
                account_b: auth.actor.clone(),
                memo_b: memo.clone(),
                amount_c: 0,
                account_c: Name::new(0),
                memo_c: "".to_string(),
                proof: AffineProofBytes::from(proof)
            });

            notes_to_mint.push(note_b);
        }

        let mut note_ct_burn = vec![];

        // encrypt notes to mint
        for note in notes_to_mint
        {
            let esk = derive_esk(&note).unwrap();
            let epk = ka_derive_public(&note, &esk);
            let ne = NoteEncryption::new(Some(fvk.ovk), note.clone());
            let encrypted_note = TransmittedNoteCiphertext {
                epk_bytes: epk.to_bytes().0,
                enc_ciphertext: ne.encrypt_note_plaintext(),
                out_ciphertext: ne.encrypt_outgoing_plaintext(rng),
            };
            note_ct_burn.push(encrypted_note.to_base64());
        }

        // add 'burn' action
        if !pls_burn_vec.is_empty()
        {
            transaction.actions.push(Action {
                account: self.settings.protocol_contract.clone(),
                name: Name::from_string(&format!("burn")).unwrap(),
                authorization: vec![auth.clone()],
                data: PlsBurnAction{
                    actions: pls_burn_vec,
                    note_ct: note_ct_burn
                }.into()
            });
        }

        Some(transaction)
    }

    pub fn transfer_asset(
        &self,
        rng: &mut impl RngCore,
        descs: Vec<String>
    ) -> Option<Transaction>
    {
        // read params files for zk-snark creation
        // TODO: params file names should be set under settings or something..
        let f = File::open("params_transfer.bin").unwrap();
        let transfer_params = Parameters::<Bls12>::read(f, false).unwrap();
        let f = File::open("params_burn.bin").unwrap();
        let burn_params = Parameters::<Bls12>::read(f, false).unwrap();

        let mut assets_to_transfer: HashMap<Symbol, Vec<(Asset, Address, String)>> = HashMap::new();
        let mut assets_to_burn: HashMap<Symbol, Vec<(Asset, Name, String)>> = HashMap::new();

        // process action descriptors
        for desc in descs
        {
            let processed_desc = self.process_transfer_desc(&desc);
            if processed_desc.is_none() { log("transfer desc invalid:"); log(&desc); return None; }
            let (asset, receiver, memo) = processed_desc.unwrap();

            // determine trasfer/burn by receiver string:
            // if parsable to eosio::Name it is a burn action and
            // if parsable to zeos Address it is a transfer action
            let address = Address::from_bech32m(&receiver);
            let account = Name::from_string(&receiver);

            if address.is_some()
            {
                assert!(account.is_none());
                if !asset.is_nft() && asset.amount() <= 0 { log("transfer desc invalid [asset amount]:"); log(&asset.to_string()); return None; }
                if assets_to_transfer.contains_key(asset.symbol())
                {
                    assets_to_transfer.get_mut(asset.symbol()).unwrap().push((asset.clone(), address.clone().unwrap(), memo.clone()));
                }
                else
                {
                    assets_to_transfer.insert(asset.symbol().clone(), vec![(asset.clone(), address.clone().unwrap(), memo.clone())]);
                }
            }
            if account.is_some()
            {
                assert!(address.is_none());
                if !asset.is_nft() && asset.amount() <= 0 { log("transfer desc invalid [asset amount]:"); log(&asset.to_string()); return None; }
                if assets_to_burn.contains_key(asset.symbol())
                {
                    assets_to_burn.get_mut(asset.symbol()).unwrap().push((asset.clone(), account.clone().unwrap(), memo.clone()));
                }
                else
                {
                    assets_to_burn.insert(asset.symbol().clone(), vec![(asset.clone(), account.clone().unwrap(), memo.clone())]);
                }
            }
            if address.is_none() && account.is_none() { log("transfer desc invalid [address/account]:"); log(&receiver); return None; } // must be either one or the other
        }

        let spend_actions = self.spend_notes(rng, &mut assets_to_transfer, &mut assets_to_burn, true, 50000);
        if spend_actions.is_none() { log("requested transaction impossible"); return None; }
        let (spend_actions, _) = spend_actions.unwrap();
        //println!("{:?}", spend_actions);

        let sk = SpendingKey::from_seed(&self.seed);
        let fvk = FullViewingKey::from_spending_key(&sk);
        let mut transfer_notes_to_mint = vec![];
        let mut burn_notes_to_mint = vec![];
        let mut pls_transfer_vec = vec![];
        let mut pls_burn_vec = vec![];

        for sa in spend_actions
        {
            if 'T' == sa.kind
            {
                // create proof
                let (sister_path, root) = self.get_sister_path_and_root(&sa.note_a).unwrap();
                let circuit_instance = Transfer {
                    note_a: Some(sa.note_a.note.clone()),
                    proof_generation_key: Some(sk.proof_generation_key()),
                    auth_path: sister_path,
                    value_b: Some(sa.note_b.amount()),
                    address_b: Some(sa.note_b.address()),
                    rcm_b: Some(sa.note_b.rcm()),
                    value_c: Some(sa.note_c.amount()),
                    address_c: Some(sa.note_c.address()),
                    rcm_c: Some(sa.note_c.rcm()),
                };
                let proof = create_random_proof(circuit_instance, &transfer_params, rng).unwrap();
                let nf: ExtractedNullifier = sa.note_a.note.nullifier(&fvk.nk, sa.note_a.position()).into();

                pls_transfer_vec.push(PlsTransfer{
                    root,
                    nf: ScalarBytes(nf.to_bytes()),
                    cm_b: ScalarBytes(sa.note_b.commitment().to_bytes()),
                    cm_c: ScalarBytes(sa.note_c.commitment().to_bytes()),
                    proof: AffineProofBytes::from(proof)
                });

                transfer_notes_to_mint.push(sa.note_b);
                transfer_notes_to_mint.push(sa.note_c);
            }
            else if 'B' == sa.kind
            {
                // create proof
                let (sister_path, root) = self.get_sister_path_and_root(&sa.note_a).unwrap();
                let circuit_instance = Burn {
                    note_a: Some(sa.note_a.note.clone()),
                    proof_generation_key: Some(sk.proof_generation_key()),
                    auth_path: sister_path,
                    value_b: Some(sa.note_b.amount()),
                    account_b: Some(sa.account_b.raw()),
                    value_c: Some(sa.note_c.amount()),
                    account_c: Some(sa.account_c.raw()),
                    value_d: Some(sa.note_d.amount()),
                    address_d: Some(sa.note_d.address()),
                    rcm_d: Some(sa.note_d.rcm()),
                };
                let proof = create_random_proof(circuit_instance, &burn_params, rng).unwrap();
                let nf: ExtractedNullifier = sa.note_a.note.nullifier(&fvk.nk, sa.note_a.position()).into();

                pls_burn_vec.push(PlsBurn{
                    root,
                    nf: ScalarBytes(nf.to_bytes()),
                    cm_d: ScalarBytes(sa.note_d.commitment().to_bytes()),
                    value_b: sa.note_b.amount(),
                    symbol: sa.note_b.symbol().clone(),
                    code: sa.note_b.code().clone(),
                    account_b: sa.account_b.clone(),
                    memo_b: sa.memo_b.clone(),
                    amount_c: sa.note_c.amount(),
                    account_c: sa.account_c.clone(),
                    memo_c: sa.memo_c.clone(),
                    proof: AffineProofBytes::from(proof)
                });

                burn_notes_to_mint.push(sa.note_b);
                burn_notes_to_mint.push(sa.note_c);
                burn_notes_to_mint.push(sa.note_d);
            }
        }

        let mut note_ct_transfer = vec![];
        let mut note_ct_burn = vec![];
        let mut transaction = Transaction{ actions: vec![] };

        // add 'begin' action
        transaction.actions.push(Action {
            account: self.settings.alias_authority.actor.clone(),
            name: Name::from_string(&format!("begin")).unwrap(),
            authorization: vec![self.settings.alias_authority.clone()],
            data: json!({})
        });

        // encrypt transfer notes to mint
        for note in transfer_notes_to_mint
        {
            let esk = derive_esk(&note).unwrap();
            let epk = ka_derive_public(&note, &esk);
            let ne = NoteEncryption::new(Some(fvk.ovk), note.clone());
            let encrypted_note = TransmittedNoteCiphertext {
                epk_bytes: epk.to_bytes().0,
                enc_ciphertext: ne.encrypt_note_plaintext(),
                out_ciphertext: ne.encrypt_outgoing_plaintext(rng),
            };
            note_ct_transfer.push(encrypted_note.to_base64());
        }

        // add 'transfer' action
        if !pls_transfer_vec.is_empty()
        {
            transaction.actions.push(Action {
                account: self.settings.alias_authority.actor.clone(),
                name: Name::from_string(&format!("transfer")).unwrap(),
                authorization: vec![self.settings.alias_authority.clone()],
                data: PlsTransferAction{
                    actions: pls_transfer_vec,
                    note_ct: note_ct_transfer
                }.into()
            });
        }

        // encrypt burn notes to mint
        for note in burn_notes_to_mint
        {
            let esk = derive_esk(&note).unwrap();
            let epk = ka_derive_public(&note, &esk);
            let ne = NoteEncryption::new(Some(fvk.ovk), note.clone());
            let encrypted_note = TransmittedNoteCiphertext {
                epk_bytes: epk.to_bytes().0,
                enc_ciphertext: ne.encrypt_note_plaintext(),
                out_ciphertext: ne.encrypt_outgoing_plaintext(rng),
            };
            note_ct_burn.push(encrypted_note.to_base64());
        }

        // add 'burn' action
        if !pls_burn_vec.is_empty()
        {
            transaction.actions.push(Action {
                account: self.settings.alias_authority.actor.clone(),
                name: Name::from_string(&format!("burn")).unwrap(),
                authorization: vec![self.settings.alias_authority.clone()],
                data: PlsBurnAction{
                    actions: pls_burn_vec,
                    note_ct: note_ct_burn
                }.into()
            });
        }

        // add 'end' action
        transaction.actions.push(Action {
            account: self.settings.alias_authority.actor.clone(),
            name: Name::from_string(&format!("end")).unwrap(),
            authorization: vec![self.settings.alias_authority.clone()],
            data: json!({})
        });

        Some(transaction)
    }

    pub fn balances(&self) -> Vec<Asset>
    {
        let mut map = HashMap::new();
        for note in &self.unspent_notes
        {
            if !note.note.asset().is_nft()
            {
                if !map.contains_key(&note.note.symbol().raw())
                {
                    map.insert(note.note.symbol().raw(), note.note.amount());
                }
                else
                {
                    *map.get_mut(&note.note.symbol().raw()).unwrap() += note.note.amount();
                }
            }
        }
        let mut v = vec![];
        for k in map.keys()
        {
            v.push(Asset::new(
                *map.get(k).unwrap() as i64,
                Symbol::new(*k)
            ).unwrap())
        }
        v
    }

    pub fn notes(&self) -> Vec<Asset>
    {
        let mut v = vec![];
        for note in &self.unspent_notes
        {
            v.push(note.note.asset().clone());
        }
        v
    }

    pub fn addresses(&self) -> Vec<Address>
    {
        let mut v = vec![];
        let sk = SpendingKey::from_seed(&self.seed);
        let fvk = FullViewingKey::from_spending_key(&sk);
        for d in &self.diversifiers
        {
            v.push(fvk.find_address((*d).into()).unwrap().1);
        }
        v
    }

    pub fn derive_next_address(&mut self) -> Address
    {
        let sk = SpendingKey::from_seed(&self.seed);
        let fvk = FullViewingKey::from_spending_key(&sk);
        let mut latest_di = *self.diversifiers.last().unwrap();
        latest_di += 1;
        let (di, addr) = fvk.find_address(latest_di.into()).unwrap();
        latest_di = u64::try_from(di).unwrap();
        self.diversifiers.push(latest_di);
        addr
    }

    pub fn add_leaves(&mut self, leaves: &[u8])
    {
        assert!(leaves.len() % 32 == 0);
        for i in 0..leaves.len()/32
        {
            let mut bytes = [0; 32];
            bytes.copy_from_slice(&leaves[i*32..(i+1)*32]);
            let leaf = ScalarBytes(bytes);
            self.insert_into_merkle_tree(&leaf);
        }
    }

    pub fn process_block(&mut self, block: &String) -> u64
    {
        let sk = SpendingKey::from_seed(&self.seed);
        let fvk = FullViewingKey::from_spending_key(&sk);
        let j: Value = serde_json::from_str(&block).unwrap();
        let block_num = j["block_num"].as_u64().unwrap() as u32;
        let dt_str = j["timestamp"].as_str().unwrap().to_string() + " +0000"; // need to add (utc) timezone for valid format
        let dt = DateTime::parse_from_str(&dt_str, "%Y-%m-%dT%H:%M:%S%.3f %z").unwrap();
        let block_ts = dt.timestamp_millis() as u64;
        let wallet_ts = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis() as u64;
        let mut notes_found = 0;

        // make sure to not sync a block twice
        if block_num <= self.block_num { return notes_found; }

        for tx in j["transactions"].as_array().unwrap()
        {
            for action in tx["trx"]["transaction"]["actions"].as_array().unwrap()
            {
                if (action["account"].as_str().unwrap().eq(&self.settings.protocol_contract.to_string()) || 
                    action["account"].as_str().unwrap().eq(&self.settings.alias_authority.actor.to_string())) && (
                    action["name"].as_str().unwrap().eq("mint") ||
                    action["name"].as_str().unwrap().eq("transfer") ||
                    action["name"].as_str().unwrap().eq("burn") ||
                    action["name"].as_str().unwrap().eq("publishct"))
                {
                    for ct in action["data"]["note_ct"].as_array().unwrap()
                    {
                        let b64_str = ct.as_str().unwrap().to_string();
                        let encrypted_note = TransmittedNoteCiphertext::from_base64(&b64_str);
                        if encrypted_note.is_none() { continue; }
                        let encrypted_note = encrypted_note.unwrap();

                        // test receiver decryption
                        match try_note_decryption(&PreparedIncomingViewingKey::new(&fvk.ivk()), &encrypted_note) {
                            Some(note) => {
                                // Merkle tree must be up to date! We check if there's a leaf for this note and get it's array index in the merkle
                                // tree. If there is no index (i.e. leaf), this note can't be valid and is discarded.
                                let cm = note.commitment();
                                let idx = self.merkle_tree.iter().find_map(|(key, val)| if val.0 == cm.to_bytes() { Some(key) } else { None });
                                if idx.is_none() { continue; }
                                let note_ex = NoteEx{
                                    block_num,
                                    block_ts,
                                    wallet_ts,
                                    leaf_idx_arr: *idx.unwrap(),
                                    note
                                };
                                self.unspent_notes.push(note_ex);
                                notes_found += 1;
                            },
                            None => {},
                        }

                        // test sender decryption
                        match try_output_recovery_with_ovk(&fvk.ovk, &encrypted_note) {
                            Some(note) => {
                                let note_ex = NoteEx{
                                    block_num,
                                    block_ts,
                                    wallet_ts,
                                    leaf_idx_arr: 0,
                                    note: note.clone()
                                };
                                self.outgoing_notes.push(note_ex);
                                // Look for parent note (by nullifier) and move it from 'unspent' to 'spent'
                                let index = self.unspent_notes.iter().position(|n| n.note.nullifier(&fvk.nk, n.position()).extract() == *note.rho());
                                if index.is_some()
                                {
                                    self.spent_notes.push(self.unspent_notes.remove(index.unwrap()));
                                }
                            },
                            None => {},
                        }
                    }
                }
            }
        }

        self.block_num = block_num;

        notes_found
    }

    /// Very simple note selection algorithm: walk through all notes and pick notes of the demanded type until the sum
    /// is equal or greater than the requested 'amount'. Returns tuple of vector of notes to be spent and the change that
    /// is left over from the last note. Returns 'None' if there are not enough notes to reach 'amount'.
    fn select_notes(&self, notes: &mut Vec<NoteEx>, asset: &Asset) -> Option<(Vec<NoteEx>, u64)>
    {
        let mut code = &self.settings.nft_contract;
        if !asset.is_nft()
        {
            let ft_code = self.settings.ft_symbols.get(&asset.symbol().code());
            if ft_code.is_none() { log("symbol code invalid [select notes]:"); log(&asset.symbol().to_string()); return None; }
            code = &ft_code.unwrap().0;
        }
        // sort 'notes' by note amount, ascending order and walk backwards through them in order to be able to safely remove elements
        notes.sort_by(|a, b| a.note.amount().cmp(&b.note.amount()));
        let mut res = Vec::new();
        let mut sum = 0;
        for i in (0..notes.len()).rev()
        {
            if code.eq(notes[i].note.code()) &&             // same contract
                asset.symbol().eq(notes[i].note.symbol())   // same symbol
                // TODO:                                    // filter out AUTH TOKEN
            {
                if asset.is_nft() && asset.amount() as u64 == notes[i].note.amount()
                {
                    // found NFT
                    res.push(notes.remove(i));
                    return Some((res, 0));
                }
                sum += notes[i].note.amount() as u64;
                res.push(notes.remove(i));
                if sum >= asset.amount() as u64
                {
                    // collected enough fungible notes, return notes & change amount
                    return Some((res, sum - asset.amount() as u64));
                }
            }
        }
        // Not enough notes! Move picked notes in 'res' back to 'notes' and return 'None'.
        notes.append(&mut res);

        log("insufficient notes [select notes]:");
        log(&asset.to_string());
        None
    }

    fn find_nft(&self, notes: &mut Vec<NoteEx>, asset: &Asset) -> Option<NoteEx>
    {
        if !asset.is_nft() || asset.amount() == 0
        {
            return None;
        }

        for i in (0..notes.len()).rev()
        {
            if notes[i].note.code().eq(&self.settings.nft_contract) && notes[i].note.symbol().raw() == 0
            {
                if asset.amount() as u64 == notes[i].note.amount()
                {
                    // found NFT
                    return Some(notes.remove(i));
                }
            }
        }

        log("nft not found");
        log(&asset.to_string());
        None
    }

    fn insert_into_merkle_tree(&mut self, leaf: &ScalarBytes) -> u64
    {
        // calculate array index of next free leaf in current tree
        let mut idx = MT_ARR_LEAF_ROW_OFFSET!(MERKLE_TREE_DEPTH) + self.leaf_count % MT_NUM_LEAVES!(MERKLE_TREE_DEPTH);
        // calculate tree offset to translate local array indices of current tree to absolute array indices of global array
        let tos = self.leaf_count / MT_NUM_LEAVES!(MERKLE_TREE_DEPTH) * MT_ARR_FULL_TREE_OFFSET!(MERKLE_TREE_DEPTH);

        // insert this leaf into tree
        self.merkle_tree.insert(tos + idx, leaf.clone());

        // update merkle path
        for d in 0..MERKLE_TREE_DEPTH
        {
            let is_left_child = 1 == idx % 2;
            let sis_idx = if is_left_child { idx + 1 } else { idx - 1 };

            // get values of both sibling nodes and determin which is the right/left one
            //                                                         (parent)                 |                     (parent)
            //                                                         /       \                |                     /       \
            //                                                      (idx)      (0)              |                (sis_idx)   (idx)
            let l = if is_left_child { self.merkle_tree.get(&(tos + idx)).unwrap() }    else { self.merkle_tree.get(&(tos + sis_idx)).unwrap() };
            let r = if is_left_child { &EMPTY_ROOTS[d] }                                else { self.merkle_tree.get(&(tos + idx)).unwrap() };

            // take advantage of the fact that WASM uses little-endian byte encoding
            let mut parent_val: [u8; 32] = Blake2s7rParams::new()
                .hash_length(32)
                .personal(crate::constants::MERKLE_TREE_PERSONALIZATION)
                .to_state()
                .update(&l.0)
                .update(&r.0)
                .finalize()
                .as_bytes()
                .try_into()
                .expect("output length is correct");

            // in case of merkle root: mask the 2 MSBs off the root value, since the arithmetic
            // circuit only supports roots of 254 bits width.
            if d == MERKLE_TREE_DEPTH - 1
            {
                parent_val[31] &= 0x3F;
            }

            // left child's array index divided by two (integer division) equals array index of parent node
            idx = if is_left_child { idx / 2 } else { sis_idx / 2 };

            // check if parent node already exists
            self.merkle_tree.entry(tos + idx).and_modify(|e| *e = ScalarBytes(parent_val)).or_insert(ScalarBytes(parent_val));
        }

        self.leaf_count += 1;
        return tos;
    }

    fn get_sister_path_and_root(&self, note: &NoteEx) -> Option<(Vec<Option<([u8; 32], bool)>>, ScalarBytes)>
    {
        let mut idx = note.leaf_idx_arr % MT_ARR_FULL_TREE_OFFSET!(MERKLE_TREE_DEPTH);
        let tos = note.leaf_idx_arr / MT_ARR_FULL_TREE_OFFSET!(MERKLE_TREE_DEPTH) * MT_ARR_FULL_TREE_OFFSET!(MERKLE_TREE_DEPTH);

        let mut sis_path = vec![];
        for d in 0..MERKLE_TREE_DEPTH
        {
            let is_left_child = 1 == idx % 2;
            let sis_idx = if is_left_child { idx + 1 } else { idx - 1 };

            let sister = if self.merkle_tree.contains_key(&(tos + sis_idx)) { self.merkle_tree.get(&(tos + sis_idx)).unwrap().clone() } else { EMPTY_ROOTS[d].clone() };
            sis_path.push(Some((sister.0, !is_left_child)));

            // left child's array index divided by two (integer division) equals array index of parent node
            idx = if is_left_child { idx / 2 } else { sis_idx / 2 };
        }

        Some((sis_path, self.merkle_tree.get(&tos).unwrap().clone()))
    }
}

#[cfg(test)]
mod tests
{
    use crate::{
        wallet::{Wallet, NoteEx},
        eosio::{Authorization, Name, Transaction, Action, Symbol, Asset},
        contract::{PlsMint, ScalarBytes, AffineProofBytes}
    };
    use rand::rngs::OsRng;
    use super::EMPTY_ROOTS;
    use crate::wallet::Note;

    #[test]
    fn test_serde()
    {
        let mut w = Wallet::create(
            b"this is a sample seed which should be at least 32 bytes long...",
            false
        ).unwrap();
        w.insert_into_merkle_tree(&EMPTY_ROOTS[1]);
        w.insert_into_merkle_tree(&EMPTY_ROOTS[2]);
        w.insert_into_merkle_tree(&EMPTY_ROOTS[3]);
        w.insert_into_merkle_tree(&EMPTY_ROOTS[0]);
        w.insert_into_merkle_tree(&EMPTY_ROOTS[1]);
        w.insert_into_merkle_tree(&EMPTY_ROOTS[2]);
        w.insert_into_merkle_tree(&EMPTY_ROOTS[3]);
        w.insert_into_merkle_tree(&EMPTY_ROOTS[0]);
        w.insert_into_merkle_tree(&EMPTY_ROOTS[1]);
        w.insert_into_merkle_tree(&EMPTY_ROOTS[2]);
        w.insert_into_merkle_tree(&EMPTY_ROOTS[3]);
        w.insert_into_merkle_tree(&EMPTY_ROOTS[0]);
        println!("Wallet size: {}", w.size());

        let mut rng = OsRng.clone();
        w.unspent_notes.push(NoteEx{block_num: 1337, block_ts: 1234, leaf_idx_arr: 1234, wallet_ts: 0, note: Note::dummy(&mut rng, None, None, None).2});

        let mut v = vec![];
        assert!(w.write(&mut v).is_ok());
        assert_eq!(v.len(), w.size());
        let w_de = Wallet::read(&v[..]).unwrap();
        assert!(w == w_de);

        let encoded = w.to_json(false);
        println!("{}", encoded);
        let decoded = Wallet::from_json(&encoded).unwrap();
        assert_eq!(w, decoded);
    }

    #[test]
    fn test_payload_serde()
    {
        let tx = Transaction{
            actions: vec![
                Action{
                    account: Name::new(0),
                    name: Name::new(0),
                    authorization: vec![Authorization{
                        actor: Name::new(0),
                        permission: Name::new(0)
                    }],
                    data: PlsMint{
                        cm: ScalarBytes([0; 32]),
                        value: 0,
                        symbol: Symbol::new(0),
                        code: Name::new(0),
                        proof: AffineProofBytes([0; 384])
                    }.into()
                }
            ]
        };

        println!("{}", serde_json::to_string(&tx).unwrap());
    }

    #[test]
    fn test_process_move_desc()
    {
        let w = Wallet::create(
            b"this is a sample seed which should be at least 32 bytes long...",
            false
        ).unwrap();

        let nft = w.process_move_desc(&"i 1234567890".to_string());
        assert!(nft.is_some());
        println!("{:?}", nft.unwrap());

        let nft = w.process_move_desc(&"+ 123456     'miau miau miau'".to_string());
        assert!(nft.is_some());
        println!("{:?}", nft.unwrap());

        let ft = w.process_move_desc(&"+ 10.5 EOS     \"'miau miau miau'\"".to_string());
        assert!(ft.is_some());
        println!("{:?}", ft.unwrap());

        let ft = w.process_move_desc(&"- 10.5 ZEOS 'moving out!'".to_string());
        assert!(ft.is_some());
        println!("{:?}", ft.unwrap());
    }

    #[test]
    fn test_move_asset()
    {
        let mut rng = OsRng.clone();
        let w = Wallet::create(
            b"this is a sample seed which should be at least 32 bytes long...",
            false
        ).unwrap();

        let tx = w.move_asset(
            &mut rng,
            format!("mschoenebeck"),
            vec![
                format!("+ 10 EOS 'moving in!'"),
                format!("- 10.5 ZEOS 'moving out!'"),
                format!("i 1234567890"),
                format!("in 1234567890987654321"),
            ]
        );
        assert!(tx.is_some());
        println!("{}", serde_json::to_string(&tx.unwrap()).unwrap());
    }

    #[test]
    fn test_process_block()
    {
        //let mut rng = OsRng.clone();

        let blocks = vec![
            "{\"timestamp\":\"2023-07-03T12:11:15.000\",\"producer\":\"eosio\",\"confirmed\":0,\"previous\":\"00000011249132b6a362cc0a14c32757dfc95de75edcf2877cf26295c112d0c7\",\"transaction_mroot\":\"1e6dd8b26fe8ab6477086ec3b674cf6ef078b8b2ee112cd127f7dd6917ee5a68\",\"action_mroot\":\"0b0cb5cac4410c56f7a4fa528b693c41814f8c796ca0f0662bcefef41f19af7b\",\"schedule_version\":0,\"new_producers\":null,\"producer_signature\":\"SIG_K1_K45NeZREbayVbUJW3sbQrbdsWHmpq7EfL3BGUsVgYptD4HuuFNoWwjKCQstjnkKUfw1xEkUgdafVXgv9f6NfbG76j3r7Jt\",\"transactions\":[{\"status\":\"executed\",\"cpu_usage_us\":147,\"net_usage_words\":13,\"trx\":{\"id\":\"f7719c4bc8518ad60e49951c0503d24f8242e3b4967cc7f473485e64a90ba622\",\"signatures\":[\"SIG_K1_K2eLbS3k5FFQdNYLhAZzx8AgBoRp8k6VYa44PGS4whvNeKPwKZKTRvxaACRFPKiCgCFABaNDs2B7C4sianz25JMcNuMNyq\"],\"compression\":\"none\",\"packed_context_free_data\":\"\",\"context_free_data\":[],\"packed_trx\":\"00bba2641000335d50c200000000019091b9795284a9fa00000000889eb1ca019091b9795284a9fa00000000a8ed323208000000000000000000\",\"transaction\":{\"expiration\":\"2023-07-03T12:11:44\",\"ref_block_num\":16,\"ref_block_prefix\":3260046643,\"max_net_usage_words\":0,\"max_cpu_usage_ms\":0,\"delay_sec\":0,\"context_free_actions\":[],\"actions\":[{\"account\":\"zeoscontract\",\"name\":\"testx2\",\"authorization\":[{\"actor\":\"zeoscontract\",\"permission\":\"active\"}],\"data\":{\"x\":\"0,\"},\"hex_data\":\"0000000000000000\"}]}}},{\"status\":\"executed\",\"cpu_usage_us\":211,\"net_usage_words\":18,\"trx\":{\"id\":\"84c0e3ea98e7f9b057587583b652190621f5babf7c2d202ccc83ef794bc4405d\",\"signatures\":[\"SIG_K1_KVvHxeiWkYwyyCnN1pvBpboEa3DXjjUDYRT3M9DscMhCqx7jrDgFqQcvwrLcwyQshTkmjWfkmERgLQV1of4pXseH8nt6ZQ\"],\"compression\":\"none\",\"packed_context_free_data\":\"\",\"context_free_data\":[],\"packed_trx\":\"00bba2641000335d50c2000000000100a6823403ea3055000000572d3ccdcd010000000000ea305500000000a8ed32322e0000000000ea30559091b9795284a9fa00e1f5050000000004454f53000000000d74657374207472616e7366657200\",\"transaction\":{\"expiration\":\"2023-07-03T12:11:44\",\"ref_block_num\":16,\"ref_block_prefix\":3260046643,\"max_net_usage_words\":0,\"max_cpu_usage_ms\":0,\"delay_sec\":0,\"context_free_actions\":[],\"actions\":[{\"account\":\"eosio.token\",\"name\":\"transfer\",\"authorization\":[{\"actor\":\"eosio\",\"permission\":\"active\"}],\"data\":{\"from\":\"eosio\",\"to\":\"zeoscontract\",\"quantity\":\"10000.0000 EOS\",\"memo\":\"test transfer\"},\"hex_data\":\"0000000000ea30559091b9795284a9fa00e1f5050000000004454f53000000000d74657374207472616e73666572\"}]}}},{\"status\":\"executed\",\"cpu_usage_us\":2736,\"net_usage_words\":68,\"trx\":{\"id\":\"4e32d14eff869fd7d31ec41a1ca91ad54afb746567ec38130aedb6c45d0f6b20\",\"signatures\":[\"SIG_K1_KW11LpkogV58AReC5hQuQ9pd7VevHxULqmZp9h51AuG5F2vwGREntip246KWhjoGdpXcHoBJMLNKL2tet25eq9TaBk3SxK\"],\"compression\":\"none\",\"packed_context_free_data\":\"\",\"context_free_data\":[],\"packed_trx\":\"00bba2641000335d50c200000000019091b9795284a9fa000000000090a793019091b9795284a9fa00000000a8ed3232bd030120a71045795b5c8931ed61f8cc794700ea43fd30237e3c5d65e173b829f275005980f0fa020000000004454f530000000000a6823403ea305580037bd9928fe71be67b9e61ed4f3e6c5d806712caf4590e96eef43bfe1db76c72527dcc45e83da45160fc7ec6ffdc648d0fb6d913d04c2a223f6e210164ff6b8b06d17fedef5d52f86236ae66323465a79f8da8f98057541715952080f8f1a9a5179efebba3eefee0850c16410663cc4dabc06607ca5d77ab3633f69ed2fa6f73278c1dda6ce6bc139f92fe9b849de1380b55ba4f91c05cc94442b72a2796cca4b7378abb61cdc06720cfd627eac495f7ff9adbd587ddd22ecce4b524a22e4c9e07354f25f00560c9a92630b0e834e88f360adb89108f3d5fe1b0b1bf3a0fce84aa25f9b7b14bfb395537e9abddd7943307dbe28806bfa124caba7880b8f12bc6051b76dbb8f77f5908d409eeda3dc63d77a33db7324b64761b721bf840be869702fc9d7cb61f8557436bd7523e8499fb8e17efb19d4c7324c41f87e8234602807c1a06728b5afee4b838cf7917407cd1012cfc3ff77a54840ce5c7cd6f8f0a1834a3623bca2421f91a3324e66ee7888e095138b6b8680896ca8c8c1fdd03e0ed160000\",\"transaction\":{\"expiration\":\"2023-07-03T12:11:44\",\"ref_block_num\":16,\"ref_block_prefix\":3260046643,\"max_net_usage_words\":0,\"max_cpu_usage_ms\":0,\"delay_sec\":0,\"context_free_actions\":[],\"actions\":[{\"account\":\"zeoscontract\",\"name\":\"mint\",\"authorization\":[{\"actor\":\"zeoscontract\",\"permission\":\"active\"}],\"data\":{\"actions\":[{\"cm\":\"a71045795b5c8931ed61f8cc794700ea43fd30237e3c5d65e173b829f2750059\",\"value\":50000000,\"symbol\":\"4,EOS\",\"code\":\"eosio.token\",\"proof\":\"7bd9928fe71be67b9e61ed4f3e6c5d806712caf4590e96eef43bfe1db76c72527dcc45e83da45160fc7ec6ffdc648d0fb6d913d04c2a223f6e210164ff6b8b06d17fedef5d52f86236ae66323465a79f8da8f98057541715952080f8f1a9a5179efebba3eefee0850c16410663cc4dabc06607ca5d77ab3633f69ed2fa6f73278c1dda6ce6bc139f92fe9b849de1380b55ba4f91c05cc94442b72a2796cca4b7378abb61cdc06720cfd627eac495f7ff9adbd587ddd22ecce4b524a22e4c9e07354f25f00560c9a92630b0e834e88f360adb89108f3d5fe1b0b1bf3a0fce84aa25f9b7b14bfb395537e9abddd7943307dbe28806bfa124caba7880b8f12bc6051b76dbb8f77f5908d409eeda3dc63d77a33db7324b64761b721bf840be869702fc9d7cb61f8557436bd7523e8499fb8e17efb19d4c7324c41f87e8234602807c1a06728b5afee4b838cf7917407cd1012cfc3ff77a54840ce5c7cd6f8f0a1834a3623bca2421f91a3324e66ee7888e095138b6b8680896ca8c8c1fdd03e0ed16\"}],\"note_ct\":[]},\"hex_data\":\"0120a71045795b5c8931ed61f8cc794700ea43fd30237e3c5d65e173b829f275005980f0fa020000000004454f530000000000a6823403ea305580037bd9928fe71be67b9e61ed4f3e6c5d806712caf4590e96eef43bfe1db76c72527dcc45e83da45160fc7ec6ffdc648d0fb6d913d04c2a223f6e210164ff6b8b06d17fedef5d52f86236ae66323465a79f8da8f98057541715952080f8f1a9a5179efebba3eefee0850c16410663cc4dabc06607ca5d77ab3633f69ed2fa6f73278c1dda6ce6bc139f92fe9b849de1380b55ba4f91c05cc94442b72a2796cca4b7378abb61cdc06720cfd627eac495f7ff9adbd587ddd22ecce4b524a22e4c9e07354f25f00560c9a92630b0e834e88f360adb89108f3d5fe1b0b1bf3a0fce84aa25f9b7b14bfb395537e9abddd7943307dbe28806bfa124caba7880b8f12bc6051b76dbb8f77f5908d409eeda3dc63d77a33db7324b64761b721bf840be869702fc9d7cb61f8557436bd7523e8499fb8e17efb19d4c7324c41f87e8234602807c1a06728b5afee4b838cf7917407cd1012cfc3ff77a54840ce5c7cd6f8f0a1834a3623bca2421f91a3324e66ee7888e095138b6b8680896ca8c8c1fdd03e0ed1600\"}]}}}],\"id\":\"0000001219fb316774e216460585a02ba48740125457653b14b551a07129339b\",\"block_num\":18,\"ref_block_prefix\":1175904884}",
            "{\"timestamp\":\"2023-07-03T12:11:17.000\",\"producer\":\"eosio\",\"confirmed\":0,\"previous\":\"00000015df442fecd581a8d2d5e7a8ec08aad10521ae979dd7490087031bde98\",\"transaction_mroot\":\"decf5952f974b495eff7b5ae8eeb82c51d580b6978d54cef81e5d783a21cf0f9\",\"action_mroot\":\"03567a8f23b9edbe333596a4bb7e1c3d111d7845c04d66c9bca88e2619b488d0\",\"schedule_version\":0,\"new_producers\":null,\"producer_signature\":\"SIG_K1_K6RZirn7XYcfZBqBVz7kM97RZF6929DrzRSf7rgLSVThWQWZPEdQeYZTFXaDsnDzKrH3437cSsEVLp8AUR4HUDh7gMobnv\",\"transactions\":[{\"status\":\"executed\",\"cpu_usage_us\":2647,\"net_usage_words\":80,\"trx\":{\"id\":\"f171a2569157802ebe96d784a2280e5b57f2fe37b6d3fac99fe697bb744e09a5\",\"signatures\":[\"SIG_K1_K6Bf2o15EoAi85HqST7zK4RbN6DmcBP1h68N5yQbXVLYKt8UtvX67G5BhjcXPNha6hWeb7pbe6JnrSxiBSmqFxBEj7eoTu\"],\"compression\":\"none\",\"packed_context_free_data\":\"\",\"context_free_data\":[],\"packed_trx\":\"02bba2641400a5a6c9e000000000019091b9795284a9fa000000000030af3e019091b9795284a9fa00000000a8ed3232a204012021d8af5774b0cd332a36822748ef525f005a6630cb292dd1e384c45e6656cd11207ec79d84ad4a6d05a121ea9707ea5fd5cb948e07fe60a39ed05c299d5a22fe66206886a72b946485ce50976db4d087f18ab6e0a954bd10b865480bb3c0c5ae465880c3c9010000000004454f530000000000a6823403ea30550000000000ea30550974657374206d656d6f00000000000000000000000000000000008003acc3e8c4ab8b32b62117da2ccded2193d9541f903099fe0a51f44eb1c0975cafb9b3ab8aab4dc68798e1651faeccb417649b5f982df0ecb51dfd97c7620e441a0e65f5c5d88dd072d897e8a9dccc7503c8222d7cba25ec04fbac201b19673915253a1e8c27e596a994e8b3f1846cb976c3fcece27816c552e262fd460a154704d7d51df5f44a378851ce0ac0481b6d086f0f2500d97bccad6d58d8fd9bef41ec711f4b398b3ef80cc51bdf049a464302a020570f246d8a6b041555e1d48a20131d183cb72d41ba6b5fb11addbe3311cc144e80e97658af797a83699119ba37bddc959a460980bc412e737feb8c676309891cf54031140b6829dab359526993551e0cd5621be556435791cf33bdc27b006e0e69455435578181035ccd48511304671a8969f15e00bcc3d02edeef8d7127d14f4b4f964b0a13c740d29d8461a374031c0151298adc9ffcc5bddd5f1a0b16d53f44b4d9315d65fd30a567ae4fcec7802ee091617b48b711f2909e5b579189628ac45671a46acbb2042594513a5c0b0000\",\"transaction\":{\"expiration\":\"2023-07-03T12:11:46\",\"ref_block_num\":20,\"ref_block_prefix\":3771311781,\"max_net_usage_words\":0,\"max_cpu_usage_ms\":0,\"delay_sec\":0,\"context_free_actions\":[],\"actions\":[{\"account\":\"zeoscontract\",\"name\":\"burn\",\"authorization\":[{\"actor\":\"zeoscontract\",\"permission\":\"active\"}],\"data\":{\"actions\":[{\"root\":\"21d8af5774b0cd332a36822748ef525f005a6630cb292dd1e384c45e6656cd11\",\"nf\":\"7ec79d84ad4a6d05a121ea9707ea5fd5cb948e07fe60a39ed05c299d5a22fe66\",\"cm_d\":\"6886a72b946485ce50976db4d087f18ab6e0a954bd10b865480bb3c0c5ae4658\",\"value_b\":30000000,\"symbol\":\"4,EOS\",\"code\":\"eosio.token\",\"account_b\":\"eosio\",\"memo_b\":\"test memo\",\"amount_c\":0,\"account_c\":\"\",\"memo_c\":\"\",\"proof\":\"acc3e8c4ab8b32b62117da2ccded2193d9541f903099fe0a51f44eb1c0975cafb9b3ab8aab4dc68798e1651faeccb417649b5f982df0ecb51dfd97c7620e441a0e65f5c5d88dd072d897e8a9dccc7503c8222d7cba25ec04fbac201b19673915253a1e8c27e596a994e8b3f1846cb976c3fcece27816c552e262fd460a154704d7d51df5f44a378851ce0ac0481b6d086f0f2500d97bccad6d58d8fd9bef41ec711f4b398b3ef80cc51bdf049a464302a020570f246d8a6b041555e1d48a20131d183cb72d41ba6b5fb11addbe3311cc144e80e97658af797a83699119ba37bddc959a460980bc412e737feb8c676309891cf54031140b6829dab359526993551e0cd5621be556435791cf33bdc27b006e0e69455435578181035ccd48511304671a8969f15e00bcc3d02edeef8d7127d14f4b4f964b0a13c740d29d8461a374031c0151298adc9ffcc5bddd5f1a0b16d53f44b4d9315d65fd30a567ae4fcec7802ee091617b48b711f2909e5b579189628ac45671a46acbb2042594513a5c0b\"}],\"note_ct\":[]},\"hex_data\":\"012021d8af5774b0cd332a36822748ef525f005a6630cb292dd1e384c45e6656cd11207ec79d84ad4a6d05a121ea9707ea5fd5cb948e07fe60a39ed05c299d5a22fe66206886a72b946485ce50976db4d087f18ab6e0a954bd10b865480bb3c0c5ae465880c3c9010000000004454f530000000000a6823403ea30550000000000ea30550974657374206d656d6f00000000000000000000000000000000008003acc3e8c4ab8b32b62117da2ccded2193d9541f903099fe0a51f44eb1c0975cafb9b3ab8aab4dc68798e1651faeccb417649b5f982df0ecb51dfd97c7620e441a0e65f5c5d88dd072d897e8a9dccc7503c8222d7cba25ec04fbac201b19673915253a1e8c27e596a994e8b3f1846cb976c3fcece27816c552e262fd460a154704d7d51df5f44a378851ce0ac0481b6d086f0f2500d97bccad6d58d8fd9bef41ec711f4b398b3ef80cc51bdf049a464302a020570f246d8a6b041555e1d48a20131d183cb72d41ba6b5fb11addbe3311cc144e80e97658af797a83699119ba37bddc959a460980bc412e737feb8c676309891cf54031140b6829dab359526993551e0cd5621be556435791cf33bdc27b006e0e69455435578181035ccd48511304671a8969f15e00bcc3d02edeef8d7127d14f4b4f964b0a13c740d29d8461a374031c0151298adc9ffcc5bddd5f1a0b16d53f44b4d9315d65fd30a567ae4fcec7802ee091617b48b711f2909e5b579189628ac45671a46acbb2042594513a5c0b00\"}]}}}],\"id\":\"00000016782c1d79621f52bd9fa9f94713feed2f047ab6b219e473bbe6c5f11b\",\"block_num\":22,\"ref_block_prefix\":3176275810}",
            "{\"timestamp\":\"2023-07-03T14:17:20.000\",\"producer\":\"eosio\",\"confirmed\":0,\"previous\":\"00003b2b81fd6ed974adc29d6a9b47f1ab9f850dacfd8fc4a426c0f5159f656c\",\"transaction_mroot\":\"287ad63c70283bf2dfe188f6e87affa84f266be2890b3f3a1f021f00a4bb578e\",\"action_mroot\":\"f416d4d78000083957eb66da4d9d1c5c8e0fdf4d2722382ae74a9171985f06a3\",\"schedule_version\":0,\"new_producers\":null,\"producer_signature\":\"SIG_K1_KBd5znqZ7PxvhdUGqxCKrtEEJpEVmVjnWAznKrGTzkNSpYfqJnx8wxEhiY91SsNSMXAH7J67T9q6WDud5iezGYeW72cpbx\",\"transactions\":[{\"status\":\"executed\",\"cpu_usage_us\":3882,\"net_usage_words\":392,\"trx\":{\"id\":\"ee554e45549fee263a971bcf404dbf0e46e1e22bd8cf81799b140a21325b13ad\",\"signatures\":[\"SIG_K1_Kf5Z1abpthKee32g4r2gfPE44WTvjdq8P4CoRXH12gHLVh5XHrVEYicbECvQ7cfLxYuzMrATrHSvqjqhGQfftC3p6WJXCb\"],\"compression\":\"none\",\"packed_context_free_data\":\"\",\"context_free_data\":[],\"packed_trx\":\"8dd8a2642a3ba41d08bc000000000300a6823403ea3055000000572d3ccdcd010000000000ea305500000000a8ed32322a0000000000ea30559091b9795284a9faa08601000000000004454f5300000000095a454f53204d494e5400a6823403ea3055000000572d3ccdcd010000000000ea305500000000a8ed32322a0000000000ea30559091b9795284a9faa08601000000000004454f5300000000095a454f53204d494e549091b9795284a9fa000000000090a793010000000000ea305500000000a8ed3232c41602202a2c4d4a2875d83f35d4614658f718f8feb3e2f93dd3272721e3b03b71b26605a08601000000000004454f530000000000a6823403ea30558003bffdfd919a57fbf6000ed8ebea1ff97f03c6ca348122d22ebbaf802caef9681474a7606653e11f0b6e3d0331cb791b0cc5f5974d4d4b34140ef04377ee729693c24ab18a6008809ab05d1534caa686f2ebb9ca289aa2efe45ee447d8990afe14f7b1a4b7b4bf49ec1bc0a682c615f39e2b761292402b1ccd18e89f3e1c7b0d29c556a4331c00c0431bf470a2f43d59064204b7ac22b196013ab9076f84a23b2f3d43e3d4fbb8d81852a6eed6cdd2d5483f73cade7ccbd0701a20cf42be8fcd0e3177deac42941ee00a3c50fdebcb97a62f36edc0aca70f9fc46811f1827f068f2d91c7254e4296a741c9d57afa5e34149926c31f05e8424a23727525a30b44c8d747414f9470edbf8781b8f889af6df31e492d860e58ecb5afa7716ccd9b200a75e26913c58695a8ace1895958a843fa7a526cfe66d25ccf463ff4c292472c91bdef45078e54437e32bf2aa9e71c530351cb034039129d02d7d5031cb01f54ef95eb15e79674e5a096e7af33ec7c33ea950408de08d35f759ef711e1df18ec0e2089a39d9bea68e79209837f0ebed29ce4b333a5572710430c203df5ea6345d11ba08601000000000004454f530000000000a6823403ea30558003e25151132a1a70522b3d9c1de03569154aab30b8089b8b3e24e21464eaeadac6b125dff4e6a869dea48e9c3a99be1d147c0d9b9ab5fb88cb66270badabba91ad9ebba09fac7ef4065faded38af3ead500298a13c5ce83778e32923b6225da107929efb8806449db781647e7387542ea0933d93296477dc55b7ef2315579b8d9c2f10e608e8bcb8c4701d631fa60b370392d783b66b7b952f568e58928727097657ea96ecf2a1aea27795d92e1b17716effdff91eb08dcbaa96c2cb5a64b5b7198fc5ee0f71ba3afb1fd22f25a0cbad676db3b885ed7cf4647fe4960606470df547438f454c0f9c9153f062f4e228b80665320dfd8ff73b88ca1f43239872781b68de57136941e5ae9bf41552d95fe74de076302c74f2291e6708299608395b0652aa516f31fd26474d1cbdc6ac50d8c7b5b8d576842cc9c1d652d8071529ddaf13879bb3877f3a2c6501bdd636fa780a00b459a12d6866e840eb0e05d89321abd0efc1544bfdb0efaf5e43b5ace45979e2e84a432fd5a26601d41c6b28f0f90802e4076278347763416935725572306378373339476b484b69637a33364349637a4b774877506e3278357a4f6a735a317958516835372b756736577937567a584c345730304647427366566b6c732b63372b725268343731537a62364977414c4f655964715849455859597452662b6550584b3044786f624455447661556e516d514e3073486847343155564c6859574f504752647676744141744f32786d6a6d506f5a6a6e352b533155363770737256737638786442584e36524369705650634a785062394a6366514b426b646c7332736572754e645731395a46315373502f444b6b4372496579375552486c5336676746364a5870357849526869453961565178653962666c5875626e386649506f545976316632376e3932364457396a7764617754386465694b6d596c6b644f3449765a3337786b6c4c33375455507a4964782f717271767354782b5247704b5761552f584c2f46677a302b586b5968515a5643625668716650797a65674130527354464865624b6f446a4c43475153666f54417463474f597734372b5a373754624136426465654c4450644a68494654595331595767744f42674b4e52554237746c665351344c2b366a2f344b49666b2f636d554136774d316e7868554a474152666f43634b387939436d746a4a54736c4c35733042364e58767a2f546e64516e454754686279305131417955566f72484e35514c435451325a52334243572f383335474a6344656c384f484147644e6b7544513858612f55425556384d30656e79505657323744582b7356426b516678596a483864684662732b6456414f364b53447470706d66392b7930443435724b4853704e306f715a7671716d72706e6850454864616c6e437674324d384644776b644f36725a574a594837456166474d37784446415867547348525a34365864773274575a5964706f72775733566b54465a35675667682b765867477643444d72344e564b6849526f38723668344d69685a51544c593072463638443642724b726c7649314d6b386f6e4c6a3770376b526d684e306e35646e784668424d6855744231312f57623362766673715631476f6b6a396c796b7449366f656b42567a7252616b7537332f66683477646157776d594169414262644d667753426e4e356a7563334b316f534a362f664e6679764d6c42596e657358534249306e734c6437483253717964475a5156767971564c42373330624f764c6750386e424c694253444d6e59514e2f49342f527a4a4b5251692b6e4c455a785236717437654d4467534a6f58772b7051415a5531546e584173536554424a33742b52466e446e486d2b644335774f687879554a4f546245457179667461423637365046613030736558444c6be407626c364c7151425378742f597152332f4b794263726e77434a66763174597445426f375765754a6f62315967714c73785869557368596d353642337846396a7153436678417a474d6e6879774e6f5978415651386f43334b343342365962434343356f5559424c363879572b615532566e306d71316a652b52376371794b6a54626b347156506b31623163717558777a757a5771645372524d4d6a577964716678303243786e2b52613259796b714f7a583441325a52552f4641325157614c51514b37314f644f59477a66443679536a376352536131334553766f65574f586e2f6235724b77586549313961614a535a794678476a526e575255416c55624a696c4a7731376d74453052674f55797a7731357a4a414a66565235577738313247304f53376a77636d2f74754653466b567556754879554377396c6e4b4d6c6c533472546d464a352f426e387069626869646c7753654366755551506b78337833704a667a7739667576462b4c427034317234556a5252504e58683349343356496575336765755576486c77433962473569693062307259674136645a4b564354365a7747714e4a6e7a6537344c585453583264593246656c4f4a7576373459336d35592b37564a6c376a7376337a796747366a2b6c4933744547654e4b76536746366b6b6e7077525242744b68755338576e61454a4169746d53374c6b666478575669555157557146556a4e426245576646556b726c354254394244656e764678475a393731794563386334613144516c64357a7a50524a6c326b345644506441746c5542747a485237396858337264344d593665722b4a5539504b356c6c307a396d7670636435686b6a69475953317933794e4d575a6473635a4b7850414b377242786b336a687474306f314b6e7632672f5275484f58675132796742597979396146443962336e436b345962516c6166794c32433574423149574748516b3174786133496e31723153643644496a5045506d414c5a72564d5a724d4d767753566a52356361436871354670354971746c39654362756e6a6c4c7978674b48506b72396f4435675836613741643532363752595248303248654b6a6f435878516c307130614f654449555661493450306862426743465a507976467844704b304a733639507a5858747933794b5936462f694362476f655238694c6d417739644d694d6b5151373449456d4d78796b4e4a495a6931345348784e4c706a76707a6f7846325642646235626f316635624c55394341496a5a4d4f36616f3872685a337263475766574336794c47316165646e33764741396e6d736355542b716d386474624d64416b37704643365071633931626e4e367457634d6864307649493968585500\",\"transaction\":{\"expiration\":\"2023-07-03T14:17:49\",\"ref_block_num\":15146,\"ref_block_prefix\":3154648484,\"max_net_usage_words\":0,\"max_cpu_usage_ms\":0,\"delay_sec\":0,\"context_free_actions\":[],\"actions\":[{\"account\":\"eosio.token\",\"name\":\"transfer\",\"authorization\":[{\"actor\":\"eosio\",\"permission\":\"active\"}],\"data\":{\"from\":\"eosio\",\"to\":\"zeoscontract\",\"quantity\":\"10.0000 EOS\",\"memo\":\"ZEOS MINT\"},\"hex_data\":\"0000000000ea30559091b9795284a9faa08601000000000004454f5300000000095a454f53204d494e54\"},{\"account\":\"eosio.token\",\"name\":\"transfer\",\"authorization\":[{\"actor\":\"eosio\",\"permission\":\"active\"}],\"data\":{\"from\":\"eosio\",\"to\":\"zeoscontract\",\"quantity\":\"10.0000 EOS\",\"memo\":\"ZEOS MINT\"},\"hex_data\":\"0000000000ea30559091b9795284a9faa08601000000000004454f5300000000095a454f53204d494e54\"},{\"account\":\"zeoscontract\",\"name\":\"mint\",\"authorization\":[{\"actor\":\"eosio\",\"permission\":\"active\"}],\"data\":{\"actions\":[{\"cm\":\"2a2c4d4a2875d83f35d4614658f718f8feb3e2f93dd3272721e3b03b71b26605\",\"value\":100000,\"symbol\":\"4,EOS\",\"code\":\"eosio.token\",\"proof\":\"bffdfd919a57fbf6000ed8ebea1ff97f03c6ca348122d22ebbaf802caef9681474a7606653e11f0b6e3d0331cb791b0cc5f5974d4d4b34140ef04377ee729693c24ab18a6008809ab05d1534caa686f2ebb9ca289aa2efe45ee447d8990afe14f7b1a4b7b4bf49ec1bc0a682c615f39e2b761292402b1ccd18e89f3e1c7b0d29c556a4331c00c0431bf470a2f43d59064204b7ac22b196013ab9076f84a23b2f3d43e3d4fbb8d81852a6eed6cdd2d5483f73cade7ccbd0701a20cf42be8fcd0e3177deac42941ee00a3c50fdebcb97a62f36edc0aca70f9fc46811f1827f068f2d91c7254e4296a741c9d57afa5e34149926c31f05e8424a23727525a30b44c8d747414f9470edbf8781b8f889af6df31e492d860e58ecb5afa7716ccd9b200a75e26913c58695a8ace1895958a843fa7a526cfe66d25ccf463ff4c292472c91bdef45078e54437e32bf2aa9e71c530351cb034039129d02d7d5031cb01f54ef95eb15e79674e5a096e7af33ec7c33ea950408de08d35f759ef711e1df18ec0e\"},{\"cm\":\"89a39d9bea68e79209837f0ebed29ce4b333a5572710430c203df5ea6345d11b\",\"value\":100000,\"symbol\":\"4,EOS\",\"code\":\"eosio.token\",\"proof\":\"e25151132a1a70522b3d9c1de03569154aab30b8089b8b3e24e21464eaeadac6b125dff4e6a869dea48e9c3a99be1d147c0d9b9ab5fb88cb66270badabba91ad9ebba09fac7ef4065faded38af3ead500298a13c5ce83778e32923b6225da107929efb8806449db781647e7387542ea0933d93296477dc55b7ef2315579b8d9c2f10e608e8bcb8c4701d631fa60b370392d783b66b7b952f568e58928727097657ea96ecf2a1aea27795d92e1b17716effdff91eb08dcbaa96c2cb5a64b5b7198fc5ee0f71ba3afb1fd22f25a0cbad676db3b885ed7cf4647fe4960606470df547438f454c0f9c9153f062f4e228b80665320dfd8ff73b88ca1f43239872781b68de57136941e5ae9bf41552d95fe74de076302c74f2291e6708299608395b0652aa516f31fd26474d1cbdc6ac50d8c7b5b8d576842cc9c1d652d8071529ddaf13879bb3877f3a2c6501bdd636fa780a00b459a12d6866e840eb0e05d89321abd0efc1544bfdb0efaf5e43b5ace45979e2e84a432fd5a26601d41c6b28f0f908\"}],\"note_ct\":[\"bx4wcAi5rUr0cx739GkHKicz36CIczKwHwPn2x5zOjsZ1yXQh57+ug6Wy7VzXL4W00FGBsfVkls+c7+rRh471Szb6IwALOeYdqXIEXYYtRf+ePXK0DxobDUDvaUnQmQN0sHhG41UVLhYWOPGRdvvtAAtO2xmjmPoZjn5+S1U67psrVsv8xdBXN6RCipVPcJxPb9JcfQKBkdls2seruNdW19ZF1SsP/DKkCrIey7URHlS6ggF6JXp5xIRhiE9aVQxe9bflXubn8fIPoTYv1f27n926DW9jwdawT8deiKmYlkdO4IvZ37xklL37TUPzIdx/qrqvsTx+RGpKWaU/XL/Fgz0+XkYhQZVCbVhqfPyzegA0RsTFHebKoDjLCGQSfoTAtcGOYw47+Z77TbA6BdeeLDPdJhIFTYS1YWgtOBgKNRUB7tlfSQ4L+6j/4KIfk/cmUA6wM1nxhUJGARfoCcK8y9CmtjJTslL5s0B6NXvz/TndQnEGThby0Q1AyUVorHN5QLCTQ2ZR3BCW/835GJcDel8OHAGdNkuDQ8Xa/UBUV8M0enyPVW27DX+sVBkQfxYjH8dhFbs+dVAO6KSDtppmf9+y0D45rKHSpN0oqZvqqmrpnhPEHdalnCvt2M8FDwkdO6rZWJYH7EafGM7xDFAXgTsHRZ46Xdw2tWZYdporwW3VkTFZ5gVgh+vXgGvCDMr4NVKhIRo8r6h4MihZQTLY0rF68D6BrKrlvI1Mk8onLj7p7kRmhN0n5dnxFhBMhUtB11/Wb3bvfsqV1Gokj9lyktI6oekBVzrRaku73/fh4wdaWwmYAiABbdMfwSBnN5juc3K1oSJ6/fNfyvMlBYnesXSBI0nsLd7H2SqydGZQVvyqVLB730bOvLgP8nBLiBSDMnYQN/I4/RzJKRQi+nLEZxR6qt7eMDgSJoXw+pQAZU1TnXAsSeTBJ3t+RFnDnHm+dC5wOhxyUJOTbEEqyftaB676PFa00seXDLk\",\"bl6LqQBSxt/YqR3/KyBcrnwCJfv1tYtEBo7WeuJob1YgqLsxXiUshYm56B3xF9jqSCfxAzGMnhywNoYxAVQ8oC3K43B6YbCCC5oUYBL68yW+aU2Vn0mq1je+R7cqyKjTbk4qVPk1b1cquXwzuzWqdSrRMMjWydqfx02Cxn+Ra2YykqOzX4A2ZRU/FA2QWaLQQK71OdOYGzfD6ySj7cRSa13ESvoeWOXn/b5rKwXeI19aaJSZyFxGjRnWRUAlUbJilJw17mtE0RgOUyzw15zJAJfVR5Ww812G0OS7jwcm/tuFSFkVuVuHyUCw9lnKMllS4rTmFJ5/Bn8pibhidlwSeCfuUQPkx3x3pJfzw9fuvF+LBp41r4UjRRPNXh3I43VIeu3geuUvHlwC9bG5ii0b0rYgA6dZKVCT6ZwGqNJnze74LXTSX2dY2FelOJuv74Y3m5Y+7VJl7jsv3zygG6j+lI3tEGeNKvSgF6kknpwRRBtKhuS8WnaEJAitmS7LkfdxWViUQWUqFUjNBbEWfFUkrl5BT9BDenvFxGZ971yEc8c4a1DQld5zzPRJl2k4VDPdAtlUBtzHR79hX3rd4MY6er+JU9PK5ll0z9mvpcd5hkjiGYS1y3yNMWZdscZKxPAK7rBxk3jhtt0o1Knv2g/RuHOXgQ2ygBYyy9aFD9b3nCk4YbQlafyL2C5tB1IWGHQk1txa3In1r1Sd6DIjPEPmALZrVMZrMMvwSVjR5caChq5Fp5Iqtl9eCbunjlLyxgKHPkr9oD5gX6a7Ad5267RYRH02HeKjoCXxQl0q0aOeDIUVaI4P0hbBgCFZPyvFxDpK0Js69PzXXty3yKY6F/iCbGoeR8iLmAw9dMiMkQQ74IEmMxykNJIZi14SHxNLpjvpzoxF2VBdb5bo1f5bLU9CAIjZMO6ao8rhZ3rcGWfWC6yLG1aedn3vGA9nmscUT+qm8dtbMdAk7pFC6Pqc91bnN6tWcMhd0vII9hXU\"]},\"hex_data\":\"02202a2c4d4a2875d83f35d4614658f718f8feb3e2f93dd3272721e3b03b71b26605a08601000000000004454f530000000000a6823403ea30558003bffdfd919a57fbf6000ed8ebea1ff97f03c6ca348122d22ebbaf802caef9681474a7606653e11f0b6e3d0331cb791b0cc5f5974d4d4b34140ef04377ee729693c24ab18a6008809ab05d1534caa686f2ebb9ca289aa2efe45ee447d8990afe14f7b1a4b7b4bf49ec1bc0a682c615f39e2b761292402b1ccd18e89f3e1c7b0d29c556a4331c00c0431bf470a2f43d59064204b7ac22b196013ab9076f84a23b2f3d43e3d4fbb8d81852a6eed6cdd2d5483f73cade7ccbd0701a20cf42be8fcd0e3177deac42941ee00a3c50fdebcb97a62f36edc0aca70f9fc46811f1827f068f2d91c7254e4296a741c9d57afa5e34149926c31f05e8424a23727525a30b44c8d747414f9470edbf8781b8f889af6df31e492d860e58ecb5afa7716ccd9b200a75e26913c58695a8ace1895958a843fa7a526cfe66d25ccf463ff4c292472c91bdef45078e54437e32bf2aa9e71c530351cb034039129d02d7d5031cb01f54ef95eb15e79674e5a096e7af33ec7c33ea950408de08d35f759ef711e1df18ec0e2089a39d9bea68e79209837f0ebed29ce4b333a5572710430c203df5ea6345d11ba08601000000000004454f530000000000a6823403ea30558003e25151132a1a70522b3d9c1de03569154aab30b8089b8b3e24e21464eaeadac6b125dff4e6a869dea48e9c3a99be1d147c0d9b9ab5fb88cb66270badabba91ad9ebba09fac7ef4065faded38af3ead500298a13c5ce83778e32923b6225da107929efb8806449db781647e7387542ea0933d93296477dc55b7ef2315579b8d9c2f10e608e8bcb8c4701d631fa60b370392d783b66b7b952f568e58928727097657ea96ecf2a1aea27795d92e1b17716effdff91eb08dcbaa96c2cb5a64b5b7198fc5ee0f71ba3afb1fd22f25a0cbad676db3b885ed7cf4647fe4960606470df547438f454c0f9c9153f062f4e228b80665320dfd8ff73b88ca1f43239872781b68de57136941e5ae9bf41552d95fe74de076302c74f2291e6708299608395b0652aa516f31fd26474d1cbdc6ac50d8c7b5b8d576842cc9c1d652d8071529ddaf13879bb3877f3a2c6501bdd636fa780a00b459a12d6866e840eb0e05d89321abd0efc1544bfdb0efaf5e43b5ace45979e2e84a432fd5a26601d41c6b28f0f90802e4076278347763416935725572306378373339476b484b69637a33364349637a4b774877506e3278357a4f6a735a317958516835372b756736577937567a584c345730304647427366566b6c732b63372b725268343731537a62364977414c4f655964715849455859597452662b6550584b3044786f624455447661556e516d514e3073486847343155564c6859574f504752647676744141744f32786d6a6d506f5a6a6e352b533155363770737256737638786442584e36524369705650634a785062394a6366514b426b646c7332736572754e645731395a46315373502f444b6b4372496579375552486c5336676746364a5870357849526869453961565178653962666c5875626e386649506f545976316632376e3932364457396a7764617754386465694b6d596c6b644f3449765a3337786b6c4c33375455507a4964782f717271767354782b5247704b5761552f584c2f46677a302b586b5968515a5643625668716650797a65674130527354464865624b6f446a4c43475153666f54417463474f597734372b5a373754624136426465654c4450644a68494654595331595767744f42674b4e52554237746c665351344c2b366a2f344b49666b2f636d554136774d316e7868554a474152666f43634b387939436d746a4a54736c4c35733042364e58767a2f546e64516e454754686279305131417955566f72484e35514c435451325a52334243572f383335474a6344656c384f484147644e6b7544513858612f55425556384d30656e79505657323744582b7356426b516678596a483864684662732b6456414f364b53447470706d66392b7930443435724b4853704e306f715a7671716d72706e6850454864616c6e437674324d384644776b644f36725a574a594837456166474d37784446415867547348525a34365864773274575a5964706f72775733566b54465a35675667682b765867477643444d72344e564b6849526f38723668344d69685a51544c593072463638443642724b726c7649314d6b386f6e4c6a3770376b526d684e306e35646e784668424d6855744231312f57623362766673715631476f6b6a396c796b7449366f656b42567a7252616b7537332f66683477646157776d594169414262644d667753426e4e356a7563334b316f534a362f664e6679764d6c42596e657358534249306e734c6437483253717964475a5156767971564c42373330624f764c6750386e424c694253444d6e59514e2f49342f527a4a4b5251692b6e4c455a785236717437654d4467534a6f58772b7051415a5531546e584173536554424a33742b52466e446e486d2b644335774f687879554a4f546245457179667461423637365046613030736558444c6be407626c364c7151425378742f597152332f4b794263726e77434a66763174597445426f375765754a6f62315967714c73785869557368596d353642337846396a7153436678417a474d6e6879774e6f5978415651386f43334b343342365962434343356f5559424c363879572b615532566e306d71316a652b52376371794b6a54626b347156506b31623163717558777a757a5771645372524d4d6a577964716678303243786e2b52613259796b714f7a583441325a52552f4641325157614c51514b37314f644f59477a66443679536a376352536131334553766f65574f586e2f6235724b77586549313961614a535a794678476a526e575255416c55624a696c4a7731376d74453052674f55797a7731357a4a414a66565235577738313247304f53376a77636d2f74754653466b567556754879554377396c6e4b4d6c6c533472546d464a352f426e387069626869646c7753654366755551506b78337833704a667a7739667576462b4c427034317234556a5252504e58683349343356496575336765755576486c77433962473569693062307259674136645a4b564354365a7747714e4a6e7a6537344c585453583264593246656c4f4a7576373459336d35592b37564a6c376a7376337a796747366a2b6c4933744547654e4b76536746366b6b6e7077525242744b68755338576e61454a4169746d53374c6b666478575669555157557146556a4e426245576646556b726c354254394244656e764678475a393731794563386334613144516c64357a7a50524a6c326b345644506441746c5542747a485237396858337264344d593665722b4a5539504b356c6c307a396d7670636435686b6a69475953317933794e4d575a6473635a4b7850414b377242786b336a687474306f314b6e7632672f5275484f58675132796742597979396146443962336e436b345962516c6166794c32433574423149574748516b3174786133496e31723153643644496a5045506d414c5a72564d5a724d4d767753566a52356361436871354670354971746c39654362756e6a6c4c7978674b48506b72396f4435675836613741643532363752595248303248654b6a6f435878516c307130614f654449555661493450306862426743465a507976467844704b304a733639507a5858747933794b5936462f694362476f655238694c6d417739644d694d6b5151373449456d4d78796b4e4a495a6931345348784e4c706a76707a6f7846325642646235626f316635624c55394341496a5a4d4f36616f3872685a337263475766574336794c47316165646e33764741396e6d736355542b716d386474624d64416b37704643365071633931626e4e367457634d68643076494939685855\"}]}}}],\"id\":\"00003b2c1e2d163c1b3348ca15002a50451d0ad703e1a8dda4dcb190596ab95d\",\"block_num\":15148,\"ref_block_prefix\":3393729307}",
            "{\"timestamp\":\"2023-07-03T14:21:19.500\",\"producer\":\"eosio\",\"confirmed\":0,\"previous\":\"00003d0aca04864d2a1c06c64b65e5890d63d81169bea501597cab196ee4cdcd\",\"transaction_mroot\":\"ce6be49ad4236f6af3e611044bb272f373611de40157d4b0a51c2c9acd8345a0\",\"action_mroot\":\"d3d3a498c01f9ac8e430aeadf4f6cf33bca65b29cbea8add59046ab452710067\",\"schedule_version\":0,\"new_producers\":null,\"producer_signature\":\"SIG_K1_JyEo6NXreJ1HNdvgpucrcL1M7i4dnzzxbmKyCra4QTcs3nMS6MrvwrhYD3xeaHEYJjrGFYVgWjE7ro5BhXotzmxMHxHWLA\",\"transactions\":[{\"status\":\"executed\",\"cpu_usage_us\":5160,\"net_usage_words\":202,\"trx\":{\"id\":\"065a637b287b690a40b5ab5849ee0e711ae19c5eb5f7ffa3e4d5e510ea536c90\",\"signatures\":[\"SIG_K1_KebjKqjaM5ano7Z4ENNQEavaWhsLrzTyMpTZWaTjg8x9UFPvd8m8iRkoFSicg2X1dwuQxgsjoqBAUmDsUCPgN8zZNHC5Rv\"],\"compression\":\"none\",\"packed_context_free_data\":\"\",\"context_free_data\":[],\"packed_trx\":\"7dd9a264093d8ba5a7dc000000000200a6823403ea3055000000572d3ccdcd010000000000ea305500000000a8ed32322a0000000000ea30559091b9795284a9faa08601000000000004454f5300000000095a454f53204d494e549091b9795284a9fa000000000090a793010000000000ea305500000000a8ed3232a30b01209e1af72ab60fe1dd57cc605f8b9c73865a4f692fc9f8e78527cee869d23d136fa08601000000000004454f530000000000a6823403ea30558003a855b0c2bc9841094de8bd0aa0bfeae2ebcd72a44d130565163991092dfe793144c7f0dacc85245d0380bf5ff5670114e022dc226955bfd87bdf2cf147b41fc62631117ad9ad766dbdcd3d36b753641f25c125d529539be97c2afb534666140abb4fbb9379d7fe28ae7336cdc6098da79b95a5b849ca5c10d2976d57e7053aa0433aa926784924d08f1d3b82e27fe710e01108cb300fd853941511456689c7ee76cfa3de7f02e68165b314433b99b46a192e021e2306ca3211fa7e42357601071a9608703a282fea9f5f0325a218d92dfc1a823a3a262af7e2efa38d58dfdfa4472a014f2668266b5dc18ef060a7db06fe93f94acce35e9f98fa24e89c7423923395597217bfc6d1c472822c06c014cc56568cddd0d7e5a5f05fa2449c6cba1298490f3d0841aa0a9b64177e86232da679cc364d682c2a951c94652f523f92e6fe7edff58d3607b9d5e4dbbf5e39d90690d7bf5c34d7bcfc1fea9f11f9a0598d79895c3ab2be7ecc45e4db3f09eec50768e1058f461dbfbccc79a11f2410b20901e407746c6f642f77544a61322b64732b6d7a654c474654726a6770544477776e74515a4545575555304435314f6c552b6938744155684a7267667839687a6630364f365963595a767145574c4d6e476c714e5541544863663055385a33446d497746532b59532f4e544d2b4e6b533162376b352f334f356b334d475936767335434e426b52675439556b7849546475752f6a714366346f5144487a3572706c5269617a685458552b646358476a6f7952596231345855696e2b4c564b757361377276725a33454f5265634951395045475564797144476e546a434c636f5366484f364e4c4a6f55665235494733504977596a3164634f656e49564c3548666a62654f723063544f4a376e4472362f4a626a6f726d76506a553063776446324a2b5a323377734f64537973736d6d5572535859766d7958734f75335a3469644c79334d5846514e766975542f346f7a377a3871485833552f6347473535364d6f7a362b785a314531304246646b514755647046624859464b59754e755974306a2f5a62434d48706c4a6d426b6d3754706f356155443939594731464b557568374d4e7a3737502b677176703933685569613752764b4b4e534b6a4a7668764a3133654b52713345724746746272346b6a78477a784e51694e4155375269764e55594c55744e36656e6877393741636843764e414b314e64454a4d6a312f3654306733312f5839744a3166373534482b6f4c4337586266385362356c56344e397654434f61742f516d786c74467175646c5a482f4c6c65634462566a4b5a784c634a3063334f6a35553578754a6b535346416b6943686837526d3839576d74624d5a67455437576373384a484255796c75646734363039534b6c45635876626f356575674a3771434637356e45637232434745387a624779506943456f47426938425032424864796e546b4d4d4d6848775469594a6143566b61544d793344595a3350733943426f74576c54694f653135626d6f4c4858794b4e5868722f6e534e35466e703176326d30366d2f2b78523358594c3134485357363647354c34624e34436a445835486b3244424b304a565a3673627330374650312b6972427435674e5a32576f6b4a487347597853483773766a547072336f654e3668536133324f674466387742727335367271705247355859524474666a48656934424c462f654b666c5078474c436d556a38346a314363504e3663516132784551516d3937326d3648657738316c32347070374971672f77654a564d565562556e34664d42643456424568704b78782b6a666e375051485332576c307a52757639732b365a7a4a46577a6a56654771504854612f44776e4d7441566237657873374f356766716e566c51416d6900\",\"transaction\":{\"expiration\":\"2023-07-03T14:21:49\",\"ref_block_num\":15625,\"ref_block_prefix\":3701974411,\"max_net_usage_words\":0,\"max_cpu_usage_ms\":0,\"delay_sec\":0,\"context_free_actions\":[],\"actions\":[{\"account\":\"eosio.token\",\"name\":\"transfer\",\"authorization\":[{\"actor\":\"eosio\",\"permission\":\"active\"}],\"data\":{\"from\":\"eosio\",\"to\":\"zeoscontract\",\"quantity\":\"10.0000 EOS\",\"memo\":\"ZEOS MINT\"},\"hex_data\":\"0000000000ea30559091b9795284a9faa08601000000000004454f5300000000095a454f53204d494e54\"},{\"account\":\"zeoscontract\",\"name\":\"mint\",\"authorization\":[{\"actor\":\"eosio\",\"permission\":\"active\"}],\"data\":{\"actions\":[{\"cm\":\"9e1af72ab60fe1dd57cc605f8b9c73865a4f692fc9f8e78527cee869d23d136f\",\"value\":100000,\"symbol\":\"4,EOS\",\"code\":\"eosio.token\",\"proof\":\"a855b0c2bc9841094de8bd0aa0bfeae2ebcd72a44d130565163991092dfe793144c7f0dacc85245d0380bf5ff5670114e022dc226955bfd87bdf2cf147b41fc62631117ad9ad766dbdcd3d36b753641f25c125d529539be97c2afb534666140abb4fbb9379d7fe28ae7336cdc6098da79b95a5b849ca5c10d2976d57e7053aa0433aa926784924d08f1d3b82e27fe710e01108cb300fd853941511456689c7ee76cfa3de7f02e68165b314433b99b46a192e021e2306ca3211fa7e42357601071a9608703a282fea9f5f0325a218d92dfc1a823a3a262af7e2efa38d58dfdfa4472a014f2668266b5dc18ef060a7db06fe93f94acce35e9f98fa24e89c7423923395597217bfc6d1c472822c06c014cc56568cddd0d7e5a5f05fa2449c6cba1298490f3d0841aa0a9b64177e86232da679cc364d682c2a951c94652f523f92e6fe7edff58d3607b9d5e4dbbf5e39d90690d7bf5c34d7bcfc1fea9f11f9a0598d79895c3ab2be7ecc45e4db3f09eec50768e1058f461dbfbccc79a11f2410b209\"}],\"note_ct\":[\"tlod/wTJa2+ds+mzeLGFTrjgpTDwwntQZEEWUU0D51OlU+i8tAUhJrgfx9hzf06O6YcYZvqEWLMnGlqNUATHcf0U8Z3DmIwFS+YS/NTM+NkS1b7k5/3O5k3MGY6vs5CNBkRgT9UkxITduu/jqCf4oQDHz5rplRiazhTXU+dcXGjoyRYb14XUin+LVKusa7rvrZ3EORecIQ9PEGUdyqDGnTjCLcoSfHO6NLJoUfR5IG3PIwYj1dcOenIVL5HfjbeOr0cTOJ7nDr6/JbjormvPjU0cwdF2J+Z23wsOdSyssmmUrSXYvmyXsOu3Z4idLy3MXFQNviuT/4oz7z8qHX3U/cGG556Moz6+xZ1E10BFdkQGUdpFbHYFKYuNuYt0j/ZbCMHplJmBkm7Tpo5aUD99YG1FKUuh7MNz77P+gqvp93hUia7RvKKNSKjJvhvJ13eKRq3ErGFtbr4kjxGzxNQiNAU7RivNUYLUtN6enhw97AchCvNAK1NdEJMj1/6T0g31/X9tJ1f754H+oLC7Xbf8Sb5lV4N9vTCOat/QmxltFqudlZH/LlecDbVjKZxLcJ0c3Oj5U5xuJkSSFAkiChh7Rm89WmtbMZgET7Wcs8JHBUyludg4609SKlEcXvbo5eugJ7qCF75nEcr2CGE8zbGyPiCEoGBi8BP2BHdynTkMMMhHwTiYJaCVkaTMy3DYZ3Ps9CBotWlTiOe15bmoLHXyKNXhr/nSN5Fnp1v2m06m/+xR3XYL14HSW66G5L4bN4CjDX5Hk2DBK0JVZ6sbs07FP1+irBt5gNZ2WokJHsGYxSH7svjTpr3oeN6hSa32OgDf8wBrs56rqpRG5XYRDtfjHei4BLF/eKflPxGLCmUj84j1CcPN6cQa2xEQQm972m6Hew81l24pp7Iqg/weJVMVUbUn4fMBd4VBEhpKxx+jfn7PQHS2Wl0zRuv9s+6ZzJFWzjVeGqPHTa/DwnMtAVb7exs7O5gfqnVlQAmi\"]},\"hex_data\":\"01209e1af72ab60fe1dd57cc605f8b9c73865a4f692fc9f8e78527cee869d23d136fa08601000000000004454f530000000000a6823403ea30558003a855b0c2bc9841094de8bd0aa0bfeae2ebcd72a44d130565163991092dfe793144c7f0dacc85245d0380bf5ff5670114e022dc226955bfd87bdf2cf147b41fc62631117ad9ad766dbdcd3d36b753641f25c125d529539be97c2afb534666140abb4fbb9379d7fe28ae7336cdc6098da79b95a5b849ca5c10d2976d57e7053aa0433aa926784924d08f1d3b82e27fe710e01108cb300fd853941511456689c7ee76cfa3de7f02e68165b314433b99b46a192e021e2306ca3211fa7e42357601071a9608703a282fea9f5f0325a218d92dfc1a823a3a262af7e2efa38d58dfdfa4472a014f2668266b5dc18ef060a7db06fe93f94acce35e9f98fa24e89c7423923395597217bfc6d1c472822c06c014cc56568cddd0d7e5a5f05fa2449c6cba1298490f3d0841aa0a9b64177e86232da679cc364d682c2a951c94652f523f92e6fe7edff58d3607b9d5e4dbbf5e39d90690d7bf5c34d7bcfc1fea9f11f9a0598d79895c3ab2be7ecc45e4db3f09eec50768e1058f461dbfbccc79a11f2410b20901e407746c6f642f77544a61322b64732b6d7a654c474654726a6770544477776e74515a4545575555304435314f6c552b6938744155684a7267667839687a6630364f365963595a767145574c4d6e476c714e5541544863663055385a33446d497746532b59532f4e544d2b4e6b533162376b352f334f356b334d475936767335434e426b52675439556b7849546475752f6a714366346f5144487a3572706c5269617a685458552b646358476a6f7952596231345855696e2b4c564b757361377276725a33454f5265634951395045475564797144476e546a434c636f5366484f364e4c4a6f55665235494733504977596a3164634f656e49564c3548666a62654f723063544f4a376e4472362f4a626a6f726d76506a553063776446324a2b5a323377734f64537973736d6d5572535859766d7958734f75335a3469644c79334d5846514e766975542f346f7a377a3871485833552f6347473535364d6f7a362b785a314531304246646b514755647046624859464b59754e755974306a2f5a62434d48706c4a6d426b6d3754706f356155443939594731464b557568374d4e7a3737502b677176703933685569613752764b4b4e534b6a4a7668764a3133654b52713345724746746272346b6a78477a784e51694e4155375269764e55594c55744e36656e6877393741636843764e414b314e64454a4d6a312f3654306733312f5839744a3166373534482b6f4c4337586266385362356c56344e397654434f61742f516d786c74467175646c5a482f4c6c65634462566a4b5a784c634a3063334f6a35553578754a6b535346416b6943686837526d3839576d74624d5a67455437576373384a484255796c75646734363039534b6c45635876626f356575674a3771434637356e45637232434745387a624779506943456f47426938425032424864796e546b4d4d4d6848775469594a6143566b61544d793344595a3350733943426f74576c54694f653135626d6f4c4858794b4e5868722f6e534e35466e703176326d30366d2f2b78523358594c3134485357363647354c34624e34436a445835486b3244424b304a565a3673627330374650312b6972427435674e5a32576f6b4a487347597853483773766a547072336f654e3668536133324f674466387742727335367271705247355859524474666a48656934424c462f654b666c5078474c436d556a38346a314363504e3663516132784551516d3937326d3648657738316c32347070374971672f77654a564d565562556e34664d42643456424568704b78782b6a666e375051485332576c307a52757639732b365a7a4a46577a6a56654771504854612f44776e4d7441566237657873374f356766716e566c51416d69\"}]}}}],\"id\":\"00003d0b220c35d7738c22470ddc50e1ad600fa3a4b6b5391996bb143fb7feb2\",\"block_num\":15627,\"ref_block_prefix\":1193446515}",
            "{\"timestamp\":\"2023-07-03T14:23:41.500\",\"producer\":\"eosio\",\"confirmed\":0,\"previous\":\"00003e26dc347f07cc0c4745a9f18c3de49b63039dfbe7b12fe2be496e00f47b\",\"transaction_mroot\":\"bdeff298ce490e701a02d6675aebd6010a5927158b178de307fd8140edc17d16\",\"action_mroot\":\"3187919b7804520514d28981cbba485d5cfff2cc4cec4d9da6b8b3ec4d2a33fa\",\"schedule_version\":0,\"new_producers\":null,\"producer_signature\":\"SIG_K1_JyxG7oGZNDZALbGu6gbiMZPv1UNwdbFp3aCqw1DvZie63sTrGbsfLRyu4RgfAMT7gkjWy58uRzB8q1yPHoRv7wtSFEz91A\",\"transactions\":[{\"status\":\"executed\",\"cpu_usage_us\":1862,\"net_usage_words\":202,\"trx\":{\"id\":\"3149c75ab1dcf411e8cd4d0520c691f78b26ae5e501dd04db0d55e548f69fe7a\",\"signatures\":[\"SIG_K1_Kc36TZJLvPbw5UBaTubV7tsGsUFKX4RD1YGFaUDVxo2niWaTAasBXBiHrHD4QjcmELNxzsa2Q8a7Mx3kwVV9pBJ7MKqzdQ\"],\"compression\":\"none\",\"packed_context_free_data\":\"\",\"context_free_data\":[],\"packed_trx\":\"0bdaa264253e097fa8ca000000000200a6823403ea3055000000572d3ccdcd010000000000ea305500000000a8ed32322a0000000000ea30559091b9795284a9faa08601000000000004454f5300000000095a454f53204d494e549091b9795284a9fa000000000090a793010000000000ea305500000000a8ed3232a30b0120564937a38ab594aa3b63a340621b6fae6472ec634beb9de918cadbb864185a43a08601000000000004454f530000000000a6823403ea305580032b61c63c5d419f5f0472dd908303a852bd2d104fde1e98c5a03f26b73cc4b5cfd371cd32c7a72463e1e4c01f6b6f61131c9eea2643087bd50f2b2c1c1be872f82f121deaef9a7aaf56c5c01fbd3fb54f9febbe87e247e392f6bf326da41d640f0618508027fa301020e37041fc9a022ac48fffcb4cec110eb1e03903dcfe4ba3ccdf5ca42b137bba431ad4df890535047089593d0457d7331989f6817a124571a6060159e5e037f67f9237276fbb2c807bec43a8745c3d00e5e109a2f48a8c06ffae294517faf856ee7ed876d358b5f287751da3737e9362ccf24a065adb703c1b6ae574ff7a54a8718fe657b7584c135f1c5d386b0948490968bfff4b9fe165ace97ceef0d703d9b5940f6878c4294f76b645c357d586a4b220d5ba1c59f718425847ebae55de102462767f022cfa90f98ba301e31fa2c315e91d1c0a0666175adb47a7f729e81b16b2107c1b880b18ab59457a05c03e59529f6bbc3423c3187b7724fab8b284d1214976228dd42f9792886f6a9d1a76cb98a6b1072baf051101e407727951766d4e7377612b37656776506f357768694b4d59616a626c574d503658682f43474a78643952346270304932365439487935705765487235507a6a703374635466484a774a4352786637426d526b6642617955446b2b576169625844664a755673694d796f4e506b395179792f523759506d4d48646d3939756865704f54316f615966674d2b4f4a4b56555864376b4f3333484953734d6c6d6a36542b47323456467163653234336742735a4154534c775547694a6e7a5748584a55623335792b2b3663585676527a4853777747665361674942515459733431725135374a625559696b6b686b5654577a3965354f75584a56422f4f3344696e6962454951486e325a507a4b76684179506b616f67483670364e75786f7449636e346f2b59465477474b6b7842644353364e497733387834775738736e31784e45732b6c665068633741676461695a45332b5847306575756346676f747a554e4d374958493673454870667877592b5130686e7942716e532b4f4e71745236367139502b6752306e62623878796a4247662b51675a2f41334e705330444145462b58593138756563616e49356d7a48434c6d5155555761356b667a5559526231784d74344174556a317362724e4f4e634f744f3536656d5a55355666346b374e71546b5958324d74636a6e592b47767967374c58564346395a68356b4134626945635362686a6e494b796b482b4664614c3254376465356c4e5557332b455554384556547a3176756f675766684b4c6d52524f55445472496c4c4d39655477354e506835334e6737317771397854394468484c4c6e686e696e307771707647463637654d64646e71374a79686c506c693434724d634e6537656b7337307752373830486c34375a413275584f6c7433547a322f595077496e56465446697846394c3034412b4a31727a48746f69674878583148534833567447302b3378712f49614b2b4c6263482b726f44325a7a546c686f4430676a72733446676342537079494d554b5948447954724a436c3763344c4e425a58795947577a647167522f79594f78434b6c6c2b467333396f304b62766136594156623437474232786e3230364d32662b742f6a4844314d645455426c4f2b3744515277684245704f51587835456a466f73613676693835442b396a6f53447367723031613232584d5271373066656e6a374a5863675245426d6d6d7844336a516a773345492f38485457392f417555625636654b555a764c67424d7675444b5764794a475836347a595a4477782f5154685362696f473335525a6b4c616f6c764b577277756a6d314a756c435a383830616e4649354a6961337733796e534e4f313062303176554d735470423262426b6a7200\",\"transaction\":{\"expiration\":\"2023-07-03T14:24:11\",\"ref_block_num\":15909,\"ref_block_prefix\":3400040201,\"max_net_usage_words\":0,\"max_cpu_usage_ms\":0,\"delay_sec\":0,\"context_free_actions\":[],\"actions\":[{\"account\":\"eosio.token\",\"name\":\"transfer\",\"authorization\":[{\"actor\":\"eosio\",\"permission\":\"active\"}],\"data\":{\"from\":\"eosio\",\"to\":\"zeoscontract\",\"quantity\":\"10.0000 EOS\",\"memo\":\"ZEOS MINT\"},\"hex_data\":\"0000000000ea30559091b9795284a9faa08601000000000004454f5300000000095a454f53204d494e54\"},{\"account\":\"zeoscontract\",\"name\":\"mint\",\"authorization\":[{\"actor\":\"eosio\",\"permission\":\"active\"}],\"data\":{\"actions\":[{\"cm\":\"564937a38ab594aa3b63a340621b6fae6472ec634beb9de918cadbb864185a43\",\"value\":100000,\"symbol\":\"4,EOS\",\"code\":\"eosio.token\",\"proof\":\"2b61c63c5d419f5f0472dd908303a852bd2d104fde1e98c5a03f26b73cc4b5cfd371cd32c7a72463e1e4c01f6b6f61131c9eea2643087bd50f2b2c1c1be872f82f121deaef9a7aaf56c5c01fbd3fb54f9febbe87e247e392f6bf326da41d640f0618508027fa301020e37041fc9a022ac48fffcb4cec110eb1e03903dcfe4ba3ccdf5ca42b137bba431ad4df890535047089593d0457d7331989f6817a124571a6060159e5e037f67f9237276fbb2c807bec43a8745c3d00e5e109a2f48a8c06ffae294517faf856ee7ed876d358b5f287751da3737e9362ccf24a065adb703c1b6ae574ff7a54a8718fe657b7584c135f1c5d386b0948490968bfff4b9fe165ace97ceef0d703d9b5940f6878c4294f76b645c357d586a4b220d5ba1c59f718425847ebae55de102462767f022cfa90f98ba301e31fa2c315e91d1c0a0666175adb47a7f729e81b16b2107c1b880b18ab59457a05c03e59529f6bbc3423c3187b7724fab8b284d1214976228dd42f9792886f6a9d1a76cb98a6b1072baf0511\"}],\"note_ct\":[\"ryQvmNswa+7egvPo5whiKMYajblWMP6Xh/CGJxd9R4bp0I26T9Hy5pWeHr5Pzjp3tcTfHJwJCRxf7BmRkfBayUDk+WaibXDfJuVsiMyoNPk9Qyy/R7YPmMHdm99uhepOT1oaYfgM+OJKVUXd7kO33HISsMlmj6T+G24VFqce243gBsZATSLwUGiJnzWHXJUb35y++6cXVvRzHSwwGfSagIBQTYs41rQ57JbUYikkhkVTWz9e5OuXJVB/O3DinibEIQHn2ZPzKvhAyPkaogH6p6NuxotIcn4o+YFTwGKkxBdCS6NIw38x4wW8sn1xNEs+lfPhc7AgdaiZE3+XG0euucFgotzUNM7IXI6sEHpfxwY+Q0hnyBqnS+ONqtR66q9P+gR0nbb8xyjBGf+QgZ/A3NpS0DAEF+XY18uecanI5mzHCLmQUUWa5kfzUYRb1xMt4AtUj1sbrNONcOtO56emZU5Vf4k7NqTkYX2MtcjnY+Gvyg7LXVCF9Zh5kA4biEcSbhjnIKykH+FdaL2T7de5lNUW3+EUT8EVTz1vuogWfhKLmRROUDTrIlLM9eTw5NPh53Ng71wq9xT9DhHLLnhnin0wqpvGF67eMddnq7JyhlPli44rMcNe7eks70wR780Hl47ZA2uXOlt3Tz2/YPwInVFTFixF9L04A+J1rzHtoigHxX1HSH3VtG0+3xq/IaK+LbcH+roD2ZzTlhoD0gjrs4FgcBSpyIMUKYHDyTrJCl7c4LNBZXyYGWzdqgR/yYOxCKll+Fs39o0Kbva6YAVb47GB2xn206M2f+t/jHD1MdTUBlO+7DQRwhBEpOQXx5EjFosa6vi85D+9joSDsgr01a22XMRq70fenj7JXcgREBmmmxD3jQjw3EI/8HTW9/AuUbV6eKUZvLgBMvuDKWdyJGX64zYZDwx/QThSbioG35RZkLaolvKWrwujm1JulCZ880anFI5Jia3w3ynSNO10b01vUMsTpB2bBkjr\"]},\"hex_data\":\"0120564937a38ab594aa3b63a340621b6fae6472ec634beb9de918cadbb864185a43a08601000000000004454f530000000000a6823403ea305580032b61c63c5d419f5f0472dd908303a852bd2d104fde1e98c5a03f26b73cc4b5cfd371cd32c7a72463e1e4c01f6b6f61131c9eea2643087bd50f2b2c1c1be872f82f121deaef9a7aaf56c5c01fbd3fb54f9febbe87e247e392f6bf326da41d640f0618508027fa301020e37041fc9a022ac48fffcb4cec110eb1e03903dcfe4ba3ccdf5ca42b137bba431ad4df890535047089593d0457d7331989f6817a124571a6060159e5e037f67f9237276fbb2c807bec43a8745c3d00e5e109a2f48a8c06ffae294517faf856ee7ed876d358b5f287751da3737e9362ccf24a065adb703c1b6ae574ff7a54a8718fe657b7584c135f1c5d386b0948490968bfff4b9fe165ace97ceef0d703d9b5940f6878c4294f76b645c357d586a4b220d5ba1c59f718425847ebae55de102462767f022cfa90f98ba301e31fa2c315e91d1c0a0666175adb47a7f729e81b16b2107c1b880b18ab59457a05c03e59529f6bbc3423c3187b7724fab8b284d1214976228dd42f9792886f6a9d1a76cb98a6b1072baf051101e407727951766d4e7377612b37656776506f357768694b4d59616a626c574d503658682f43474a78643952346270304932365439487935705765487235507a6a703374635466484a774a4352786637426d526b6642617955446b2b576169625844664a755673694d796f4e506b395179792f523759506d4d48646d3939756865704f54316f615966674d2b4f4a4b56555864376b4f3333484953734d6c6d6a36542b47323456467163653234336742735a4154534c775547694a6e7a5748584a55623335792b2b3663585676527a4853777747665361674942515459733431725135374a625559696b6b686b5654577a3965354f75584a56422f4f3344696e6962454951486e325a507a4b76684179506b616f67483670364e75786f7449636e346f2b59465477474b6b7842644353364e497733387834775738736e31784e45732b6c665068633741676461695a45332b5847306575756346676f747a554e4d374958493673454870667877592b5130686e7942716e532b4f4e71745236367139502b6752306e62623878796a4247662b51675a2f41334e705330444145462b58593138756563616e49356d7a48434c6d5155555761356b667a5559526231784d74344174556a317362724e4f4e634f744f3536656d5a55355666346b374e71546b5958324d74636a6e592b47767967374c58564346395a68356b4134626945635362686a6e494b796b482b4664614c3254376465356c4e5557332b455554384556547a3176756f675766684b4c6d52524f55445472496c4c4d39655477354e506835334e6737317771397854394468484c4c6e686e696e307771707647463637654d64646e71374a79686c506c693434724d634e6537656b7337307752373830486c34375a413275584f6c7433547a322f595077496e56465446697846394c3034412b4a31727a48746f69674878583148534833567447302b3378712f49614b2b4c6263482b726f44325a7a546c686f4430676a72733446676342537079494d554b5948447954724a436c3763344c4e425a58795947577a647167522f79594f78434b6c6c2b467333396f304b62766136594156623437474232786e3230364d32662b742f6a4844314d645455426c4f2b3744515277684245704f51587835456a466f73613676693835442b396a6f53447367723031613232584d5271373066656e6a374a5863675245426d6d6d7844336a516a773345492f38485457392f417555625636654b555a764c67424d7675444b5764794a475836347a595a4477782f5154685362696f473335525a6b4c616f6c764b577277756a6d314a756c435a383830616e4649354a6961337733796e534e4f313062303176554d735470423262426b6a72\"}]}}}],\"id\":\"00003e27a431020af377f4dfcf4d5eb429418c85994075034f1d4886629010d2\",\"block_num\":15911,\"ref_block_prefix\":3757340659}",
            "{\"timestamp\":\"2023-07-03T14:26:16.500\",\"producer\":\"eosio\",\"confirmed\":0,\"previous\":\"00003f5c2fde8913710da5b663889935a1348a24aec6eeafc042c153c6a26fa4\",\"transaction_mroot\":\"7514eb675d1c31a735d672c25267887a17aa0eeca0da622c31bc39f75b93c03c\",\"action_mroot\":\"60687dde727699bc9fdd5e322e589b5af987f00a8fca854bf789db60cae9441e\",\"schedule_version\":0,\"new_producers\":null,\"producer_signature\":\"SIG_K1_JywiQJc5wtdc6iLq8Ros9XrTyRHGhkw5bvop2ASkN5bjUsZDF8DkJ8egZMyGhcaxM197bD5bWZcV7cazVKxSdcrzQoFFZT\",\"transactions\":[{\"status\":\"executed\",\"cpu_usage_us\":1894,\"net_usage_words\":202,\"trx\":{\"id\":\"d33081539ecb769d84cd8b46683ff4add7e6aefdec163d92df6c3a4790fb6825\",\"signatures\":[\"SIG_K1_JwAJh2BWVRbB5qbRYFpqbpBmp2j24VMZsgk26jL95wwZw42C6yiuTR3fkCFQjCS4AYydeTRYSJnNLDbz42K7PGoVzjwDUT\"],\"compression\":\"none\",\"packed_context_free_data\":\"\",\"context_free_data\":[],\"packed_trx\":\"a6daa2645b3f728f6b8d000000000200a6823403ea3055000000572d3ccdcd010000000000ea305500000000a8ed32322a0000000000ea30559091b9795284a9fa400d03000000000004454f5300000000095a454f53204d494e549091b9795284a9fa000000000090a793010000000000ea305500000000a8ed3232a30b01201c908c98147d20586d0d9c92ff0cc55f1060acdb759d4f46618f315c4f477f4e400d03000000000004454f530000000000a6823403ea30558003d952db359a20731f4539cf2b85c9a64e32f46a0363d6ff1c57fafefa0f27b1873a02d190feac3a0963e259f9dc68fd00e8a08923c1bcc280257c67a1cf3fcb8ae34e9c1e35adc9464d388d15ccd4dc6c0455a1d62dc03bb2920fc8353ba1190a1c946f1abd1bdcf234f67623cdf6514bc4a46298b79820a4c7fb74e47d5f231c887cf8fa90fb541d9312d98b63d15903d4856388e31a07ca76c2dc0f27c9e9f6e53a892927e21f66f19ac44bde747e088e1a8fab2b15f4e6b4a586c2e337f6069f7dbb3679263bb6bf380e678ed4b6f1aac5acc11f35232801fd7b1dafe95581580daa5b7e96758a95dc27bd5f0a520c59aa88aa2b37a7841ed265e1ff908e830c0ef08a3c7a01c2b9a9db2431ee46a131ac5dfc289a8030d07ff15056477600beec67339b4b9637da1ecb8fd78f28f25d58c7b8e1bed79073d54e3e85dd4d9508e6f9fd5494a7852c417e281769900fc6e5dd5f1ee25495d22638c39b872703d1fb219a5455de9b5397b85582f906c4bcd25e70526837d46c976e396855b81201e407636f76637035354c45647a564a36767a737a684b656352524d4451417a4147634a7343537a4849644e76494e515735726d694e4a6e4c4371525a2b69574944535941414355786c583862337131453545536e6e6c4965456a635a30304f4457316535585257305967417679526b524f3752757433443230326f76784668746b66754368594f2b754471684c783266544439794b337245306241513366766c766c3831434a487244457575655535304a566e776e5136622f44453034627a35495553667053483739306878346f3966506e50596d414f4c394c347a65516e3965536f44353845306856727959705579393550776c6c6e577339636a4961466f2b2b6678322b2f58772f746c485a5a667761624a5a4153764c48644a766d5672636c5566326d4164676f6e38516751466377384a5151457139646d4f43334d616574564b66474c554751373361786d734a6c462b574d7a6e702b6b79325a524c4d6f41794b4b704e4f567447484c59554c464c324b3254614652627a447156547548704d42677a59516c3968524a693466646e2b61474e47745570784c7272554e56654472334e394f49393972554a35657530474e5a6f64355170456b2b365843727852475247756f7a574a3474385051647845392b3979495350305647535262746e46784436686c4d6f626a4e4f4a674e55617a393176355a6253424d767164746462326a796f41786f36463344762f456b7838506347732b6770416365466b477572316e7358333979374258684e442f62514f6d7748596267327256674b475531444347424f465552344878462f48714c41752b357269635130452f2b376f4d7337646c74444566707866796d33464f6b75477669736b47335355575144676947487756464c6d4b345358486a4271744c5251775472627759455147433944326b6377502f6c66734a6c4e5a6a2f6f6c573850676369556944646542634162526335644c79326576736861595135497748464174643249324a67534e6453455338616934534a4730367a526a74733231426165614546695263514e7a5657466138305a64502b37514564786968484738542f66627764336a6c3163622b692b7a57504575304d68645579507552635072454561334668716a32725236514d31784878794c5356595a44486c4c712f2f4d6f5a553859594152664b576455305a66394d41324a306a6e793445634a4243794e637a68505630694b654b34462f7a7132416f62754c49765674537253777a2f50544c7a414b776350474e416f6244506d6d69656f444764724f4e584550616b453175666e4d48664c587a346853385457674854794438594b42543452543052644e6945434e4957306e414372355a7a4570584f00\",\"transaction\":{\"expiration\":\"2023-07-03T14:26:46\",\"ref_block_num\":16219,\"ref_block_prefix\":2372636530,\"max_net_usage_words\":0,\"max_cpu_usage_ms\":0,\"delay_sec\":0,\"context_free_actions\":[],\"actions\":[{\"account\":\"eosio.token\",\"name\":\"transfer\",\"authorization\":[{\"actor\":\"eosio\",\"permission\":\"active\"}],\"data\":{\"from\":\"eosio\",\"to\":\"zeoscontract\",\"quantity\":\"20.0000 EOS\",\"memo\":\"ZEOS MINT\"},\"hex_data\":\"0000000000ea30559091b9795284a9fa400d03000000000004454f5300000000095a454f53204d494e54\"},{\"account\":\"zeoscontract\",\"name\":\"mint\",\"authorization\":[{\"actor\":\"eosio\",\"permission\":\"active\"}],\"data\":{\"actions\":[{\"cm\":\"1c908c98147d20586d0d9c92ff0cc55f1060acdb759d4f46618f315c4f477f4e\",\"value\":200000,\"symbol\":\"4,EOS\",\"code\":\"eosio.token\",\"proof\":\"d952db359a20731f4539cf2b85c9a64e32f46a0363d6ff1c57fafefa0f27b1873a02d190feac3a0963e259f9dc68fd00e8a08923c1bcc280257c67a1cf3fcb8ae34e9c1e35adc9464d388d15ccd4dc6c0455a1d62dc03bb2920fc8353ba1190a1c946f1abd1bdcf234f67623cdf6514bc4a46298b79820a4c7fb74e47d5f231c887cf8fa90fb541d9312d98b63d15903d4856388e31a07ca76c2dc0f27c9e9f6e53a892927e21f66f19ac44bde747e088e1a8fab2b15f4e6b4a586c2e337f6069f7dbb3679263bb6bf380e678ed4b6f1aac5acc11f35232801fd7b1dafe95581580daa5b7e96758a95dc27bd5f0a520c59aa88aa2b37a7841ed265e1ff908e830c0ef08a3c7a01c2b9a9db2431ee46a131ac5dfc289a8030d07ff15056477600beec67339b4b9637da1ecb8fd78f28f25d58c7b8e1bed79073d54e3e85dd4d9508e6f9fd5494a7852c417e281769900fc6e5dd5f1ee25495d22638c39b872703d1fb219a5455de9b5397b85582f906c4bcd25e70526837d46c976e396855b812\"}],\"note_ct\":[\"covcp55LEdzVJ6vzszhKecRRMDQAzAGcJsCSzHIdNvINQW5rmiNJnLCqRZ+iWIDSYAACUxlX8b3q1E5ESnnlIeEjcZ00ODW1e5XRW0YgAvyRkRO7Rut3D202ovxFhtkfuChYO+uDqhLx2fTD9yK3rE0bAQ3fvlvl81CJHrDEuueU50JVnwnQ6b/DE04bz5IUSfpSH790hx4o9fPnPYmAOL9L4zeQn9eSoD58E0hVryYpUy95PwllnWs9cjIaFo++fx2+/Xw/tlHZZfwabJZASvLHdJvmVrclUf2mAdgon8QgQFcw8JQQEq9dmOC3MaetVKfGLUGQ73axmsJlF+WMznp+ky2ZRLMoAyKKpNOVtGHLYULFL2K2TaFRbzDqVTuHpMBgzYQl9hRJi4fdn+aGNGtUpxLrrUNVeDr3N9OI99rUJ5eu0GNZod5QpEk+6XCrxRGRGuozWJ4t8PQdxE9+9yISP0VGSRbtnFxD6hlMobjNOJgNUaz91v5ZbSBMvqdtdb2jyoAxo6F3Dv/Ekx8PcGs+gpAceFkGur1nsX39y7BXhND/bQOmwHYbg2rVgKGU1DCGBOFUR4HxF/HqLAu+5ricQ0E/+7oMs7dltDEfpxfym3FOkuGviskG3SUWQDgiGHwVFLmK4SXHjBqtLRQwTrbwYEQGC9D2kcwP/lfsJlNZj/olW8PgciUiDdeBcAbRc5dLy2evshaYQ5IwHFAtd2I2JgSNdSES8ai4SJG06zRjts21BaeaEFiRcQNzVWFa80ZdP+7QEdxihHG8T/fbwd3jl1cb+i+zWPEu0MhdUyPuRcPrEEa3Fhqj2rR6QM1xHxyLSVYZDHlLq//MoZU8YYARfKWdU0Zf9MA2J0jny4EcJBCyNczhPV0iKeK4F/zq2AobuLIvVtSrSwz/PTLzAKwcPGNAobDPmmieoDGdrONXEPakE1ufnMHfLXz4hS8TWgHTyD8YKBT4RT0RdNiECNIW0nACr5ZzEpXO\"]},\"hex_data\":\"01201c908c98147d20586d0d9c92ff0cc55f1060acdb759d4f46618f315c4f477f4e400d03000000000004454f530000000000a6823403ea30558003d952db359a20731f4539cf2b85c9a64e32f46a0363d6ff1c57fafefa0f27b1873a02d190feac3a0963e259f9dc68fd00e8a08923c1bcc280257c67a1cf3fcb8ae34e9c1e35adc9464d388d15ccd4dc6c0455a1d62dc03bb2920fc8353ba1190a1c946f1abd1bdcf234f67623cdf6514bc4a46298b79820a4c7fb74e47d5f231c887cf8fa90fb541d9312d98b63d15903d4856388e31a07ca76c2dc0f27c9e9f6e53a892927e21f66f19ac44bde747e088e1a8fab2b15f4e6b4a586c2e337f6069f7dbb3679263bb6bf380e678ed4b6f1aac5acc11f35232801fd7b1dafe95581580daa5b7e96758a95dc27bd5f0a520c59aa88aa2b37a7841ed265e1ff908e830c0ef08a3c7a01c2b9a9db2431ee46a131ac5dfc289a8030d07ff15056477600beec67339b4b9637da1ecb8fd78f28f25d58c7b8e1bed79073d54e3e85dd4d9508e6f9fd5494a7852c417e281769900fc6e5dd5f1ee25495d22638c39b872703d1fb219a5455de9b5397b85582f906c4bcd25e70526837d46c976e396855b81201e407636f76637035354c45647a564a36767a737a684b656352524d4451417a4147634a7343537a4849644e76494e515735726d694e4a6e4c4371525a2b69574944535941414355786c583862337131453545536e6e6c4965456a635a30304f4457316535585257305967417679526b524f3752757433443230326f76784668746b66754368594f2b754471684c783266544439794b337245306241513366766c766c3831434a487244457575655535304a566e776e5136622f44453034627a35495553667053483739306878346f3966506e50596d414f4c394c347a65516e3965536f44353845306856727959705579393550776c6c6e577339636a4961466f2b2b6678322b2f58772f746c485a5a667761624a5a4153764c48644a766d5672636c5566326d4164676f6e38516751466377384a5151457139646d4f43334d616574564b66474c554751373361786d734a6c462b574d7a6e702b6b79325a524c4d6f41794b4b704e4f567447484c59554c464c324b3254614652627a447156547548704d42677a59516c3968524a693466646e2b61474e47745570784c7272554e56654472334e394f49393972554a35657530474e5a6f64355170456b2b365843727852475247756f7a574a3474385051647845392b3979495350305647535262746e46784436686c4d6f626a4e4f4a674e55617a393176355a6253424d767164746462326a796f41786f36463344762f456b7838506347732b6770416365466b477572316e7358333979374258684e442f62514f6d7748596267327256674b475531444347424f465552344878462f48714c41752b357269635130452f2b376f4d7337646c74444566707866796d33464f6b75477669736b47335355575144676947487756464c6d4b345358486a4271744c5251775472627759455147433944326b6377502f6c66734a6c4e5a6a2f6f6c573850676369556944646542634162526335644c79326576736861595135497748464174643249324a67534e6453455338616934534a4730367a526a74733231426165614546695263514e7a5657466138305a64502b37514564786968484738542f66627764336a6c3163622b692b7a57504575304d68645579507552635072454561334668716a32725236514d31784878794c5356595a44486c4c712f2f4d6f5a553859594152664b576455305a66394d41324a306a6e793445634a4243794e637a68505630694b654b34462f7a7132416f62754c49765674537253777a2f50544c7a414b776350474e416f6244506d6d69656f444764724f4e584550616b453175666e4d48664c587a346853385457674854794438594b42543452543052644e6945434e4957306e414372355a7a4570584f\"}]}}}],\"id\":\"00003f5d3de16842b01d9da216b177701524512385022f5d8abf35c746675d4e\",\"block_num\":16221,\"ref_block_prefix\":2728205744}",
            "{\"timestamp\":\"2023-07-03T14:27:20.500\",\"producer\":\"eosio\",\"confirmed\":0,\"previous\":\"00003fdc83cfa9d68e077c21f96411cde16c20cf9a1302025513d91f523bf32c\",\"transaction_mroot\":\"ee657b3300cec49af97ea02476a967399dc88be42c7b494f00d4adabd7e49e85\",\"action_mroot\":\"d2f10e69317e638450a30999959bdd916196626b4c46465e822263325515d692\",\"schedule_version\":0,\"new_producers\":null,\"producer_signature\":\"SIG_K1_KfYQVMcD7spwqzAkrv9pLtR9ejRchpG8kzq4kgFVnscZezALaDXmBYSjoYGyAeyEGRmqC5uJDeTHBV6P3xmNQJZWUBCSNc\",\"transactions\":[{\"status\":\"executed\",\"cpu_usage_us\":5268,\"net_usage_words\":202,\"trx\":{\"id\":\"7879b1b91121b50ffa9ec0133950a064c7feef54cee48c4968364a564542ea1b\",\"signatures\":[\"SIG_K1_KmTrRP3uZfUAB2T7HUN7tg6YKYxCr6Qb6KFNT7vwtjEjd55evGHmRuZRfVmFx1QxnTnE3zt4YF6NQ4yVHbuKpwbFq2G2WQ\"],\"compression\":\"none\",\"packed_context_free_data\":\"\",\"context_free_data\":[],\"packed_trx\":\"e6daa264db3f59b607f8000000000200a6823403ea3055000000572d3ccdcd010000000000ea305500000000a8ed32322a0000000000ea30559091b9795284a9fa102700000000000004454f5300000000095a454f53204d494e549091b9795284a9fa000000000090a793010000000000ea305500000000a8ed3232a30b0120d6f08433c8a9e73f35f365a5865a3b34c87585e8260b1f556ec02efd2462c225102700000000000004454f530000000000a6823403ea30558003d2611ee0f8fdc1ffc91fbb757fcc4bf657bbd44a00dfd7ef71af96700aaa2a0e391e5c5a910d75eeeab45a839bb11805424610f7c98eff24d6de0b9af5a54e14fa351208098f4b647b8cb5f18c4e17d12da4d170bf2e835b1ee14c33eabb62167972117b462abb39590c3814b47b875679996b58bc85582bc593c030ab721f8556abfadb6e8989536d409e09c41a941625f87dd4fbb8a5a2873a1bff45b10ac798f5033b1a0171c0c942d07b08273d06fde80360383f7243f220d3dcf290fa15996dcf2230ab1d73083fef87fedcd23f713adce2fbd16483a4ced3f5a523a90290e5cda1454ca1381edaa8ee53e0b00fce1069f201067376a834b1fbec37548bbe690d55b3f62378f2ce081e354d815fd8ce0f331bf5ef5d5a668882c9829315b60262de2299185a0a19301936b0ff82efe356d3f8a0dd8a2e40754b09e20fc1f8d3ff7064a26d9da8cb17ca4387ee1332330ed64c4fe47fb1840f27710115781d66fbc882d2aad5c580198234015cdbc7f2cbdd4a389df95a7ee7fb86443b0601e40739582f2f4b566567506d456f58634868536c4b4f7646334479584e676257396754514646474b56467079362b4f6e4152576e427371515061367a78787931776778314d7341373037623951496e52457172387468372b315a2f644952596546514276372f4f455062526b47594a4a71463134434366723845375876696f7262736262453765457271754579797863486c4474715734617250694a74434f66357a42557a4e316d75685447582f4b494b723474304b456a56554844626a734d58317446616b4c652f3269774247624f317157726b364c54453545656a635752327a614844665754794e636331382b7535705a5270364d472f754a4c596f7571594c2b7656545a563971793542714e4c55704f6f5656435a7034732f773774656f6a397934386b65454e3177305854466273747157776c494646325a562f4d67647479416371344f51767a7a755a4e5a692f797372733165586f38504c512b36346132716d745530784358494d793555744531434165444b4562684c75576343514e65593578564d64654b6b565a7175696f6d326b5248546a75703763734150553972736c6849326a544a763449444d45463844413647547a6d5a532b4c386373637932433247465170513876577436422b7650722b41475a326e7055456f47506655466736554c2b796c6a4b4e5266687263644a6e516c58334c4f753139302f616b6b5474494e4e7a3672322f726d534f2f553875757055674e35314a4e63664937466e4c6e33564b744d4a685442493057646c72682b354577305045395233704d524f5363633872624e62336e636d71516b66333243464d305a32667168454670706a6d543837343932507830633559584965716d37577457665270646b4b73552b4747546c61614a485131616650564e644749554a4e65564d58775251516e4537774d74566e4379546e72317a497a424e4853347a6a73674f674970736662556d7745756a466a334f4a64727351576b79435356493335516b6c31435843696836784d5256726841312f33726349734e6853484175375541437a386f7230524d6a6576727768344273342b324244626d54626e436e7a3049684b7a692b486b53614d4a7a6d335173664d445246315343567a334a6f4535784d7a65306b787835395356737161645654726d4b6550756f6672325054394c6b64625a4d664c4f3575794a5665345067453349347835386a4851694354796e3255693566536e5a77354a70357149694476744855774f426a37794838646d6335647073314f4377624f6444754e577059715351436232494d76442f77372f396c7a6d4b5275473662667a7941384f4655486930464730784e586453517547314a73485764534a344263634e00\",\"transaction\":{\"expiration\":\"2023-07-03T14:27:50\",\"ref_block_num\":16347,\"ref_block_prefix\":4161255001,\"max_net_usage_words\":0,\"max_cpu_usage_ms\":0,\"delay_sec\":0,\"context_free_actions\":[],\"actions\":[{\"account\":\"eosio.token\",\"name\":\"transfer\",\"authorization\":[{\"actor\":\"eosio\",\"permission\":\"active\"}],\"data\":{\"from\":\"eosio\",\"to\":\"zeoscontract\",\"quantity\":\"1.0000 EOS\",\"memo\":\"ZEOS MINT\"},\"hex_data\":\"0000000000ea30559091b9795284a9fa102700000000000004454f5300000000095a454f53204d494e54\"},{\"account\":\"zeoscontract\",\"name\":\"mint\",\"authorization\":[{\"actor\":\"eosio\",\"permission\":\"active\"}],\"data\":{\"actions\":[{\"cm\":\"d6f08433c8a9e73f35f365a5865a3b34c87585e8260b1f556ec02efd2462c225\",\"value\":10000,\"symbol\":\"4,EOS\",\"code\":\"eosio.token\",\"proof\":\"d2611ee0f8fdc1ffc91fbb757fcc4bf657bbd44a00dfd7ef71af96700aaa2a0e391e5c5a910d75eeeab45a839bb11805424610f7c98eff24d6de0b9af5a54e14fa351208098f4b647b8cb5f18c4e17d12da4d170bf2e835b1ee14c33eabb62167972117b462abb39590c3814b47b875679996b58bc85582bc593c030ab721f8556abfadb6e8989536d409e09c41a941625f87dd4fbb8a5a2873a1bff45b10ac798f5033b1a0171c0c942d07b08273d06fde80360383f7243f220d3dcf290fa15996dcf2230ab1d73083fef87fedcd23f713adce2fbd16483a4ced3f5a523a90290e5cda1454ca1381edaa8ee53e0b00fce1069f201067376a834b1fbec37548bbe690d55b3f62378f2ce081e354d815fd8ce0f331bf5ef5d5a668882c9829315b60262de2299185a0a19301936b0ff82efe356d3f8a0dd8a2e40754b09e20fc1f8d3ff7064a26d9da8cb17ca4387ee1332330ed64c4fe47fb1840f27710115781d66fbc882d2aad5c580198234015cdbc7f2cbdd4a389df95a7ee7fb86443b06\"}],\"note_ct\":[\"9X//KVegPmEoXcHhSlKOvF3DyXNgbW9gTQFFGKVFpy6+OnARWnBsqQPa6zxxy1wgx1MsA707b9QInREqr8th7+1Z/dIRYeFQBv7/OEPbRkGYJJqF14CCfr8E7XviorbsbbE7eErquEyyxcHlDtqW4arPiJtCOf5zBUzN1muhTGX/KIKr4t0KEjVUHDbjsMX1tFakLe/2iwBGbO1qWrk6LTE5EejcWR2zaHDfWTyNcc18+u5pZRp6MG/uJLYouqYL+vVTZV9qy5BqNLUpOoVVCZp4s/w7teoj9y48keEN1w0XTFbstqWwlIFF2ZV/MgdtyAcq4OQvzzuZNZi/ysrs1eXo8PLQ+64a2qmtU0xCXIMy5UtE1CAeDKEbhLuWcCQNeY5xVMdeKkVZquiom2kRHTjup7csAPU9rslhI2jTJv4IDMEF8DA6GTzmZS+L8cscy2C2GFQpQ8vWt6B+vPr+AGZ2npUEoGPfUFg6UL+yljKNRfhrcdJnQlX3LOu190/akkTtINNz6r2/rmSO/U8uupUgN51JNcfI7FnLn3VKtMJhTBI0Wdlrh+5Ew0PE9R3pMROScc8rbNb3ncmqQkf32CFM0Z2fqhEFppjmT87492Px0c5YXIeqm7WtWfRpdkKsU+GGTlaaJHQ1afPVNdGIUJNeVMXwRQQnE7wMtVnCyTnr1zIzBNHS4zjsgOgIpsfbUmwEujFj3OJdrsQWkyCSVI35Qkl1CXCih6xMRVrhA1/3rcIsNhSHAu7UACz8or0RMjevrwh4Bs4+2BDbmTbnCnz0IhKzi+HkSaMJzm3QsfMDRF1SCVz3JoE5xMze0kxx59SVsqadVTrmKePuofr2PT9LkdbZMfLO5uyJVe4PgE3I4x58jHQiCTyn2Ui5fSnZw5Jp5qIiDvtHUwOBj7yH8dmc5dps1OCwbOdDuNWpYqSQCb2IMvD/w7/9lzmKRuG6bfzyA8OFUHi0FG0xNXdSQuG1JsHWdSJ4BccN\"]},\"hex_data\":\"0120d6f08433c8a9e73f35f365a5865a3b34c87585e8260b1f556ec02efd2462c225102700000000000004454f530000000000a6823403ea30558003d2611ee0f8fdc1ffc91fbb757fcc4bf657bbd44a00dfd7ef71af96700aaa2a0e391e5c5a910d75eeeab45a839bb11805424610f7c98eff24d6de0b9af5a54e14fa351208098f4b647b8cb5f18c4e17d12da4d170bf2e835b1ee14c33eabb62167972117b462abb39590c3814b47b875679996b58bc85582bc593c030ab721f8556abfadb6e8989536d409e09c41a941625f87dd4fbb8a5a2873a1bff45b10ac798f5033b1a0171c0c942d07b08273d06fde80360383f7243f220d3dcf290fa15996dcf2230ab1d73083fef87fedcd23f713adce2fbd16483a4ced3f5a523a90290e5cda1454ca1381edaa8ee53e0b00fce1069f201067376a834b1fbec37548bbe690d55b3f62378f2ce081e354d815fd8ce0f331bf5ef5d5a668882c9829315b60262de2299185a0a19301936b0ff82efe356d3f8a0dd8a2e40754b09e20fc1f8d3ff7064a26d9da8cb17ca4387ee1332330ed64c4fe47fb1840f27710115781d66fbc882d2aad5c580198234015cdbc7f2cbdd4a389df95a7ee7fb86443b0601e40739582f2f4b566567506d456f58634868536c4b4f7646334479584e676257396754514646474b56467079362b4f6e4152576e427371515061367a78787931776778314d7341373037623951496e52457172387468372b315a2f644952596546514276372f4f455062526b47594a4a71463134434366723845375876696f7262736262453765457271754579797863486c4474715734617250694a74434f66357a42557a4e316d75685447582f4b494b723474304b456a56554844626a734d58317446616b4c652f3269774247624f317157726b364c54453545656a635752327a614844665754794e636331382b7535705a5270364d472f754a4c596f7571594c2b7656545a563971793542714e4c55704f6f5656435a7034732f773774656f6a397934386b65454e3177305854466273747157776c494646325a562f4d67647479416371344f51767a7a755a4e5a692f797372733165586f38504c512b36346132716d745530784358494d793555744531434165444b4562684c75576343514e65593578564d64654b6b565a7175696f6d326b5248546a75703763734150553972736c6849326a544a763449444d45463844413647547a6d5a532b4c386373637932433247465170513876577436422b7650722b41475a326e7055456f47506655466736554c2b796c6a4b4e5266687263644a6e516c58334c4f753139302f616b6b5474494e4e7a3672322f726d534f2f553875757055674e35314a4e63664937466e4c6e33564b744d4a685442493057646c72682b354577305045395233704d524f5363633872624e62336e636d71516b66333243464d305a32667168454670706a6d543837343932507830633559584965716d37577457665270646b4b73552b4747546c61614a485131616650564e644749554a4e65564d58775251516e4537774d74566e4379546e72317a497a424e4853347a6a73674f674970736662556d7745756a466a334f4a64727351576b79435356493335516b6c31435843696836784d5256726841312f33726349734e6853484175375541437a386f7230524d6a6576727768344273342b324244626d54626e436e7a3049684b7a692b486b53614d4a7a6d335173664d445246315343567a334a6f4535784d7a65306b787835395356737161645654726d4b6550756f6672325054394c6b64625a4d664c4f3575794a5665345067453349347835386a4851694354796e3255693566536e5a77354a70357149694476744855774f426a37794838646d6335647073314f4377624f6444754e577059715351436232494d76442f77372f396c7a6d4b5275473662667a7941384f4655486930464730784e586453517547314a73485764534a344263634e\"}]}}}],\"id\":\"00003fdd27ed7fde1fc11d12fea57f22201a499ffe88b58f2a073bfb0fd2b6a8\",\"block_num\":16349,\"ref_block_prefix\":303939871}",
            "{\"timestamp\":\"2023-07-05T13:05:09.500\",\"producer\":\"eosio\",\"confirmed\":0,\"previous\":\"00055f5680dd8ce86899ecf13998e77e78130e4dacc1a3b73b6bfa5b4d193762\",\"transaction_mroot\":\"ceaf7528aecf6d50262bb14c34a1f8e06badf705e6bdf6de8d67763eeea1d39b\",\"action_mroot\":\"f1e9be40c804fc5c90a2021600c8081c615d37bd937fdda66e7417adf94ca373\",\"schedule_version\":0,\"new_producers\":null,\"producer_signature\":\"SIG_K1_JvZRLQtA8ZcV9WRdn6XaqYX29dphJUjQLSgKfnvGL1j7ejGyR7XndYTdAg6u5uta6S47TZ4GL49Z4mL2Bg8FRst61W9h1T\",\"transactions\":[{\"status\":\"executed\",\"cpu_usage_us\":7292,\"net_usage_words\":202,\"trx\":{\"id\":\"485faf008f5399ceef4e599c19895c0fa630b4ecf28555584a78a7f9b8725534\",\"signatures\":[\"SIG_K1_KaqXEPcdEqgHQrnufnAXnasv5ZFNatPgZmLpbvezyP6FtAD5hUtVatFHVPstp3mtULyjZSyRyoAqBqqo3Qz6Mni3EXTzJ3\"],\"compression\":\"none\",\"packed_context_free_data\":\"\",\"context_free_data\":[],\"packed_trx\":\"a36aa564555fc45e8aef000000000200a6823403ea3055000000572d3ccdcd010000000000ea305500000000a8ed32322a0000000000ea30559091b9795284a9fa102700000000000004454f5300000000095a454f53204d494e549091b9795284a9fa000000000090a793010000000000ea305500000000a8ed3232a30b012079d1f50418eaad4781f578408b2ea817b78121f034e84fbfff1351beb18a9c4a102700000000000004454f530000000000a6823403ea30558003e7b59c17db602f531fd13448e141a37a292531a27c3a5d62b0d0f5a79985cedbdfcab40bdb6604703b3f57da57cd4c17ba499262a4bee1d8487929f5a469177f8175dc4e7cfcd43237c7b087f7951bc4d62a445c12c9a99a49d6314d19085a171eb24b69c1946a7ced4ec5c1985dfb0cc0265c1f58a5b792325fda09eea390e7d44401fc25c6198d0fff259ecdf07b0b35f8b3bddba03f1c1336107230b1db286b7f5b47eb7a378385c6cc158b76342889cb4abc6f50c43788f99e0df4aeb301158a3256d173d9a3bb4f3ac20ccfd0ae93224f6fd02b20bc1e2905c5a912049e44223d7583b0d33e6e68831a20b6d10a72c1d419e132768240c28677d4c7a11130b49c19a7df39cb30e7e5a221f24234bf4bf5250cd41b59dc80ede55532aa01cc2312f8f4478d80507569701aee9f85052d2e9da1391e3b753045984b5af5a024e9b97c0f96e600b69d1dbc990cb80866cb8c60ed63c55a14325d007321f92014d6188f16a5275561d046cf6d6971858a5e682cb54d6edb18faf29db030000101e407675372786371626e65466d793045624c6763632b41305a653877476a5a6d457533654d536a50596969465272305648507761493266496b5a436365496d586747546c3479466b4741706138616b3750704832625a306f696e31593141552f786279454767512b4c3049555955326a33446c5430334f4d78797a4e326478546764384a493852716d7279633769486c54786f32696332474670477433697162785955562f647145725a695976723945426b7839354b63437a61424665505133306839395a6e7946704452526b37526b52656e4e795064366e693754674d4768786f472f4c336546546664546c70686573354f4e77736c4d454f556a476d49665532562f4b2b704c54706f54656b636f64797a764f35536f536439525a537852776d7a747a70494c396338684172316e355a6a487239314f326c6f51673736577a4576645053505649515a393144387444342f535478547571496d52645271526f566e325a7450524b32655479596b633644366b62794266375276445a75753038674e30383733515957766175443375384b69794f446e66343465356575313635505a6c62384b4a6d65494562616d336956572b514d2f66303563304f5538554f342f4a6433376a3872593633467150392f4d3670486a55526d4b584d624268736452645a384d4f7761647331344c717a6576444c776458484d4e5538574e42662f6b3678694b522f396c51586d772f553161552f39596d6d513477625757557434346d3935686f5969462b6158476f49396e45373655364e6c54464769745546637430436c78734e3253565559324671466e6a3063536b31716b71476453426e5a4c764a2f332b33492f676632376a50343947456d7267715a7177657274394c465757666e474a546f77462b696969656d5947474d767a4d52517a724c4a55694e3671686d676d4932674850504d434b4a4f42397333316745587a6e524a6a2f7237797151445547475555524f324553304747683742347a30394d6153494c6777564f7077336971462f5635533143535a3632714662524a6d726c78385554455164313830683772447a4763387535457043382b3665464b4741396b6a6a714e4155644861357a6b714e5642463972744f59453074483364316c36706a2f4448767a3563624250755a4a466a5a77336b6c4c63362b4b2f57756e55474c625764622f644931592f3847786c523466694e62484d7064434d6d527569373767346648516531446e78724e466f71573439326f506377654f5438416b64586e41587948356e74476c76434d66417233546f76516a2f6e345231496e6e5739694c657a30715569526a352b5a446e597663695a7172704a71744a377177594f75765758794f674d7500\",\"transaction\":{\"expiration\":\"2023-07-05T13:05:39\",\"ref_block_num\":24405,\"ref_block_prefix\":4018822852,\"max_net_usage_words\":0,\"max_cpu_usage_ms\":0,\"delay_sec\":0,\"context_free_actions\":[],\"actions\":[{\"account\":\"eosio.token\",\"name\":\"transfer\",\"authorization\":[{\"actor\":\"eosio\",\"permission\":\"active\"}],\"data\":{\"from\":\"eosio\",\"to\":\"zeoscontract\",\"quantity\":\"1.0000 EOS\",\"memo\":\"ZEOS MINT\"},\"hex_data\":\"0000000000ea30559091b9795284a9fa102700000000000004454f5300000000095a454f53204d494e54\"},{\"account\":\"zeoscontract\",\"name\":\"mint\",\"authorization\":[{\"actor\":\"eosio\",\"permission\":\"active\"}],\"data\":{\"actions\":[{\"cm\":\"79d1f50418eaad4781f578408b2ea817b78121f034e84fbfff1351beb18a9c4a\",\"value\":10000,\"symbol\":\"4,EOS\",\"code\":\"eosio.token\",\"proof\":\"e7b59c17db602f531fd13448e141a37a292531a27c3a5d62b0d0f5a79985cedbdfcab40bdb6604703b3f57da57cd4c17ba499262a4bee1d8487929f5a469177f8175dc4e7cfcd43237c7b087f7951bc4d62a445c12c9a99a49d6314d19085a171eb24b69c1946a7ced4ec5c1985dfb0cc0265c1f58a5b792325fda09eea390e7d44401fc25c6198d0fff259ecdf07b0b35f8b3bddba03f1c1336107230b1db286b7f5b47eb7a378385c6cc158b76342889cb4abc6f50c43788f99e0df4aeb301158a3256d173d9a3bb4f3ac20ccfd0ae93224f6fd02b20bc1e2905c5a912049e44223d7583b0d33e6e68831a20b6d10a72c1d419e132768240c28677d4c7a11130b49c19a7df39cb30e7e5a221f24234bf4bf5250cd41b59dc80ede55532aa01cc2312f8f4478d80507569701aee9f85052d2e9da1391e3b753045984b5af5a024e9b97c0f96e600b69d1dbc990cb80866cb8c60ed63c55a14325d007321f92014d6188f16a5275561d046cf6d6971858a5e682cb54d6edb18faf29db0300001\"}],\"note_ct\":[\"gSrxcqbneFmy0EbLgcc+A0Ze8wGjZmEu3eMSjPYiiFRr0VHPwaI2fIkZCceImXgGTl4yFkGApa8ak7PpH2bZ0oin1Y1AU/xbyEGgQ+L0IUYU2j3DlT03OMxyzN2dxTgd8JI8Rqmryc7iHlTxo2ic2GFpGt3iqbxYUV/dqErZiYvr9EBkx95KcCzaBFePQ30h99ZnyFpDRRk7RkRenNyPd6ni7TgMGhxoG/L3eFTfdTlphes5ONwslMEOUjGmIfU2V/K+pLTpoTekcodyzvO5SoSd9RZSxRwmztzpIL9c8hAr1n5ZjHr91O2loQg76WzEvdPSPVIQZ91D8tD4/STxTuqImRdRqRoVn2ZtPRK2eTyYkc6D6kbyBf7RvDZuu08gN0873QYWvauD3u8KiyODnf44e5eu165PZlb8KJmeIEbam3iVW+QM/f05c0OU8UO4/Jd37j8rY63FqP9/M6pHjURmKXMbBhsdRdZ8MOwads14LqzevDLwdXHMNU8WNBf/k6xiKR/9lQXmw/U1aU/9YmmQ4wbWWUt44m95hoYiF+aXGoI9nE76U6NlTFGitUFct0ClxsN2SVUY2FqFnj0cSk1qkqGdSBnZLvJ/3+3I/gf27jP49GEmrgqZqwert9LFWWfnGJTowF+iiiemYGGMvzMRQzrLJUiN6qhmgmI2gHPPMCKJOB9s31gEXznRJj/r7yqQDUGGUURO2ES0GGh7B4z09MaSILgwVOpw3iqF/V5S1CSZ62qFbRJmrlx8UTEQd180h7rDzGc8u5EpC8+6eFKGA9kjjqNAUdHa5zkqNVBF9rtOYE0tH3d1l6pj/DHvz5cbBPuZJFjZw3klLc6+K/WunUGLbWdb/dI1Y/8GxlR4fiNbHMpdCMmRui77g4fHQe1DnxrNFoqW492oPcweOT8AkdXnAXyH5ntGlvCMfAr3TovQj/n4R1InnW9iLez0qUiRj5+ZDnYvciZqrpJqtJ7qwYOuvWXyOgMu\"]},\"hex_data\":\"012079d1f50418eaad4781f578408b2ea817b78121f034e84fbfff1351beb18a9c4a102700000000000004454f530000000000a6823403ea30558003e7b59c17db602f531fd13448e141a37a292531a27c3a5d62b0d0f5a79985cedbdfcab40bdb6604703b3f57da57cd4c17ba499262a4bee1d8487929f5a469177f8175dc4e7cfcd43237c7b087f7951bc4d62a445c12c9a99a49d6314d19085a171eb24b69c1946a7ced4ec5c1985dfb0cc0265c1f58a5b792325fda09eea390e7d44401fc25c6198d0fff259ecdf07b0b35f8b3bddba03f1c1336107230b1db286b7f5b47eb7a378385c6cc158b76342889cb4abc6f50c43788f99e0df4aeb301158a3256d173d9a3bb4f3ac20ccfd0ae93224f6fd02b20bc1e2905c5a912049e44223d7583b0d33e6e68831a20b6d10a72c1d419e132768240c28677d4c7a11130b49c19a7df39cb30e7e5a221f24234bf4bf5250cd41b59dc80ede55532aa01cc2312f8f4478d80507569701aee9f85052d2e9da1391e3b753045984b5af5a024e9b97c0f96e600b69d1dbc990cb80866cb8c60ed63c55a14325d007321f92014d6188f16a5275561d046cf6d6971858a5e682cb54d6edb18faf29db030000101e407675372786371626e65466d793045624c6763632b41305a653877476a5a6d457533654d536a50596969465272305648507761493266496b5a436365496d586747546c3479466b4741706138616b3750704832625a306f696e31593141552f786279454767512b4c3049555955326a33446c5430334f4d78797a4e326478546764384a493852716d7279633769486c54786f32696332474670477433697162785955562f647145725a695976723945426b7839354b63437a61424665505133306839395a6e7946704452526b37526b52656e4e795064366e693754674d4768786f472f4c336546546664546c70686573354f4e77736c4d454f556a476d49665532562f4b2b704c54706f54656b636f64797a764f35536f536439525a537852776d7a747a70494c396338684172316e355a6a487239314f326c6f51673736577a4576645053505649515a393144387444342f535478547571496d52645271526f566e325a7450524b32655479596b633644366b62794266375276445a75753038674e30383733515957766175443375384b69794f446e66343465356575313635505a6c62384b4a6d65494562616d336956572b514d2f66303563304f5538554f342f4a6433376a3872593633467150392f4d3670486a55526d4b584d624268736452645a384d4f7761647331344c717a6576444c776458484d4e5538574e42662f6b3678694b522f396c51586d772f553161552f39596d6d513477625757557434346d3935686f5969462b6158476f49396e45373655364e6c54464769745546637430436c78734e3253565559324671466e6a3063536b31716b71476453426e5a4c764a2f332b33492f676632376a50343947456d7267715a7177657274394c465757666e474a546f77462b696969656d5947474d767a4d52517a724c4a55694e3671686d676d4932674850504d434b4a4f42397333316745587a6e524a6a2f7237797151445547475555524f324553304747683742347a30394d6153494c6777564f7077336971462f5635533143535a3632714662524a6d726c78385554455164313830683772447a4763387535457043382b3665464b4741396b6a6a714e4155644861357a6b714e5642463972744f59453074483364316c36706a2f4448767a3563624250755a4a466a5a77336b6c4c63362b4b2f57756e55474c625764622f644931592f3847786c523466694e62484d7064434d6d527569373767346648516531446e78724e466f71573439326f506377654f5438416b64586e41587948356e74476c76434d66417233546f76516a2f6e345231496e6e5739694c657a30715569526a352b5a446e597663695a7172704a71744a377177594f75765758794f674d75\"}]}}}],\"id\":\"00055f571f04dae6a2ff0385d1b97674e2ed397038e7d104c4f0e628ac27d206\",\"block_num\":352087,\"ref_block_prefix\":2231631778}"
        ];

        //let leaves = vec![
        //    hex::decode("a71045795b5c8931ed61f8cc794700ea43fd30237e3c5d65e173b829f2750059").unwrap(),
        //    hex::decode("6886a72b946485ce50976db4d087f18ab6e0a954bd10b865480bb3c0c5ae4658").unwrap(),
        //    hex::decode("2a2c4d4a2875d83f35d4614658f718f8feb3e2f93dd3272721e3b03b71b26605").unwrap(),
        //    hex::decode("89a39d9bea68e79209837f0ebed29ce4b333a5572710430c203df5ea6345d11b").unwrap(),
        //    hex::decode("9e1af72ab60fe1dd57cc605f8b9c73865a4f692fc9f8e78527cee869d23d136f").unwrap(),
        //    hex::decode("564937a38ab594aa3b63a340621b6fae6472ec634beb9de918cadbb864185a43").unwrap(),
        //    hex::decode("1c908c98147d20586d0d9c92ff0cc55f1060acdb759d4f46618f315c4f477f4e").unwrap(),
        //    hex::decode("d6f08433c8a9e73f35f365a5865a3b34c87585e8260b1f556ec02efd2462c225").unwrap(),
        //    hex::decode("e13f10dd1c739cda2e9b8ba30f39282e72b818d3fd939de2a94f5b9f79475080").unwrap(),
        //    hex::decode("79d1f50418eaad4781f578408b2ea817b78121f034e84fbfff1351beb18a9c4a").unwrap(),
        //];
        // same data as vec of vec's above but as a single vec
        let leaves = hex::decode("a71045795b5c8931ed61f8cc794700ea43fd30237e3c5d65e173b829f27500596886a72b946485ce50976db4d087f18ab6e0a954bd10b865480bb3c0c5ae46582a2c4d4a2875d83f35d4614658f718f8feb3e2f93dd3272721e3b03b71b2660589a39d9bea68e79209837f0ebed29ce4b333a5572710430c203df5ea6345d11b9e1af72ab60fe1dd57cc605f8b9c73865a4f692fc9f8e78527cee869d23d136f564937a38ab594aa3b63a340621b6fae6472ec634beb9de918cadbb864185a431c908c98147d20586d0d9c92ff0cc55f1060acdb759d4f46618f315c4f477f4ed6f08433c8a9e73f35f365a5865a3b34c87585e8260b1f556ec02efd2462c225e13f10dd1c739cda2e9b8ba30f39282e72b818d3fd939de2a94f5b9f7947508079d1f50418eaad4781f578408b2ea817b78121f034e84fbfff1351beb18a9c4a").unwrap();

        let mut w = Wallet::create(
            &vec![116,104,105,115,32,105,115,32,97,32,114,97,110,100,111,109,32,115,101,101,100,32,119,104,105,99,104,32,105,115,32,97,116,32,108,101,97,115,116,32,51,50,32,98,121,116,101,115,32,108,111,110,103,33],
            false
        ).unwrap();

        w.add_leaves(leaves.as_slice());
        for b in blocks
        {
            w.process_block(&b.to_string());
        }

        //println!("{}", serde_json::to_string(&w.move_asset(&mut rng, "mschoenebeck@active".to_string(), vec!["- 1 EOS".to_string()]).unwrap()).unwrap());

        println!("{}", w.to_json(true));
        println!("{:?}", serde_json::to_string(&w.get_sister_path_and_root(&w.unspent_notes[0])));

    }

    #[test]
    fn test_transfer_asset()
    {
        let mut rng = OsRng.clone();
        let mut w = Wallet::create(
            b"this is a sample seed which should be at least 32 bytes long...",
            false
        ).unwrap();

        w.unspent_notes.push(NoteEx { block_num: 0, block_ts: 0, wallet_ts: 0, leaf_idx_arr: 7, note: Note::dummy(&mut rng, None, Some(Asset::new(100000, Symbol::from_string(&"4,ZEOS".to_string()).unwrap()).unwrap()), Some(Name::new(6138663591592764928))).2 });
        w.unspent_notes.push(NoteEx { block_num: 0, block_ts: 0, wallet_ts: 0, leaf_idx_arr: 8, note: Note::dummy(&mut rng, None, Some(Asset::new(50000, Symbol::from_string(&"4,EOS".to_string()).unwrap()).unwrap()), Some(Name::new(6138663591592764928))).2 });
        w.unspent_notes.push(NoteEx { block_num: 0, block_ts: 0, wallet_ts: 0, leaf_idx_arr: 9, note: Note::dummy(&mut rng, None, Some(Asset::new(50000, Symbol::from_string(&"4,EOS".to_string()).unwrap()).unwrap()), Some(Name::new(6138663591592764928))).2 });

        let tx = w.transfer_asset(
            &mut rng,
            vec![
                format!("1 EOS mschoenebeck 'this is memo one'"),
                format!("3 EOS randomaccoun 'here is another memo'"),
                format!("4 EOS aliceaccount 'let's try to make it more interesting'"),
                format!("2 EOS bobssaccount 'last action in this transaction'"),
            ]
        );
        assert!(tx.is_some());
        println!("{}", serde_json::to_string(&tx.unwrap()).unwrap());
    }

    #[test]
    fn test_subsets()
    {
        let res = Wallet::subsets(&vec![1,2,3,4]);
        println!("{:?}", res);
    }

    #[test]
    fn test_permutations()
    {
        let mut array = vec![1,2,3,4];
        let mut out = vec![];
        Wallet::permutations(4, &mut array, &mut out);
        println!("{:?}", out);

        let mut array: Vec<i32> = vec![];
        let mut out = vec![];
        Wallet::permutations(0, &mut array, &mut out);
        println!("{:?}", out);
    }


}
