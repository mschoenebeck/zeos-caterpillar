use chrono::{DateTime, Local};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use crate::contract::{PlsSpendSequence, PlsAuthenticate};
use crate::eosio::ExtendedAsset;
use crate::{
    address::Address,
    blake2s7r::Params as Blake2s7rParams,
    constants::{MERKLE_TREE_DEPTH, MEMO_CHANGE_NOTE},
    contract::ScalarBytes,
    eosio::{Asset, Authorization, Name, Symbol},
    keys::{IncomingViewingKey, SpendingKey, FullViewingKey, PreparedIncomingViewingKey},
    note::{Note, NoteEx},
    note_encryption::{try_note_decryption, try_output_recovery_with_ovk, TransmittedNoteCiphertext},
    log
};
use bls12_381::Scalar;

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
pub struct Wallet
{
    // keys & addresses
    seed: Vec<u8>,
    ivk: IncomingViewingKey, // READ-ONLY WALLET: only valid if seed == ""
    diversifiers: Vec<u64>,
    
    // wallet metadata
    chain_id: [u8; 32],
    protocol_contract: Name,
    alias_authority: Authorization,
    block_num: u32,
    leaf_count: u64,

    // the different note pools
    unspent_notes: Vec<NoteEx>,
    spent_notes: Vec<NoteEx>,
    outgoing_notes: Vec<NoteEx>,

    // merkle tree leaves
    merkle_tree: HashMap<u64, ScalarBytes>,

    // storage of all unpublished notes
    unpublished_notes: HashMap<u64, HashMap<String, Vec<String>>>
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HistoryTransaction
{
    pub tx_type: String,
    pub date_time: String,
    pub tx_fee: String,
    pub account_asset_memo: Vec<(String, String, String)>  // asset, receiver, memo
}

impl Wallet
{
    pub fn create(
        seed: &[u8],
        is_ivk: bool,
        chain_id: [u8; 32],
        protocol_contract: Name,
        alias_authority: Authorization
    ) -> Option<Self>
    {
        if is_ivk { if seed.len() != 64 { log("ivk length must equal 64 bytes"); return None; } }
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
            seed: if !is_ivk { seed.to_vec() } else { vec![] },
            ivk,
            diversifiers,
            chain_id,
            protocol_contract,
            alias_authority,
            block_num: 0,
            leaf_count: 0,
            unspent_notes: vec![],
            spent_notes: vec![],
            outgoing_notes: vec![],
            merkle_tree: HashMap::new(),
            unpublished_notes: HashMap::new()
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
        writer.write_all(&self.chain_id)?;
        writer.write_u64::<LittleEndian>(self.protocol_contract.raw())?;
        writer.write_u64::<LittleEndian>(self.alias_authority.actor.raw())?;
        writer.write_u64::<LittleEndian>(self.alias_authority.permission.raw())?;
        writer.write_u32::<LittleEndian>(self.block_num)?;
        writer.write_u64::<LittleEndian>(self.leaf_count)?;
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
        let unpublished_notes_str = serde_json::to_string(&self.unpublished_notes).unwrap();
        writer.write_u32::<LittleEndian>(unpublished_notes_str.as_bytes().len() as u32)?;
        writer.write_all(unpublished_notes_str.as_bytes())?;

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

        let mut chain_id = [0; 32];
        reader.read_exact(&mut chain_id)?;
        let protocol_contract = Name(reader.read_u64::<LittleEndian>()?);
        let alias_authority = Authorization{
            actor: Name(reader.read_u64::<LittleEndian>()?),
            permission: Name(reader.read_u64::<LittleEndian>()?)
        };
        let block_num = reader.read_u32::<LittleEndian>()?;
        let leaf_count = reader.read_u64::<LittleEndian>()?;

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
            chain_id,
            protocol_contract,
            alias_authority,
            block_num,
            leaf_count: 0,
            unspent_notes,
            spent_notes,
            outgoing_notes,
            merkle_tree,
            unpublished_notes: HashMap::new()
        };

        for _ in 0..leaf_count
        {
            let mut leaf = [0; 32];
            reader.read_exact(&mut leaf)?;
            wallet.insert_into_merkle_tree(&ScalarBytes(leaf));
        }

        let unpublished_notes_bytes_len = reader.read_u32::<LittleEndian>()? as usize;
        let mut unpublished_notes_bytes = vec![];
        unpublished_notes_bytes.resize(unpublished_notes_bytes_len, 0);
        reader.read_exact(&mut unpublished_notes_bytes)?;
        wallet.unpublished_notes = serde_json::from_str(&String::from_utf8(unpublished_notes_bytes).unwrap()).unwrap();

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
        32 +                                // chain ID
        8 +                                 // protocol contract
        16 +                                // alias authority
        4 +                                 // latest block number
        8 +                                 // leaf count
        4 +                                 // unspent_notes.len()
        self.unspent_notes.len() * 655 +
        4 +                                 // spent_notes.len()
        self.spent_notes.len() * 655 +
        4 +                                 // outgoing_notes.len()
        self.outgoing_notes.len() * 655 +
        self.leaf_count as usize * 32 +     // merkle tree leaves only
        4 +                                 // unpublished_notes.len()
        serde_json::to_string(&self.unpublished_notes).unwrap().as_bytes().len()

        // less verbose but much heavier alternative:
        //let mut v = vec![];
        //assert!(self.write(&mut v).is_ok());
        //v.len()
    }

    pub fn chain_id(&self) -> [u8; 32]
    {
        self.chain_id
    }

    pub fn protocol_contract(&self) -> Name
    {
        self.protocol_contract
    }

    pub fn alias_authority(&self) -> &Authorization
    {
        &self.alias_authority
    }

    pub fn block_num(&self) -> u32
    {
        self.block_num
    }

    pub fn leaf_count(&self) -> u64
    {
        self.leaf_count
    }

    pub fn is_ivk(&self) -> bool
    {
        self.seed.len() == 0
    }

    pub fn balances(&self) -> Vec<ExtendedAsset>
    {
        let mut map = HashMap::new();
        for note in &self.unspent_notes
        {
            if !note.note().quantity().is_nft()
            {
                let k = ((note.note().symbol().raw() as u128) << 64) | (note.note().contract().raw() as u128);
                if !map.contains_key(&k)
                {
                    map.insert(k, note.note().amount());
                }
                else
                {
                    *map.get_mut(&k).unwrap() += note.note().amount();
                }
            }
        }
        let mut v = vec![];
        for k in map.keys()
        {
            v.push(ExtendedAsset::new(Asset::new(
                *map.get(k).unwrap() as i64,
                Symbol((*k >> 64) as u64)).unwrap(),
                Name(*k as u64)
            ))
        }
        v
    }

    pub fn unspent_notes(&self) -> &Vec<NoteEx>
    {
        &self.unspent_notes
    }

    pub fn fungible_tokens(&self, symbol: &Symbol, contract: &Name) -> Vec<NoteEx>
    {
        if symbol.raw() == 0 && contract.raw() == 0
        {
            // select all fungible tokens from all contracts
            return self.unspent_notes.iter().map(|n| n.clone()).filter(|n| n.note().symbol().raw() != 0).collect();
        }
        if symbol.raw() == 0 && contract.raw() != 0
        {
            // select all fungible tokens from this particular contract
            return self.unspent_notes.iter().map(|n| n.clone()).filter(|n| n.note().contract().eq(&contract) && n.note().symbol().raw() != 0).collect();
        }
        if symbol.raw() != 0 && contract.raw() == 0
        {
            // select this particular fungible token from all contracts
            return self.unspent_notes.iter().map(|n| n.clone()).filter(|n| n.note().symbol().eq(&symbol)).collect();
        }
        if symbol.raw() != 0 && contract.raw() != 0
        {
            // select this particular fungible token from this particular contract
            return self.unspent_notes.iter().map(|n| n.clone()).filter(|n| n.note().contract().eq(&contract) && n.note().symbol().eq(&symbol)).collect();
        }
        vec![]
    }

    pub fn non_fungible_tokens(&self, contract: &Name) -> Vec<NoteEx>
    {
        if contract.raw() == 0
        {
            // select all nfts from all contracts
            return self.unspent_notes.iter().map(|n| n.clone()).filter(|n| n.note().symbol().raw() == 0 && n.note().amount() != 0).collect();
        }
        if contract.raw() != 0
        {
            // select all nfts from this particular contract
            return self.unspent_notes.iter().map(|n| n.clone()).filter(|n| n.note().contract().eq(&contract) && n.note().symbol().raw() == 0 && n.note().amount() != 0).collect();
        }
        vec![]
    }

    pub fn authentication_tokens(&self, contract: &Name) -> Vec<NoteEx>
    {
        if contract.raw() == 0
        {
            // select all auth tokens from all contracts
            return self.unspent_notes.iter().map(|n| n.clone()).filter(|n| n.note().symbol().raw() == 0 && n.note().amount() == 0).collect();
        }
        if contract.raw() != 0
        {
            // select all auth tokens from this particular contract
            return self.unspent_notes.iter().map(|n| n.clone()).filter(|n| n.note().contract().eq(&contract) && n.note().symbol().raw() == 0 && n.note().amount() == 0).collect()
        }
        vec![]
    }

    pub fn unpublished_notes(&self) -> &HashMap<u64, HashMap<String, Vec<String>>>
    {
        &self.unpublished_notes
    }

    pub fn spending_key(&self) -> Option<SpendingKey>
    {
        if self.is_ivk()
        {
            None
        }
        else
        {
            Some(SpendingKey::from_seed(&self.seed))
        }
    }

    pub fn default_address(&self) -> Option<Address>
    {
        if self.seed.len() == 0
        {
            return None;
        }
        Some(FullViewingKey::from_spending_key(&SpendingKey::from_seed(&self.seed)).default_address().1)
    }

    pub fn addresses(&self) -> Vec<Address>
    {
        let mut v = vec![];
        if self.seed.len() == 0
        {
            return v;
        }
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
        // TODO: what if IVK wallet?
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

    fn note_exist_in_unspent(&self, note: &Note) -> bool
    {
        let v: Vec<&NoteEx> = self.unspent_notes.iter().filter(|n| n.note().eq(&note)).collect();
        v.len() > 0
    }

    fn note_exist_in_spent(&self, note: &Note) -> bool
    {
        let v: Vec<&NoteEx> = self.spent_notes.iter().filter(|n| n.note().eq(&note)).collect();
        v.len() > 0
    }

    fn note_exist_in_outgoing(&self, note: &Note) -> bool
    {
        let v: Vec<&NoteEx> = self.outgoing_notes.iter().filter(|n| n.note().eq(&note)).collect();
        v.len() > 0
    }

    // Merkle Tree must be up-to-date before calling this function!
    pub fn add_notes(&mut self, notes: &Vec<String>, block_num: u32, block_ts: u64) -> u64
    {
        let sk = SpendingKey::from_seed(&self.seed);
        let fvk = FullViewingKey::from_spending_key(&sk);
        let wallet_ts = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis() as u64;
        let mut fts_received = 0;
        let mut nfts_received = 0;
        let mut ats_received = 0;

        for n in notes
        {
            let encrypted_note = TransmittedNoteCiphertext::from_base64(n);
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
                    let note_ex = NoteEx::from_parts(
                        block_num,
                        block_ts,
                        wallet_ts,
                        *idx.unwrap(),
                        note
                    );
                    // make sure a note is not added twice
                    if !self.note_exist_in_unspent(note_ex.note()) && !self.note_exist_in_spent(note_ex.note())
                    {
                        if note_ex.note().symbol().raw() == 0 && note_ex.note().amount() == 0 { ats_received += 1; }
                        else if note_ex.note().symbol().raw() == 0 && note_ex.note().amount() != 0 { nfts_received += 1; }
                        else { if !note_ex.note().memo().eq(&MEMO_CHANGE_NOTE) { fts_received += 1; } } // don't count 'change' notes
                        self.unspent_notes.push(note_ex);
                    }
                },
                None => {},
            }

            // test sender decryption
            match try_output_recovery_with_ovk(&fvk.ovk, &encrypted_note) {
                Some(note) => {
                    let note_ex = NoteEx::from_parts(
                        block_num,
                        block_ts,
                        wallet_ts,
                        0,
                        note.clone()
                    );
                    // make sure a note is not added twice
                    if !self.note_exist_in_outgoing(note_ex.note())
                    {
                        self.outgoing_notes.push(note_ex);
                    }
                },
                None => {},
            }
        }

        (ats_received << 16) | (nfts_received << 8) | fts_received
    }

    pub fn transaction_history(&self) -> Vec<HistoryTransaction>
    {
        let mut history = vec![];
        let mut received = self.unspent_notes.clone();
        received.append(&mut self.spent_notes.clone());
        received.sort_by(|a, b| b.wallet_ts().cmp(&a.wallet_ts()));
        let mut sent = self.outgoing_notes.clone();
        sent.sort_by(|a, b| b.wallet_ts().cmp(&a.wallet_ts()));
        while !received.is_empty() || !sent.is_empty()
        {
            let mut htx = HistoryTransaction{
                tx_type: "".to_string(),
                date_time: "".to_string(),
                tx_fee: "".to_string(),
                account_asset_memo: vec![]
            };
            let mut tx = vec![];

            if !received.is_empty() && !sent.is_empty()
            {
                if sent[0].wallet_ts() <= received[0].wallet_ts()
                {
                    tx.push(sent.remove(0));
                    while !sent.is_empty() && sent[0].wallet_ts() == tx[0].wallet_ts()
                    {
                        tx.push(sent.remove(0));
                    }
                    htx.tx_type = "Sent".to_string();
                    htx.date_time = DateTime::<Local>::from(UNIX_EPOCH + Duration::from_millis(tx[0].wallet_ts())).format("%Y-%m-%d %H:%M:%S").to_string();
                }
                else
                {
                    tx.push(received.remove(0));
                    while !received.is_empty() && received[0].wallet_ts() == tx[0].wallet_ts()
                    {
                        tx.push(received.remove(0));
                    }
                    htx.tx_type = "Received".to_string();
                    htx.date_time = DateTime::<Local>::from(UNIX_EPOCH + Duration::from_millis(tx[0].wallet_ts())).format("%Y-%m-%d %H:%M:%S").to_string();
                }

            }
            else if !received.is_empty() && sent.is_empty()
            {
                tx.push(received.remove(0));
                while !received.is_empty() && received[0].wallet_ts() == tx[0].wallet_ts()
                {
                    tx.push(received.remove(0));
                }
                htx.tx_type = "Received".to_string();
                htx.date_time = DateTime::<Local>::from(UNIX_EPOCH + Duration::from_millis(tx[0].wallet_ts())).format("%Y-%m-%d %H:%M:%S").to_string();
            }
            else if received.is_empty() && !sent.is_empty()
            {
                tx.push(sent.remove(0));
                while !sent.is_empty() && sent[0].wallet_ts() == tx[0].wallet_ts()
                {
                    tx.push(sent.remove(0));
                }
                htx.tx_type = "Sent".to_string();
                htx.date_time = DateTime::<Local>::from(UNIX_EPOCH + Duration::from_millis(tx[0].wallet_ts())).format("%Y-%m-%d %H:%M:%S").to_string();
            }

            for n in tx.iter()
            {
                if !n.note().memo().eq(&MEMO_CHANGE_NOTE)
                {
                    if n.note().account().eq(&self.alias_authority.actor)
                    {
                        htx.tx_fee = n.note().asset().quantity().to_string();
                    }
                    else if n.note().account().raw() != 0
                    {
                        htx.account_asset_memo.push((
                            n.note().account().to_string(),
                            n.note().asset().to_string() + &if htx.tx_type.eq("Received") { " (@".to_owned() + &n.note().address().to_bech32m().unwrap() + ")" } else { "".to_string() },
                            String::from_utf8(n.note().memo()[0..{let len = n.note().memo().iter().position(|&c| c == 0); if len.is_none() {512} else {len.unwrap()}}].to_vec()).unwrap()
                        ));
                    }
                    else
                    {
                        htx.account_asset_memo.push((
                            if htx.tx_type.eq("Sent") { n.note().address().to_bech32m().unwrap() } else { "".to_string() },
                            n.note().asset().to_string() + &if htx.tx_type.eq("Received") { " (@".to_owned() + &n.note().address().to_bech32m().unwrap() + ")" } else { "".to_string() },
                            String::from_utf8(n.note().memo()[0..{let len = n.note().memo().iter().position(|&c| c == 0); if len.is_none() {512} else {len.unwrap()}}].to_vec()).unwrap()
                        ));
                    }
                }
            }
            if !htx.account_asset_memo.is_empty()
            {
                history.push(htx);
            }
        }
        history
    }

    // Merkle Tree must be up-to-date before calling this function!
    pub fn digest_block(&mut self, block: &String) -> u64
    {
        let sk = SpendingKey::from_seed(&self.seed);
        let fvk = FullViewingKey::from_spending_key(&sk);
        let j: Value = serde_json::from_str(&block).unwrap();
        let block_num = j["block_num"].as_u64().unwrap() as u32;
        let dt_str = j["timestamp"].as_str().unwrap().to_string() + " +0000"; // need to add (utc) timezone for valid format
        let dt = DateTime::parse_from_str(&dt_str, "%Y-%m-%dT%H:%M:%S%.3f %z").unwrap();
        let block_ts = dt.timestamp_millis() as u64;
        let mut notes_received = 0;
        let mut fts_spent = 0;
        let mut nfts_spent = 0;
        let mut ats_spent = 0;

        // make sure to not sync a block twice
        if block_num <= self.block_num { return 0; }

        for tx in j["transactions"].as_array().unwrap()
        {
            for action in tx["trx"]["transaction"]["actions"].as_array().unwrap()
            {
                if action["account"].as_str().unwrap().eq(&self.alias_authority.actor.to_string())
                {
                    if  action["name"].as_str().unwrap().eq("mint") ||
                        action["name"].as_str().unwrap().eq("spend") ||
                        action["name"].as_str().unwrap().eq("publishnotes")
                    {
                        let mut notes_b64 = vec![];
                        for ct in action["data"]["note_ct"].as_array().unwrap()
                        {
                            notes_b64.push(ct.as_str().unwrap().to_string());
                        }
                        notes_received = self.add_notes(&notes_b64, block_num, block_ts);
                    }
                    if action["name"].as_str().unwrap().eq("spend")
                    {
                        for seq in action["data"]["actions"].as_array().unwrap()
                        {
                            let seq: PlsSpendSequence = serde_json::from_value(seq.clone()).unwrap();

                            for so in seq.spend_output.iter()
                            {
                                // check if published nullifier belongs to one of our notes
                                let index = self.unspent_notes.iter().position(|n| n.note().nullifier(&fvk.nk, n.position()).extract().0.eq(&Scalar::from(so.nf.clone())));
                                if index.is_some()
                                {
                                    let note = self.unspent_notes.remove(index.unwrap());
                                    if note.note().symbol().raw() == 0 && note.note().amount() != 0 { nfts_spent += 1; } else { fts_spent += 1; }
                                    self.spent_notes.push(note);
                                }
                            }

                            for s in seq.spend.iter()
                            {
                                // check if published nullifier belongs to one of our notes
                                let index = self.unspent_notes.iter().position(|n| n.note().nullifier(&fvk.nk, n.position()).extract().0.eq(&Scalar::from(s.nf.clone())));
                                if index.is_some()
                                {
                                    let note = self.unspent_notes.remove(index.unwrap());
                                    if note.note().symbol().raw() == 0 && note.note().amount() != 0 { nfts_spent += 1; } else { fts_spent += 1; }
                                    self.spent_notes.push(note);
                                }
                            }
                        }
                    }
                    if action["name"].as_str().unwrap().eq("authenticate")
                    {
                        let a: PlsAuthenticate = serde_json::from_value(action["data"]["action"].clone()).unwrap();

                        // check if published note commitment belongs to one of our auth notes
                        let index = self.unspent_notes.iter().position(|n| n.note().commitment().0.eq(&Scalar::from(a.cm.clone())));
                        if index.is_some()
                        {
                            if a.burn == 0
                            {
                                // normal access via auth token
                                // TODO: log this somehow?
                            }
                            else
                            {
                                // auth note was burned
                                self.spent_notes.push(self.unspent_notes.remove(index.unwrap()));
                                ats_spent += 1;
                            }
                        }
                    }
                }
            }
        }

        // with every block also loop through all unpublished notes and attempt to add every single one of them to this wallet (i.e. try to
        // decrypt them as sender or receiver). This way it is ensured that all unpublished notes related to this wallet are always added
        // automatically which means the user doesn't have to add them manually
        for(_, map) in self.unpublished_notes.clone().into_iter()
        {
            for(_, notes) in map.into_iter()
            {
                notes_received += self.add_notes(&notes, 0, 0);
            }
        }

        self.block_num = block_num;
        (ats_spent << 48) | (nfts_spent << 40) | (fts_spent << 32) | notes_received //(ats_received << 16) | (nfts_received << 8) | fts_received
    }

    pub fn add_unpublished_notes(&mut self, unpublished_notes: &HashMap<String, Vec<String>>)
    {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis() as u64;
        self.unpublished_notes.insert(ts, unpublished_notes.clone());
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

    pub fn get_sister_path_and_root(&self, note: &NoteEx) -> Option<(Vec<Option<([u8; 32], bool)>>, ScalarBytes)>
    {
        let mut idx = note.leaf_idx_arr() % MT_ARR_FULL_TREE_OFFSET!(MERKLE_TREE_DEPTH);
        let tos = note.leaf_idx_arr() / MT_ARR_FULL_TREE_OFFSET!(MERKLE_TREE_DEPTH) * MT_ARR_FULL_TREE_OFFSET!(MERKLE_TREE_DEPTH);

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
        wallet::Wallet,
        note::{Note, Rseed},
        eosio::{Authorization, Name, Transaction, Action, Symbol, ExtendedAsset},
        contract::{PlsMint, ScalarBytes, AffineProofBytesLE},
        note_encryption::{NoteEncryption, TransmittedNoteCiphertext, derive_esk, ka_derive_public},
        keys::{SpendingKey, FullViewingKey}
    };
    use rand::rngs::OsRng;

    #[test]
    fn test_serde()
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
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"17.0000 ZEOS@thezeostoken".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"10.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"5.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"4.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"4.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"3.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"3.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"20.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"2.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"2.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"2.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"12345678987654321@atomicassets".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"99999999998765431@atomicassets".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"88888888887654321@atomicassets".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"12345677777777321@atomicassets".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512])
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
        println!("Wallet size: {}", w.size());
        assert!(w.note_exist_in_unspent(w.unspent_notes[0].note()));
        assert!(!w.note_exist_in_unspent(&Note::dummy(&mut rng, None, None).2));

        let mut v = vec![];
        assert!(w.write(&mut v).is_ok());
        assert_eq!(v.len(), w.size());
        let w_de = Wallet::read(&v[..]).unwrap();
        assert!(w == w_de);

        let encoded = w.to_json(false);
        println!("{}", encoded);
        let decoded = Wallet::from_json(&encoded).unwrap();
        assert_eq!(w, decoded);

        println!("{}", serde_json::to_string_pretty(&w.balances()).unwrap());
        println!("{}", serde_json::to_string_pretty(&w.non_fungible_tokens(&Name(0))).unwrap());
    }

    #[test]
    fn test_payload_serde()
    {
        let tx = Transaction{
            actions: vec![
                Action{
                    account: Name(0),
                    name: Name(0),
                    authorization: vec![Authorization{
                        actor: Name(0),
                        permission: Name(0)
                    }],
                    data: serde_json::to_value(PlsMint{
                        cm: ScalarBytes([0; 32]),
                        value: 0,
                        symbol: Symbol(0),
                        contract: Name(0),
                        proof: AffineProofBytesLE([0; 384])
                    }).unwrap()
                }
            ]
        };

        println!("{}", serde_json::to_string(&tx).unwrap());
    }

    #[test]
    fn test_digest_block()
    {
        //let mut rng = OsRng.clone();

        let blocks = vec![
            r#"{"timestamp":"2024-01-25T00:29:25.000","producer":"eosio","confirmed":0,"previous":"0002b6f5739e885a31d00e6ada3ba0e6d93203260ad96297b9fa09dd6b7d7e3c","transaction_mroot":"1f3664d2f8a6dbcfd2380c53a8fbd8cc72d731ee9bbbc6d48eee8c09b24cfbe7","action_mroot":"8126db3a437e5f9ba0d462e250507c124a3878c0afba8d7deb86df9911098ab5","schedule_version":0,"new_producers":null,"producer_signature":"SIG_K1_JwBxUmkk5RZbdPiHyy5eNNB3NnTuL1fTprtMf669moCSuhAoRuxzcdBpe1pbJ1GdLpiU5fzNDub6d3cSP7kFHKCYKo7uXt","transactions":[{"status":"executed","cpu_usage_us":4219,"net_usage_words":354,"trx":{"id":"9ca5f9d36c727140b31aa59b4ddcf707d81170a44d8d2bc531413da8aa2290e7","signatures":["SIG_K1_KkjbeeVA4FJm3xJR3FZx3qeFTBzg5yqyaif3JRVGCZBV6gf63xnkhEf8GW6KA9ux4y2C6f2ZMRLT4CRvVuuXNqg1G5dPjY","SIG_K1_KigpnoaV1YnbWbUCqxKk7fzXXQZ4ttAesZgMtQc8CRxmdAbd1QTbdzT9oFQVWHRYf1oxLyphkAMZ6JwUTSWk2LdAVKMjU6"],"compression":"zlib","packed_context_free_data":"789c63000000010001","context_free_data":[],"packed_trx":"789c9d5769d4d3541afed8ddc511655c90cf055133d03469bab8276d92b6499aa6591b454ddaa46d92366dba07150417d4516154c4ed388a823b8aa2e3eec8221e054101d711758e0b0c3a88eba00cf3791cce51677ecc99fbe7def7b9f73cf7bdef7d9ff7dcbbeabe878d558f1d1cd8f5c3c0501b3df3aa2b47f35f8b2fff68ccdcb2e0e4613f0706c75ff3e0c0c0a259a1115b4171c896a79cba66cdb0b98b17ed75d82567877e5c71f7671084ec01de9ff7d6e7d2ac7b766e4f0dff716e6024cef23ff6e3d4a1c160cbd36a4dd3f0068f1fac566a2df0903b0ffbf73eff23eddc75237ea2557fe2fdff6827ef01f61cb47ed0b05fd08e6ef5064dc3f8791c06e62ebef63f0273f1a1c307e77efbc111ebd6ae9f786be88377362cacf809d3ff121d7eeb8ddc0347ab33affdc369bf76798f7733475c597bf2c91ba73c73daf74eecc4754b666f1876fed927ae00ce4e5273be79baa705b55b96dd3f78c5b41b3f7beca12f67cdbb70e3a8674f1aec4e192f2cedaf5112f483d3c9c9fc9bef9c5581c863fefccd586dcc470fde033d3c2d337b898e81a368ecfbaf46bc1758f5c671272fdb90bd5e856eea4f3ffda22d2bdffe78f92b7bb3b7c6472d3cf0d5d0165efe507af99ebf3f7fcb09e3fe39f18e03a833fd2b2f3f51bc203ff2a4c217a336103ba6acf8e8b8a3b64f3e9fd839d59ca1cef8cbb21b16dfbce4e0f9f3b65f6c21edc6e8d9f94583ad812dbb5e5f7afb2727cc7befc259abb75d7f6cf701fefdcc751bbe1f7b06b5f4838ff7eabe7b5af85da039ffd11fce1ebbe8cea9d6210f3dbcf59935175dbe7326a03f3569f0f17bb74f889f873ffde243bde70e218f0b8c79e6b2199f7f237ebafeb4972b6327ec7fd3c41da753f10577be76eeaab58ddcb8a9d39ef8f45eedb035ff58858edb3ded80e0c4c3e71dbe641a3f6f7e6efedfb023c79e31815fe9ee63bc3866ddc76b371e69edb56bc7ed7bfdf5ebcbeda56b9fbe64ef031fd977b2b6099e65240fc03fbae3a52ddcf8f1834b66df70eeee57b4b1d1cf1794c9a5e282f3d7f684e817ccc60d473791530ffb5df8d749bc470633473cb6afb4fd03425878e4139b774ef87c65851ab8fcbcca598bd19be65c7acac2d5c7bf7ae1d5d853bafee1b6172e9af6d61ba73023df64af7e5aff76fd1d977e3afb8009cd2f4f592d3ff2c7feeeb7d6de347bd4db1f2daf4ba70eac73971df9c9cdbbb75c71e027feddc3f73971db6dabf77be9fa095fcdae6c237718e9dc4679c7b373d4e37b1ee5ac5c3ef26876eb97ebc9334fbe6bd282f766fa0f8f810fd4a5795f4cb9ed89f1de25af0daac2e6bb4ed8efe08b7bd7d6dfb96177f3d2ab26c94f5eb3f49c396fa672a7de72d635fcee91efed3b7d9eface514b37abcb6e7e6174ee99690f5dbd70e48e0f43c7a6e5eb26cbcaa6dea5bfd934e7e82b169ffe4a66db412b3f1db56bb731e3b66b7e5f70ef5f75df734de698494b9cfdbed9f8a7a7becdedfd5d75f209a3b71c74e8575be73ff6f5058fce9a38159b78c8d6b38e587fdc85072d3e7ceec5af6f7ffc45ebb71f624f6c40669c5bc48a534ef7d7b2e79c326b6b70b9b764e7a4bdfda9c6fc91573c625fbb68fa0ae7ba779f3d2a43eec2377db7ede37df06f876d36638a397dff1b9fbf65f5f77767c65db6dfa6fb475cbf79f9b8e12bc6f40a3d295324847c3aa0551a98a7b70b1da082f83d2361671b541baf1449b988990e044744892d35834e396ed26e2544f008151c52a358aff5f0964d0335878b753255066fd83e5b0c415c27db2e116151e8d48b4d94efdba29c93f1721be574d72d4793f10694cad2881f000cd09068b615b75828acb18c055aed12c234a34492a1b98c1b90f4622f6b7035d2d09544aedb558d52315c262ca85af6b900a9d7fa690196b488982c97f2715093ea36ebd47aae8ad09027f826ef5453a6edba781a03c82654eba77a79226d47f8ba8566a362ba2d9b4eb80bea78806eb6ea780e4f143bcd8c14b2b3158992cb089310492b6d875136ea41e17237693555132841beac75035dd5a7b162510d74bb71d0ca31a61642e1b8c10b6c2165d034516c36a5882a262ae90888d5e0789e83f21d8b8a239e1709b9d188c3f56c255a53e96056888b150c071d2f9360326986540b094252c43c93f235bb926368205a69784c9026421ad497a87c7fe8561c960bc086d683153090aac74b09ae982b70093e1940025eb8c51bed463f948bf47b292951d475d7409d724854f1021a54dc929bcac1021f0d63741f726d50ee0865188937e14e4220a950a0158395462aa35720b65f325b0d28cb6180daaaa26d1d9492b1a60ab723498441e1483182965cbe94734b1a12b2f0702528e57305316985181c1019ad5a0f57793c95d5ea9d9227c48a05060473f526804559b6d128188e28aa6290cbc430d52994f51e1151dc246d09688529292810514424e6e68544b6d8b1e114d66fb678ae15d78016e42818d1e6b3225605a52cdf0fba6ea4a6330952a6dd029ec1a15c14512acd68816a92e150914efb051d23c345a88b16752dc4ca445b887842b200e78bf1ba0506e35c95a823c10a99f71b9452566a9d4cb0e4364b043914c55aaceda4d896cec88570c04e59703be4e7f88457ad0a84a3e5b5760ccae0dd743bdae9a5c28946b88a397dca13e4463dafb605a691adf35a86ad479c16ef5800d63531a81d90643d97656051403b3a5172540934aa7ab5c13b14dbe6ba6ac3c5a5503a40510c9da2ec1aaa48919660a484240281f148aebc628cafca7001f63cc1a9072b10e12a1480f491be419442482eaae1392609ca8ed197aaa2dd04a30dc0b45b25962879a60060580a24404b4e00f92a2247d2244a87182bcc66c2a65ccf7b289c47e2f94c3911f601b6c5b16858573cbf0c6166ac928b84694aa24d54ed44da31366d2b313a93a3518d909ab49621e86eb61b4bdb512a0a08d9d490a0870865d013dab936a501b52c605721bc19b662824f114991b0436ca2946cc9f986d0e9d4b1a61480d4721d29c03890aa44bd20ed0b608b57984649d178a0158dc78b4636edc852434ae149a0458720a06b01816cab8d11a56c276f44380ead174d54e724bbd3f7e56ccdf1199ea9f5b570b5a2c6ba7236e57b095328997db293e473b5b051412b59be80cb39a4c9451908128dae52b09a0e64b1a626702e668529bd2133c1a012e5e47cd10e1a380936c858a82efb25d433801aac2512324f0492202a05f85207964c9141e215282df48cb80469625e88cb9c2cf4a4aae12b9d54856f892ee5069aee506d50914cbe1641e29002325a96552320dcadf43a483e2ea25695a1713705d61805c5abb93ad50eba51bfe6d6b9360856e586532e159c1e25f101a147788a05d51265320089253958ccf052278ad0d9be04a2053303910c69c7143de68010c8e4c9b8518e0cd57d4a36dc643c00512510219a9e8dd7ca5cb68183689506398713ca288de4fd981c92bb0eec02a2418200213624b12b04421d05815b5ccd1613e5aa6c5929b5df04d3959cc95341265308ea0936a8604389e2784800c7f3a2a9ea1c468b16dfb5fcba431699545808f5c31180e5d279ba4e504ecfcd9a22d5d56b40ce36f336a4e0467828591d18843d3b6966a4ae4806f06a9024a31e150c14fa710fb7cb9d3ed44eb211dca9b56a05ac2e87fa8adf2b30a96822ed6a55b79ff16941e269cfb6bb4a84ac97aa64b9cff278d8d28276b145507cb74523753d0b757022d5f3430847a018cc96e31e582c9779198d825a2051c8f552880c37c1980e57cb193b5cac925e528c5544269cd61b2d8a8807ba896c0666450e466262d2755c9347e57a3185095cc610132aeb837a83b7cc44bff68b67f2c06bc27ff93ffc0b205aa15c","transaction":{"expiration":"2024-01-25T00:31:02","ref_block_num":46790,"ref_block_prefix":4244451091,"max_net_usage_words":0,"max_cpu_usage_ms":0,"delay_sec":0,"context_free_actions":[],"actions":[{"account":"thezeosalias","name":"begin","authorization":[{"actor":"thezeosalias","permission":"public"}],"data":"","hex_data":""},{"account":"eosio.token","name":"transfer","authorization":[{"actor":"aliceaccount","permission":"active"}],"data":{"from":"aliceaccount","to":"zeos4privacy","quantity":"15.0000 EOS","memo":"ZEOS transfer & mint"},"hex_data":"90a7a60819855c34e091d9ee5682a9faf04902000000000004454f5300000000145a454f53207472616e736665722026206d696e74"},{"account":"thezeostoken","name":"transfer","authorization":[{"actor":"aliceaccount","permission":"active"}],"data":{"from":"aliceaccount","to":"zeos4privacy","quantity":"25.0000 ZEOS","memo":"ZEOS transfer & mint"},"hex_data":"90a7a60819855c34e091d9ee5682a9fa90d0030000000000045a454f53000000145a454f53207472616e736665722026206d696e74"},{"account":"thezeostoken","name":"transfer","authorization":[{"actor":"aliceaccount","permission":"active"}],"data":{"from":"aliceaccount","to":"thezeosalias","quantity":"7.0000 ZEOS","memo":"tx fee"},"hex_data":"90a7a60819855c34808d8b0653f555cb7011010000000000045a454f5300000006747820666565"},{"account":"thezeosalias","name":"mint","authorization":[{"actor":"thezeosalias","permission":"public"}],"data":{"actions":[{"cm":"90f7e11bd0ced11f9d34e1dbd4a3697a44667af341029d9951ad215a8093923d","value":250000,"symbol":"4,ZEOS","contract":"thezeostoken","proof":"8b6ebaba992dbd3dfb6c3929d0af83d4017c5c29c42b5c484b88f6bc786131619cb5ac208a5d99edb6b0f382917ed505be2a20772d1754b279cd58444cae7b472753d8db5b69324722c1f6106107e5aea932b15d4e83af624230054c42fbf403de2fc6d7243ab5d450955a329a797b3e81e9c5dae6c3cc094f9d4305a30fcf34e95357e256cba9efc09c2814fe1fa20e4b407a8b8929557d59042a63f105d446f22dc4e5241ef0277c46fa2e667f5a7fddb597a79baf139691f0846a357571068359a6207400e9fdd3b2a1e72891de7e82c8ec952377ad53e04e94d4fb103f4bb2e1e60877dc3d36dc2b7396b4fc5c10a6a42e6a15b0b1eabdcd8189fa802b62bb2520b7aaf01d436045bcc7b078bf1547242f07bd877feef655e8d13dcb69101d0d9a1ff23e4b4398a4d25fc6ce7152142e5db9e8aa6119cdf9c64114ff5d0e311f1a911aaf5d5391965296eb421c103f1d53c56f0a65c707d0e6ced51c6a08fdf2a108e3f5896bb2cebc85090fb30b2761d6338265480e45e5a2c9e9511717"},{"cm":"af83975fffcc611038ee986847b255987cce785438f14dd5d42173353c192c36","value":150000,"symbol":"4,EOS","contract":"eosio.token","proof":"b60b56f0e14654a31cb9dffa1deec5694b008960695ba7419a88863ba3c826cf7e8e42bb6262e2ecc2815dd9d73b4d04d84f8ebc62f7d1a286e8830e1d73f33bc857b3a079ffd9ce9a8305dae5c370563c00d06fb51ce79bffe98a0fe77aa8020a29ec9fc80cc9951df48369ec47f2654a52d557f2be885a2678724b6cc5c304214feaf3d147403aa52598de807ab107330f625691f12d9fb9177285d2205a54dfa5280c1384789370db97ff73868d2557ba8fb25e88d849523c9c5b8f53ff04de0b7b915adb1eb2df5ab59bc20652bd5db08ea304f2e234234a5794275758d6788612d688218aa73ecc4eec11c5e805fdff657f9f8f8c636facc6abbf734d2225af6c0cf6d5b8bbf75209f86d272806e91116f4ea96b6f57db4821f2e421f15ea5b1bd1247e11a71a9084d3f0b7c76a18e242b9d4357f5f6442642d3e7ace4f5e3b82ea31c372affa25097a2e6596048ab36b93a67bc46c94dcbe1e4e47fd45d6f8ece60a45f701df663958667b0d99c09cc8fba84e14870cd6ac0395dfc314"}],"note_ct":["xcxVNdFTYJ/aiqBrbucv+i5zxeDkPqKuEidGWdBfl237UVOgs1lhCfLoi4FS5K1ZEOUpnxEtkL+nlQ9vNmMEqkzOd42QvPugF6UTvpdsASykUWRWEhuAQbooh8HCq2IPL5z/+e0eVLOtCjO26aOMj0jug5Ms8FHMLQNo/VbdxPeQnGebXDRwwZegd6hFj2mhzQ/GbnyJT3Va7UHhgYC0aVpkOlnxoZ5L2rTzfSlmIfkooEJB+Gs2nyIxYFJk7SpjAP8UJuWfl6w0bE/LstpEREDdvsNV4kPiVKWh5MDUGjJk6AO8r26hwHjsZf+g2zWaw/wZzLBddZ/wwC0jRMfa4A3CeSTOcIeLLFdssV7ZUDiJ70Bn3CYQ2YvjKC5rr74o87lQxkX8nZL1PTCUiBE0lrNDMNJMGZcDFVXUYMIzakiRML+8iqrM1LF4a2yVKYy237lOQ/3eax3X0/IpCgDQdRcQDSH/5/r6tSeuqy4R7yxIVDdbboeAlh4UZEcA1XogoIR3TS86BLy2ok0WvTh35Cs3vDTGK4/t93XqINbi2Oygftq2PQB+ZtmAub0VH9sZ3u7H5MA37d7AgoSgRoga54jE6i1VYRcUHj4ME+UMamp6mSEIPapvgrT9dcM00Rps+B8OOqqcelUUZU1QN9BZlchbxF7XoHLjTAiMgXA+7XU59oYTDPdvk3IBystSQtCa+t2lXBFuSPUBm0VPSy1oo7nbMDGWLocENE2R85Xis8cKsG64dLJzcbBG6d2wAdba4OWFuT7rTHc3YdCpj01CQmFp51iGYzqKXhXnvN1gosgFGR7yn9ulIOtbMWc6/kIj3u4zRSDrmmTFlaYau92NEwJu8vxI6Dq6mBlyKrTWqpYZuTMqPpSaNOp7ltSlj+BwfB2u/VWbRPM3UTAvbFglZV0embmqSlKOuQwZqoEV4J/KKMLIKknAXV7tTeITH520C7Rh","zZW3c3rrTlp1i2FoXK+5y5yeFg45R8aERMH0WleyVmUks08q+fktgOFgrfT+BBI0F0jWD+Ym5W7JGAL4Mj6ON6fWpYrA3Y5CYNhD6z+OtQOA6bXrzh2Bf9iR76LKVLfAZv7u9OJkX9LNRLAaFVsLaNFLwPw9Jk8K8+TPIMs8WpYW0rTuRuKa+nP+km2Es6j9TzKFHUFk4ODgHtWYqTvvpBsV/2Zhp5c3E+Ii8r1LzT0tSXMqgXaS+t8CCdePJlWVqVIEH+tL42+wj+/PtuBFgPvYe7QQApdfAbQVkvyzWPnlzMSMnya6miZ9wWPIzrDfTgfyGvHSRn6eiAiPScEWR5sQ8M22UewXcjsl2jOfaTQoBj6KbqWM11X8QWYdk1eEG0qG94pWzgAre+n3aDDWSF/H0AV/Sgv3VfUM5Ci2JTxeCV2aUYTCWQWTxVmezXvIiStUoKo/so2YvZ5NYn75C2X0MaPOZ703wixv5YCUAjmMLEoI0nMXAEmRpKu1o8znopQu00mWqlhgclxKVS/TxFrXj2nDhG/2UgW1dNSVv85LPyV0AcfN2GMGk9Xb9l020MYGCeh75zxKWeoHC/2Kg05FsrkEnhQPqE0AmL0QlQThAL5Yz9W4Wwl3o+UeG0+FUqVUwT/4vX53tQnkUDhmWjjIZys0JiRfSK1MNc1bDO1XB9OJlr5/EEYUfZbQBLUjSwjzplGdMI6T4y67+OQJYLpFKlxoPfUKwbn+RkfYk2XEe60jWl303rkHfNVwUG/Em1GG8rK1/cyCrEkhvy2uHO7ElntncBpW4yXzxcMI8DJoamoyNzLTVSLrkkwX7GpgmGhyOSE6ja1kdtFKSwtL5pbP2vEFIxz45QFAB3OhCr0dhhSWA80a/DcRxI5W3s09b3mhNk6dmGrHU9iUM6JbqtKFC/wDPN3OUQ359UHolofSAWpdIBTQNeUDZOz0bqSjfDyn"]},"hex_data":"022090f7e11bd0ced11f9d34e1dbd4a3697a44667af341029d9951ad215a8093923d90d0030000000000045a454f530000003015a41953f555cb80038b6ebaba992dbd3dfb6c3929d0af83d4017c5c29c42b5c484b88f6bc786131619cb5ac208a5d99edb6b0f382917ed505be2a20772d1754b279cd58444cae7b472753d8db5b69324722c1f6106107e5aea932b15d4e83af624230054c42fbf403de2fc6d7243ab5d450955a329a797b3e81e9c5dae6c3cc094f9d4305a30fcf34e95357e256cba9efc09c2814fe1fa20e4b407a8b8929557d59042a63f105d446f22dc4e5241ef0277c46fa2e667f5a7fddb597a79baf139691f0846a357571068359a6207400e9fdd3b2a1e72891de7e82c8ec952377ad53e04e94d4fb103f4bb2e1e60877dc3d36dc2b7396b4fc5c10a6a42e6a15b0b1eabdcd8189fa802b62bb2520b7aaf01d436045bcc7b078bf1547242f07bd877feef655e8d13dcb69101d0d9a1ff23e4b4398a4d25fc6ce7152142e5db9e8aa6119cdf9c64114ff5d0e311f1a911aaf5d5391965296eb421c103f1d53c56f0a65c707d0e6ced51c6a08fdf2a108e3f5896bb2cebc85090fb30b2761d6338265480e45e5a2c9e951171720af83975fffcc611038ee986847b255987cce785438f14dd5d42173353c192c36f04902000000000004454f530000000000a6823403ea30558003b60b56f0e14654a31cb9dffa1deec5694b008960695ba7419a88863ba3c826cf7e8e42bb6262e2ecc2815dd9d73b4d04d84f8ebc62f7d1a286e8830e1d73f33bc857b3a079ffd9ce9a8305dae5c370563c00d06fb51ce79bffe98a0fe77aa8020a29ec9fc80cc9951df48369ec47f2654a52d557f2be885a2678724b6cc5c304214feaf3d147403aa52598de807ab107330f625691f12d9fb9177285d2205a54dfa5280c1384789370db97ff73868d2557ba8fb25e88d849523c9c5b8f53ff04de0b7b915adb1eb2df5ab59bc20652bd5db08ea304f2e234234a5794275758d6788612d688218aa73ecc4eec11c5e805fdff657f9f8f8c636facc6abbf734d2225af6c0cf6d5b8bbf75209f86d272806e91116f4ea96b6f57db4821f2e421f15ea5b1bd1247e11a71a9084d3f0b7c76a18e242b9d4357f5f6442642d3e7ace4f5e3b82ea31c372affa25097a2e6596048ab36b93a67bc46c94dcbe1e4e47fd45d6f8ece60a45f701df663958667b0d99c09cc8fba84e14870cd6ac0395dfc31402c407786378564e644654594a2f6169714272627563762b69357a7865446b50714b7545696447576442666c32333755564f6773316c6843664c6f69344653354b315a454f55706e7845746b4c2b6e6c5139764e6d4d45716b7a4f643432517650756746365554767064734153796b555752574568754151626f6f68384843713249504c357a2f2b653065564c4f74436a4f3236614f4d6a306a7567354d733846484d4c514e6f2f566264785065516e47656258445277775a6567643668466a326d687a512f47626e794a5433566137554868675943306156706b4f6c6e786f5a354c3272547a66536c6d49666b6f6f454a422b4773326e79497859464a6b3753706a415038554a7557666c36773062452f4c737470455245446476734e56346b5069564b5768354d4455476a4a6b36414f387232366877486a735a662b67327a5761772f775a7a4c4264645a2f777743306a524d6661344133436553544f6349654c4c4664737356375a5544694a3730426e334359513259766a4b4335727237346f38376c51786b58386e5a4c3150544355694245306c724e444d4e4a4d475a634446565855594d497a616b69524d4c2b386971724d314c4634613279564b59793233376c4f512f336561783358302f497043674451645263514453482f352f723674536575717934523779784956446462626f65416c6834555a45634131586f676f49523354533836424c79326f6b30577654683335437333764454474b342f7439335871494e6269324f7967667471325051422b5a746d41756230564839735a33753748354d413337643741676f5367526f676135346a453669315659526355486a344d452b554d616d70366d534549506170766772543964634d30305270732b42384f4f717163656c55555a5531514e39425a6c636862784637586f484c6a5441694d6758412b37585535396f5954445064766b33494279737453517443612b74326c58424675535055426d3056505379316f6f376e624d4447574c6f63454e453252383558697338634b73473634644c4a7a636242473664327741646261344f57467554377254486333596443706a303143516d467035316947597a714b5868586e764e31676f736746475237796e39756c494f74624d5763362f6b496a3375347a525344726d6d54466c6159617539324e45774a7538767849364471366d426c794b7254577170595a75544d71507053614e4f70376c74536c6a2b4277664232752f56576252504d33555441766246676c5a5630656d626d71536c4b4f7551775a716f4556344a2f4b4b4d4c494b6b6e4158563774546549544835323043375268c4077a5a573363337272546c70316932466f584b2b35793579654667343552386145524d4830576c6579566d556b733038712b666b74674f46677266542b4242493046306a57442b596d3557374a47414c344d6a364f4e3666577059724133593543594e6844367a2b4f74514f41366258727a6832426639695237364c4b564c66415a763775394f4a6b58394c4e524c41614656734c614e464c775077394a6b384b382b5450494d7338577059573072547552754b612b6e502b6b6d324573366a39547a4b464855466b344f44674874575971547676704273562f325a6870356333452b49693872314c7a54307453584d71675861532b743843436465504a6c575671564945482b744c34322b776a2b2f5074754246675076596537515141706466416251566b76797a57506e6c7a4d534d6e7961366d695a39775750497a7244665467667947764853526e3665694169505363455752357351384d323255657758636a736c326a4f666154516f426a364b6271574d31315838515759646b31654547307147393470577a674172652b6e336144445753462f483041562f536776335666554d354369324a54786543563261555954435751575478566d657a587649695374556f4b6f2f736f3259765a354e596e3735433258304d61504f5a3730337769787635594355416a6d4d4c456f49306e4d5841456d52704b75316f387a6e6f70517530306d57716c6867636c784b56532f54784672586a326e4468472f3255675731644e53567638354c507956304163664e32474d476b395862396c3032304d594743656837357a784b57656f48432f324b6730354673726b456e685150714530416d4c30516c515468414c35597a39573457776c336f2b556547302b465571565577542f347658353374516e6b5544686d576a6a495a7973304a695266534b314d4e633162444f315842394f4a6c72352f45455955665a6251424c556a53776a7a706c47644d493654347936372b4f514a594c70464b6c786f5066554b77626e2b526b66596b3258456536306a576c333033726b48664e567755472f456d31474738724b312f63794372456b6876793275484f37456c6e746e634270573479587a78634d4938444a6f616d6f794e7a4c5456534c726b6b7758374770676d4768794f5345366a61316b6474464b5377744c357062503276454649787a343551464142334f684372306468685357413830612f446352784935573373303962336d684e6b36646d477248553969554d364a6271744b46432f7744504e334f555133353955486f6c6f665341577064494254514e6555445a4f7a306271536a6644796e"},{"account":"thezeosalias","name":"end","authorization":[{"actor":"thezeosalias","permission":"public"}],"data":"","hex_data":""}]}}}],"id":"0002b6f62abb8b161f47f7e9dad878d5034aa95528b410ea0ca60c0a543c2b43","block_num":177910,"ref_block_prefix":3925296927}"#.to_string(),
        ];

        //let leaves = vec![
        //    hex::decode("90f7e11bd0ced11f9d34e1dbd4a3697a44667af341029d9951ad215a8093923d").unwrap(),
        //    hex::decode("af83975fffcc611038ee986847b255987cce785438f14dd5d42173353c192c36").unwrap(),
        //];
        // same data as vec of vec's above but as a single vec
        let leaves = hex::decode("90f7e11bd0ced11f9d34e1dbd4a3697a44667af341029d9951ad215a8093923daf83975fffcc611038ee986847b255987cce785438f14dd5d42173353c192c36").unwrap();

        let mut w = Wallet::create(
            b"army add gossip wrist squeeze chronic simple gold like island wheel north cave praise buddy shine monitor damp into another expose tortoise educate army",
            false,
            [0; 32],
            Name::from_string(&format!("zeos4privacy")).unwrap(),
            Authorization::from_string(&format!("thezeosalias@public")).unwrap()
        ).unwrap();

        w.add_leaves(leaves.as_slice());
        for b in blocks
        {
            w.digest_block(&b.to_string());
        }

        println!("{}", w.to_json(true));
        println!("{:?}", serde_json::to_string(&w.get_sister_path_and_root(&w.unspent_notes[0])).unwrap());

    }
}
