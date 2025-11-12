use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
use group::GroupEncoding;
use rand_core::RngCore;
use serde::{Serialize, Serializer, Deserialize, ser::SerializeStruct, Deserializer, de::Visitor, de::SeqAccess, de::MapAccess, de};
use std::fmt;
use std::io::{self, Read, Write};
use crate::eosio::Asset;
use crate::{
    eosio::{ExtendedAsset, Name, Symbol},
    keys::{EphemeralSecretKey, NullifierDerivingKey, SpendingKey, FullViewingKey, prf_expand},
    note::nullifier::Nullifier, address::Address,
};
use crate::constants::{MERKLE_TREE_DEPTH, RSEED_PERSONALIZATION};
use blake2s_simd::Params as Blake2sParams;

mod commitment;
pub use self::commitment::{ExtractedNoteCommitment, NoteCommitment};
pub(super) mod nullifier;

/// Enum for note randomness before and after [ZIP 212](https://zips.z.cash/zip-0212).
///
/// Before ZIP 212, the note commitment trapdoor `rcm` must be a scalar value.
/// After ZIP 212, the note randomness `rseed` is a 32-byte sequence, used to derive
/// both the note commitment trapdoor `rcm` and the ephemeral private key `esk`.
#[derive(Copy, Clone, Debug)]
pub struct Rseed(pub [u8; 32]);

impl Rseed
{
    pub fn new(rng: &mut impl RngCore) -> Self
    {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        Rseed(bytes)
    }

    pub fn from_seed(seed: &[u8]) -> Self {
        let h: [u8; 32] = Blake2sParams::new()
            .hash_length(32)
            .personal(RSEED_PERSONALIZATION)
            .to_state()
            .update(seed)
            .finalize()
            .as_bytes()
            .try_into()
            .expect("output length is correct");
        Rseed(h)
    }

    /// Defined in [Zcash Protocol Spec § 4.7.2: Sending Notes (Sapling)][saplingsend].
    ///
    /// [saplingsend]: https://zips.z.cash/protocol/protocol.pdf#saplingsend
    pub(crate) fn rcm(&self) -> commitment::NoteCommitTrapdoor {
        commitment::NoteCommitTrapdoor(jubjub::Fr::from_bytes_wide(prf_expand(&self.0, &[0x04]).as_array()))
    }
}

/// A discrete amount of funds or an NFT received by an address.
#[derive(Clone, Debug)]
pub struct Note
{
    /// The header field
    header: u64,
    /// The recipient of the funds.
    address: Address,
    /// The EOSIO account which is involved with this note:
    /// Mint: The EOSIO account which sent this note
    /// Transfer: 0
    /// Burn: The EOSIO account which receives this note
    /// Auth: == code
    account: Name,
    /// The actual asset this note represents:
    /// amount: The amount/uid of this note.
    /// symbol: The symbol of this note, 0 if NFT/AT
    /// contract: The EOSIO smart contract this code is associated with:
    /// FT/NFT: The token contract
    /// Auth: The contract this Auth token was issued for
    asset: ExtendedAsset,
    /// The seed randomness for various note components.
    rseed: Rseed,
    /// The 512 bytes wide memo field
    memo: [u8; 512],
}

impl PartialEq for Note {
    fn eq(&self, other: &Self) -> bool {
        // Notes are canonically defined by their commitments.
        self.commitment().eq(&other.commitment())
    }
}

impl Eq for Note {}

impl Note {
    /// Creates a note from its component parts.
    ///
    /// # Caveats
    ///
    /// This low-level constructor enforces that the provided arguments produce an
    /// internally valid `Note`. However, it allows notes to be constructed in a way that
    /// violates required security checks for note decryption, as specified in
    /// [Section 4.19] of the Zcash Protocol Specification. Users of this constructor
    /// should only call it with note components that have been fully validated by
    /// decrypting a received note according to [Section 4.19].
    ///
    /// [Section 4.19]: https://zips.z.cash/protocol/protocol.pdf#saplingandorchardinband
    pub fn from_parts(
        header: u64,
        recipient: Address,
        account: Name,
        asset: ExtendedAsset,
        rseed: Rseed,
        memo: [u8; 512]
    ) -> Self
    {
        Note {
            header,
            address: recipient,
            account,
            asset,
            rseed,
            memo
        }
    }

    /// Generates a dummy spent note.
    pub fn dummy(
        rng: &mut impl RngCore,
        account: Option<Name>,
        asset: Option<ExtendedAsset>,
    ) -> (SpendingKey, FullViewingKey, Self) {
        let sk = SpendingKey::random(rng);
        let fvk = FullViewingKey::from_spending_key(&sk);
        let recipient = fvk.default_address().1;
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);

        let note = Note::from_parts(
            0,
            recipient,
            account.unwrap_or_else(|| Name(0)),
            asset.unwrap_or_else(|| ExtendedAsset::new(Asset::new(0, Symbol(0)).unwrap(), Name(0))),
            Rseed(bytes),
            [0; 512]
        );

        (sk, fvk, note)
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()>
    {
        writer.write_u64::<LittleEndian>(self.header)?;                             // 8
        writer.write_all(self.address.to_bytes().as_ref())?;                    // 43
        writer.write_u64::<LittleEndian>(self.account().raw())?;                    // 8
        // For notes, we enforce non-negative amounts (commitments expect that).
        let amt = self.asset.quantity().amount();
        if amt < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "note amount must be non-negative"));
        }
        writer.write_u64::<LittleEndian>(amt as u64)?;                              // 8
        writer.write_u64::<LittleEndian>(self.asset.quantity().symbol().raw())?;    // 8
        writer.write_u64::<LittleEndian>(self.asset.contract().raw())?;             // 8
        writer.write_all(self.rseed.0.as_ref())?;                               // 32
        writer.write_all(self.memo.as_ref())?;                                  // 512

        Ok(()) // 627 bytes total
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self>
    {
        let header = reader.read_u64::<LittleEndian>()?;
        // address (43 bytes)
        let mut recipient = [0u8; 43];
        reader.read_exact(&mut recipient)?;
        let recipient = Address::from_bytes(&recipient)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid address: {e}")))?;
        // account
        let account_raw = reader.read_u64::<LittleEndian>()?;
        let account = Name(account_raw);
        // amount (stored as u64; must fit into i64 if you want to build an Asset)
        let amount_u64 = reader.read_u64::<LittleEndian>()?;
        if amount_u64 > i64::MAX as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "amount exceeds i64::MAX"));
        }
        let amount_i64 = amount_u64 as i64;
        // symbol
        let symbol_raw = reader.read_u64::<LittleEndian>()?;
        let symbol = Symbol(symbol_raw);
        let quantity = Asset::new(amount_i64, symbol)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid Asset"))?;
        // contract
        let contract_raw = reader.read_u64::<LittleEndian>()?;
        let contract = Name(contract_raw);
        let asset = ExtendedAsset::new(quantity, contract);
        // rseed (32 bytes)
        let mut rseed = [0u8; 32];
        reader.read_exact(&mut rseed)?;
        let rseed = Rseed(rseed);
        // memo (512 bytes)
        let mut memo = [0u8; 512];
        reader.read_exact(&mut memo)?;

        Ok(Note::from_parts(header, recipient, account, asset, rseed, memo))
    }

    /// Returns the recipient of this note.
    pub fn header(&self) -> u64 {
        self.header
    }

    /// Returns the recipient of this note.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns the account of this note.
    pub fn account(&self) -> Name {
        self.account
    }

    /// Returns the quantity of this note.
    pub fn quantity(&self) -> &Asset {
        self.asset.quantity()
    }

    /// Returns the amount of this note.
    pub fn amount(&self) -> u64 {
        self.asset.quantity().amount() as u64
    }

    /// Returns the symbol of this note.
    pub fn symbol(&self) -> &Symbol {
        self.asset.quantity().symbol()
    }

    /// Returns the (extended) asset of this note.
    pub fn asset(&self) -> &ExtendedAsset {
        &self.asset
    }

    /// Returns the asset's contract of this note.
    pub fn contract(&self) -> &Name {
        self.asset().contract()
    }

    /// Returns the rseed value of this note.
    pub fn rseed(&self) -> &Rseed {
        &self.rseed
    }

    /// Returns the memo field of this note.
    pub fn memo(&self) -> &[u8; 512] {
        &self.memo
    }

    /// Is this note an NFT
    pub fn is_nft(&self) -> bool {
        self.symbol().raw() == 0
    }

    /// Is this note an auth token (AT)
    pub fn is_auth_token(&self) -> bool {
        self.symbol().raw() == 0 && self.amount() == 0
    }

    /// Sets the amount of this note.
    pub fn set_amount(&mut self, amount: u64) {
        // Invariant: notes are non-negative
        let new_qty = Asset::new(amount as i64, self.symbol().clone())
            .expect("symbol unchanged; non-negative amount must be valid");
        self.asset = ExtendedAsset::new(new_qty, *self.contract());
    }

    /// Computes the note commitment, returning the full point.
    fn cm_full_point(&self) -> NoteCommitment {
        NoteCommitment::derive(
            self.address.g_d().to_bytes(),
            self.address.pk_d().to_bytes(),
            self.account.raw(),
            self.asset.quantity().amount() as u64,
            self.asset.quantity().symbol().raw(),
            self.asset.contract().raw(),
            self.rseed.rcm(),
        )
    }

    /// Computes the nullifier given the nullifier deriving key and
    /// note position
    pub fn nullifier(&self, nk: &NullifierDerivingKey, position: u64) -> Nullifier {
        Nullifier::derive(nk, self.cm_full_point(), position)
    }

    /// Computes the note commitment
    pub fn commitment(&self) -> ExtractedNoteCommitment {
        self.cm_full_point().into()
    }

    /// Defined in [Zcash Protocol Spec § 4.7.2: Sending Notes (Sapling)][saplingsend].
    ///
    /// [saplingsend]: https://zips.z.cash/protocol/protocol.pdf#saplingsend
    pub fn rcm(&self) -> jubjub::Fr {
        self.rseed.rcm().0
    }

    /// Returns the derived `esk` if this note was created after ZIP 212 activated.
    pub fn esk(&self) -> EphemeralSecretKey {
        EphemeralSecretKey(jubjub::Fr::from_bytes_wide(
                prf_expand(&self.rseed.0, &[0x05]).as_array(),
            ))
    }
}

impl Serialize for Note
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 6 is the number of fields in the struct.
        let mut state = serializer.serialize_struct("Note", 6)?;
        let addr = self.address.to_bech32m()
            .map_err(serde::ser::Error::custom)?;
        state.serialize_field("header", &self.header)?;
        state.serialize_field("address", &addr)?;
        state.serialize_field("account", &self.account)?;
        state.serialize_field("asset", &self.asset)?;
        state.serialize_field("rseed", &hex::encode(self.rseed.0))?;
        state.serialize_field("memo", &hex::encode(self.memo))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Note {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field { Header, Address, Account, Asset, RSeed, Memo }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D2>(deserializer: D2) -> Result<Field, D2::Error>
            where
                D2: Deserializer<'de>,
            {
                struct FieldVisitor;
                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;
                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        f.write_str("`header` | `address` | `account` | `asset` | `rseed` | `memo`")
                    }
                    fn visit_str<E>(self, v: &str) -> Result<Field, E>
                    where E: de::Error {
                        match v {
                            "header"  => Ok(Field::Header),
                            "address" => Ok(Field::Address),
                            "account" => Ok(Field::Account),
                            "asset"   => Ok(Field::Asset),
                            "rseed"   => Ok(Field::RSeed),
                            "memo"    => Ok(Field::Memo),
                            _ => Err(de::Error::unknown_field(v, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct NoteVisitor;

        impl<'de> Visitor<'de> for NoteVisitor {
            type Value = Note;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("struct Note")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Note, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut header: Option<u64> = None;
                let mut address: Option<String> = None;
                let mut account: Option<String> = None;
                let mut asset: Option<ExtendedAsset> = None;
                let mut rseed_hex: Option<String> = None;
                let mut memo_hex: Option<String> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Header  => { if header.is_some()  { return Err(de::Error::duplicate_field("header"));  } header  = Some(map.next_value()?); }
                        Field::Address => { if address.is_some() { return Err(de::Error::duplicate_field("address")); } address = Some(map.next_value()?); }
                        Field::Account => { if account.is_some() { return Err(de::Error::duplicate_field("account")); } account = Some(map.next_value()?); }
                        Field::Asset   => { if asset.is_some()   { return Err(de::Error::duplicate_field("asset"));   } asset   = Some(map.next_value()?); }
                        Field::RSeed   => { if rseed_hex.is_some(){ return Err(de::Error::duplicate_field("rseed"));   } rseed_hex= Some(map.next_value()?); }
                        Field::Memo    => { if memo_hex.is_some(){ return Err(de::Error::duplicate_field("memo"));    } memo_hex = Some(map.next_value()?); }
                    }
                }

                let header  = header.ok_or_else(|| de::Error::missing_field("header"))?;
                let address = address.ok_or_else(|| de::Error::missing_field("address"))?;
                let account = account.ok_or_else(|| de::Error::missing_field("account"))?;
                let asset   = asset.ok_or_else(|| de::Error::missing_field("asset"))?;
                let rseed_hex = rseed_hex.ok_or_else(|| de::Error::missing_field("rseed"))?;
                let memo_hex  = memo_hex.ok_or_else(|| de::Error::missing_field("memo"))?;

                let addr = Address::from_bech32m(&address)
                    .map_err(de::Error::custom)?;

                let acct_name = Name::from_string(&account)
                    .map_err(|e| de::Error::custom(format!("invalid account: {e}")))?;

                let rseed_vec = hex::decode(&rseed_hex)
                    .map_err(|e| de::Error::custom(format!("invalid rseed hex: {e}")))?;
                if rseed_vec.len() != 32 {
                    return Err(de::Error::custom(format!("rseed must be 32 bytes, got {}", rseed_vec.len())));
                }
                let mut rseed = [0u8; 32];
                rseed.copy_from_slice(&rseed_vec);

                let memo_vec = hex::decode(&memo_hex)
                    .map_err(|e| de::Error::custom(format!("invalid memo hex: {e}")))?;
                if memo_vec.len() != 512 {
                    return Err(de::Error::custom(format!("memo must be 512 bytes, got {}", memo_vec.len())));
                }
                let mut memo = [0u8; 512];
                memo.copy_from_slice(&memo_vec);

                Ok(Note::from_parts(header, addr, acct_name, asset, Rseed(rseed), memo))
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Note, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let header: u64 = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let address: String = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let account: String = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let asset: ExtendedAsset = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(3, &self))?;
                let rseed_hex: String = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(4, &self))?;
                let memo_hex: String  = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(5, &self))?;

                let addr = Address::from_bech32m(&address).map_err(de::Error::custom)?;
                let acct_name = Name::from_string(&account)
                    .map_err(|e| de::Error::custom(format!("invalid account: {e}")))?;

                let rseed_vec = hex::decode(&rseed_hex).map_err(de::Error::custom)?;
                if rseed_vec.len() != 32 {
                    return Err(de::Error::custom(format!("rseed must be 32 bytes, got {}", rseed_vec.len())));
                }
                let mut rseed = [0u8; 32];
                rseed.copy_from_slice(&rseed_vec);

                let memo_vec = hex::decode(&memo_hex).map_err(de::Error::custom)?;
                if memo_vec.len() != 512 {
                    return Err(de::Error::custom(format!("memo must be 512 bytes, got {}", memo_vec.len())));
                }
                let mut memo = [0u8; 512];
                memo.copy_from_slice(&memo_vec);

                Ok(Note::from_parts(header, addr, acct_name, asset, Rseed(rseed), memo))
            }
        }

        const FIELDS: &'static [&'static str] = &["header", "address", "account", "asset", "rseed", "memo"];
        deserializer.deserialize_struct("Note", FIELDS, NoteVisitor)
    }
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
        self.note.write(&mut writer)?;                          // 627

        Ok(())                                                  // 655 bytes in total
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

    pub fn block_ts(&self) -> u64
    {
        self.block_ts
    }

    pub fn wallet_ts(&self) -> u64
    {
        self.wallet_ts
    }

    pub fn leaf_idx_arr(&self) -> u64
    {
        self.leaf_idx_arr
    }

    pub fn block_num(&self) -> u32
    {
        self.block_num
    }

    pub fn note(&self) -> &Note
    {
        &self.note
    }
}

#[cfg(test)]
mod tests
{
    use super::Note;
    use rand::rngs::OsRng;
    use crate::eosio::ExtendedAsset;

    #[test]
    fn test_serde()
    {
        let mut rng = OsRng.clone();
        let a = ExtendedAsset::from_string(&"5000.0000 EOS@eosio.token".to_string()).unwrap();
        let (_, _, n) = Note::dummy(&mut rng, None, Some(a));

        let mut v = vec![];

        n.write(&mut v).unwrap();
        assert_eq!(v.len(), 627);

        let de_n = Note::read(&v[..]).unwrap();
        assert!(n == de_n);

        let encoded = serde_json::to_string(&n).unwrap();
        println!("{}", encoded);
        let decoded: Note = serde_json::from_str(&encoded).unwrap();
        assert_eq!(n, decoded);
    }
}