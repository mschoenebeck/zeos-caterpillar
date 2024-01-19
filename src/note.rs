use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
use group::GroupEncoding;
use rand_core::RngCore;
use serde::{Serialize, Serializer, Deserialize, ser::SerializeStruct, Deserializer, de::Visitor, de::SeqAccess, de::MapAccess, de};
use std::fmt;
use std::io::{self, Read, Write};
use crate::{
    eosio::{Asset, Name, Symbol},
    keys::{EphemeralSecretKey, NullifierDerivingKey, SpendingKey, FullViewingKey, prf_expand},
    note::nullifier::Nullifier, address::Address,
};
use crate::constants::MERKLE_TREE_DEPTH;

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
    asset: Asset,
    /// The EOSIO smart contract this code is associated with:
    /// FT/NFT: The token contract
    /// Auth: The contract this Auth token was issued for
    code: Name,
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
        asset: Asset,
        code: Name,
        rseed: Rseed,
        memo: [u8; 512]
    ) -> Self
    {
        Note {
            header,
            address: recipient,
            account,
            asset,
            code,
            rseed,
            memo
        }
    }

    /// Generates a dummy spent note.
    pub fn dummy(
        rng: &mut impl RngCore,
        asset: Option<Asset>,
        code: Option<Name>,
    ) -> (SpendingKey, FullViewingKey, Self) {
        let sk = SpendingKey::random(rng);
        let fvk = FullViewingKey::from_spending_key(&sk);
        let recipient = fvk.default_address().1;
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);

        let note = Note::from_parts(
            0,
            recipient,
            Name(0),
            asset.unwrap_or_else(|| Asset::new(0, Symbol(0)).unwrap()),
            code.unwrap_or_else(|| Name(0)),
            Rseed(bytes),
            [0; 512]
        );

        (sk, fvk, note)
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()>
    {
        writer.write_u64::<LittleEndian>(self.header)?;                 // 8
        writer.write_all(self.address.to_bytes().as_ref())?;            // 43
        writer.write_u64::<LittleEndian>(self.account().raw())?;        // 8
        writer.write_u64::<LittleEndian>(self.asset.amount() as u64)?;  // 8
        writer.write_u64::<LittleEndian>(self.asset.symbol().raw())?;   // 8
        writer.write_u64::<LittleEndian>(self.code.raw())?;             // 8
        writer.write_all(self.rseed.0.as_ref())?;                       // 32
        writer.write_all(self.memo.as_ref())?;                          // 512

        Ok(())                                                          // 627 bytes in total
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self>
    {
        let header = reader.read_u64::<LittleEndian>()?;
        let mut recipient = [0; 43];
        reader.read_exact(&mut recipient)?;
        let recipient = Address::from_bytes(&recipient).unwrap();
        let account = reader.read_u64::<LittleEndian>()?;
        let account = Name(account);
        let amount = reader.read_u64::<LittleEndian>()? as i64;
        let symbol = reader.read_u64::<LittleEndian>()?;
        let asset = Asset::new(amount, Symbol(symbol)).unwrap();
        let code = reader.read_u64::<LittleEndian>()?;
        let code = Name(code);
        let mut rseed = [0; 32];
        reader.read_exact(&mut rseed)?;
        let rseed = Rseed(rseed);
        let mut memo = [0; 512];
        reader.read_exact(&mut memo)?;

        Ok(Note::from_parts(header, recipient, account, asset, code, rseed, memo))
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

    /// Returns the amount of this note.
    pub fn amount(&self) -> u64 {
        self.asset.amount() as u64
    }

    /// Returns the symbol of this note.
    pub fn symbol(&self) -> &Symbol {
        self.asset.symbol()
    }

    /// Returns the symbol of this note.
    pub fn asset(&self) -> &Asset {
        &self.asset
    }

    /// Returns the code of this note.
    pub fn code(&self) -> &Name {
        &self.code
    }

    /// Returns the rseed value of this note.
    pub fn rseed(&self) -> &Rseed {
        &self.rseed
    }

    /// Returns the memo field of this note.
    pub fn memo(&self) -> &[u8; 512] {
        &self.memo
    }

    /// Returns the amount of this note.
    pub fn set_amount(&mut self, amount: u64) {
        self.asset.set_amount(amount as i64)
    }

    /// Computes the note commitment, returning the full point.
    fn cm_full_point(&self) -> NoteCommitment {
        NoteCommitment::derive(
            self.address.g_d().to_bytes(),
            self.address.pk_d().to_bytes(),
            self.account.raw(),
            self.asset.amount() as u64,
            self.asset.symbol().raw(),
            self.code.raw(),
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
        // 7 is the number of fields in the struct.
        let mut state = serializer.serialize_struct("Note", 7)?;
        state.serialize_field("header", &self.header)?;
        state.serialize_field("address", &self.address.to_bech32m().unwrap())?;
        state.serialize_field("account", &self.account.to_string())?;
        state.serialize_field("asset", &self.asset)?;
        state.serialize_field("code", &self.code)?;
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
        enum Field { Header, Address, Account, Asset, Code, RSeed, /*Rho, */Memo }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`header` or `address` or `account` or `asset` or `code` or `rseed` or `memo`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "header" => Ok(Field::Header),
                            "address" => Ok(Field::Address),
                            "account" => Ok(Field::Account),
                            "asset" => Ok(Field::Asset),
                            "code" => Ok(Field::Code),
                            "rseed" => Ok(Field::RSeed),
                            "memo" => Ok(Field::Memo),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct NoteVisitor;

        impl<'de> Visitor<'de> for NoteVisitor {
            type Value = Note;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Note")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Note, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let header = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let address: String = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let account: String = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let asset = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;
                let code = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(4, &self))?;
                let rseed: String = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(5, &self))?;
                let memo: String = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(6, &self))?;
                let rseed = Rseed(hex::decode(rseed).unwrap()[0..32].try_into().unwrap());
                let memo = hex::decode(memo).unwrap()[0..512].try_into().unwrap();
                Ok(Note{
                    header,
                    address: Address::from_bech32m(&address).unwrap(),
                    account: Name::from_string(&account).unwrap(),
                    asset,
                    code,
                    rseed,
                    memo
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<Note, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut header = None;
                let mut address = None;
                let mut account = None;
                let mut asset = None;
                let mut code = None;
                let mut rseed = None;
                let mut memo = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Header => {
                            if header.is_some() {
                                return Err(de::Error::duplicate_field("header"));
                            }
                            header = Some(map.next_value()?);
                        }
                        Field::Address => {
                            if address.is_some() {
                                return Err(de::Error::duplicate_field("address"));
                            }
                            address = Some(map.next_value()?);
                        }
                        Field::Account => {
                            if account.is_some() {
                                return Err(de::Error::duplicate_field("account"));
                            }
                            account = Some(map.next_value()?);
                        }
                        Field::Asset => {
                            if asset.is_some() {
                                return Err(de::Error::duplicate_field("asset"));
                            }
                            asset = Some(map.next_value()?);
                        }
                        Field::Code => {
                            if code.is_some() {
                                return Err(de::Error::duplicate_field("code"));
                            }
                            code = Some(map.next_value()?);
                        }
                        Field::RSeed => {
                            if rseed.is_some() {
                                return Err(de::Error::duplicate_field("rseed"));
                            }
                            rseed = Some(map.next_value()?);
                        }
                        Field::Memo => {
                            if memo.is_some() {
                                return Err(de::Error::duplicate_field("memo"));
                            }
                            memo = Some(map.next_value()?);
                        }
                    }
                }
                let header = header.ok_or_else(|| de::Error::missing_field("header"))?;
                let address: String = address.ok_or_else(|| de::Error::missing_field("address"))?;
                let account: String = account.ok_or_else(|| de::Error::missing_field("account"))?;
                let asset = asset.ok_or_else(|| de::Error::missing_field("asset"))?;
                let code = code.ok_or_else(|| de::Error::missing_field("code"))?;
                let rseed: String = rseed.ok_or_else(|| de::Error::missing_field("rseed"))?;
                let memo: String = memo.ok_or_else(|| de::Error::missing_field("memo"))?;
                Ok(Note{
                    header,
                    address: Address::from_bech32m(&address).unwrap(),
                    account: Name::from_string(&account).unwrap(),
                    asset,
                    code,
                    rseed: Rseed(hex::decode(rseed).unwrap()[0..32].try_into().unwrap()),
                    memo: hex::decode(memo).unwrap()[0..512].try_into().unwrap()
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["header", "address", "account", "asset", "code", "rseed", "memo"];
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
    use crate::eosio::{Asset, Name};

    #[test]
    fn test_serde()
    {
        let mut rng = OsRng.clone();
        let a = Asset::from_string(&"5000.0000 EOS".to_string()).unwrap();
        let (_, _, n) = Note::dummy(&mut rng, Some(a), Some(Name::from_string(&"eosio.token".to_string()).unwrap()));

        let mut v = vec![];

        n.write(&mut v).unwrap();
        assert_eq!(v.len(), 651);

        let de_n = Note::read(&v[..]).unwrap();
        assert!(n == de_n);

        let encoded = serde_json::to_string(&n).unwrap();
        println!("{}", encoded);
        let decoded: Note = serde_json::from_str(&encoded).unwrap();
        assert_eq!(n, decoded);
    }
}