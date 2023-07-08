//! Helper structs to deal with EOSIO/Antelope related types.

use std::cmp::{min, max};
use serde::{Serialize, Serializer, ser::SerializeStruct, Deserialize, Deserializer, de::Visitor, de::SeqAccess, de::MapAccess, de};
use serde_json::Value;
use std::fmt;
use std::iter::successors;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Name(u64);

impl Name
{
    pub fn new(raw: u64) -> Self
    {
        Name(raw)
    }

    pub fn from_string(str: &String) -> Option<Self>
    {
        let mut value = 0;
        if str.len() > 13
        {
            // string is too long to be a valid name
            return None;
        }
        if str.is_empty()
        {
            return Some(Name(0));
        }
        let n = min(str.len(), 12);
        for i in 0..n
        {
            value <<= 5;
            let c = Self::char_to_value(str.as_bytes()[i]);
            if c.is_none() { return None; }
            value |= c.unwrap() as u64;
        }
        value <<= 4 + 5*(12 - n);
        if str.len() == 13
        {
            let c = Self::char_to_value(str.as_bytes()[12]);
            if c.is_none() { return None; }
            let v = c.unwrap() as u64;
            if v > 0x0F
            {
                // thirteenth character in name cannot be a letter that comes after j
                return None;
            }
            value |= v;
        }
        Some(Name(value))
    }

    pub fn char_to_value(c: u8) -> Option<u8>
    {
        if c == '.' as u8
        {
        return Some(0);
        }
        else if  c >= '1' as u8 && c <= '5' as u8
        {
        return Some((c - '1' as u8) + 1);
        }
        else if c >= 'a' as u8 && c <= 'z' as u8
        {
        return Some((c - 'a' as u8) + 6);
        }
        // character is not in allowed character set for names
        return None;
    }

    pub fn length(&self) -> u8
    {
        let mask = 0xF800000000000000u64;

        if self.0 == 0
        {
            return 0;
        }

        let mut l = 0;
        let mut i = 0;
        let mut v = self.0;
        while i < 13
        {
            if (v & mask) > 0
            {
                l = i;
            }
            i += 1;
            v <<= 5;
        }

        l + 1
    }

    pub fn raw(&self) -> u64
    {
        self.0
    }

    pub fn suffix(&self) -> Self
    {
        let mut remaining_bits_after_last_actual_dot = 0;
        let mut tmp = 0;
        let mut remaining_bits = 59;
        while remaining_bits >= 4
        {
            // Get characters one-by-one in name in order from left to right (not including the 13th character)
            let c = (self.0 >> remaining_bits) & 0x1F;
            if 0 == c // if this character is a dot
            {
                tmp = remaining_bits as u32;
            }
            else // if this character is not a dot
            {
                remaining_bits_after_last_actual_dot = tmp;
            }
            remaining_bits -= 5;
        }

        let thirteenth_character = self.0 & 0x0F;
        if 0 != thirteenth_character // if 13th character is not a dot
        {
            remaining_bits_after_last_actual_dot = tmp;
        }

        if remaining_bits_after_last_actual_dot == 0  // there is no actual dot in the %name other than potentially leading dots
        {
            return Name{0: self.0};
        }

        // At this point remaining_bits_after_last_actual_dot has to be within the range of 4 to 59 (and restricted to increments of 5).

        // Mask for remaining bits corresponding to characters after last actual dot, except for 4 least significant bits (corresponds to 13th character).
        let mask = (1 << remaining_bits_after_last_actual_dot) - 16;
        let shift = 64 - remaining_bits_after_last_actual_dot;

        Name{0: ((self.0 & mask) << shift) + (thirteenth_character << (shift-1)) }
    }

    pub fn prefix(&self) -> Self
    {
        let mut result = self.0;
        let mut not_dot_character_seen = false;
        let mut mask = 0xF;

        // Get characters one-by-one in name in order from right to left
        let mut offset = 0;
        //for( int32_t offset = 0; offset <= 59; ) {
        while offset <= 59
        {
            let c = (self.0 >> offset) & mask;

            if 0 == c // if this character is a dot
            {
                if not_dot_character_seen // we found the rightmost dot character
                {
                    result = (self.0 >> offset) << offset;
                    break;
                }
            }
            else
            {
                not_dot_character_seen = true;
            }

            if offset == 0
            {
                offset += 4;
                mask = 0x1F;
            }
            else
            {
                offset += 5;
            }
        }

        Name{0: result }
    }

    pub fn to_string(&self) -> String
    {
        let charmap = vec!['.', '1', '2', '3', '4', '5', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];
        let mask = 0xF800000000000000;

        let mut v = self.0;
        let mut str = "".to_string();
        for i in 0..13
        {
            if v == 0
            {
                return str;
            }

            let indx = (v & mask) >> (if i == 12 { 60 } else { 59 });
            str.push(charmap[indx as usize]);

            v <<= 5;
        }
        str
    }
}

// serde_json traits
impl Serialize for Name
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
struct NameVisitor;
impl<'de> Visitor<'de> for NameVisitor {
    type Value = Name;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string with 12 characters containing 'a' to 'z' and '1' to '5'")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Name::from_string(&value.to_string()).unwrap())
    }
}
impl<'de> Deserialize<'de> for Name
{
    fn deserialize<D>(deserializer: D) -> Result<Name, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(NameVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SymbolCode(u64);

impl SymbolCode
{
    pub fn new(raw: u64) -> Self
    {
        SymbolCode(raw)
    }

    pub fn from_string(str: &String) -> Option<Self>
    {
        if str.len() > 7
        {
            // string is too long to be a valid symbol_code
            return None;
        }
        let mut value = 0;
        for itr in str.chars().rev()
        {
            if itr < 'A' || itr > 'Z'
            {
                // only uppercase letters allowed in symbol_code string
                return None;
            }
            value <<= 8;
            value |= itr as u64;
        }
        Some(SymbolCode(value))
    }

    pub fn is_valid(&self) -> bool
    {
        if self.0 == 0 { return true; } // make NFT symbol code: '0,' (i.e. raw == 0) a valid symbol code
        let mut sym = self.0;
        let mut i = 0;
        while i < 7
        {
            let c = (sym & 0xFF) as u8 as char;
            if !('A' <= c && c <= 'Z') { return false; }
            sym >>= 8;
            if 0 == (sym & 0xFF)
            {
                loop {
                    sym >>= 8;
                    if 0 != (sym & 0xFF) { return false; }
                    i += 1;
                    if i >= 7 { break; }
                }
            }
            i += 1;
        }
        return true;
    }

    pub fn length(&self) -> u32
    {
        let mut sym = self.0;
        let mut len = 0;
        while 0 != (sym & 0xFF) && len <= 7
        {
            len += 1;
            sym >>= 8;
        }
        return len;
    }

    pub fn raw(&self) -> u64
    {
        self.0
    }

    pub fn to_string(&self) -> String
    {
        let mut v = self.0;
        let mut s = "".to_string();
        while v > 0
        {
            s.push((v & 0xFF) as u8 as char);
            v >>= 8;
        }
        s
    }
}

// serde_json traits
impl Serialize for SymbolCode
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
struct SymbolCodeVisitor;
impl<'de> Visitor<'de> for SymbolCodeVisitor {
    type Value = SymbolCode;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string of the format: 'EOS' max 7 characters, containing only 'A' to 'Z'")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(SymbolCode::from_string(&value.to_string()).unwrap())
    }
}
impl<'de> Deserialize<'de> for SymbolCode
{
    fn deserialize<D>(deserializer: D) -> Result<SymbolCode, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(SymbolCodeVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Symbol(u64);

impl Symbol
{
    pub fn new(raw: u64) -> Self
    {
        Symbol(raw)
    }

    pub fn from_sc_precision(sc: SymbolCode, precision: u8) -> Self
    {
        Symbol((sc.raw() << 8) | precision as u64)
    }

    pub fn from_string(str: &String) -> Option<Self>
    {
        let parts: Vec<String> = str.split(",").map(|s| s.to_string()).collect();
        if parts.len() != 2 { return None; }
        let precision = parts[0].parse::<u8>();
        if precision.is_err() { return None; }
        let precision = precision.unwrap();
        let sc = SymbolCode::from_string(&parts[1]);
        if sc.is_none() { return None; }
        let sc = sc.unwrap();
        Some(Self::from_sc_precision(sc, precision))
    }

    pub fn is_valid(&self) -> bool
    {
        return self.code().is_valid();
    }

    pub fn precision(&self) -> u8
    {
        (self.0 & 0xFF) as u8
    }

    pub fn code(&self) -> SymbolCode
    {
        SymbolCode(self.0 >> 8)
    }

    pub fn raw(&self) -> u64
    {
        self.0
    }

    pub fn to_string(&self) -> String
    {
        self.precision().to_string() + "," + &self.code().to_string()
    }
}

// serde_json traits
impl Serialize for Symbol
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
struct SymbolVisitor;
impl<'de> Visitor<'de> for SymbolVisitor {
    type Value = Symbol;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string of the format: '4,EOS' max 7 characters, containing only 'A' to 'Z'")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Symbol::from_string(&value.to_string()).unwrap())
    }
}
impl<'de> Deserialize<'de> for Symbol
{
    fn deserialize<D>(deserializer: D) -> Result<Symbol, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(SymbolVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Asset
{
    amount: i64,
    symbol: Symbol
}

impl Asset
{
    const MAX_AMOUNT: i64 = (1 << 62) - 1;

    pub fn new(amount: i64, symbol: Symbol) -> Option<Self>
    {
        if !symbol.is_valid()
        {
            return None;
        }
        if symbol.raw() != 0 && !(-Self::MAX_AMOUNT <= amount && amount <= Self::MAX_AMOUNT)
        {
            return None;
        }
        Some(Asset{amount, symbol})
    }

    pub fn from_string(str: &String) -> Option<Self>
    {
        let parts: Vec<String> = str.split(" ").map(|s| s.to_string()).collect();
        if parts.len() == 1 // NFT case
        {
            let amount = parts[0].parse::<u64>();
            if amount.is_err() { return None; }
            return Some(Asset { amount: amount.unwrap() as i64, symbol: Symbol(0) })
        }
        if parts.len() == 2 // FT case
        {
            let dot = parts[0].find('.');
            if dot.is_none() // no dot
            {
                let amount = parts[0].parse::<i64>();
                if amount.is_err() { return None; }
                let sc = SymbolCode::from_string(&parts[1]);
                if sc.is_none() { return None; }
                let symbol = Symbol::from_sc_precision(sc.unwrap(), 0);
                return Some(Asset { amount: amount.unwrap(), symbol })
            }
            let dot = dot.unwrap();
            let precision = parts[0].len()-1 - dot;
            let num_parts: Vec<String> = parts[0].split(".").map(|s| s.to_string()).collect();
            if num_parts.len() != 2 { return None; }
            let amount = (num_parts[0].clone() + &num_parts[1]).parse::<i64>();
            if amount.is_err() { return None; }
            let sc = SymbolCode::from_string(&parts[1]);
            if sc.is_none() { return None; }
            let symbol = Symbol::from_sc_precision(sc.unwrap(), precision as u8);
            return Some(Asset { amount: amount.unwrap(), symbol })
        }

        None
    }

    pub fn is_amount_within_range(&self) -> bool
    {
        -Self::MAX_AMOUNT <= self.amount && self.amount <= Self::MAX_AMOUNT
    }

    pub fn is_valid(&self) -> bool
    {
        if !self.symbol.is_valid()
        {
            return false;
        }
        if self.symbol.raw() != 0
        {
            return self.is_amount_within_range();
        }
        true
    }

    pub fn is_nft(&self) -> bool
    {
        return self.symbol().raw() == 0;
    }

    pub fn amount(&self) -> i64
    {
        self.amount
    }

    pub fn symbol(&self) -> &Symbol
    {
        &self.symbol
    }

    pub fn write_decimal(number: u64, precision: u8, negative: bool) -> String
    {
        let num_digits = successors(Some(number), |&n| (n >= 10).then(|| n / 10)).count() as i64;
        let precision = precision as i64;
        let mut number = number;

        let mut characters_needed = max(num_digits, precision);
        let mut decimal_point_pos = num_digits;
        if precision >= num_digits
        {
            characters_needed += 1; // space needing for additional leading zero digit
            decimal_point_pos = 1;
        }
        else
        {
            decimal_point_pos -= precision;
        }
        if precision > 0
        {
            characters_needed += 1; // space for decimal point
        }
        let mut after_minus_pos = 0;
        if negative
        {
            characters_needed += 1; // space for minus sign
            after_minus_pos += 1;
            decimal_point_pos += 1;
        }
        // 1 <= characters_needed <= 258
        // 1 <= decimal_point_pos <= num_digits + 1 <= 21

        let mut str = vec![' '; characters_needed as usize];

        let mut i = characters_needed - 1;
        while number > 0 && i > decimal_point_pos
        {
            str[i as usize] = (number % 10 + 48) as u8 as char;  // '0' == 48
            number /= 10;
            i -= 1;
        }
        while i > decimal_point_pos
        {
            str[i as usize] = '0';
            i -= 1;
        }
        if i == decimal_point_pos
        {
            str[i as usize] = '.';
            i -= 1;
        }
        while i >= after_minus_pos
        {
            str[i as usize] = (number % 10 + 48) as u8 as char;  // '0' == 48
            number /= 10;
            i -= 1;
        }

        if i == 0
        {
            str[i as usize] = '-';
        }

        let str: String = str.into_iter().collect();
        str
    }

    pub fn to_string(&self) -> String
    {
        if self.symbol.raw() == 0
        {
            return (self.amount as u64).to_string();
        }
        let negative = self.amount < 0;
        let abs_amount = self.amount.unsigned_abs();
        let precision = self.symbol.precision();
        return Self::write_decimal(abs_amount, precision, negative) + " " + &self.symbol.code().to_string();
    }
}

// serde_json traits
impl Serialize for Asset
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
struct AssetVisitor;
impl<'de> Visitor<'de> for AssetVisitor {
    type Value = Asset;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string of the format: '10.000 EOS'")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Asset::from_string(&value.to_string()).unwrap())
    }
}
impl<'de> Deserialize<'de> for Asset
{
    fn deserialize<D>(deserializer: D) -> Result<Asset, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(AssetVisitor)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Authorization
{
    pub actor: Name,
    pub permission: Name,
}

impl Authorization
{
    pub fn from_string(str: &String) -> Option<Self>
    {
        // determine EOSIO Authorization tuple: actor@permission
        let authorization_parts: Vec<String> = str.split('@').map(|s| s.to_string()).collect();
        let actor = Name::from_string(&authorization_parts[0]);
        let permission =
            if authorization_parts.len() == 1 { Name::from_string(&"active".to_string()) } else
            if authorization_parts.len() == 2 { Name::from_string(&authorization_parts[1]) } else
            { None };
        if actor.is_none() || permission.is_none() { return None; }
        Some(Authorization{
            actor: actor.unwrap(),
            permission: permission.unwrap()
        })
    }
}

impl Serialize for Authorization
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 2 is the number of fields in the struct.
        let mut state = serializer.serialize_struct("Authorization", 2)?;
        state.serialize_field("actor", &self.actor)?;
        state.serialize_field("permission", &self.permission)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Authorization {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field { Actor, Permission }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`actor` or `permission`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "actor" => Ok(Field::Actor),
                            "permission" => Ok(Field::Permission),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct AuthorizationVisitor;

        impl<'de> Visitor<'de> for AuthorizationVisitor {
            type Value = Authorization;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Authorization")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Authorization, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let actor = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let permission = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                Ok(Authorization{
                    actor,
                    permission
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<Authorization, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut actor = None;
                let mut permission = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Actor => {
                            if actor.is_some() {
                                return Err(de::Error::duplicate_field("actor"));
                            }
                            actor = Some(map.next_value()?);
                        }
                        Field::Permission => {
                            if permission.is_some() {
                                return Err(de::Error::duplicate_field("permission"));
                            }
                            permission = Some(map.next_value()?);
                        }
                    }
                }
                let actor = actor.ok_or_else(|| de::Error::missing_field("actor"))?;
                let permission = permission.ok_or_else(|| de::Error::missing_field("permission"))?;
                Ok(Authorization{
                    actor,
                    permission
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["actor", "permission"];
        deserializer.deserialize_struct("Authorization", FIELDS, AuthorizationVisitor)
    }
}

#[derive(Debug, Clone)]
pub struct Action
{
    pub account: Name,
    pub name: Name,
    pub authorization: Vec<Authorization>,
    pub data: Value,
}

impl Serialize for Action
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 4 is the number of fields in the struct.
        let mut state = serializer.serialize_struct("Action", 4)?;
        state.serialize_field("account", &self.account)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("authorization", &self.authorization)?;
        state.serialize_field("data", &self.data)?;
        state.end()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Transaction
{
    // For now, we simplify EOSIO transactions to just a single vector of actions.
    pub actions: Vec<Action>
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::contract::{PlsFtTransfer, PlsNftTransfer};

    #[test]
    fn test0()
    {
        let a = Asset::from_string(&"18446744073709551615".to_string()).unwrap();
        println!("{}", a.to_string());
        let b = Asset::from_string(&a.to_string()).unwrap();
        println!("{}", b.to_string());
        let a = Asset { amount: 100000, symbol: Symbol::from_string(&"0,".to_string()).unwrap() };
        println!("asset: {}", a.to_string());
        assert_eq!(Symbol::from_string(&"0,".to_string()).unwrap().raw(), 0);
    }

    #[test]
    fn test1()
    {
        assert_eq!(Name::from_string(&"eosio".to_string()).unwrap().raw(), 6138663577826885632);
        assert_eq!(Name::from_string(&"eosio.msig".to_string()).unwrap().raw(), 6138663587900751872);
        assert_eq!(Name::from_string(&"eosio.token".to_string()).unwrap().raw(), 6138663591592764928);
        assert_eq!(SymbolCode::from_string(&"ZEOSZEOS".to_string()), None);
        assert_eq!(SymbolCode::from_string(&"eos".to_string()), None);
        assert_eq!(SymbolCode::from_string(&"EOS".to_string()).unwrap().raw(), 5459781);
        assert_eq!(Symbol::from_sc_precision(SymbolCode::from_string(&"EOS".to_string()).unwrap(), 4).raw(), 1397703940);
        assert_eq!(Symbol::from_sc_precision(SymbolCode::from_string(&"ZEOS".to_string()).unwrap(), 4).raw(), 357812230660);
        assert_eq!(SymbolCode(5459781).to_string(), "EOS".to_string());
        assert_eq!(Symbol(357812230660).to_string(), "4,ZEOS".to_string());
        assert_eq!(Name(6138663577826885632).to_string(), "eosio".to_string());
        assert_eq!(Name(6138663587900751872).to_string(), "eosio.msig".to_string());
        assert_eq!(Name(6138663591592764928).to_string(), "eosio.token".to_string());
        assert_eq!(Symbol::from_string(&"4,EOS".to_string()).unwrap().raw(), 1397703940);
        assert_eq!(Symbol::from_string(&"0,".to_string()).unwrap().raw(), 0);
        assert_eq!(Symbol::from_string(&"4,EOS".to_string()).unwrap().is_valid(), true);
        assert_eq!(Symbol::from_string(&"0,".to_string()).unwrap().is_valid(), true);
    }

    #[test]
    fn test2()
    {
        println!("{:?}", Name::from_string(&"zeos1fractal".to_string()).unwrap().raw().to_le_bytes());
        println!("{:?}", Name::from_string(&"cryptkeeper".to_string()).unwrap().raw().to_le_bytes());
        println!("{:?}", Symbol::from_string(&"4,EOS".to_string()).unwrap().raw().to_le_bytes());
        println!("{:?}", Name::from_string(&"active".to_string()).unwrap().raw().to_le_bytes());
        println!("{:?}", Name::from_string(&"teamgreymass".to_string()).unwrap().raw().to_le_bytes());
    }

    #[test]
    fn action_serde()
    {
        let a = Action{
            account: Name::from_string(&"eosio.token".to_string()).unwrap(),
            name: Name::from_string(&"transfer".to_string()).unwrap(),
            authorization: vec![Authorization{
                actor: Name::from_string(&"eosio".to_string()).unwrap(),
                permission: Name::from_string(&"active".to_string()).unwrap()
            }],
            data: serde_json::from_str(r#"{
                "from": "eosio",
                "to": "zeoscontract",
                "quantity": "1.0000 EOS",
                "memo": "this is a memo!"
            }"#).unwrap()
        };
        let tx = Transaction{ actions: vec![a] };
        println!("{}", serde_json::to_string(&tx).unwrap());
    }

    #[test]
    fn pls_transfer_serde()
    {
        let a = Action{
            account: Name::from_string(&"eosio.token".to_string()).unwrap(),
            name: Name::from_string(&"transfer".to_string()).unwrap(),
            authorization: vec![Authorization{
                actor: Name::from_string(&"eosio".to_string()).unwrap(),
                permission: Name::from_string(&"active".to_string()).unwrap()
            }],
            data: PlsFtTransfer{
                from: Name::from_string(&"eosio".to_string()).unwrap(),
                to: Name::from_string(&"zeoscontract".to_string()).unwrap(),
                quantity: Asset::from_string(&"1.0000 EOS".to_string()).unwrap(),
                memo: "this is a memo!".to_string()
            }.into()
        };
        let tx = Transaction{ actions: vec![a] };
        println!("{}", serde_json::to_string(&tx).unwrap());

        let a = Action{
            account: Name::from_string(&"atomicassets".to_string()).unwrap(),
            name: Name::from_string(&"transfer".to_string()).unwrap(),
            authorization: vec![Authorization{
                actor: Name::from_string(&"eosio".to_string()).unwrap(),
                permission: Name::from_string(&"active".to_string()).unwrap()
            }],
            data: PlsNftTransfer{
                from: Name::from_string(&"eosio".to_string()).unwrap(),
                to: Name::from_string(&"zeoscontract".to_string()).unwrap(),
                asset_ids: vec![Asset::from_string(&"1234567890987654321".to_string()).unwrap()],
                memo: "this is a memo!".to_string()
            }.into()
        };
        let tx = Transaction{ actions: vec![a] };
        println!("{}", serde_json::to_string(&tx).unwrap());
    }
}