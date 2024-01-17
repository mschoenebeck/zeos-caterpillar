use super::keys::{DiversifiedTransmissionKey, Diversifier, SpendingKey, FullViewingKey};
use bech32::{FromBase32, ToBase32, Variant};
use rand::RngCore;
use serde::{Serialize, Serializer, Deserialize, Deserializer, de::Visitor, de};
use std::{error::Error, fmt};

#[derive(Debug)]
pub enum AddressError
{
    InvalidStringLength,
    InvalidDiversifier,
    IvkWallet
}
impl Error for AddressError {}
impl fmt::Display for AddressError
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        match self
        {
            Self::InvalidStringLength => write!(f, "invalid bech32m address string length (must be 78)"),
            Self::InvalidDiversifier => write!(f, "invalid address diversifier"),
            Self::IvkWallet => write!(f, "Read-Only Wallet (spending not possible)")
        }
    }
}

/// A Sapling payment address.
///
/// # Invariants
///
/// - `diversifier` is guaranteed to be valid for Sapling (only 50% of diversifiers are).
/// - `pk_d` is guaranteed to be prime-order (i.e. in the prime-order subgroup of Jubjub,
///  and not the identity).
#[derive(Clone, Copy, Debug)]
pub struct Address {
    pk_d: DiversifiedTransmissionKey,
    d: Diversifier,
}

impl PartialEq for Address {
    fn eq(&self, other: &Self) -> bool {
        self.pk_d == other.pk_d && self.d == other.d
    }
}

impl Eq for Address {}

impl Address {
    /// Constructs a PaymentAddress from a diversifier and a Jubjub point.
    ///
    /// Returns None if `diversifier` is not valid for Sapling, or `pk_d` is the identity.
    /// Note that we cannot verify in this constructor that `pk_d` is derived from
    /// `diversifier`, so addresses for which these values have no known relationship
    /// (and therefore no-one can receive funds at them) can still be constructed.
    pub fn from_parts(
        diversifier: Diversifier,
        pk_d: DiversifiedTransmissionKey
    ) -> Option<Self> {
        // Check that the diversifier is valid
        diversifier.g_d()?;

        if pk_d.is_identity() {
            None
        } else {
            Some(Address { pk_d, d: diversifier })
        }
    }

    /// Parses a PaymentAddress from bytes.
    pub fn from_bytes(bytes: &[u8; 43]) -> Result<Self, AddressError> {
        let diversifier = {
            let mut tmp = [0; 11];
            tmp.copy_from_slice(&bytes[0..11]);
            Diversifier(tmp)
        };

        let pk_d = DiversifiedTransmissionKey::from_bytes(bytes[11..43].try_into().unwrap());
        if pk_d.is_some().into() {
            // The remaining invariants are checked here.
            Ok(Address::from_parts(diversifier, pk_d.unwrap()).unwrap())
        } else {
            Err(AddressError::InvalidDiversifier)
        }
    }

    /// Returns the byte encoding of this `PaymentAddress`.
    pub fn to_bytes(&self) -> [u8; 43] {
        let mut bytes = [0; 43];
        bytes[0..11].copy_from_slice(&self.d.0);
        bytes[11..].copy_from_slice(&self.pk_d.to_bytes());
        bytes
    }

    /// Encodes this address as Bech32m
    pub fn to_bech32m(&self) -> Result<String, bech32::Error>
    {
        bech32::encode("za", self.to_bytes().to_base32(), Variant::Bech32m)
    }

    /// Parse a Bech32m encoded address
    pub fn from_bech32m(str: &String) -> Result<Self, Box<dyn Error>>
    {
        if str.len() < 78 { Err(AddressError::InvalidStringLength)? }
        let (hrp, data, variant) = bech32::decode(&str).unwrap();
        let bytes: [u8; 43] = Vec::<u8>::from_base32(&data)?[0..43].try_into().expect("from_bech32m: incorrect length");
        assert_eq!(hrp, "za");
        assert_eq!(variant, Variant::Bech32m);
        Ok(Address::from_bytes(&bytes)?)
    }

    /// creates a dummy address
    pub fn dummy(rng: &mut impl RngCore) -> Self
    {
        let sk = SpendingKey::random(rng);
        let fvk  = FullViewingKey::from_spending_key(&sk);
        fvk.default_address().1
    }

    /// Returns the [`Diversifier`] for this `PaymentAddress`.
    pub fn diversifier(&self) -> &Diversifier {
        &self.d
    }

    /// Returns `pk_d` for this `PaymentAddress`.
    pub fn pk_d(&self) -> &DiversifiedTransmissionKey {
        &self.pk_d
    }

    pub(crate) fn g_d(&self) -> jubjub::SubgroupPoint {
        self.d.g_d().expect("checked at construction")
    }
}

// serde_json traits
impl Serialize for Address
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_bech32m().unwrap())
    }
}
struct AddressVisitor;
impl<'de> Visitor<'de> for AddressVisitor {
    type Value = Address;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string of the format: '10.000 EOS'")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Address::from_bech32m(&value.to_string()).unwrap())
    }
}
impl<'de> Deserialize<'de> for Address
{
    fn deserialize<D>(deserializer: D) -> Result<Address, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(AddressVisitor)
    }
}

/*
impl Serialize for Address
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 3 is the number of fields in the struct.
        let mut state = serializer.serialize_struct("Address", 2)?;
        state.serialize_field("pk_d", &hex::encode(self.pk_d.to_bytes()))?;
        state.serialize_field("d", &hex::encode(self.d.0))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field { PkD, D }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`pk_d` or `d`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "pk_d" => Ok(Field::PkD),
                            "d" => Ok(Field::D),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct AddressVisitor;

        impl<'de> Visitor<'de> for AddressVisitor {
            type Value = Address;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Address")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Address, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let pk_d: String = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let d: String = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let pk_d = hex::decode(pk_d).unwrap()[0..32].try_into().unwrap();
                let d = hex::decode(d).unwrap()[0..11].try_into().unwrap();
                Ok(Address{
                    pk_d: DiversifiedTransmissionKey::from_bytes(&pk_d).unwrap(),
                    d: Diversifier::from_bytes(d)
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<Address, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut pk_d = None;
                let mut d = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::PkD => {
                            if pk_d.is_some() {
                                return Err(de::Error::duplicate_field("pk_d"));
                            }
                            pk_d = Some(map.next_value()?);
                        }
                        Field::D => {
                            if d.is_some() {
                                return Err(de::Error::duplicate_field("d"));
                            }
                            d = Some(map.next_value()?);
                        }
                    }
                }
                let pk_d: String = pk_d.ok_or_else(|| de::Error::missing_field("pk_d"))?;
                let d: String = d.ok_or_else(|| de::Error::missing_field("d"))?;
                let pk_d = hex::decode(pk_d).unwrap()[0..32].try_into().unwrap();
                let d = hex::decode(d).unwrap()[0..11].try_into().unwrap();
                Ok(Address{
                    pk_d: DiversifiedTransmissionKey::from_bytes(&pk_d).unwrap(),
                    d: Diversifier::from_bytes(d)
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["pk_d", "d"];
        deserializer.deserialize_struct("Address", FIELDS, AddressVisitor)
    }
}
*/

#[cfg(test)]
mod tests
{
    use rand::rngs::OsRng;
    use super::Address;

    #[test]
    fn test_bech32m_encode_decode()
    {
        let mut rng = OsRng.clone();
        let a = Address::dummy(&mut rng);
        let encoded = a.to_bech32m().unwrap();
        println!("{}", encoded);
        let decoded = Address::from_bech32m(&encoded).unwrap();
        assert_eq!(a.to_bytes(), decoded.to_bytes());
    }

    #[test]
    fn test_json_serde()
    {
        let mut rng = OsRng.clone();
        let a = Address::dummy(&mut rng);
        let encoded = serde_json::to_string(&a).unwrap();
        println!("{}", encoded);
        let decoded: Address = serde_json::from_str(&encoded).unwrap();
        assert_eq!(a.to_bytes(), decoded.to_bytes());
    }
}
