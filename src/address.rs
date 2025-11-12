use super::keys::{DiversifiedTransmissionKey, Diversifier, SpendingKey, FullViewingKey};
use bech32::{FromBase32, ToBase32, Variant};
use rand::RngCore;
use serde::{Serialize, Serializer, Deserialize, Deserializer, de::Visitor, de};
use std::{error::Error, fmt};

#[derive(Debug)]
pub enum AddressError
{
    InvalidStringLength,       // bech32m string too short
    InvalidDiversifier,        // diversifier.g_d() failed
    IvkWallet,                 // unchanged
    InvalidHrp,                // hrp != "za"
    InvalidVariant,            // not Bech32m
    InvalidLength,             // wrong decoded byte length
    InvalidPkD,                // pk_d is identity or fails construction
    Bech32(bech32::Error),     // bech32 decode/encode error
}
impl Error for AddressError {}
impl fmt::Display for AddressError
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        match self
        {
            Self::InvalidStringLength => write!(f, "invalid bech32m address string length (must be 78)"),
            Self::InvalidDiversifier   => write!(f, "invalid address diversifier"),
            Self::IvkWallet            => write!(f, "Read-Only Wallet (spending not possible)"),
            Self::InvalidHrp           => write!(f, "invalid HRP (expected \"za\")"),
            Self::InvalidVariant       => write!(f, "invalid bech32 variant (expected Bech32m)"),
            Self::InvalidLength        => write!(f, "decoded address payload has invalid length"),
            Self::InvalidPkD           => write!(f, "invalid pk_d (identity or malformed)"),
            Self::Bech32(e)            => write!(f, "bech32 error: {e}"),
        }
    }
}

impl From<bech32::Error> for AddressError {
    fn from(e: bech32::Error) -> Self { AddressError::Bech32(e) }
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
        // Diversifier (11 bytes)
        let mut d_bytes = [0u8; 11];
        d_bytes.copy_from_slice(&bytes[0..11]);
        let diversifier = Diversifier(d_bytes);

        // pk_d (32 bytes)
        let mut pkd_bytes = [0u8; 32];
        pkd_bytes.copy_from_slice(&bytes[11..43]);

        // from_bytes -> CtOption<DTK>; convert to Option<DTK>
        let pk_d = Option::<DiversifiedTransmissionKey>::from(
            DiversifiedTransmissionKey::from_bytes(&pkd_bytes)
        ).ok_or(AddressError::InvalidPkD)?;

        // Validate invariants (diversifier valid, pk_d non-identity)
        Address::from_parts(diversifier, pk_d).ok_or(AddressError::InvalidDiversifier)
    }

    /// Returns the byte encoding of this `PaymentAddress`.
    pub fn to_bytes(&self) -> [u8; 43] {
        let mut bytes = [0; 43];
        bytes[0..11].copy_from_slice(&self.d.0);
        bytes[11..].copy_from_slice(&self.pk_d.to_bytes());
        bytes
    }

    /// Encodes this address as Bech32m
    pub fn to_bech32m(&self) -> Result<String, AddressError>
    {
        Ok(bech32::encode("za", self.to_bytes().to_base32(), Variant::Bech32m)?)
    }

    /// Parse a Bech32m encoded address
    pub fn from_bech32m(s: &str) -> Result<Self, AddressError> {
        if s.len() < 78 {
            return Err(AddressError::InvalidStringLength);
        }
        let (hrp, data, variant) = bech32::decode(s)?; // -> bech32::Error maps via From
        if hrp != "za" {
            return Err(AddressError::InvalidHrp);
        }
        if variant != Variant::Bech32m {
            return Err(AddressError::InvalidVariant);
        }

        // Convert base32 payload to bytes
        let decoded = Vec::<u8>::from_base32(&data)?; // bech32::Error again
        if decoded.len() < 43 {
            return Err(AddressError::InvalidLength);
        }

        let mut payload = [0u8; 43];
        payload.copy_from_slice(&decoded[0..43]);

        Address::from_bytes(&payload)
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

    pub(crate) fn try_g_d(&self) -> Result<jubjub::SubgroupPoint, AddressError> {
        self.d.g_d().ok_or(AddressError::InvalidDiversifier)
    }

    // If you want to keep the old method:
    pub(crate) fn g_d(&self) -> jubjub::SubgroupPoint {
        self.try_g_d().expect("checked at construction")
    }
}

// serde_json traits
impl Serialize for Address
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_bech32m()
            .map_err(serde::ser::Error::custom)
            .and_then(|s| serializer.serialize_str(&s))
    }
}
struct AddressVisitor;
impl<'de> Visitor<'de> for AddressVisitor {
    type Value = Address;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a bech32m-encoded CLOAK address with HRP \"za\"")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Address::from_bech32m(value).map_err(E::custom)
    }
}
impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Address, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(AddressVisitor)
    }
}

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
