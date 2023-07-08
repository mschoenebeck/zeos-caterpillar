//! Note encryption for Zcash transactions.
//!
//! This crate implements the [in-band secret distribution scheme] for the Sapling and
//! Orchard protocols. It provides reusable methods that implement common note encryption
//! and trial decryption logic, and enforce protocol-agnostic verification requirements.
//!
//! Protocol-specific logic is handled via the [`Domain`] trait. Implementations of this
//! trait are provided in the [`zcash_primitives`] (for Sapling) and [`orchard`] crates;
//! users with their own existing types can similarly implement the trait themselves.
//!
//! [in-band secret distribution scheme]: https://zips.z.cash/protocol/protocol.pdf#saplingandorchardinband
//! [`zcash_primitives`]: https://crates.io/crates/zcash_primitives
//! [`orchard`]: https://crates.io/crates/orchard

//#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Catch documentation errors caused by code changes.
#![deny(broken_intra_doc_links)]
#![deny(unsafe_code)]
#![deny(missing_docs)]

use core::fmt;
use bls12_381::Scalar;
use chacha20poly1305::{
    aead::AeadInPlace,
    ChaCha20Poly1305,
    KeyInit
};
use std::io::{self, Read, Write};
use base64::{engine::general_purpose, Engine as _};
use crate::{
    note::{Note, nullifier::ExtractedNullifier},
    eosio::Symbol
};
use rand_core::RngCore;
use subtle::{Choice, ConstantTimeEq};

/// The size of [`NotePlaintextBytes`].
pub const NOTE_PLAINTEXT_SIZE: usize = 
    8  + // header
    11 + // diversifier
    8  + // value
    8  + // symbol
    8  + // code
    32 + // rseed (or rcm prior to ZIP 212)
    32 + // rho
    512; // memo
/// The size of [`OutPlaintextBytes`].
pub const OUT_PLAINTEXT_SIZE: usize = 
    32 + // pk_d
    32;  // esk
const AEAD_TAG_SIZE: usize = 16;
/// The size of an encrypted note plaintext.
pub const ENC_CIPHERTEXT_SIZE: usize = NOTE_PLAINTEXT_SIZE + AEAD_TAG_SIZE;
/// The size of an encrypted outgoing plaintext.
pub const OUT_CIPHERTEXT_SIZE: usize = OUT_PLAINTEXT_SIZE + AEAD_TAG_SIZE;

/// An encrypted note.
#[derive(Clone)]
pub struct TransmittedNoteCiphertext {
    /// The serialization of the ephemeral public key
    pub epk_bytes: [u8; 32],
    /// The encrypted note ciphertext
    pub enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    /// An encrypted value that allows the holder of the outgoing cipher
    /// key for the note to recover the note plaintext.
    pub out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
}

impl fmt::Debug for TransmittedNoteCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransmittedNoteCiphertext")
            .field("epk_bytes", &self.epk_bytes)
            .field("enc_ciphertext", &hex::encode(self.enc_ciphertext))
            .field("out_ciphertext", &hex::encode(self.out_ciphertext))
            .finish()
    }
}

impl TransmittedNoteCiphertext
{
    ///
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()>
    {
        writer.write_all(self.epk_bytes.as_ref())?;         // 32
        writer.write_all(self.enc_ciphertext.as_ref())?;    // ENC_CIPHERTEXT_SIZE
        writer.write_all(self.out_ciphertext.as_ref())?;    // OUT_CIPHERTEXT_SIZE

        Ok(())
    }

    ///
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self>
    {
        let mut epk_bytes = [0; 32];
        reader.read_exact(&mut epk_bytes)?;
        let mut enc_ciphertext = [0; ENC_CIPHERTEXT_SIZE];
        reader.read_exact(&mut enc_ciphertext)?;
        let mut out_ciphertext = [0; OUT_CIPHERTEXT_SIZE];
        reader.read_exact(&mut out_ciphertext)?;

        Ok(TransmittedNoteCiphertext{
            epk_bytes,
            enc_ciphertext,
            out_ciphertext
        })
    }

    ///
    pub fn to_base64(&self) -> String
    {
        let mut data = vec![];
        let _ = self.write(&mut data);
        general_purpose::STANDARD.encode(&data)
    }

    ///
    pub fn from_base64(b64: &String) -> Option<TransmittedNoteCiphertext>
    {
        let data = general_purpose::STANDARD.decode(b64);
        if data.is_err()
        {
            return None;
        }
        let tnc = TransmittedNoteCiphertext::read(data.unwrap().as_slice());
        if tnc.is_err()
        {
            return None;
        }
        Some(tnc.unwrap())
    }
}

/// A symmetric key that can be used to recover a single Sapling or Orchard output.
#[derive(Debug)]
pub struct OutgoingCipherKey(pub [u8; 32]);

impl From<[u8; 32]> for OutgoingCipherKey {
    fn from(ock: [u8; 32]) -> Self {
        OutgoingCipherKey(ock)
    }
}

impl AsRef<[u8]> for OutgoingCipherKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Newtype representing the byte encoding of an [`EphemeralPublicKey`].
///
/// [`EphemeralPublicKey`]: Domain::EphemeralPublicKey
#[derive(Clone, Debug)]
pub struct EphemeralKeyBytes(pub [u8; 32]);

impl AsRef<[u8]> for EphemeralKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for EphemeralKeyBytes {
    fn from(value: [u8; 32]) -> EphemeralKeyBytes {
        EphemeralKeyBytes(value)
    }
}

impl ConstantTimeEq for EphemeralKeyBytes {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Newtype representing the byte encoding of a note plaintext.
#[derive(Debug)]
pub struct NotePlaintextBytes(pub [u8; NOTE_PLAINTEXT_SIZE]);
/// Newtype representing the byte encoding of a outgoing plaintext.
#[derive(Debug)]
pub struct OutPlaintextBytes(pub [u8; OUT_PLAINTEXT_SIZE]);

#[derive(Copy, Clone, PartialEq, Eq)]
enum NoteValidity {
    Valid,
    Invalid,
}

/// Implementation of in-band secret distribution for Orchard bundles.
/// A struct containing context required for encrypting Orchard notes.
///
/// This struct provides a safe API for encrypting Orchard notes. In particular, it
/// enforces that fresh ephemeral keys are used for every note, and that the ciphertexts are
/// consistent with each other.
///
/// Implements section 4.19 of the
/// [Zcash Protocol Specification](https://zips.z.cash/protocol/nu5.pdf#saplingandorchardinband)
#[derive(Debug)]
pub struct NoteEncryption {
    epk: EphemeralPublicKey,
    esk: EphemeralSecretKey,
    note: Note,
    /// `None` represents the `ovk = ⊥` case.
    ovk: Option<OutgoingViewingKey>,
}

impl NoteEncryption {
    /// Construct a new note encryption context for the specified note,
    /// recipient, and memo.
    pub fn new(
        ovk: Option<OutgoingViewingKey>,
        note: Note,
    ) -> Self {
        let esk = derive_esk(&note).expect("ZIP 212 is active.");
        NoteEncryption {
            epk: ka_derive_public(&note, &esk),
            esk,
            note,
            ovk,
        }
    }

    /// Exposes the ephemeral secret key being used to encrypt this note.
    pub fn esk(&self) -> &EphemeralSecretKey {
        &self.esk
    }

    /// Exposes the encoding of the ephemeral public key being used to encrypt this note.
    pub fn epk(&self) -> &EphemeralPublicKey {
        &self.epk
    }

    /// Generates `encCiphertext` for this note.
    pub fn encrypt_note_plaintext(&self) -> [u8; ENC_CIPHERTEXT_SIZE] {
        let pk_d = get_pk_d(&self.note);
        let shared_secret = ka_agree_enc(&self.esk, &pk_d);
        let key = kdf(shared_secret, &epk_bytes(&self.epk));
        let input = note_plaintext_bytes(&self.note);

        let mut output = [0u8; ENC_CIPHERTEXT_SIZE];
        output[..NOTE_PLAINTEXT_SIZE].copy_from_slice(&input.0);
        let tag = ChaCha20Poly1305::new(key.as_ref().into())
            .encrypt_in_place_detached(
                [0u8; 12][..].into(),
                &[],
                &mut output[..NOTE_PLAINTEXT_SIZE],
            )
            .unwrap();
        output[NOTE_PLAINTEXT_SIZE..].copy_from_slice(&tag);

        output
    }

    /// Generates `outCiphertext` for this note.
    pub fn encrypt_outgoing_plaintext<R: RngCore>(
        &self,
        rng: &mut R,
    ) -> [u8; OUT_CIPHERTEXT_SIZE] {
        let (ock, input) = if let Some(ovk) = &self.ovk {
            let ock = derive_ock(ovk, &epk_bytes(&self.epk));
            let input = outgoing_plaintext_bytes(&self.note, &self.esk);

            (ock, input)
        } else {
            // ovk = ⊥
            let mut ock = OutgoingCipherKey([0; 32]);
            let mut input = [0u8; OUT_PLAINTEXT_SIZE];

            rng.fill_bytes(&mut ock.0);
            rng.fill_bytes(&mut input);

            (ock, OutPlaintextBytes(input))
        };

        let mut output = [0u8; OUT_CIPHERTEXT_SIZE];
        output[..OUT_PLAINTEXT_SIZE].copy_from_slice(&input.0);
        let tag = ChaCha20Poly1305::new(ock.as_ref().into())
            .encrypt_in_place_detached([0u8; 12][..].into(), &[], &mut output[..OUT_PLAINTEXT_SIZE])
            .unwrap();
        output[OUT_PLAINTEXT_SIZE..].copy_from_slice(&tag);

        output
    }
}

/// Trial decryption of the full note plaintext by the recipient.
///
/// Attempts to decrypt and validate the given shielded output using the given `ivk`.
/// If successful, the corresponding note and memo are returned, along with the address to
/// which the note was sent.
///
/// Implements section 4.19.2 of the
/// [Zcash Protocol Specification](https://zips.z.cash/protocol/nu5.pdf#decryptivk).
pub fn try_note_decryption(
    ivk: &PreparedIncomingViewingKey,
    encrypted_note: &TransmittedNoteCiphertext,
) -> Option<Note> {
    let ephemeral_key = EphemeralKeyBytes(encrypted_note.epk_bytes);

    let epk = prepare_epk(epk(&ephemeral_key)?);
    let shared_secret = ka_agree_dec(ivk, &epk);
    let key = kdf(shared_secret, &ephemeral_key);

    try_note_decryption_inner(ivk, &ephemeral_key, encrypted_note, key)
}

fn try_note_decryption_inner(
    ivk: &PreparedIncomingViewingKey,
    ephemeral_key: &EphemeralKeyBytes,
    encrypted_note: &TransmittedNoteCiphertext,
    key: Hash,
) -> Option<Note> {
    let enc_ciphertext = encrypted_note.enc_ciphertext;

    let mut plaintext =
        NotePlaintextBytes(enc_ciphertext[..NOTE_PLAINTEXT_SIZE].try_into().unwrap());

    ChaCha20Poly1305::new(key.as_ref().into())
        .decrypt_in_place_detached(
            [0u8; 12][..].into(),
            &[],
            &mut plaintext.0,
            enc_ciphertext[NOTE_PLAINTEXT_SIZE..].into(),
        )
        .ok()?;

    let note = parse_note_plaintext_ivk(
        ivk,
        ephemeral_key,
        &plaintext.0,
    )?;

    Some(note)
}

fn parse_note_plaintext_ivk(
    ivk: &PreparedIncomingViewingKey,
    ephemeral_key: &EphemeralKeyBytes,
    plaintext: &[u8],
) -> Option<Note> {
    let note = orchard_parse_note_plaintext_ivk(ivk, &plaintext)?;

    if let NoteValidity::Valid = check_note_validity(&note, ephemeral_key) {
        Some(note)
    } else {
        None
    }
}

fn check_note_validity(
    note: &Note,
    ephemeral_key: &EphemeralKeyBytes,
) -> NoteValidity {
    if let Some(derived_esk) = derive_esk(note) {
        if epk_bytes(&ka_derive_public(&note, &derived_esk))
            .ct_eq(&ephemeral_key)
            .into()
        {
            NoteValidity::Valid
        } else {
            NoteValidity::Invalid
        }
    } else {
        // Before ZIP 212
        NoteValidity::Valid
    }
}

/// Recovery of the full note plaintext by the sender.
///
/// Attempts to decrypt and validate the given shielded output using the given `ovk`.
/// If successful, the corresponding note and memo are returned, along with the address to
/// which the note was sent.
///
/// Implements [Zcash Protocol Specification section 4.19.3][decryptovk].
///
/// [decryptovk]: https://zips.z.cash/protocol/nu5.pdf#decryptovk
pub fn try_output_recovery_with_ovk(
    ovk: &OutgoingViewingKey,
    encrypted_note: &TransmittedNoteCiphertext,
) -> Option<Note> {
    let ock = derive_ock(ovk, &EphemeralKeyBytes(encrypted_note.epk_bytes));
    try_output_recovery_with_ock(&ock, encrypted_note, &encrypted_note.out_ciphertext)
}

/// Recovery of the full note plaintext by the sender.
///
/// Attempts to decrypt and validate the given shielded output using the given `ock`.
/// If successful, the corresponding note and memo are returned, along with the address to
/// which the note was sent.
///
/// Implements part of section 4.19.3 of the
/// [Zcash Protocol Specification](https://zips.z.cash/protocol/nu5.pdf#decryptovk).
/// For decryption using a Full Viewing Key see [`try_output_recovery_with_ovk`].
pub fn try_output_recovery_with_ock(
    ock: &OutgoingCipherKey,
    encrypted_note: &TransmittedNoteCiphertext,
    out_ciphertext: &[u8; OUT_CIPHERTEXT_SIZE],
) -> Option<Note> {
    let enc_ciphertext = encrypted_note.enc_ciphertext;

    let mut op = OutPlaintextBytes([0; OUT_PLAINTEXT_SIZE]);
    op.0.copy_from_slice(&out_ciphertext[..OUT_PLAINTEXT_SIZE]);

    ChaCha20Poly1305::new(ock.as_ref().into())
        .decrypt_in_place_detached(
            [0u8; 12][..].into(),
            &[],
            &mut op.0,
            out_ciphertext[OUT_PLAINTEXT_SIZE..].into(),
        )
        .ok()?;

    let pk_d = extract_pk_d(&op)?;
    let esk = extract_esk(&op)?;

    let ephemeral_key = EphemeralKeyBytes(encrypted_note.epk_bytes);
    let shared_secret = ka_agree_enc(&esk, &pk_d);
    // The small-order point check at the point of output parsing rejects
    // non-canonical encodings, so reencoding here for the KDF should
    // be okay.
    let key = kdf(shared_secret, &ephemeral_key);

    let mut plaintext = NotePlaintextBytes([0; NOTE_PLAINTEXT_SIZE]);
    plaintext
        .0
        .copy_from_slice(&enc_ciphertext[..NOTE_PLAINTEXT_SIZE]);

    ChaCha20Poly1305::new(key.as_ref().into())
        .decrypt_in_place_detached(
            [0u8; 12][..].into(),
            &[],
            &mut plaintext.0,
            enc_ciphertext[NOTE_PLAINTEXT_SIZE..].into(),
        )
        .ok()?;

    let note = parse_note_plaintext_ovk(&pk_d, &esk, &ephemeral_key, &plaintext)?;

    // ZIP 212: Check that the esk provided to this function is consistent with the esk we
    // can derive from the note.
    if let Some(derived_esk) = derive_esk(&note) {
        if (!derived_esk.ct_eq(&esk)).into() {
            return None;
        }
    }

    if let NoteValidity::Valid =
        check_note_validity(&note, &ephemeral_key)
    {
        Some(note)
    } else {
        None
    }
}




// ! In-band secret distribution for Orchard bundles.
use blake2b_simd::{Hash, Params};
use group::ff::PrimeField;

use crate::{
    keys::{
        DiversifiedTransmissionKey, Diversifier, EphemeralPublicKey, EphemeralSecretKey,
        OutgoingViewingKey, PreparedEphemeralPublicKey, PreparedIncomingViewingKey, SharedSecret,
    },
    note::Rseed,
    spec::diversify_hash,
    address::Address,
    eosio::{Asset, Name}
};

///
pub const KDF_SAPLING_PERSONALIZATION: &[u8; 16] = b"Zcash_SaplingKDF";
const PRF_OCK_ORCHARD_PERSONALIZATION: &[u8; 16] = b"Zcash_Orchardock";

/// Defined in [Zcash Protocol Spec § 5.4.2: Pseudo Random Functions][concreteprfs].
///
/// [concreteprfs]: https://zips.z.cash/protocol/nu5.pdf#concreteprfs
pub(crate) fn prf_ock_orchard(
    ovk: &OutgoingViewingKey,
    ephemeral_key: &EphemeralKeyBytes,
) -> OutgoingCipherKey {
    OutgoingCipherKey(
        Params::new()
            .hash_length(32)
            .personal(PRF_OCK_ORCHARD_PERSONALIZATION)
            .to_state()
            .update(ovk.as_ref())
            .update(ephemeral_key.as_ref())
            .finalize()
            .as_bytes()
            .try_into()
            .unwrap(),
    )
}

fn orchard_parse_note_plaintext<F>(
    plaintext: &[u8],
    get_validated_pk_d: F,
) -> Option<Note>
where
    F: FnOnce(&Diversifier) -> Option<DiversifiedTransmissionKey>,
{
    assert!(plaintext.len() == NOTE_PLAINTEXT_SIZE);

    // Check note plaintext version
    //if plaintext[0] != 0x02 {
    //    return None;
    //}

    let header = u64::from_le_bytes(plaintext[0..8].try_into().unwrap());
    // TODO: check if header field is correct?
    let diversifier = Diversifier(plaintext[8..19].try_into().unwrap());
    let amount = u64::from_le_bytes(plaintext[19..27].try_into().unwrap()) as i64;
    let symbol = u64::from_le_bytes(plaintext[27..35].try_into().unwrap());
    let asset = Asset::new(amount, Symbol::new(symbol)).unwrap();
    let code = u64::from_le_bytes(plaintext[35..43].try_into().unwrap());
    let code = Name::new(code);
    let r: [u8; 32] = plaintext[43..75].try_into().unwrap();
    let rseed = Rseed(r);
    let r: [u8; 32] = plaintext[75..107].try_into().unwrap();
    let rho = ExtractedNullifier(Scalar::from_bytes(&r).unwrap());
    let memo = plaintext[107..NOTE_PLAINTEXT_SIZE].try_into().unwrap();

    let pk_d = get_validated_pk_d(&diversifier)?;
    let recipient = Address::from_parts(diversifier, pk_d)?;
    Some(Note::from_parts(header, recipient, asset, code, rseed, rho, memo))
}

/// Derives the `EphemeralSecretKey` corresponding to this note.
///
/// Returns `None` if the note was created prior to [ZIP 212], and doesn't have a
/// deterministic `EphemeralSecretKey`.
///
/// [ZIP 212]: https://zips.z.cash/zip-0212
pub fn derive_esk(note: &Note) -> Option<EphemeralSecretKey> {
    Some(note.esk())
}

/// Extracts the `DiversifiedTransmissionKey` from the note.
fn get_pk_d(note: &Note) -> DiversifiedTransmissionKey {
    *note.address().pk_d()
}

fn prepare_epk(epk: EphemeralPublicKey) -> PreparedEphemeralPublicKey {
    PreparedEphemeralPublicKey::new(epk)
}

/// Derives `EphemeralPublicKey` from `esk` and the note's diversifier.
pub fn ka_derive_public(
    note: &Note,
    esk: &EphemeralSecretKey,
) -> EphemeralPublicKey{
    esk.derive_public(note.address().g_d().into())
}

/// Derives the `SharedSecret` from the sender's information during note encryption.
fn ka_agree_enc(
    esk: &EphemeralSecretKey,
    pk_d: &DiversifiedTransmissionKey,
) -> SharedSecret {
    esk.agree(pk_d)
}

/// Derives the `SharedSecret` from the recipient's information during note trial
/// decryption.
fn ka_agree_dec(
    ivk: &PreparedIncomingViewingKey,
    epk: &PreparedEphemeralPublicKey
) -> SharedSecret {
    epk.agree(ivk)
}

/// Derives the `SymmetricKey` used to encrypt the note plaintext.
///
/// `secret` is the `SharedSecret` obtained from [`Self::ka_agree_enc`] or
/// [`Self::ka_agree_dec`].
///
/// `ephemeral_key` is the byte encoding of the [`EphemeralPublicKey`] used to derive
/// `secret`. During encryption it is derived via [`Self::epk_bytes`]; during trial
/// decryption it is obtained from [`ShieldedOutput::ephemeral_key`].
///
/// [`EphemeralPublicKey`]: Self::EphemeralPublicKey
/// [`EphemeralSecretKey`]: Self::EphemeralSecretKey
fn kdf(secret: SharedSecret, ephemeral_key: &EphemeralKeyBytes) -> Hash {
    secret.kdf_sapling(ephemeral_key)
}

/// Encodes the given `Note` and `Memo` as a note plaintext.
///
/// [`zcash_primitives` has been refactored]: https://github.com/zcash/librustzcash/issues/454
fn note_plaintext_bytes(
    note: &Note,
) -> NotePlaintextBytes {
    let mut np = [0; NOTE_PLAINTEXT_SIZE];
    np[0..8].copy_from_slice(&note.header().to_le_bytes());
    np[8..19].copy_from_slice(&note.address().diversifier().0);
    np[19..27].copy_from_slice(&note.amount().to_le_bytes());
    np[27..35].copy_from_slice(&note.symbol().raw().to_le_bytes());
    np[35..43].copy_from_slice(&note.code().raw().to_le_bytes());
    np[43..75].copy_from_slice(&note.rseed().0);
    np[75..107].copy_from_slice(&note.rho().to_bytes());
    np[107..NOTE_PLAINTEXT_SIZE].copy_from_slice(note.memo());
    NotePlaintextBytes(np)
}

/// Derives the [`OutgoingCipherKey`] for an encrypted note, given the note-specific
/// public data and an `OutgoingViewingKey`.
fn derive_ock(
    ovk: &OutgoingViewingKey,
    ephemeral_key: &EphemeralKeyBytes,
) -> OutgoingCipherKey {
    prf_ock_orchard(ovk, ephemeral_key)
}

/// Encodes the outgoing plaintext for the given note.
fn outgoing_plaintext_bytes(
    note: &Note,
    esk: &EphemeralSecretKey,
) -> OutPlaintextBytes {
    let mut op = [0; OUT_PLAINTEXT_SIZE];
    op[..32].copy_from_slice(&note.address().pk_d().to_bytes());
    op[32..].copy_from_slice(&esk.0.to_repr());
    OutPlaintextBytes(op)
}

/// Returns the byte encoding of the given `EphemeralPublicKey`.
fn epk_bytes(epk: &EphemeralPublicKey) -> EphemeralKeyBytes {
    epk.to_bytes()
}

/// Attempts to parse `ephemeral_key` as an `EphemeralPublicKey`.
///
/// Returns `None` if `ephemeral_key` is not a valid byte encoding of an
/// `EphemeralPublicKey`.
fn epk(ephemeral_key: &EphemeralKeyBytes) -> Option<EphemeralPublicKey> {
    EphemeralPublicKey::from_bytes(&ephemeral_key.0).into()
}

/// Parses the given note plaintext from the recipient's perspective.
///
/// The implementation of this method must check that:
/// - The note plaintext version is valid (for the given decryption domain's context,
///   which may be passed via `self`).
/// - The note plaintext contains valid encodings of its various fields.
/// - Any domain-specific requirements are satisfied.
///
/// `&self` is passed here to enable the implementation to enforce contextual checks,
/// such as rules like [ZIP 212] that become active at a specific block height.
///
/// [ZIP 212]: https://zips.z.cash/zip-0212
///
/// # Panics
///
/// Panics if `plaintext` is shorter than [`COMPACT_NOTE_SIZE`].
fn orchard_parse_note_plaintext_ivk(
    ivk: &PreparedIncomingViewingKey,
    plaintext: &[u8],
) -> Option<Note> {
    orchard_parse_note_plaintext(plaintext, |diversifier| {
        Some(DiversifiedTransmissionKey::derive(ivk, diversifier)?)
    })
}

/// Parses the given note plaintext from the sender's perspective.
///
/// The implementation of this method must check that:
/// - The note plaintext version is valid (for the given decryption domain's context,
///   which may be passed via `self`).
/// - The note plaintext contains valid encodings of its various fields.
/// - Any domain-specific requirements are satisfied.
/// - `ephemeral_key` can be derived from `esk` and the diversifier within the note
///   plaintext.
///
/// `&self` is passed here to enable the implementation to enforce contextual checks,
/// such as rules like [ZIP 212] that become active at a specific block height.
///
/// [ZIP 212]: https://zips.z.cash/zip-0212
fn parse_note_plaintext_ovk(
    pk_d: &DiversifiedTransmissionKey,
    esk: &EphemeralSecretKey,
    ephemeral_key: &EphemeralKeyBytes,
    plaintext: &NotePlaintextBytes,
) -> Option<Note> {
    orchard_parse_note_plaintext(&plaintext.0, |diversifier| {
        if esk
            .derive_public(diversify_hash(&diversifier.0)?.into())
            .to_bytes()
            .0
            == ephemeral_key.0
        {
            Some(*pk_d)
        } else {
            None
        }
    })
}

/// Parses the `DiversifiedTransmissionKey` field of the outgoing plaintext.
///
/// Returns `None` if `out_plaintext` does not contain a valid byte encoding of a
/// `DiversifiedTransmissionKey`.
fn extract_pk_d(out_plaintext: &OutPlaintextBytes) -> Option<DiversifiedTransmissionKey> {
    DiversifiedTransmissionKey::from_bytes(out_plaintext.0[0..32].try_into().unwrap()).into()
}

/// Parses the `EphemeralSecretKey` field of the outgoing plaintext.
///
/// Returns `None` if `out_plaintext` does not contain a valid byte encoding of an
/// `EphemeralSecretKey`.
fn extract_esk(out_plaintext: &OutPlaintextBytes) -> Option<EphemeralSecretKey> {
    EphemeralSecretKey::from_bytes(out_plaintext.0[32..OUT_PLAINTEXT_SIZE].try_into().unwrap())
        .into()
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use bls12_381::Scalar;
    use super::{try_note_decryption, try_output_recovery_with_ovk};
    use super::{derive_esk, ka_derive_public, NoteEncryption, TransmittedNoteCiphertext};
    use crate::{
        keys::{PreparedIncomingViewingKey, SpendingKey, FullViewingKey},
        note::{Note, Rseed, nullifier::ExtractedNullifier},
        eosio::{Asset, Name}
    };

    #[test]
    fn test_key_derivation_and_encryption()
    {
        let mut rng = OsRng.clone();

        // Alice' key material
        let sk_alice = SpendingKey::from_seed(b"This is Alice seed string! Usually this is just a listing of words. Here we just use sentences.");
        let fvk_alice = FullViewingKey::from_spending_key(&sk_alice);

        // Bob's key material
        let sk_bob = SpendingKey::from_seed(b"This is Bob's seed string. His seed is a little shorter...");
        let fvk_bob = FullViewingKey::from_spending_key(&sk_bob);
        let recipient = fvk_bob.default_address().1;

        // Note material
        let note = Note::from_parts(
            0,
            recipient,
            Asset::from_string(&"10.0000 ZEOS".to_string()).unwrap(),
            Name::from_string(&"thezeostoken".to_string()).unwrap(),
            Rseed([42; 32]),
            ExtractedNullifier(Scalar::one()),
            [0; 512]
        );

        // the ephermeral key pair which is used for encryption/decryption is derived deterministically from the note
        let esk = derive_esk(&note).unwrap();
        let epk = ka_derive_public(&note, &esk);
        
        let ne = NoteEncryption::new(Some(fvk_alice.ovk), note.clone());
        // a dummy action to test encryption/decryption
        let encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: epk.to_bytes().0,
            enc_ciphertext: ne.encrypt_note_plaintext(),
            out_ciphertext: ne.encrypt_outgoing_plaintext(&mut rng),
        };

        let b64_str = encrypted_note.to_base64();
        println!("{}", b64_str);
        let encrypted_note = TransmittedNoteCiphertext::from_base64(&b64_str).unwrap();

        // test receiver decryption
        match try_note_decryption(&PreparedIncomingViewingKey::new(&fvk_bob.ivk()), &encrypted_note) {
            Some(decrypted_note) => assert_eq!(decrypted_note, note),
            None => panic!("Note decryption failed"),
        }

        // test sender decryption
        match try_output_recovery_with_ovk(&fvk_alice.ovk, &encrypted_note) {
            Some(decrypted_note) => assert_eq!(decrypted_note, note),
            None => panic!("Output recovery failed"),
        }

    }
}
