use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

pub const WALLET_MAGIC: &[u8; 8] = b"CLOAKWAL";
pub const WALLET_VERSION: u8 = 1;

// magic(8) + version(1) + kdf_id(1) + params(12) + salt(16) + nonce(12)
pub const WALLET_HEADER_LEN: usize = 50;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

// kdf_id values
const KDF_ARGON2ID: u8 = 1;

#[derive(Debug, Clone)]
pub struct KdfParams {
    pub mem_kib: u32,
    pub iters: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // Desktop-safe defaults; tune later if needed.
        // 64 MiB, 3 iterations, single lane.
        Self {
            mem_kib: 64 * 1024,
            iters: 3,
            parallelism: 1,
        }
    }
}

#[derive(Debug)]
pub enum WalletCryptoError {
    InvalidFormat,
    UnsupportedVersion(u8),
    UnsupportedKdf(u8),
    EncryptFailed,
    DecryptFailed, // wrong password OR corrupted data
}

pub fn is_encrypted_wallet(data: &[u8]) -> bool {
    data.len() >= WALLET_HEADER_LEN && &data[0..8] == WALLET_MAGIC
}

pub fn encrypted_size(plain_len: usize) -> usize {
    WALLET_HEADER_LEN + plain_len + TAG_LEN
}

pub fn decrypted_size(enc: &[u8]) -> Result<usize, WalletCryptoError> {
    let (_ver, _kdf, _salt, _nonce, ciphertext) = parse_header(enc)?;
    if ciphertext.len() < TAG_LEN {
        return Err(WalletCryptoError::InvalidFormat);
    }
    Ok(ciphertext.len() - TAG_LEN)
}

fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    p: &KdfParams,
) -> Result<[u8; 32], WalletCryptoError> {
    let params = Argon2Params::new(p.mem_kib, p.iters, p.parallelism, Some(32))
        .map_err(|_| WalletCryptoError::EncryptFailed)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; 32];
    // IMPORTANT: hash_password_into expects raw salt bytes (&[u8]), not SaltString.
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| WalletCryptoError::EncryptFailed)?;

    Ok(out)
}

pub fn encrypt_wallet_bytes(
    plaintext: &[u8],
    password: &[u8],
    kdf: KdfParams,
) -> Result<Vec<u8>, WalletCryptoError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut key_bytes = derive_key(password, &salt, &kdf)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    key_bytes.zeroize();

    // AAD binds header fields so attacker can't tamper params without detection.
    let aad = build_aad(WALLET_VERSION, &kdf, &salt, &nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| WalletCryptoError::EncryptFailed)?;

    let mut out = Vec::with_capacity(WALLET_HEADER_LEN + ciphertext.len());
    out.extend_from_slice(WALLET_MAGIC);
    out.push(WALLET_VERSION);
    out.push(KDF_ARGON2ID);
    out.extend_from_slice(&kdf.mem_kib.to_le_bytes());
    out.extend_from_slice(&kdf.iters.to_le_bytes());
    out.extend_from_slice(&kdf.parallelism.to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

pub fn decrypt_wallet_bytes(encrypted: &[u8], password: &[u8]) -> Result<Vec<u8>, WalletCryptoError> {
    let (version, kdf, salt, nonce, ciphertext) = parse_header(encrypted)?;

    if version != WALLET_VERSION {
        return Err(WalletCryptoError::UnsupportedVersion(version));
    }

    let mut key_bytes = derive_key(password, &salt, &kdf)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    key_bytes.zeroize();

    let aad = build_aad(version, &kdf, &salt, &nonce);

    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| WalletCryptoError::DecryptFailed)
}

fn build_aad(version: u8, kdf: &KdfParams, salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 1 + 12 + SALT_LEN + NONCE_LEN);
    aad.push(version);
    aad.push(KDF_ARGON2ID);
    aad.extend_from_slice(&kdf.mem_kib.to_le_bytes());
    aad.extend_from_slice(&kdf.iters.to_le_bytes());
    aad.extend_from_slice(&kdf.parallelism.to_le_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

fn parse_header(
    data: &[u8],
) -> Result<(u8, KdfParams, [u8; SALT_LEN], [u8; NONCE_LEN], &[u8]), WalletCryptoError> {
    if data.len() < WALLET_HEADER_LEN || &data[0..8] != WALLET_MAGIC {
        return Err(WalletCryptoError::InvalidFormat);
    }

    let version = data[8];
    let kdf_id = data[9];
    if kdf_id != KDF_ARGON2ID {
        return Err(WalletCryptoError::UnsupportedKdf(kdf_id));
    }

    let mem_kib = u32::from_le_bytes(data[10..14].try_into().unwrap());
    let iters = u32::from_le_bytes(data[14..18].try_into().unwrap());
    let parallelism = u32::from_le_bytes(data[18..22].try_into().unwrap());

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&data[22..38]);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&data[38..50]);

    let ciphertext = &data[WALLET_HEADER_LEN..];
    if ciphertext.is_empty() {
        return Err(WalletCryptoError::InvalidFormat);
    }

    Ok((
        version,
        KdfParams {
            mem_kib,
            iters,
            parallelism,
        },
        salt,
        nonce,
        ciphertext,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_encrypted_header() {
        assert!(!is_encrypted_wallet(b""));
        assert!(!is_encrypted_wallet(b"12345678"));
        let mut v = Vec::new();
        v.extend_from_slice(WALLET_MAGIC);
        v.resize(WALLET_HEADER_LEN, 0);
        assert!(is_encrypted_wallet(&v));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plain = b"hello wallet bytes";
        let pw = b"correct horse battery staple";

        let enc = encrypt_wallet_bytes(plain, pw, KdfParams::default()).unwrap();
        assert!(is_encrypted_wallet(&enc));
        assert_eq!(encrypted_size(plain.len()), enc.len());

        let dec = decrypt_wallet_bytes(&enc, pw).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn wrong_password_fails() {
        let plain = b"wallet bytes";
        let enc = encrypt_wallet_bytes(plain, b"pw1", KdfParams::default()).unwrap();
        let dec = decrypt_wallet_bytes(&enc, b"pw2");
        assert!(dec.is_err());
    }

    #[test]
    fn tamper_fails() {
        let plain = b"wallet bytes";
        let mut enc = encrypt_wallet_bytes(plain, b"pw", KdfParams::default()).unwrap();
        // flip one byte in ciphertext
        let last = enc.len() - 1;
        enc[last] ^= 0x01;
        let dec = decrypt_wallet_bytes(&enc, b"pw");
        assert!(dec.is_err());
    }
}
