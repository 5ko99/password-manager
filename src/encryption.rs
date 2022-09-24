use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use pbkdf2::{
    password_hash::{Output, PasswordHasher, SaltString},
    Pbkdf2,
};
use snafu::Snafu;
use std::error::Error;

use crate::program::User;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Debug, Snafu, PartialEq, Eq)]
pub enum EncryptionError {
    #[snafu(display("Error while creating the cipher! Error: '{info}'"))]
    CipherError { info: String },
    #[snafu(display("Error while decripting the data! Error: '{info}'"))]
    DecryptionError { info: String },
    #[snafu(display("Error while hashing! Error: '{info}'"))]
    HashError { info: String },
    #[snafu(display("Error while creating the salt! Error: '{info}'"))]
    SaltError { info: String },
    #[snafu(display("Empty block!"))]
    EmptyBlockError {},
    #[snafu(display("Empty user!'"))]
    EmptyUserError {},
}

fn creating_username_for_salt(username: &str) -> String {
    let mut username_for_salt = String::from(username);
    username_for_salt.shrink_to(16);
    for _ in username.len()..16 {
        username_for_salt.push('p');
    }
    assert_eq!(username_for_salt.len(), 16);
    username_for_salt
}

fn creating_salt(username_for_salt: &str) -> Result<SaltString, EncryptionError> {
    match SaltString::new(username_for_salt) {
        Ok(salt) => Ok(salt),
        Err(e) => Err(EncryptionError::SaltError {
            info: e.to_string(),
        }),
    }
}

fn creating_password_hash(password: &[u8], salt: &SaltString) -> Result<Output, EncryptionError> {
    match Pbkdf2.hash_password(password, &salt) {
        Ok(hash) => match hash.hash {
            Some(hash) => Ok(hash),
            None => Err(EncryptionError::HashError {
                info: "Hash is None!".to_string(),
            }),
        },
        Err(e) => Err(EncryptionError::HashError {
            info: e.to_string(),
        }),
    }
}

fn creating_cipher_enc(
    password_hash: &Output,
    username_for_salt: &str,
) -> Result<Aes128CbcEnc, EncryptionError> {
    let mut key: [u8; 16] = [0; 16];

    key[..16].copy_from_slice(&password_hash.as_bytes()[..16]);

    let iv = username_for_salt.as_bytes();

    let cipher = Aes128CbcEnc::new_from_slices(&key, iv);

    match cipher {
        Ok(cipher) => Ok(cipher),
        Err(e) => Err(EncryptionError::CipherError {
            info: e.to_string(),
        }),
    }
}

fn creating_cipher_dec(
    password_hash: &Output,
    username_for_salt: &str,
) -> Result<Aes128CbcDec, EncryptionError> {
    let mut key: [u8; 16] = [0; 16];

    key[..16].copy_from_slice(&password_hash.as_bytes()[..16]);

    let iv = username_for_salt.as_bytes();

    let cipher = Aes128CbcDec::new_from_slices(&key, iv);

    match cipher {
        Ok(cipher) => Ok(cipher),
        Err(e) => Err(EncryptionError::CipherError {
            info: e.to_string(),
        }),
    }
}

pub fn encrypt_data(user: &User, block: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if block.is_empty() {
        return Err(EncryptionError::EmptyBlockError {}.into());
    }

    if user.is_empty() {
        return Err(EncryptionError::EmptyUserError {}.into());
    }

    let password = user.password.as_bytes();

    let username_for_salt = creating_username_for_salt(&user.username);

    let salt = match creating_salt(&username_for_salt) {
        Ok(salt) => salt,
        Err(e) => return Err(e.into()),
    };

    let password_hash = match creating_password_hash(password, &salt) {
        Ok(hash) => hash,
        Err(e) => return Err(e.into()),
    };

    let cipher = match creating_cipher_enc(&password_hash, &username_for_salt) {
        Ok(cipher) => cipher,
        Err(e) => return Err(e.into()),
    };

    let encrypt_block = cipher.encrypt_padded_vec_mut::<Pkcs7>(block.as_bytes());

    Ok(encrypt_block)
}

fn decrypt_block_to_string(decrypt_block: &Vec<u8>) -> String {
    let mut decrypt_block_string: String = String::new();

    for item in decrypt_block {
        decrypt_block_string.push(*item as char);
    }
    decrypt_block_string
}

pub fn decrypt_data(user: &User, block: &Vec<u8>) -> Result<String, Box<dyn Error>> {
    if block.is_empty() {
        return Err(EncryptionError::EmptyBlockError {}.into());
    }

    if user.is_empty() {
        return Err(EncryptionError::EmptyUserError {}.into());
    }

    let password = user.password.as_bytes();

    let username_for_salt = creating_username_for_salt(&user.username);

    let salt = match creating_salt(&username_for_salt) {
        Ok(salt) => salt,
        Err(e) => return Err(e.into()),
    };

    let password_hash = match creating_password_hash(password, &salt) {
        Ok(hash) => hash,
        Err(e) => return Err(e.into()),
    };

    let cipher = match creating_cipher_dec(&password_hash, &username_for_salt) {
        Ok(cipher) => cipher,
        Err(e) => return Err(e.into()),
    };

    let decrypt_block = cipher.decrypt_padded_vec_mut::<Pkcs7>(block.as_slice());

    let decrypt_block = match decrypt_block {
        Ok(block) => block,
        Err(e) => {
            return Err(EncryptionError::DecryptionError {
                info: e.to_string(),
            }
            .into());
        }
    };

    let decrypt_block_string = decrypt_block_to_string(&decrypt_block);

    Ok(decrypt_block_string)
}
