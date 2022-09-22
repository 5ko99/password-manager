use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use pbkdf2::{
    password_hash::{PasswordHasher, SaltString},
    Pbkdf2,
};
use snafu::Snafu;
use std::error::Error;

use crate::program::{User};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Debug, Snafu,PartialEq,Eq)]
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

pub fn encrypt_data(user: &User, block: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if block.is_empty() {
        return Err(EncryptionError::EmptyBlockError {}.into());
    }

    if user.is_empty() {
        return Err(EncryptionError::EmptyUserError {}.into());
    }

    let password = user.password.as_bytes();

    let mut username_for_salt = user.username.clone();
    username_for_salt.shrink_to(16);
    for _ in user.username.len()..16 {
        username_for_salt.push('p');
    }

    assert_eq!(username_for_salt.len(), 16);

    let salt = match SaltString::new(&username_for_salt) {
        Ok(salt) => salt,
        Err(e) => {
            return Err(EncryptionError::SaltError {
                info: e.to_string(),
            }
            .into());
        }
    };

    let password_hash = match Pbkdf2.hash_password(password, &salt) {
        Ok(hash) => match hash.hash {
            Some(hash) => hash,
            None => {
                return Err(EncryptionError::HashError {
                    info: "Hash is None!".to_string(),
                }
                .into());
            }
        },
        Err(e) => {
            return Err(EncryptionError::HashError {
                info: e.to_string(),
            }
            .into());
        }
    };

    let mut key: [u8; 16] = [0; 16];

    key[..16].copy_from_slice(&password_hash.as_bytes()[..16]);

    let iv = username_for_salt.as_bytes();

    let cipher = Aes128CbcEnc::new_from_slices(&key, iv);

    let cipher = match cipher {
        Ok(cipher) => cipher,
        Err(e) => {
            return Err(EncryptionError::CipherError {
                info: e.to_string(),
            }
            .into());
        }
    };

    let encrypt_block = cipher.encrypt_padded_vec_mut::<Pkcs7>(block.as_bytes());

    Ok(encrypt_block)
}

pub fn decrypt_data(user: &User, block: &Vec<u8>) -> Result<String, Box<dyn Error>> {
    if block.is_empty() {
        return Err(EncryptionError::EmptyBlockError {}.into());
    }

    if user.is_empty() {
        return Err(EncryptionError::EmptyUserError {}.into());
    }

    let password = user.password.as_bytes();

    let mut username_for_salt = user.username.clone();
    username_for_salt.shrink_to(16);
    for _ in user.username.len()..16 {
        username_for_salt.push('p');
    }

    assert_eq!(username_for_salt.len(), 16);

    let salt = match SaltString::new(&username_for_salt) {
        Ok(salt) => salt,
        Err(e) => {
            return Err(EncryptionError::SaltError {
                info: e.to_string(),
            }
            .into());
        }
    };

    let password_hash = match Pbkdf2.hash_password(password, &salt) {
        Ok(hash) => match hash.hash {
            Some(hash) => hash,
            None => {
                return Err(EncryptionError::HashError {
                    info: "Hash is None!".to_string(),
                }
                .into());
            }
        },
        Err(e) => {
            return Err(EncryptionError::HashError {
                info: e.to_string(),
            }
            .into());
        }
    };

    let mut key: [u8; 16] = [0; 16];

    key[..16].copy_from_slice(&password_hash.as_bytes()[..16]);

    let iv = username_for_salt.as_bytes();

    let cipher = Aes128CbcDec::new_from_slices(&key, iv);

    let cipher = match cipher {
        Ok(cipher) => cipher,
        Err(e) => {
            return Err(EncryptionError::CipherError {
                info: e.to_string(),
            }
            .into());
        }
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

    let mut decrypt_block_string: String = String::new();

    for item in &decrypt_block {
        decrypt_block_string.push(*item as char);
    }

    Ok(decrypt_block_string)
}
