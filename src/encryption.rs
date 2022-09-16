use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use pbkdf2::{
    password_hash::{PasswordHasher, SaltString},
    Pbkdf2,
};
use std::error::Error;

use crate::program::{User, LogicError};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub fn encrypt_data(user: &User, block: &str) -> Result<Vec<u8>, Box<dyn Error>> {
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
            return Err(LogicError::EncryptionError {
                info: e.to_string(),
            }.into());
        }
    };

    let password_hash = match Pbkdf2.hash_password(password, &salt) {
        Ok(hash) => hash,
        Err(e) => panic!("Error while hashing the master key:{}", e),
    };

    let password_hash = match password_hash.hash {
        Some(hash) => hash.to_string(),
        None => panic!("Error while hashing the master key"),
    };

    let mut key: [u8; 16] = [0; 16];

    key[..16].copy_from_slice(&password_hash.as_bytes()[..16]);

    let iv = username_for_salt.as_bytes();

    let cipher = Aes128CbcEnc::new_from_slices(&key, iv);

    let cipher = match cipher {
        Ok(cipher) => cipher,
        Err(e) => panic!("Error while creating the cipher: {}", e),
    };

    let encrypt_block = cipher.encrypt_padded_vec_mut::<Pkcs7>(block.as_bytes());

    Ok(encrypt_block)
}

pub fn decrypt_data(user: &User, block: &Vec<u8>) -> String {
    // if the block is empty, return an empty string
    if block.is_empty() {
        return String::new();
    }

    let password = user.password.as_bytes();

    let mut username_for_salt = user.username.clone();
    username_for_salt.shrink_to(16);
    for _ in 0..16 - user.username.len() {
        username_for_salt.push('p');
    }

    assert_eq!(username_for_salt.len(), 16);

    let salt = match SaltString::new(&username_for_salt) {
        Ok(salt) => salt,
        Err(e) => {
            panic!("Error while creating salt string:{}", e);
        }
    };

    let password_hash = match Pbkdf2.hash_password(password, &salt) {
        Ok(hash) => hash,
        Err(e) => panic!("Error while hashing the master key:{}", e),
    };

    let password_hash = match password_hash.hash {
        Some(hash) => hash.to_string(),
        None => panic!("Error while hashing the master key"),
    };

    let mut key: [u8; 16] = [0; 16];

    key[..16].copy_from_slice(&password_hash.as_bytes()[..16]);

    let iv = username_for_salt.as_bytes();

    let cipher = Aes128CbcDec::new_from_slices(&key, iv);

    let cipher = match cipher {
        Ok(cipher) => cipher,
        Err(e) => panic!("Error while creating the cipher: {}", e),
    };

    let decrypt_block = cipher.decrypt_padded_vec_mut::<Pkcs7>(block.as_slice());

    let decrypt_block = match decrypt_block {
        Ok(block) => block,
        Err(e) => panic!("Error while decrypting the block: {}", e),
    };

    let mut decrypt_block_string: String = String::new();

    for item in &decrypt_block {
        decrypt_block_string.push(*item as char);
    }

    decrypt_block_string
}
