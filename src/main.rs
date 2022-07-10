

use aes::cipher::consts::{B0, B1};
use aes::cipher::typenum::{UTerm, UInt};
use argon2::{self, Config, Variant, Version, ThreadMode};
use aes::{Aes256, Aes128};
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};



fn main() {
    let password = "password";
    let salt = b"randomsalt";
    let config = Config::default();
    // let hash = argon2::hash_encoded(password, salt, &config).unwrap();
    // println!("{}", hash.len());
    // let matches = argon2::verify_encoded(&hash, password).unwrap();
    // let salt2 = b"petko&emi";
    // let hash2 = argon2::hash_encoded(password, salt2, &config).unwrap();
    // print!("{}", hash2.len());
    // println!("{}", hash2);
    // let matches2 = argon2::verify_encoded(&hash2, password).unwrap();
    // println!("{}", matches2);
    // assert!(hash != hash2);
    // assert!(matches);

    let hash = md5::compute(password).0;

    let key  = GenericArray::from_slice(&hash);
    //&GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>,B0>>
    let mut block = GenericArray::from([42u8; 16]);
    let cipher = Aes128::new(key);

    let block_copy = block.clone();
    cipher.encrypt_block(&mut block);

    println!("{:?}", block);

    cipher.decrypt_block(&mut block);
    println!("{:?}", block);
    assert_eq!(block, block_copy);

}