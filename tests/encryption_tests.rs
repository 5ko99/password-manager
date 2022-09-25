use password_manager::{program::{User}, encryption::{encrypt_data, decrypt_data, EncryptionError}};


const USERNAME : &str = "testuser";
const PASSWORD : &str = "1234";

const USERNAME2: &str = "testuser2";
const PASSWORD2: &str = "4321";


#[test]
fn test_encryption_and_decryption() {
    let user = User::new(USERNAME.to_string(), PASSWORD.to_string());
    let result = encrypt_data(&user,"pass");
    assert!(result.is_ok());
    let result = result.unwrap();
    let decripted = decrypt_data(&user,&result);
    assert!(decripted.is_ok());
    let decripted = decripted.unwrap();
    assert_eq!(decripted, "pass");
}

#[test]
fn test_encryption_and_decryption_but_with_wrong_user() {
    let user = User::new(USERNAME.to_string(), PASSWORD.to_string());
    
    let result = encrypt_data(&user,"pass");
    assert!(result.is_ok());

    let result = result.unwrap();

    let user = User::new(USERNAME2.to_string(), PASSWORD2.to_string());

    let decrypted = decrypt_data(&user,&result);

    assert!(decrypted.is_err());

    let error = decrypted.unwrap_err();
    let error = error.downcast_ref::<EncryptionError>().unwrap();
    
    assert_eq!(std::mem::discriminant(error), std::mem::discriminant(&EncryptionError::DecryptionError{ info: "something".to_string() }));
}

#[test]
fn test_encryption_with_empty_string() {
    let user = User::new(USERNAME.to_string(), PASSWORD.to_string());

    let result = encrypt_data(&user,&"");
    assert!(result.is_err());
    let result_error = result.unwrap_err();
    let result_error = result_error.downcast_ref::<EncryptionError>().unwrap();
    assert_eq!(result_error, &EncryptionError::EmptyBlockError{});
}

#[test]
fn test_encryption_with_empty_user() {
    let user = User::new("".to_string(), "".to_string());
    let result = encrypt_data(&user,&"pass");
    assert!(result.is_err());
    let result_error = result.unwrap_err();
    let result_error = result_error.downcast_ref::<EncryptionError>().unwrap();
    assert_eq!(result_error, &EncryptionError::EmptyUserError{});
}

#[test]
fn test_decryption_with_empty_user() {
    let user = User::new("".to_string(), "".to_string());
    let test_vec : Vec<u8> = vec![0,1,2,3,4,5,6,7,8,9];
    let result = decrypt_data(&user,&test_vec);
    assert!(result.is_err());
    let result_error = result.unwrap_err();
    let result_error = result_error.downcast_ref::<EncryptionError>().unwrap();
    assert_eq!(result_error, &EncryptionError::EmptyUserError{});
}


#[test]
fn test_decryption_with_empty_vec() {
    let user = User::new(USERNAME.to_string(), PASSWORD.to_string());
    let test_vec : Vec<u8> = vec![];
    let result = decrypt_data(&user,&test_vec);
    assert!(result.is_err());
    let result_error = result.unwrap_err();
    let result_error = result_error.downcast_ref::<EncryptionError>().unwrap();
    assert_eq!(result_error, &EncryptionError::EmptyBlockError{});
}

#[test]
fn test_encryption_with_invalid_user() {
    let user = User::new("t3st@".to_string(), "1234".to_string()); //user cannot have invalid chars.
    let result = encrypt_data(&user,&"pass");
    assert!(result.is_err());
    let result_error = result.unwrap_err();
    let result_error = result_error.downcast_ref::<EncryptionError>().unwrap();
    assert_eq!(std::mem::discriminant(result_error), std::mem::discriminant(&EncryptionError::SaltError{ info: "something".to_string() }));
}

#[test]
fn test_decryption_with_invalid_user() {
    let user = User::new("t3st@".to_string(), "1234".to_string()); //user cannot have invalid chars.
    let test_vec : Vec<u8> = vec![0,1,2,3,4,5,6,7,8,9];
    let result = decrypt_data(&user,&test_vec);
    assert!(result.is_err());
    let result_error = result.unwrap_err();
    let result_error = result_error.downcast_ref::<EncryptionError>().unwrap();
    assert_eq!(std::mem::discriminant(result_error), std::mem::discriminant(&EncryptionError::SaltError{ info: "something".to_string() }));
}

#[test]
fn test_decryption_with_corrupted_file() {
    let user = User::new(USERNAME.to_string(), PASSWORD.to_string());
    let result = encrypt_data(&user,"pass");
    assert!(result.is_ok());
    let mut result = result.unwrap();

    //Now let's corrupt the file
    result[0] = 0x00;
    result[1] = 0x12;
    result[2] = 0x34;


    let decripted = decrypt_data(&user,&result);
    assert!(decripted.is_err());
    let decripted_error = decripted.unwrap_err();
    let decripted_error = decripted_error.downcast_ref::<EncryptionError>().unwrap();
    assert_eq!(std::mem::discriminant(decripted_error), std::mem::discriminant(&EncryptionError::DecryptionError{ info: "something".to_string() }));
}


//TODO: Write more tests!