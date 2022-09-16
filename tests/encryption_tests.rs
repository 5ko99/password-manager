use password_manager::{encryption::{encrypt_data, decrypt_data}, program::Program};
use sha256::digest;

const USERNAME : &str = "testuser";
const PASSWORD : &str = "1234";

const USERNAME2: &str = "testuser2";
const PASSWORD2: &str = "4321";


#[test]
fn test_encryption_and_decryption() {
    let mut program = Program::default();
    assert!(program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .is_ok());
    let result = encrypt_data(program.get_logged_user().unwrap(),"pass");
    assert_eq!(decrypt_data(program.get_logged_user().unwrap(),&result), "pass");
}

#[test]
#[should_panic]
fn test_encryption_and_decryption_but_with_wrong_user() {
    let mut program = Program::default();
    assert!(program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .is_ok());
    
    let result = encrypt_data(program.get_logged_user().unwrap(),"pass");

    assert!(program.logout().is_ok());
    assert!(program
        .login(USERNAME2.to_string(), PASSWORD2.to_string(), digest(PASSWORD2))
        .is_ok());
    
    assert_ne!(decrypt_data(program.get_logged_user().unwrap(),&result), "pass");
}

#[test]
fn test_encryption_and_decryption_with_empty_string() {
    let mut program = Program::default();
    assert!(program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .is_ok());
    let result = encrypt_data(program.get_logged_user().unwrap(),&"");
    assert_eq!(decrypt_data(program.get_logged_user().unwrap(),&result), "");
}