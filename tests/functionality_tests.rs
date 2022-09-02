use password_manager::{
    program::{Program, User},
    record::Record,
};
use sha256::digest;

const USERNAME : &str = "testuser";
const PASSWORD : &str = "1234";

const USERNAME2: &str = "testuser2";
const PASSWORD2: &str = "4321";

#[test]
fn test_add_record() {
    let mut program = Program::default();

    //login in
    program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .unwrap();

    let record1 = Record::new("rec1".to_string(), Some("Petko".to_string()), None, None);
    let record2 = Record::new(
        "rec2".to_string(),
        Some("Petko".to_string()),
        Some("petko@abv.bg".to_string()),
        Some("1234".to_string()),
    );
    let record3 = Record::new(
        "rec3".to_string(),
        Some("vanyo".to_string()),
        Some("vanyo@abv.bg".to_string()),
        Some("123456".to_string()),
    );
    assert!(program.add_record(record1.clone()).is_ok());
    assert_eq!(program.get_len_of_records(), 1);

    assert!(program.add_record(record2).is_ok());
    assert_eq!(program.get_len_of_records(), 2);

    assert!(program.add_record(record3).is_ok());
    assert_eq!(program.get_len_of_records(), 3);

    assert!(program.add_record(record1).is_err());
    assert_eq!(program.get_len_of_records(), 3);

    assert_eq!(
        program.get_record_by_name("rec1").unwrap().username,
        Some("Petko".to_string())
    );
}

#[test]
fn test_login_non_existing_user() {
    let mut program = Program::default();
    assert!(program
        .login("no_name".to_string(), "1234".to_string(), digest("1234"))
        .is_err());
}

#[test]
fn test_login_existing_user() {
    let mut program = Program::default();
    assert!(program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .is_ok());
}

#[test]
fn test_login_while_already_logged() {
    let mut program = Program::default();
    assert!(program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .is_ok());
    assert!(program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .is_err());
}

#[test]
fn test_logout() {
    let mut program = Program::default();
    assert!(program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .is_ok());
    assert!(program.logout().is_ok());

    let record1 = Record::new("rec1".to_string(), Some("Petko".to_string()), None, None);

    assert!(program.add_record(record1).is_err());
}

#[test]
fn test_delete_record() {
    let mut program = Program::default();
    assert!(program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .is_ok());
    let record1 = Record::new("rec1".to_string(), Some("Petko".to_string()), None, None);
    let record2 = Record::new(
        "rec2".to_string(),
        Some("Petko".to_string()),
        Some("petko.abv.bg".to_string()),
        Some("1234".to_string()),
    );
    assert!(program.add_record(record1).is_ok());
    assert!(program.add_record(record2).is_ok());
    assert_eq!(program.get_len_of_records(), 2);

    assert!(program.delete_record("rec1").is_ok());
    assert_eq!(program.get_len_of_records(), 1);
    assert!(program.delete_record("rec2").is_ok());
    assert_eq!(program.get_len_of_records(), 0);
}

#[test]
fn test_register_new_user() {
    let mut program = Program::default();
    let user = User::new("username".to_string(), digest("pass"));
    let user2 = User::new("username2".to_string(), digest("pass2"));

    assert!(program.register_user(user.clone()).is_ok()); // first register is successful, there is no such user

    assert!(program
        .login("username".to_string(), "pass".to_string(), digest("pass"))
        .is_ok()); // so the login should be successful

    assert!(program.register_user(user2).is_err()); // second register is not successful, because we are already logged

    assert!(program.logout().is_ok()); // logout should be successful, because we are logged

    assert!(program.register_user(user).is_err()); // third register is not successful, because we have the same user already

    assert!(program
        .login("username".to_string(), "pass".to_string(), digest("pass"))
        .is_ok()); // now we can login again

    assert!(program.delete_user("username").is_ok()); // delete the user for the next tests
}

// Some tests for the encryption and decryption
#[test]
fn test_encryption_and_decryption() {
    let mut program = Program::default();
    assert!(program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .is_ok());
    let result = program.encrypt_data(&"pass".to_string());
    assert_eq!(program.decrypt_data(&result), "pass".to_string());
}

#[test]
#[should_panic]
fn test_encryption_and_decryption_but_with_wrong_user() {
    let mut program = Program::default();
    assert!(program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .is_ok());
    
    let result = program.encrypt_data(&"pass".to_string());

    assert!(program.logout().is_ok());
    assert!(program
        .login(USERNAME2.to_string(), PASSWORD2.to_string(), digest(PASSWORD2))
        .is_ok());
    
    assert_ne!(program.decrypt_data(&result), "pass".to_string());
}

#[test]
fn test_encryption_and_decryption_with_empty_string() {
    let mut program = Program::default();
    assert!(program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .is_ok());
    let result = program.encrypt_data(&"".to_string());
    assert_eq!(program.decrypt_data(&result), "".to_string());
}

//Searchin tests

#[test]
fn test_simple_search_function() {
    let records = vec![
        Record::new("abc".to_string(), None, None, None),
        Record::new("efg".to_string(), None, None, None),
        Record::new("pet".to_string(), None, None, None),
        Record::new("wee".to_string(), None, None, None),
    ];
    let needle = "pet";
    let result = Program::search(&records, needle);

    assert_eq!(result.len(), 1);
    assert_eq!(result[0], 2);
}

#[test]
fn test_search_with_two_matches() {
    let records = vec![
        Record::new("abc".to_string(), None, None, None),
        Record::new("efg".to_string(), None, None, None),
        Record::new("pet".to_string(), None, None, None),
        Record::new("wee".to_string(), None, None, None),
        Record::new("petko".to_string(), None, None, None),
    ];
    let needle = "pet";
    let result = Program::search(&records, needle);

    assert_eq!(result.len(), 2);
    assert_eq!(result[0], 2);
    assert_eq!(result[1], 4);
}

#[test]
fn test_search_with_four_matches() {
    let records = vec![
        Record::new("petko".to_string(), None, None, None), // 1
        Record::new("gosho".to_string(), None, None, None),
        Record::new("chefo".to_string(), None, None, None),
        Record::new("pet".to_string(), None, None, None), // 4
        Record::new("Vili".to_string(), None, None, None),
        Record::new("petko".to_string(), None, None, None), // 6
        Record::new("ivan".to_string(), None, None, None),
        Record::new("petko".to_string(), None, None, None), // 8
    ];
    let needle = "pet";
    let result = Program::search(&records, needle);

    assert_eq!(result.len(), 4);
    assert_eq!(result[0], 0);
    assert_eq!(result[1], 3);
    assert_eq!(result[2], 5);
    assert_eq!(result[3], 7);
}

#[test]
fn test_search_with_multiple_matches_2() {
    let records = vec![
        Record::new("BBC".to_string(), None, None, None), // 1
        Record::new("BBC2".to_string(), None, None, None),
        Record::new("BNT".to_string(), None, None, None),
        Record::new("BBC3".to_string(), None, None, None), // 4
    ];
    let needle = "BBC";
    let result = Program::search(&records, needle);

    assert_eq!(result.len(), 3);
    assert_eq!(result[0], 0);
    assert_eq!(result[1], 1);
    assert_eq!(result[2], 3);
}

#[test]
fn test_search_with_four_matches_and_two_matches_in_word() {
    let records = vec![
        Record::new("gosho".to_string(), None, None, None), // 1 no match
        Record::new("chefo".to_string(), None, None, None), // 2 no match
        Record::new("petko petkov petkov".to_string(), None, None, None), // match 3
        Record::new("vili petkov".to_string(), None, None, None), // match 4
        Record::new("ivan".to_string(), None, None, None), // 5 no match
        Record::new("petko".to_string(), None, None, None), // 6 match
    ];
    let needle = "petko";
    let result = Program::search(&records, needle);

    assert_eq!(result.len(), 3);
    assert_eq!(result[0], 2);
    assert_eq!(result[1], 3);
    assert_eq!(result[2], 5);
}