use password_manager::{program::Program, record::Record, user::User};

use serial_test::serial;
use sha256::digest;

const USERNAME: &str = "testuser";
const PASSWORD: &str = "1234";

//TESTS MUST BE RUNNED WITH : cargo test -- --test-threads=1

#[test]
#[serial]
fn test_add_record() {
    let mut program = Program::default();

    //login in
    program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .unwrap();

    let record1 = Record::new("rec1", "Petko", "", "");
    let record2 = Record::new("rec2", "Petko", "petko@abv.bg", "1234");
    let record3 = Record::new("rec3", "vanyo", "vanyo@abv.bg", "123456");
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
        "Petko"
    );
}

#[test]
#[serial]
fn test_login_non_existing_user() {
    let mut program = Program::default();
    assert!(program
        .login("no_name".to_string(), "1234".to_string(), digest("1234"))
        .is_err());
}

#[test]
#[serial]
fn test_login_existing_user() {
    let mut program = Program::default();
    assert!(program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .is_ok());
}

#[test]
#[serial]
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
#[serial]
fn test_logout() {
    let mut program = Program::default();
    assert!(program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .is_ok());
    assert!(program.logout().is_ok());

    let record1 = Record::new("rec1", "Petko", "", "");

    assert!(program.add_record(record1).is_err());
}

#[test]
#[serial]
fn test_delete_record() {
    let mut program = Program::default();
    assert!(program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .is_ok());
    let record1 = Record::new("rec1", "Petko", "", "");
    let record2 = Record::new("rec2", "Petko", "petko@abv.bg", "1234");
    assert!(program.add_record(record1.clone()).is_ok());
    assert!(program.add_record(record2.clone()).is_ok());
    assert_eq!(program.get_len_of_records(), 2);

    assert!(program.delete_record(record1).is_ok());
    assert_eq!(program.get_len_of_records(), 1);
    assert!(program.delete_record(record2).is_ok());
    assert_eq!(program.get_len_of_records(), 0);
}

#[test]
#[serial]
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

//Searchin tests

#[test]
fn test_simple_search_function() {
    let records = vec![
        Record::new("abc", "", "", ""),
        Record::new("efg", "", "", ""),
        Record::new("pet", "", "", ""),
        Record::new("wee", "", "", ""),
    ];
    let needle = "pet";
    let result = Program::search(&records, needle);

    assert_eq!(result.len(), 1);
    assert_eq!(result[0], 2);
}

#[test]
fn test_search_with_two_matches() {
    let records = vec![
        Record::new("abc", "", "", ""),
        Record::new("efg", "", "", ""),
        Record::new("pet", "", "", ""),
        Record::new("wee", "", "", ""),
        Record::new("petko", "", "", ""),
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
        Record::new("petko", "", "", ""), // 1
        Record::new("gosho", "", "", ""),
        Record::new("chefo", "", "", ""),
        Record::new("pet", "", "", ""), // 4
        Record::new("Vili", "", "", ""),
        Record::new("petko", "", "", ""), // 6
        Record::new("ivan", "", "", ""),
        Record::new("petko", "", "", ""), // 8
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
        Record::new("BBC", "", "", ""), // 1
        Record::new("BBC2", "", "", ""),
        Record::new("BNT", "", "", ""),
        Record::new("BBC3", "", "", ""), // 4
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
        Record::new("gosho", "", "", ""),               // 1 no match
        Record::new("chefo", "", "", ""),               // 2 no match
        Record::new("petko petkov petkov", "", "", ""), // match 3
        Record::new("vili petkov", "", "", ""),         // match 4
        Record::new("ivan", "", "", ""),                // 5 no match
        Record::new("petko", "", "", ""),               // 6 match
    ];
    let needle = "petko";
    let result = Program::search(&records, needle);

    assert_eq!(result.len(), 3);
    assert_eq!(result[0], 2);
    assert_eq!(result[1], 3);
    assert_eq!(result[2], 5);
}

#[test]
#[serial]
fn change_pass_test() {
    let mut program = Program::default();
    let record = Record::new("Twitter", "petko", "petko@abv.bg", "somepass123");

    assert!(program
        .login(USERNAME.to_string(), PASSWORD.to_string(), digest(PASSWORD))
        .is_ok());

    assert!(program.add_record(record.clone()).is_ok());

    assert!(Program::change_password("newpass",program.logged_user.as_mut().unwrap()).is_ok());
    
    assert!(program.logout().is_ok());

    assert!(program
        .login(
            USERNAME.to_string(),
            "newpass".to_string(),
            digest("newpass")
        )
        .is_ok());
    assert!(program.load_and_decrypt_data().is_ok());

    assert!(program.records.contains(&record));

    //Finally
    assert!(Program::change_password(PASSWORD,program.logged_user.as_mut().unwrap()).is_ok());
}