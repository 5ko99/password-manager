use password_manager::{program::{Program, User}, record::Record};
use sha256::digest;

#[test]
fn test_add_record() {
    let mut program = Program::default();

    //login in
    program.login("a".to_string(), "1234".to_string(),digest("1234")).unwrap();


    let record1 = Record::new("rec1".to_string(), Some("Petko".to_string()), None, None);
    let record2 = Record::new("rec2".to_string(), Some("Petko".to_string()), Some("petko@abv.bg".to_string()), Some("1234".to_string()));
    let record3 = Record::new("rec3".to_string(), Some("vanyo".to_string()), Some("vanyo@abv.bg".to_string()), Some("123456".to_string()));
    assert!(program.add_record(record1.clone()).is_ok());
    assert_eq!(program.get_len_of_records(), 1);

    assert!(program.add_record(record2).is_ok());
    assert_eq!(program.get_len_of_records(), 2);

    assert!(program.add_record(record3).is_ok());
    assert_eq!(program.get_len_of_records(), 3);

    assert!(program.add_record(record1).is_err());
    assert_eq!(program.get_len_of_records(), 3);

    assert_eq!(program.get_record_by_name("rec1").unwrap().username, Some("Petko".to_string()));
}

#[test]
fn test_login_non_existing_user() {
    let mut program = Program::default();
    assert!(program.login("no_name".to_string(), "1234".to_string(), digest("1234")).is_err());
}

#[test]
fn test_login_existing_user() {
    let mut program = Program::default();
    assert!(program.login("a".to_string(), "1234".to_string(), digest("1234")).is_ok());
}

#[test]
fn test_login_while_already_logged() {
    let mut program = Program::default();
    assert!(program.login("a".to_string(), "1234".to_string(), digest("1234")).is_ok());
    assert!(program.login("a".to_string(), "1234".to_string(), digest("1234")).is_err());
}

#[test]
fn test_logout() {
    let mut program = Program::default();
    assert!(program.login("a".to_string(), "1234".to_string(), digest("1234")).is_ok());
    assert!(program.logout().is_ok());

    let record1 = Record::new("rec1".to_string(), Some("Petko".to_string()), None, None);

    assert!(program.add_record(record1).is_err());
}

#[test]
fn test_delete_record() {
    let mut program = Program::default();
    assert!(program.login("a".to_string(), "1234".to_string(), digest("1234")).is_ok());
    let record1 = Record::new("rec1".to_string(), Some("Petko".to_string()), None, None);
    let record2 = Record::new("rec2".to_string(), Some("Petko".to_string()), Some("petko.abv.bg".to_string()), Some("1234".to_string()));
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

    assert!(program.login("username".to_string(), "pass".to_string(), digest("pass")).is_ok()); // so the login should be successful
    
    assert!(program.register_user(user2).is_err()); // second register is not successful, because we are already logged

    assert!(program.logout().is_ok()); // logout should be successful, because we are logged

    assert!(program.register_user(user).is_err()); // third register is not successful, because we have the same user already

    assert!(program.login("username".to_string(), "pass".to_string(), digest("pass")).is_ok()); // now we can login again

    assert!(program.delete_user("username").is_ok()); // delete the user for the next tests
}