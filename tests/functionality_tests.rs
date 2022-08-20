use password_manager::{program::Program, record::Record};
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