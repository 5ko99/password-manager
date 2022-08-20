use password_manager::record::Record;

#[test]
fn test_record_new() {
    let record = Record::new("test".to_string(), None, None, None);
    assert_eq!(record.record_name, "test");
    assert_eq!(record.username, None);
    assert_eq!(record.email, None);
    assert_eq!(record.password, None);
}

#[test]
fn test_record_eq() {
    let record1 = Record::new("test".to_string(), Some("Petko".to_string()), None, None);
    let record2 = Record::new("test".to_string(), None, None, None);
    assert_eq!(record1, record2);
}

#[test]
fn test_record_neq() {
    let record1 = Record::new("testche".to_string(), Some("Petko".to_string()), None, None);
    let record2 = Record::new("test".to_string(), None, None, None);
    assert_ne!(record1, record2);
}

#[test]
fn test_record_eq_username() {
    let record1 = Record::new("test".to_string(), Some("Petko".to_string()), None, None);
    let record2 = Record::new("test".to_string(), Some("Petko".to_string()), None, None);
    assert_eq!(record1, record2);
}