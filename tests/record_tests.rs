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

#[test]
fn test_get_by_index() {
    let record = Record::new("test".to_string(), Some("Petko".to_string()), None, Some("123".to_string()));
    assert_eq!(record[0], "test");
    assert_eq!(record[1], "Petko");
    assert_eq!(record[3], "123");
}

#[test]
#[should_panic]
fn test_get_by_index_panic() {
    let record = Record::new("test".to_string(), Some("Petko".to_string()), None, Some("123".to_string()));
    let _ = &record[4];
}

#[test]
#[should_panic]
fn test_get_by_index_panic2() {
    let record = Record::new("test".to_string(), Some("Petko".to_string()), None, Some("123".to_string()));
    let _ = &record[2];
}

#[test]
fn test_get_by_index_mut() {
    let mut record = Record::new("test".to_string(), Some("Petko".to_string()), None, Some("123".to_string()));
    record[0] = "test2".to_string();
    assert_eq!(record[0], "test2");
}

#[test]
fn test_get_function() {
    let record = Record::new("test".to_string(), Some("Petko".to_string()), None, Some("123".to_string()));
    assert_eq!(record.get(0).unwrap(), "test");
    assert_eq!(record.get(1).unwrap(), "Petko");
    assert_eq!(record.get(2), None);
    assert_eq!(record.get(3).unwrap(), "123");
}

#[test]
fn test_get_function_mut() {
    let mut record = Record::new("test".to_string(), Some("Petko".to_string()), None, Some("123".to_string()));
    record.get_mut(0).unwrap().clone_from(&"another_name".to_string());
    assert_eq!(record.get(0).unwrap(), "another_name");
}

#[test]
#[should_panic]
fn test_get_function_mut_panic() {
    let mut record = Record::new("test".to_string(), Some("Petko".to_string()), None, Some("123".to_string()));
    record.get_mut(4).unwrap().clone_from(&"another_name".to_string());
}