use password_manager::record::Record;

#[test]
fn test_record_new() {
    let record = Record::new("test", "", "", "");
    assert_eq!(record.name, "test");
    assert_eq!(record.username, "");
    assert_eq!(record.email, "");
    assert_eq!(record.password, "");
}

#[test]
fn test_record_eq() {
    let record1 = Record::new("test", "Petko", "", "1234");
    let record2 = Record::new("test", "ivan", "ivan@abv.bg", "1234");
    assert_eq!(record1, record2);
}

#[test]
fn test_record_neq() {
    let record1 = Record::new("facebook", "ivan", "", "");
    let record2 = Record::new("twitter", "", "", "");
    assert_ne!(record1, record2);
}

#[test]
fn test_record_eq_username() {
    let record1 = Record::new("abv", "Petko", "", "1234");
    let record2 = Record::new("gmail", "Petko", "", "1234");
    assert_ne!(record1, record2);
}

#[test]
fn test_get_by_index() {
    let record = Record::new("bnr","ivan", "ivan@abv.bg", "q1w2e3r4");
    assert_eq!(record[0], "bnr");
    assert_eq!(record[1], "ivan");
    assert_eq!(record[2], "ivan@abv.bg");
    assert_eq!(record[3], "q1w2e3r4");
}

#[test]
#[should_panic]
fn test_get_by_index_panic() {
    let record = Record::new("bnr","ivan", "ivan@abv.bg", "q1w2e3r4");
    let _ = &record[4];
}

#[test]
fn test_get_by_index_mut() {
    let mut record = Record::new("bnr","ivan", "ivan@abv.bg", "q1w2e3r4");
    record[0] = "Twitter".to_string();
    assert_eq!(record[0], "Twitter");
}

#[test]
fn test_get_function() {
    let record = Record::new("Guardian","petko99", "", "aa123456aa");
    assert_eq!(record.get(0).unwrap(), "Guardian");
    assert_eq!(record.get(1).unwrap(), "petko99");
    assert_eq!(record.get(2).unwrap(), "");
    assert_eq!(record.get(3).unwrap(), "aa123456aa");
    assert_eq!(record.get(4), None);
}

#[test]
fn test_get_invalid_field() {
    let record = Record::new("Guardian","petko99", "", "aa123456aa");
    assert_eq!(record.get(4), None);
    assert_eq!(record.get(5), None);
}

#[test]
fn test_get_function_mut() {
    let mut record = Record::new("Guardian","petko99", "", "aa123456aa");
    record.get_mut(0).unwrap().clone_from(&"another_name".to_string());
    assert_eq!(record.get(0).unwrap(), "another_name");
}

#[test]
#[should_panic]
fn test_get_function_mut_panic() {
    let mut record = Record::new("Guardian","petko99", "", "aa123456aa");
    record.get_mut(4).unwrap().clone_from(&"another_name".to_string());
}

#[test]
fn test_len() {
    assert_eq!(Record::len(), 4);
}

#[test]
fn test_is_empty_false() {
    let record = Record::new("Guardian","petko99", "", "aa123456aa");
    assert_eq!(record.is_empty(), false);
}

#[test]
fn test_is_empty_true() {
    let record = Record::new("","","","");
    assert_eq!(record.is_empty(), true);
}