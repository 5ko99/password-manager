use password_manager::directory::Directory;
use password_manager::record::Record;
use std::rc::Rc;

#[test]
fn create_directory_test_name() {
   let directory = Directory::new("test".to_string());
    assert_eq!(directory.name, "test");
}

#[test]
fn create_directory_test_records() {
    let mut directory = Directory::new("test".to_string());
    assert_eq!(directory.length(), 0);

    let record1 = Record::new("record1".to_string(), Some("TestName".to_string()), None, None);
    let record2 = Record::new("record2".to_string(), Some("TestName2".to_string()), None, Some("1234".to_string()));
    let record3 = Record::new("record3".to_string(), Some("TestName3".to_string()), None, Some("1234".to_string()));

    directory.add_record(Rc::new(record1.clone())).unwrap();
    directory.add_record(Rc::new(record2.clone())).unwrap();
    directory.add_record(Rc::new(record3.clone())).unwrap();

    assert_eq!(directory.length(), 3);

    assert_eq!(directory.get(0).unwrap().as_ref(), &record1);
    assert_eq!(directory.get(1).unwrap().as_ref(), &record2);
    assert_eq!(directory.get(2).unwrap().as_ref(), &record3);

    directory.remove_record_by_name("record2").unwrap();

    assert_eq!(directory.length(), 2);

    assert_eq!(directory.get(0).unwrap().as_ref(), &record1);
    assert_eq!(directory.get(1).unwrap().as_ref(), &record3);

    directory.remove_record_by_index(0).unwrap();

    assert_eq!(directory.length(), 1);

    assert_eq!(directory.get(0).unwrap().as_ref(), &record3);

    directory.remove_record(Rc::new(record3.clone())).unwrap();

    assert_eq!(directory.length(), 0);
}