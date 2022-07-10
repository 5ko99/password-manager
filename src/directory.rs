use crate::record::Record;
use std::rc::Rc;

#[derive(Default, Debug)]
pub struct Directory {
    pub name: String,
    pub records: Vec<Rc<Record>>,
    deleted: bool,
}

impl Directory {
    pub fn new(name: String) -> Directory {
        Directory {
            name: name,
            ..Default::default()
        }
    }

    pub fn add_record(&mut self, record: Rc<Record>) -> Result<(), std::io::Error> {
        if self.records.contains(&record) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Record already in directory",
            ));
        } else {
            self.records.push(record);
            return Ok(());
        }
    }

    fn remove_record_by_name(&mut self, record_name: &str) -> Result<(), std::io::Error> {
        let mut index = 0;
        for record in self.records.iter() {
            if record.record_name == record_name {
                self.records.remove(index);
                return Ok(());
            }
            index += 1;
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Record not in directory",
        ))
    }

    pub fn remove_record(&mut self, record: Rc<Record>) -> Result<(), std::io::Error> {
        self.remove_record_by_name(&record.record_name)
    }

    pub fn update_dir(&mut self) {
        for i in 0..self.records.len() {
            if self.records[i].is_deleted() {
                self.records.remove(i);
            }
        }
    }

    pub fn delete_directory(&mut self) {
        self.deleted = true;
    }
}
