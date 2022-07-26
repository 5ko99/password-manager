use crate::record::Record;
use std::rc::Rc;

#[derive(Default, Debug)]
pub struct Directory {
    pub name: String,
    records: Vec<Rc<Record>>,
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

    pub fn remove_record_by_name(&mut self, record_name: &str) -> Result<(), std::io::Error> {
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

    pub fn remove_record_by_index(&mut self, index: usize) -> Result<(), std::io::Error> {
        if index >= self.records.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Index out of range",
            ));
        } else {
            self.records.remove(index);
            return Ok(());
        }
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

    pub fn get(&self, index: usize) -> Option<Rc<Record>> {
        if index >= self.records.len() {
            return None;
        } else {
            return Some(self.records[index].clone());
        }
    }

    pub fn length(&self) -> usize {
        self.records.len()
    }

}
